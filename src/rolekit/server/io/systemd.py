# -*- coding: utf-8 -*-
#
# Copyright (C) 2011-2012 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>
# Stephen Gallagher <sgallagh@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import os
import shutil
import json
import configparser
import sys


from rolekit.errors import RolekitError
from rolekit.config import SYSTEMD_UNITS, SYSTEMD_DEPS, DBUS_SEND
from rolekit.config.dbus import DBUS_INTERFACE, DBUS_PATH
from rolekit.dbus_utils import SystemdJobHandler

def enable_units(units):
    '''
    This routine enables systemd units and triggers a reload.
    Without the reload, the change in behavior is not communicated
    to client applications such as systemctl (it will still take
    effect on the next boot, but tools will not reflect this
    reality).
    :param units: A list containing one or more units to enable
    :return:Nothing
    '''
    with SystemdJobHandler() as job_handler:
        job_handler.manager.EnableUnitFiles(units, False, True)
        job_handler.manager.Reload()

def disable_units(units):
    '''
    This routine disables systemd units and triggers a reload.
    Without the reload, the change in behavior is not communicated
    to client applications such as systemctl (it will still take
    effect on the next boot, but tools will not reflect this
    reality).
    :param units: A list containing one or more units to enable
    :return:Nothing
    '''
    with SystemdJobHandler() as job_handler:
        job_handler.manager.DisableUnitFiles(units, False)
        job_handler.manager.Reload()

def escape_systemd_unit(unit):
    # This is quick-and-dirty; it is not a complete implementation
    # It only addresses the escapes that we allow in our unit names
    return unit.replace(".", "_2e").replace("-", "_2d")

class SystemdTargetUnit(dict):
    """
    Class to create and write out the target units

    This unit file will establish a relationship with all of the
    necessary dependent services and sockets so that they are
    started when the role is launched.
    """


    def __init__(self, target, *args, **kwargs):
        super(SystemdTargetUnit, self).__init__(*args, **kwargs)
        self.filepath = "%s/%s" % (SYSTEMD_UNITS, target['targetname'])
        self.target = target


    def write(self):
        extension_units = {}

        try:
            shutil.copy2(self.filepath, "%s.old" % self.filepath)
        except Exception as msg:
            if os.path.exists(self.filepath):
                raise IOError("Backup of '%s' failed: %s" % (self.filepath,
                                                             msg))

        with open(self.filepath, "w") as f:
            # Write the [Unit] section
            f.write("[Unit]\n")
            f.write("Description=%s\n" % self.target['Description'])

            # Add in any supported dependencies.
            # This is intentionally a subset of systemd capabilities.
            # The expectation is that more complex dependencies should
            # be managed by the individual services, not the role
            # target.
            for dep in SYSTEMD_DEPS:
                if dep in self.target:
                    for unit in self.target[dep]:
                        # Add the unit to the extension_units list
                        # We add it as a key to automatically
                        # de-duplicate
                        extension_units[dep] = None
                        f.write("%s=%s\n" % (dep, unit))

            # Write the [Install] section
            f.write('\n[Install]\n')

            # All roles are associated with the built-in multi-user target.
            f.write('WantedBy=multi-user.target\n')

            # Return the list of extension units
            return self.filepath, extension_units.keys()


    def remove(self):
        try:
            os.remove(self.filepath)
        except OSError:
            pass

class SystemdFailureUnit(dict):
    """
    This class creates a special systemd unit file that will be called
    if systemd detects that one of the services that we depend on has
    exited unexpectedly (such as a crash). It will emit a DBUS
    message to the rolekit primary interface so that the role state
    can be updated (and registered clients can be notified)
    """
    def __init__(self, target, *args, **kwargs):
        super(SystemdFailureUnit, self).__init__(*args, **kwargs)
        self.target = target
        self.filepath = "%s/%s" % (SYSTEMD_UNITS, target['failurename'])


    def write(self):
        # First construct the dbus-send command
        dsend = "{DBUS_SEND} --system --dest={DBUS_INTERFACE} " \
                "{DBUS_PATH} {DBUS_INTERFACE}.{FAIL_METHOD} " \
                "string:'{ROLE}' string:'{INSTANCE}'".format(
                DBUS_SEND=DBUS_SEND,
                DBUS_INTERFACE=DBUS_INTERFACE,
                DBUS_PATH=DBUS_PATH,
                FAIL_METHOD="NotifyUnitFailed",
                ROLE=self.target['Role'],
                INSTANCE=self.target['Instance'])

        try:
            shutil.copy2(self.filepath, "%s.old" % self.filepath)
        except Exception as msg:
            if os.path.exists(self.filepath):
                raise IOError("Backup of '%s' failed: %s" % (self.filepath,
                                                             msg))
        with open(self.filepath, "w") as f:
            # Write the [Unit] section
            f.write("[Unit]\n")
            f.write("Description=Failure notification for %s\n\n" % (
                     self.target['targetname']))

            # Write the [Service] section
            f.write("[Service]\n")
            f.write("ExecStart=%s\n" % dsend)
            return self.filepath

    def remove(self):
        try:
            os.remove(self.filepath)
        except OSError:
            pass


class SystemdExtensionUnits(dict):
    """
    Class to write out the extension units for dependent services

    These extension units are used to ensure that if we turn off the
    role (such as calling 'systemctl stop') all of the dependent
    services will also be shutdown at the same time. It is essentially
    providing the inverse of the SystemdTargetUnit operation.
    """
    def __init__(self, target, *args, **kwargs):
        super(SystemdExtensionUnits, self).__init__(*args, **kwargs)
        self.target = target


    def write(self, unit):
        extdir = "%s/%s.d/" % (SYSTEMD_UNITS, unit)
        unitfile = "%s/%s.conf" % (extdir,
                                   self.target['targetname'])

        try:
            os.mkdir(extdir)
        except OSError:
            pass

        try:
            shutil.copy2(unitfile, "%s.old" % unitfile)
        except Exception as msg:
            if os.path.exists(unitfile):
                raise IOError("Backup of '%s' failed: %s" % (unitfile,
                                                             msg))
        with open(unitfile, "w") as f:
            f.write("[Unit]\n")
            f.write("PartOf=%s\n" % self.target['targetname'])
            f.write("OnFailure=%s\n" % self.target['failurename'])
            return unitfile


class SystemdContainerServiceUnit():
    """
    Class to write out service units for contained services

    image_name: The name of the docker image to run from
    container_name: A name to give the started image
    desc: A description for the systemd unit file
    env: An dictionary of environment variables to pass to the image
    ports: An array of port mappings. Mappings must be specified in
           the exact format that Docker uses. See docker-run(1) for
           details.
           e.g. ("1234:1234", "1235-1237:8035-8037/tcp")
    """

    def __init__(self,
                 image_name=None,
                 container_name=None,
                 desc=None,
                 env=None,
                 ports=None):

        if not image_name:
            raise RolekitError("Missing container image name")
        if not desc:
            raise RolekitError("Missing description")
        if not ports:
            raise RolekitError("No ports specified")

        self.image_name = image_name
        self.container_name = container_name
        self.desc = desc
        self.ports = ports

        if env:
            self.env = env
        else:
            self.env = {}

    def write(self):
        path = "%s/%s.service" % (SYSTEMD_UNITS, self.container_name)

        docker_run = "/usr/bin/docker run --name=%s" % self.container_name
        for key in self.env:
            docker_run += " --env %s=%s" % (key, self.env[key])

        for mapping in self.ports:
            docker_run += " -p %s" % mapping
        docker_run += " %s" % self.image_name

        with open(path, "w") as f:
            f.write("[Unit]\n")
            f.write("Description=%s\n" % self.desc)
            f.write("Requires=docker.service\n")
            f.write("After=docker.service\n\n")
            f.write("[Service]\n")
            f.write("Restart=always\n")
            f.write("ExecStart=%s\n" % docker_run)
            f.write("ExecStop=/usr/bin/docker stop -t 5 {0} ; /usr/bin/docker rm -f {0}\n\n".format(self.container_name))
            f.write("[Install]\n")
            f.write("WantedBy=multi-user.target\n")


"""
Sections of this parser are adapted from:

http://stackoverflow.com/questions/13921323/handling-duplicate-keys-with-configparser
LICENSE: https://creativecommons.org/licenses/by-sa/3.0/ (CC-BY-SA 3.0)
Original Author: Praetorian on StackExchange
"""

class SystemdUnitParser(configparser.RawConfigParser):
    """ConfigParser allowing duplicate keys. Values are stored in a list"""

    def __init__(self):
        configparser.RawConfigParser.__init__(self, empty_lines_in_values=False, strict=False)

    @staticmethod
    def optionxform(option):
        """
        Override the RawConfigParser behavior of lower-casing options
        We need the options to remain capitalized as they are.
        :param option: The option name (not) being transformed
        :return: The option exactly as it exists
        """
        return option

    def _read(self, fp, fpname):
        """Parse a sectioned configuration file.

        Each section in a configuration file contains a header, indicated by
        a name in square brackets (`[]'), plus key/value options, indicated by
        `name' and `value' delimited with a specific substring (`=' or `:' by
        default).

        Values can span multiple lines, as long as they are indented deeper
        than the first line of the value. Depending on the parser's mode, blank
        lines may be treated as parts of multiline values or ignored.

        Configuration files may include comments, prefixed by specific
        characters (`#' and `;' by default). Comments may appear on their own
        in an otherwise empty line or may be entered in lines holding values or
        section names.
        """
        elements_added = set()
        cursect = None  # None, or a dictionary
        sectname = None
        optname = None
        lineno = 0
        indent_level = 0
        e = None  # None, or an exception
        for lineno, line in enumerate(fp, start=1):
            comment_start = sys.maxsize
            # strip inline comments
            inline_prefixes = {p: -1 for p in self._inline_comment_prefixes}
            while comment_start == sys.maxsize and inline_prefixes:
                next_prefixes = {}
                for prefix, index in inline_prefixes.items():
                    index = line.find(prefix, index + 1)
                    if index == -1:
                        continue
                    next_prefixes[prefix] = index
                    if index == 0 or (index > 0 and line[index - 1].isspace()):
                        comment_start = min(comment_start, index)
                inline_prefixes = next_prefixes
            # strip full line comments
            for prefix in self._comment_prefixes:
                if line.strip().startswith(prefix):
                    comment_start = 0
                    break
            if comment_start == sys.maxsize:
                comment_start = None
            value = line[:comment_start].strip()
            if not value:
                if self._empty_lines_in_values:
                    # add empty line to the value, but only if there was no
                    # comment on the line
                    if (comment_start is None and
                                cursect is not None and
                            optname and
                                cursect[optname] is not None):
                        cursect[optname].append('')  # newlines added at join
                else:
                    # empty line marks end of value
                    indent_level = sys.maxsize
                continue
            # continuation line?
            first_nonspace = self.NONSPACECRE.search(line)
            cur_indent_level = first_nonspace.start() if first_nonspace else 0
            if (cursect is not None and optname and
                        cur_indent_level > indent_level):
                cursect[optname].append(value)
            # a section header or option header?
            else:
                indent_level = cur_indent_level
                # is it a section header?
                mo = self.SECTCRE.match(value)
                if mo:
                    sectname = mo.group('header')
                    if sectname in self._sections:
                        cursect = self._sections[sectname]
                        elements_added.add(sectname)
                    elif sectname == self.default_section:
                        cursect = self._defaults
                    else:
                        cursect = self._dict()
                        self._sections[sectname] = cursect
                        self._proxies[sectname] = configparser.SectionProxy(self, sectname)
                        elements_added.add(sectname)
                    # So sections can't start with a continuation line
                    optname = None
                # no section header in the file?
                elif cursect is None:
                    raise configparser.MissingSectionHeaderError(fpname, lineno, line)
                # an option line?
                else:
                    mo = self._optcre.match(value)
                    if mo:
                        optname, vi, optval = mo.group('option', 'vi', 'value')
                        if not optname:
                            e = self._handle_error(e, fpname, lineno, line)
                        optname = self.optionxform(optname.rstrip())
                        elements_added.add((sectname, optname))
                        # This check is fine because the OPTCRE cannot
                        # match if it would set optval to None
                        if optval is not None:
                            optval = optval.strip()
                            # Check if this optname already exists
                            if (optname in cursect) and (cursect[optname] is not None):
                                # If it does, convert it to a tuple if it isn't already one
                                if not isinstance(cursect[optname], tuple):
                                    cursect[optname] = tuple(cursect[optname])
                                cursect[optname] = cursect[optname] + tuple([optval])
                            else:
                                cursect[optname] = [optval]
                        else:
                            # valueless option handling
                            cursect[optname] = None
                    else:
                        # a non-fatal parsing error occurred. set up the
                        # exception but keep going. the exception will be
                        # raised at the end of the file and will contain a
                        # list of all bogus lines
                        e = self._handle_error(e, fpname, lineno, line)
        # if any parsing errors occurred, raise an exception
        if e:
            raise e
        self._join_multiline_values()

    def _validate_value_types(self, *, section="", option="", value=""):
        """Raises a TypeError for non-string values.

        The only legal non-string value if we allow valueless
        options is None, so we need to check if the value is a
        string if:
        - we do not allow valueless options, or
        - we allow valueless options but the value is not None

        For compatibility reasons this method is not used in classic set()
        for RawConfigParsers. It is invoked in every case for mapping protocol
        access and in ConfigParser.set().
        """
        if not isinstance(section, str):
            raise TypeError("section names must be strings")
        if not isinstance(option, str):
            raise TypeError("option keys must be strings")
        if not self._allow_no_value or value:
            if not isinstance(value, str) and not isinstance(value, tuple):
                raise TypeError("option values must be strings or a tuple of strings")

    # Write out duplicate keys with their values
    def _write_section(self, fp, section_name, section_items, delimiter):
        """Write a single section to the specified `fp'."""
        fp.write("[{}]\n".format(section_name))
        for key, vals in section_items:
            vals = self._interpolation.before_write(self, section_name, key,
                                                    vals)
            if not isinstance(vals, tuple):
                vals = tuple([vals])
            for value in vals:
                if value is not None or not self._allow_no_value:
                    value = delimiter + str(value).replace('\n', '\n\t')
                else:
                    value = ""
                fp.write("{}{}\n".format(key, value))
        fp.write("\n")

    # Default to not creating spaces around the delimiter
    def write(self, fp, space_around_delimiters=False):
        configparser.RawConfigParser.write(self, fp, space_around_delimiters)
