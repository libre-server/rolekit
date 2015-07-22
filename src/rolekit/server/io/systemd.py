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

from rolekit.errors import RolekitError
from rolekit.config import SYSTEMD_UNITS, SYSTEMD_DEPS, DBUS_SEND
from rolekit.config.dbus import DBUS_INTERFACE, DBUS_PATH

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
            return extension_units.keys()


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
        pass


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
