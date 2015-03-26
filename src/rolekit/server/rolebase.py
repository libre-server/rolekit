# -*- coding: utf-8 -*-
#
# Copyright (C) 2010-2012 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>
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

# force use of pygobject3 in python-slip
from gi.repository import GObject
import sys
from rolekit.server.io.systemd import SystemdExtensionUnits
sys.modules['gobject'] = GObject

import dbus
import dbus.service
import slip.dbus
import slip.dbus.service

from rolekit import async
from rolekit.config import *
from rolekit.config.dbus import *
from rolekit.logger import log
from rolekit.server.decorators import *
from rolekit.server.io.rolesettings import RoleSettings
from rolekit.server.io.systemd import SystemdTargetUnit
from rolekit.server.io.systemd import SystemdFailureUnit
from rolekit.server.io.systemd import SystemdExtensionUnits
from rolekit.dbus_utils import *
from rolekit.errors import *

from firewall.client import FirewallClient
from firewall.functions import getPortRange

############################################################################
#
# class RoleBase
#
############################################################################

class RoleBase(slip.dbus.service.Object):
    """Role Instance class"""

    _DEFAULTS = {
        "version": 0,
        "services": [ ],
        "packages": [ ],
        "firewall": { "ports": [ ], "services": [ ] },
        "firewall_zones": [ ],
        "custom_firewall": False,
#        "backup_paths": [ ]
    }
    # last_error is in _settings

    # properties that can not be changed within a deploy and update call
    _READONLY_SETTINGS = [
        "lasterror", "version",
        "services", "packages", "firewall",
    ]

    # maximum number of instances of this role
    _MAX_INSTANCES = 1

    default_polkit_auth_required = PK_ACTION_ALL
    """ Use PK_ACTION_ALL as a default """

    def __init__(self, parent, name, type_name, directory, settings,
                 *args, **kwargs):
        """The DBUS_INTERFACE_ROLE_INSTANCE implementation.

        :param parent: The DBusRole Object this is attached to
        :param name: Instance name
        :param type_name: Role name
        :param directory: FIXME: unused???
        :param settings: RoleSettings for the role
        :param path: (Implicit in *args) FIXME: unused???
        """
        super(RoleBase, self).__init__(*args, **kwargs)
        self._path = args[0]
        self._parent = parent
        self._name = name
        self._escaped_name = dbus_label_escape(name)
        self._type = type_name
        self._escaped_type = dbus_label_escape(type_name)
        self._log_prefix = "role.%s.%s" % (self._escaped_type,
                                           self._escaped_name)
        self._directory = directory
        self._settings = settings
        # TODO: place target_unit in settings
        self.target_unit = "role-%s-%s.target" % (self._type, self.get_name())

        # No loaded self._settings, set state to NASCENT
        if not "state" in self._settings:
            self._settings["state"] = NASCENT

        # Check role instance state if role instance is in READY_TO_START or
        # RUNNING state
        if self._settings["state"] in [ READY_TO_START, RUNNING ]:
            try:
                state = target_unit_state(self.target_unit)
            except Exception as e:
                log.error("Getting information about the unit target failed: %s", e)
            else:
                # Update state:
                #
                #  Old instance   | systemd unit | New instance
                #  state          | target state | state
                # ----------------+--------------+----------------
                #  RUNNING        | inactive     | READY_TO_START
                #  READY_TO_START | active       | RUNNING

                if state == "inactive" and self._settings["state"] == RUNNING:
                    log.warning("'%s' is inactive, moving to %s state.",
                                self.target_unit, READY_TO_START)
                    self.change_state(READY_TO_START, write=True)
                elif state == "active" and \
                     self._settings["state"] == READY_TO_START:
                    log.warning("'%s' is active, moving to %s state.",
                                self.target_unit, RUNNING)
                    self.change_state(RUNNING, write=True)

        self.timeout_restart()

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # property check methods

    # Check own properties
    def do_check_property(self, prop, value):
        """
        Check values of role specific properties

        Steps for checking:
          1) Check value for property prop.
          2) Raise RolekitError(INVALID_VALUE, prop) in case of error.
          3) Return True for the completed check.
          4) Return False otherwise.

        Use one of the alredy defined check_type_X methods:
          check_type_int(self, value)
          check_type_string(self, value)
          check_type_bool(self, value)
          check_type_dict(self, value)
          check_type_list(self, value)
          check_type_string_list(self, value)
          These methods return True for a passed test and raise in case of
          failure.
        Or write a new one if needed (see RoleBase class).

        Example for int type checking:
          if prop == "myownprop":
            return self.check_type_int(value)
          return False

        Example for dict { string: [ string ] } checking:
          if prop == "myownprop":
            self.check_type_dict(value)
            for x in value.keys():
              if x not in [ "key1", "key2", "key3" ]:
                raise RolekitError(INVALID_VALUE, x)
              self.check_type_string_list(value[x])
            return True
          return False
        """
        return False

    # check property method

    def _check_property(self, prop, value):
        if prop in [ "name", "type", "state", "lasterror" ]:
            return self.check_type_string(value)
        elif prop in [ "packages", "services", "firewall_zones" ]: # "backup_paths"
            return self.check_type_string_list(value)
        elif prop in [ "version" ]:
            return self.check_type_int(value)
        elif prop in [ "firewall" ]:
            self.check_type_dict(value)
            for x in value.keys():
                if x not in [ "ports", "services" ]:
                    raise RolekitError(INVALID_VALUE, "wrong key '%s'" % x)
                self.check_type_string_list(value[x])
            if "ports" in value:
                for x in value["ports"]:
                    try:
                        port, proto = x.split("/")
                    except:
                        raise RolekitError(INVALID_VALUE,
                                           "Port %s is invalid" % x)

                    p_range = getPortRange(port)
                    if p_range == -2:
                        raise RolekitError(INVALID_VALUE,
                                           "Port '%s' is too big" % port)
                    elif p_range == -1:
                        raise RolekitError(INVALID_VALUE,
                                           "Port range '%s' is invalid" % port)
                    elif p_range == None:
                        raise RolekitError(INVALID_VALUE,
                                            "Port range '%s' is ambiguous" % port)
                    elif len(p_range) == 2 and p_range[0] >= p_range[1]:
                        raise RolekitError(INVALID_VALUE,
                                           "Port range '%s' is invalid" % port)

                    if proto not in [ "tcp", "udp" ]:
                        raise RolekitError(INVALID_VALUE,
                                           "Protocol '%s' not from {'tcp'|'udp'}" % proto)

        elif prop in [ "custom_firewall" ]:
            return self.check_type_bool(value)

        elif hasattr(self, "do_check_property"):
            if self.do_check_property(prop, value):
                return True
        raise RolekitError(MISSING_CHECK, prop)

    # common type checking methods

    def check_type_int(self, value):
        """
        Checks if is of type int.

        Raises INVALID_VALUE error if the values is not matching,
        returns True otherwise.
        """
        if type(value) is not int:
            raise RolekitError(INVALID_VALUE, "%s is not a int" % value)
        return True

    def check_type_string(self, value):
        """
        Checks if value is of type string.

        Raises INVALID_VALUE error if the values is not matching,
        returns True otherwise.
        """
        if type(value) is not str:
            raise RolekitError(INVALID_VALUE, "%s is not a string" % value)
        return True

    def check_type_string_list(self, value):
        """
        Checks if value is of type list and containing strings.

        Raises INVALID_VALUE error if the values is not matching,
        returns True otherwise.
        """
        self.check_type_list(value)
        for x in value:
            self.check_type_string(x)
        return True

    def check_type_bool(self, value):
        """
        Checks if value is of type bool.

        Raises INVALID_VALUE error if the values is not matching,
        returns True otherwise.
        """
        if type(value) is not bool:
            raise RolekitError(INVALID_VALUE, "%s is not bool." % value)
        return True

    def check_type_dict(self, value):
        """
        Checks if value is of type dict.

        Raises INVALID_VALUE error if the values is not matching,
        returns True otherwise.
        """
        if type(value) is not dict:
            raise RolekitError(INVALID_VALUE, "%s is not a dict" % value)
        return True

    def check_type_list(self, value):
        """
        Checks if value is of type list.

        Raises INVALID_VALUE error if the values is not matching,
        returns True otherwise.
        """
        if type(value) is not list:
            raise RolekitError(INVALID_VALUE, "%s is not a list" % value)
        return True

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # Property handling

    # Static method for use in roles and instances
    #
    # Usage in roles: <class>.get_property(<class>, key)
    #   Returns values from _DEFAULTS as dbus types
    #
    # Usage in instances: role.get_property(role, key)
    #   Returns values from instance _settings if set, otherwise from _DEFAULTS
    #
    # This method needs to be extended for new role settings.
    @staticmethod
    def get_property(x, prop):
        if hasattr(x, "_settings") and prop in x._settings:
            return x._settings[prop]
        if prop == "name":
            return x._name
        elif prop == "type":
            return x._type
        elif prop == "state":
            return ""
        elif prop == "lasterror":
            return ""
        elif prop in x._DEFAULTS:
            return x._DEFAULTS[prop]

        raise RolekitError(UNKNOWN_SETTING, prop)

    # Static method for use in roles and instances
    #
    # Usage in roles: <class>.get_dbus_property(<class>, key)
    #   Returns settings as dbus types
    #
    # Usage in instances: role.get_dbus_property(role, key)
    #   Uses role.get_property(role, key)
    #
    # This method needs to be extended for new role settings.
    @staticmethod
    def get_dbus_property(x, prop):
        if prop in [ "name", "type", "state", "lasterror" ]:
            val = x.get_property(x, prop)
            if val is None:
                # Return the special string u'_NULL__' indicating
                # the NoneType
                return dbus.String(u'__NULL__')
            else:
                return dbus.String(x.get_property(x, prop))
        elif prop in [ "packages", "services", "firewall_zones" ]: # "backup_paths"
            return dbus.Array(x.get_property(x, prop), "s")
        elif prop in [ "version" ]:
            return dbus.Int32(x.get_property(x, prop))
        elif prop in [ "firewall" ]:
            return dbus.Dictionary(x.get_property(x, prop), "sas")
        elif prop in [ "custom_firewall" ]:
            return dbus.Boolean(x.get_property(x, prop))

        if hasattr(x, "do_get_dbus_property"):
            try:
                return x.do_get_dbus_property(x, prop)
            except TypeError:
                # If we get a TypeError here, it's because we couldn't
                # convert a NoneType to a D-BUS type. Return a special
                # string indicating this.
                return dbus.String(u'__NULL__')

            except RolekitError as e:
                if e.get_code(e) == INVALID_PROPERTY and prop in x._DEFAULTS:
                    raise dbus.exceptions.DBusException(
                        "org.freedesktop.DBus.Error.AccessDenied: "
                        "Property '%s' not covered in "
                        "do_get_dbus_property method" % prop)
                raise

        raise dbus.exceptions.DBusException(
            "org.freedesktop.DBus.Error.AccessDenied: "
            "Property '%s' isn't exported (or may not exist)" % prop)

    # property methods

    if hasattr(dbus.service, "property"):
        # property support in dbus.service

        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
        @dbus_handle_exceptions
        def name(self):
            return self.get_dbus_property(self, "name")

        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
        @dbus_handle_exceptions
        def type(self):
            return self.get_dbus_property(self, "type")

        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='i')
        @dbus_handle_exceptions
        def version(self):
            return self.get_dbus_property(self, "version")

        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
        @dbus_handle_exceptions
        def state(self):
            return self.get_dbus_property(self, "state")

        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='as')
        @dbus_handle_exceptions
        def packages(self):
            return self.get_dbus_property(self, "packages")

        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='as')
        @dbus_handle_exceptions
        def services(self):
            return self.get_dbus_property(self, "services")

        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='a{sas}')
        @dbus_handle_exceptions
        def firewall(self):
            return self.get_dbus_property(self, "firewall")

        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='as')
        @dbus_handle_exceptions
        def firewall_zones(self):
            return self.get_dbus_property(self, "firewall_zones")

        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='b')
        @dbus_handle_exceptions
        def custom_firewall(self):
            return self.get_dbus_property(self, "custom_firewall")

        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
        @dbus_handle_exceptions
        def lasterror(self):
            return self.get_dbus_property(self, "lasterror")

#        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='as')
#        def backup_paths(self):
#            return self.get_dbus_property(self, "backup_paths")

    else:
        # no property support in dbus.service

        @dbus_service_method(dbus.PROPERTIES_IFACE, in_signature='ss',
                             out_signature='v')
        @dbus_handle_exceptions
        def Get(self, interface_name, property_name, sender=None):
            # get a property
            interface_name = dbus_to_python(interface_name)
            property_name = dbus_to_python(property_name)
            log.debug1("config.Get('%s', '%s')", interface_name, property_name)

            if interface_name != DBUS_INTERFACE_ROLE_INSTANCE:
                raise dbus.exceptions.DBusException(
                    "org.freedesktop.DBus.Error.UnknownInterface: "
                    "RolekitD does not implement %s" % interface_name)

            return self.get_dbus_property(self, property_name)

        @dbus_service_method(dbus.PROPERTIES_IFACE, in_signature='s',
                             out_signature='a{sv}')
        @dbus_handle_exceptions
        def GetAll(self, interface_name, sender=None):
            interface_name = dbus_to_python(interface_name)
            log.debug1("config.GetAll('%s')", interface_name)

            if interface_name != DBUS_INTERFACE_ROLE_INSTANCE:
                raise dbus.exceptions.DBusException(
                    "org.freedesktop.DBus.Error.UnknownInterface: "
                    "RolekitD does not implement %s" % interface_name)

            ret = { }
            for name in self._DEFAULTS:
                ret[name] = self.get_dbus_property(self, name)
            # lasterror is not in _DEFAULTS, but in _settings
            ret["lasterror"] = self.get_dbus_property(self, "lasterror")
            return ret

        @dbus_service_method(dbus.PROPERTIES_IFACE, in_signature='ssv')
        @dbus_handle_exceptions
        def Set(self, interface_name, property_name, new_value, sender=None):
            interface_name = dbus_to_python(interface_name)
            property_name = dbus_to_python(property_name)
            new_value = dbus_to_python(new_value)
            log.debug1("config.Set('%s', '%s', '%s')", interface_name,
                       property_name, new_value)

            if interface_name != DBUS_INTERFACE_ROLE_INSTANCE:
                raise dbus.exceptions.DBusException(
                    "org.freedesktop.DBus.Error.UnknownInterface: "
                    "RolekitD does not implement %s" % interface_name)

            if property_name in self._DEFAULTS or \
               property_name in self._READONLY_SETTINGS:
                raise dbus.exceptions.DBusException(
                    "org.freedesktop.DBus.Error.PropertyReadOnly: "
                    "Property '%s' is read-only" % property_name)
            else:
                raise dbus.exceptions.DBusException(
                    "org.freedesktop.DBus.Error.AccessDenied: "
                    "Property '%s' does not exist" % property_name)

        @dbus.service.signal(dbus.PROPERTIES_IFACE, signature='sa{sv}as')
        def PropertiesChanged(self, interface_name, changed_properties,
                              invalidated_properties):
            log.debug1("config.PropertiesChanged('%s', '%s', '%s')",
                       interface_name, changed_properties,
                       invalidated_properties)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # Private methods

    def get_name(self):
        return self._name

    # get/assert and change state

    def get_state(self):
        if "state" in self._settings:
            return self._settings["state"]
        return ""

    def assert_state(self, *args):
        if self._settings["state"] in args:
            return
        raise RolekitError(INVALID_STATE, "Not in state '%s', but '%s'" % ("' or '".join(args), self._settings["state"]))

    def change_state(self, state, write=False):
        # change the state of the instance to state if it is valid and not in
        # this state already
        if state not in PERSISTENT_STATES and \
           state not in TRANSITIONAL_STATES:
            raise RolekitError(INVALID_STATE, state)
        if state != self._settings["state"]:
            self._settings["state"] = state
            if write:
                self._settings.write()
            self.StateChanged(state)

    # copy defaults

    def copy_defaults(self):
        self._settings.update(self._DEFAULTS)

    # check values

    def check_values(self, values):
        # Check key value pairs for the properties
        values = dbus_to_python(values)

        for x in values:
            if x in self._DEFAULTS:
                if x in self._READONLY_SETTINGS:
                    raise RolekitError(READONLY_SETTING, x)
                # use _check_property method from derived or parent class
                self._check_property(x, values[x])
            else:
                log.error("Unknown property: %s" % x)
                raise RolekitError(UNKNOWN_SETTING, x)

    # apply values

    def apply_values(self, values):
        # Copy key value pairs for the properties that are read-write to
        # self._settings and write the settings out.
        values = dbus_to_python(values)

        changed = [ ]
        for x in values:
            if x in self._DEFAULTS:
                if x in self._READONLY_SETTINGS:
                    raise RolekitError(READONLY_SETTING, x)
                # use _check_property method from derived or parent class
                self._check_property(x, values[x])
                # set validated setting
                self._settings[x] = values[x]
                changed.append(x)
            else:
                raise RolekitError(UNKNOWN_SETTING, x)

        if len(changed) > 0:
            dbus_changed = dbus.Dictionary(signature="sv")
            for x in changed:
                dbus_changed[x] = self.get_dbus_property(self, x)
            self.PropertiesChanged(DBUS_INTERFACE_ROLE_INSTANCE,
                                   dbus_changed, [ ])

            # write validated setting
            self._settings.write()

    # package handling

    def installPackages(self):
        """install packages"""
        log.debug1("%s.installPackages()", self._log_prefix)

        # are there any groups or packages to install?
        if len(self._settings["packages"]) < 1:
            log.debug1("No groups or packages to install")
            yield None
            return

        dnf_install = [ "dnf", "-y", "install" ] + self._settings["packages"]
        result = yield async.subprocess_future(dnf_install)

        if result.status:
            # If the subprocess returned non-zero, raise an exception
            raise RolekitError(COMMAND_FAILED, "%d" % result.status)

        # Completed successfully
        yield None

    def start_services_async(self):
        """Start services defined by self._settings["services"]"""
        log.debug1("%s.start_services_async()", self._log_prefix)

        with SystemdJobHandler() as job_handler:
            target_unit = "role-%s-%s.target" % (self._type, self.get_name())
            job_path = job_handler.manager.StartUnit(target_unit, "replace")
            job_handler.register_job(job_path)

            job_results = yield job_handler.all_jobs_done_future()

        if any([x for x in job_results.itervalues() if x not in ("skipped", "done")]):
            details = ", ".join(["%s: %s" % item for item in job_results.iteritems()])
            raise RolekitError(COMMAND_FAILED, "Starting services failed: %s" % details)

    def restartServices(self):
        """restart services"""
        log.debug1("%s.restartServices()", self._log_prefix)
        raise NotImplementedError()

    def stop_services_async(self):
        """stop_services_async"""
        log.debug1("%s.stop_services_async()", self._log_prefix)

        with SystemdJobHandler() as job_handler:
            target_unit = "role-%s-%s.target" % (self._type, self.get_name())
            job_path = job_handler.manager.StopUnit(target_unit, "replace")
            job_handler.register_job(job_path)

            job_results = yield job_handler.all_jobs_done_future()

        if any([x for x in job_results.itervalues() if x not in ("skipped", "done")]):
            details = ", ".join(["%s: %s" % item for item in job_results.iteritems()])
            raise RolekitError(COMMAND_FAILED, "Stopping services failed: %s" % details)

    def installFirewall(self):
        """install firewall"""
        log.debug1("%s.installFirewall()", self._log_prefix)

        # are there any firewall settings to apply?
        if len(self._settings["firewall"]["services"]) + \
           len(self._settings["firewall"]["ports"]) < 1:
            return

        # create firewall client
        fw = FirewallClient()

        # save changes to the firewall
        if "firewall-changes" in self._settings:
            fw_changes = self._settings["firewall-changes"]
        else:
            fw_changes = { }

        zones = self._settings["firewall_zones"]
        # if firewall_zones setting is empty, use default zone
        if len(zones) < 1:
            zones = [ fw.getDefaultZone() ]

        for zone in zones:
            # get permanent zone settings, run-time settings do not need a
            # special treatment
            z_perm = fw.config().getZoneByName(zone).getSettings()

            for service in self._settings["firewall"]["services"]:
                try:
                    fw.addService(zone, service, 0)
                except Exception as e:
                    if not "ALREADY_ENABLED" in str(e):
                        raise
                else:
                    fw_changes.setdefault(zone, {}).setdefault("services", {}).setdefault(service, []).append("runtime")

                if not z_perm.queryService(service):
                    z_perm.addService(service)
                    fw_changes.setdefault(zone, {}).setdefault("services", {}).setdefault(service, []).append("permanent")

            for port_proto in self._settings["firewall"]["ports"]:
                port, proto = port_proto.split("/")

                try:
                    fw.addPort(zone, port, proto, 0)
                except Exception as e:
                    if not "ALREADY_ENABLED" in str(e):
                        raise
                else:
                    fw_changes.setdefault(zone, {}).setdefault("ports", {}).setdefault(port_proto, []).append("runtime")

                if not z_perm.queryPort(port, proto):
                    z_perm.addPort(port, proto)
                    fw_changes.setdefault(zone, {}).setdefault("ports", {}).setdefault(port_proto, []).append("permanent")

            fw.config().getZoneByName(zone).update(z_perm)

        self._settings["firewall-changes"] = fw_changes
        self._settings.write()

    def updateFirewall(self):
        """update firewall"""
        log.debug1("%s.updateFirewall()", self._log_prefix)

        self.uninstallFirewall()
        self.installFirewall()

    def uninstallFirewall(self):
        """uninstall firewall"""
        log.debug1("%s.uninstallFirewall()", self._log_prefix)

        # Removes the settings that have been added in the installFirewall call

        # get applied changes from installFirewall call
        if "firewall-changes" in self._settings:
            fw_changes = self._settings["firewall-changes"]
        else:
            # fallback if there was a severe error in deploy before or while
            # installing the firewall
            fw_changes = { }

        # only continue if there are any changes
        if len(fw_changes) < 1:
            return

        # create firewall client
        fw = FirewallClient()

        # for all zones
        for zone in fw_changes:
            z_perm = fw.config().getZoneByName(zone).getSettings()

            if "services" in fw_changes[zone]:
                services = fw_changes[zone]["services"]
                for service in services:
                    if "runtime" in services[service]:
                        try:
                            fw.removeService(zone, service)
                        except Exception as e:
                            if not "NOT_ENABLED" in str(e):
                                raise
                    if "permanent" in services[service]:
                        try:
                            z_perm.removeService(service)
                        except Exception as e:
                            if not "NOT_ENABLED" in str(e):
                                raise

            if "ports" in fw_changes[zone]:
                ports = fw_changes[zone]["ports"]
                for port_proto in ports:
                    port, proto = port_proto.split("/")
                    if "runtime" in ports[port_proto]:
                        try:
                            fw.removePort(zone, port, proto)
                        except Exception as e:
                            if not "NOT_ENABLED" in str(e):
                                raise
                    if "permanent" in ports[port_proto]:
                        try:
                            z_perm.removePort(port, proto)
                        except Exception as e:
                            if not "NOT_ENABLED" in str(e):
                                raise

            fw.config().getZoneByName(zone).update(z_perm)

        # clear fw_changes and save it in _settings
        fw_changes.clear()
        self._settings["firewall-changes"] = fw_changes
        self._settings.write()

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # Public methods

    # Start code
    def do_start_async(self, sender=None):
        yield async.call_future(self.start_services_async())

    # Stop code
    def do_stop_async(self, sender=None):
        yield async.call_future(self.stop_services_async())

    # Deploy code
    def do_deploy_async(self, values, sender=None):
        # NOT IMPLEMENTED
        raise NotImplementedError()

    # Redeploy code
    def do_redeploy(self, values, sender=None):
        # NOT IMPLEMENTED
        raise NotImplementedError()

    # Decommission code
    def do_decommission(self, force=False, sender=None):
        # NOT IMPLEMENTED
        raise NotImplementedError()

    # Update code
    def do_update(self, sender=None):
        # NOT IMPLEMENTED
        raise NotImplementedError()

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # D-Bus methods

    @dbus.service.signal(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
    @dbus_handle_exceptions
    def StateChanged(self, state):
        log.debug1("%s.StateChanged('%s')", self._log_prefix, state)


    @dbus_service_method(DBUS_INTERFACE_ROLE_INSTANCE, out_signature='',
                         async_callbacks=('reply_handler', 'error_handler'))
    @dbus_handle_exceptions
    def start(self, reply_handler, error_handler, sender=None):
        """start role"""
        async.start_with_dbus_callbacks(self.__start_async(sender),
                                        reply_handler, error_handler)

    def __start_async(self, sender):
        self.assert_state(READY_TO_START)
        log.debug1("%s.start()", self._log_prefix)

        try:
            self.change_state(STARTING)
            yield async.call_future(self.do_start_async(sender))
            self.change_state(RUNNING, write=True)
        except:
            self.change_state(READY_TO_START, write=True)
            raise


    @dbus_service_method(DBUS_INTERFACE_ROLE_INSTANCE, out_signature='',
                         async_callbacks=('reply_handler', 'error_handler'))
    @dbus_handle_exceptions
    def stop(self, reply_handler, error_handler, sender=None):
        """stop role"""
        async.start_with_dbus_callbacks(self.__stop_async(sender),
                                        reply_handler, error_handler)

    def __stop_async(self, sender):
        self.assert_state(RUNNING)
        log.debug1("%s.stop()", self._log_prefix)

        try:
            self.change_state(STOPPING)
            yield async.call_future(self.do_stop_async(sender))
            self.change_state(READY_TO_START, write=True)
        except:
            self.change_state(ERROR, write=True)
            raise


    @dbus_service_method(DBUS_INTERFACE_ROLE_INSTANCE, out_signature='',
                         async_callbacks=('reply_handler', 'error_handler'))
    @dbus_handle_exceptions
    def restart(self, reply_handler, error_handler, sender=None):
        """restart role"""
        # Make sure we are in the proper state
        self.assert_state(RUNNING)

        # Log
        log.debug1("%s.restart()", self._log_prefix)

        # Stop
        self.stop(reply_handler, error_handler, sender)

        # Start if state is ready to start
        self.assert_state(READY_TO_START)
        self.start(reply_handler, error_handler, sender)


    def deploy_async(self, values, sender=None):
        """deploy role"""
        values = dbus_to_python(values)

        # Make sure we are in the proper state
        self.assert_state(NASCENT)

        # Log
        log.debug1("%s.deploy(%s)", self._log_prefix, values)

        # Check values
        try:
            self.check_values(values)
        except:
            # Check values failed, remove the instance again if verification
            # failed, set state to error, save it (will be visible in the
            # .old backup file).
            self.change_state(ERROR, write=True)

            # cleanup
            self._settings.remove()
            self.remove_from_connection()
            self._parent.remove_instance(self)
            raise

        try:
            # Change to deploying state
            self.change_state(DEPLOYING)

            # Copy _DEFAULTS to self._settings
            self.copy_defaults()

            # Install package groups and packages
            yield async.call_future(self.installPackages())

            # Install firewall
            self.installFirewall()

            # Call do_deploy
            target = yield async.call_future(self.do_deploy_async(values, sender))

            # Continue only after successful deployment:
            # Apply values to self._settings
            self.apply_values(values)

            # Set up systemd target files
            self.create_target(target)

            # Change to ready to start state
            self.change_state(READY_TO_START, write=True)

            # Attempt to start the newly-deployed role
            # We do this because many role-installers will conclude by
            # starting anyway and we want to ensure that our role mechanism
            # is in sync with them.
            yield async.call_future(self.__start_async(sender))

        except:
            # Something failed, set state to error
            self.change_state(ERROR, write=True)
            raise


    def create_target(self, target):
        target['targetname'] = \
            'role-%s-%s.target' % (target['Role'],
                                   target['Instance'])
        log.debug9("Creating target file {0}".format(target['targetname']))

        target['failurename'] = \
            'role-fail-%s-%s.service' % (target['Role'],
                                        target['Instance'])
        log.debug9("Creating failure file {0}".format(target['failurename']))

        # Create target unit
        target['extensions'] = SystemdTargetUnit(target).write()

        # Create failure notification unit
        SystemdFailureUnit(target).write()

        # Create extension units for required components
        extunits = SystemdExtensionUnits(target)
        for dep in SYSTEMD_DEPS:
            if dep in target:
                for unit in target[dep]:
                    log.debug9("Creating extension unit for {0}".format(unit))
                    extunits.write(unit)

        # Tell systemd to reload the daemon configuration
        log.debug9("Reloading systemd units\n")
        with SystemdJobHandler() as job_handler:
            job_handler.manager.Reload()


    @dbus_service_method(DBUS_INTERFACE_ROLE_INSTANCE, in_signature='a{sv}',
                         out_signature='')
    @dbus_handle_exceptions
    def redeploy(self, values, sender=None):
        """deploy role"""
        values = dbus_to_python(values)

        # Make sure we are in the proper state
        self.assert_state(READY_TO_START, ERROR)

        # Log
        log.debug1("%s.redeploy(%s)", self._log_prefix, values)

        # Check values
        try:
            self.check_values(values)
        except:
            # checking of values failed, set state to error
            self.change_state(ERROR, write=True)
            raise

        # Change to deploying state
        self.change_state(REDEPLOYING)

        # Call do_deploy
        try:
            self.do_redeploy(values, sender)
        except:
            # deploy failed set state to error
            self.change_state(ERROR, write=True)
            raise

        # Continue only after successful deployment:
        # Apply values to self._settings
        try:
            self.apply_values(values)
        except:
            # applying of values failed, set state to error
            self.change_state(ERROR, write=True)
            raise

        # Change to ready to start state
        self.change_state(READY_TO_START, write=True)

    @dbus_service_method(DBUS_INTERFACE_ROLE_INSTANCE, in_signature='b',
                         out_signature='',
                         async_callbacks=('reply_handler', 'error_handler'))
    @dbus_handle_exceptions
    def decommission(self, force, reply_handler, error_handler, sender=None):
        """decommission role"""
        force = dbus_to_python(force)
        async.start_with_dbus_callbacks(self.__decommission_async(force,
                                                                  sender),
                                        reply_handler, error_handler)

    def __decommission_async(self, force, sender):
        # Make sure we are in the proper state
        self.assert_state(READY_TO_START, ERROR)

        # Log
        log.debug1("%s.decommission(%s)", self._log_prefix, force)

        # Change state to decommissioning
        self.change_state(DECOMMISSIONING)

        # Call do_decommission
        try:
            yield async.call_future(self.do_decommission_async(force=force,
                                                               sender=sender))
        except:
            self.change_state(ERROR, write=True)
            if not force:
                raise

        # Uninstall firewall
        self.uninstallFirewall()

        # Continue only after successful decommission:
        # Then clean up: remove settings file, remove from dbus
        # connection and destroy instance
        self._settings.remove()
        self.remove_from_connection()
        self._parent.remove_instance(self)


    @dbus_service_method(DBUS_INTERFACE_ROLE_INSTANCE)
    @dbus_handle_exceptions
    def update(self, sender=None):
        """update role"""

        # Make sure we are in the proper state
        self.assert_state(READY_TO_START)

        # Log
        log.debug1("%s.update()", self._log_prefix)

        # Change to state updating
        self.change_state(UPDATING)

        # Call do_update
        try:
            self.do_update(sender)
        except:
            self.change_state(ERROR, write=True)

        # Continue only after successful update:
        # Change to deploying state
        self.change_state(READY_TO_START, write=True)


    @dbus_service_method(DBUS_INTERFACE_ROLE_INSTANCE, out_signature='')
    @dbus_handle_exceptions
    def resetError(self, sender=None):
        """resets error state in a role"""
        # Make sure we are in the proper state
        self.assert_state(ERROR)

        # Log
        log.debug1("%s.resetError()", self._log_prefix)

        # Change to state updating
        self.change_state(READY_TO_START, write=True)
