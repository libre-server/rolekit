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
sys.modules['gobject'] = GObject

import dbus
import dbus.service
import slip.dbus
import slip.dbus.service

from rolekit.config import *
from rolekit.config.dbus import *
from rolekit.logger import log
from rolekit.server.decorators import *
from rolekit.server.io.rolesettings import RoleSettings
from rolekit.dbus_utils import *
from rolekit.errors import *

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

    default_polkit_auth_required = PK_ACTION_ALL
    """ Use PK_ACTION_ALL as a default """

    @handle_exceptions
    def __init__(self, parent, name, type_name, directory, settings,
                 *args, **kwargs):
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

        if not "state" in self._settings:
            self._settings["state"] = NASCENT

        if not hasattr(dbus.service, "property"):
            self._exported_ro_properties = [
                "name", "version", "state", "packages", "services", "firewall",
                "lasterror"
            ]
            self._exported_rw_properties = [
                "firewall_zones", "custom_firewall",
#                "backup_paths",
            ]

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # property check methods

    @handle_exceptions
    def __check_firewall_zones(self, new_value):
        self._check_string_aray(new_value)

    @handle_exceptions
    def __check_custom_firewall(self, value):
        if type(value) is not bool:
            raise RolekitError(INVALID_VALUE, value)

    @handle_exceptions
    def _check_string_array(self, new_value):
        if type(new_value) is not list:
            raise RolekitError(INVALID_VALUE, new_value)
        for x in new_value:
            if type(x) is not str:
                raise RolekitError(INVALID_VALUE, x)

    @handle_exceptions
    def _check_bool(self, new_value):
        if type(new_value) is not bool:
            raise RolekitError(INVALID_VALUE, new_value)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # Property handling

    # Static method for use in roles and instances
    #
    # Usage in roles: <class>.get_dbus_property(<class>, key)
    #   Returns values from _DEFAULTS as dbus types
    #
    # Usage in instances: role.get_dbus_property(role, key)
    #   Returns values from instance _settings if set, otherwise from _DEFAULTS
    #   as dbus types
    #
    # This method needs to be extended for new role settings.
    @staticmethod
    @dbus_handle_exceptions
    def get_dbus_property(x, prop):
        if prop == "name":
            return dbus.String(x._name)
        elif prop == "type":
            return dbus.String(x._type)
        elif prop == "version":
            return dbus.Int32(x._DEFAULTS["version"])
        elif prop == "state":
            if hasattr(x, "_settings") and "state" in x._settings:
                return dbus.String(x._settings["state"])
            else:
                return dbus.String("")
        elif prop == "packages":
            return dbus.Array(x._DEFAULTS["packages"], "s")
        elif prop == "services":
            return dbus.Array(x._DEFAULTS["services"], "s")
        elif prop == "firewall":
            return dbus.Dictionary(x._DEFAULTS["firewall"], "sas")
        elif prop == "firewall_zones":
            if hasattr(x, "_settings") and "firewall_zones" in x._settings:
                return dbus.Array(x._settings["firewall_zones"], "s")
            return dbus.Array(x._DEFAULTS["firewall_zones"], "s")
        elif prop == "custom_firewall":
            if hasattr(x, "_settings") and "custom_firewall" in x._settings:
                return x._settings["custom_firewall"]
            return x._DEFAULTS["custom_firewall"]
#        elif prop == "backup_paths":
#            if hasattr(x, "_settings") and "backup_paths" in x._settings:
#                return dbus.Array(x._settings["backup_paths"], "s")
#            return dbus.Array(x._DEFAULTS["backup_paths"], "s")
        elif prop == "lasterror":
            if hasattr(x, "_settings") and "lasterror" in x._settings:
                return dbus.String(x._settings["lasterror"])
            else:
                return ""

        raise dbus.exceptions.DBusException(
            "org.freedesktop.DBus.Error.AccessDenied: "
            "Property '%s' isn't exported (or may not exist)" % prop)

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

        @firewall_zones.setter
        @dbus_handle_exceptions
        def firewall_zones(self, new_value):
            new_value = dbus_to_python(new_value)
            self._check_string_array(new_value)
            self._settings["firewall_zones"] = new_value
            self._settings.write()
            self.PropertiesChanged(DBUS_INTERFACE_ROLE_INSTANCE,
                                   { "firewall_zones": new_value }, [ ])

        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='b')
        @dbus_handle_exceptions
        def custom_firewall(self):
            return self.get_dbus_property(self, "custom_firewall")

        @custom_firewall.setter
        @dbus_handle_exceptions
        def custom_firewall(self, new_value):
            new_value = dbus_to_python(new_value)
            self._check_bool(new_value)
            self._settings["custom_firewall"] = new_value
            self._settings.write()
            self.PropertiesChanged(DBUS_INTERFACE_ROLE_INSTANCE,
                                   { "custom_firewall": new_value }, [ ])

        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
        @dbus_handle_exceptions
        def lasterror(self):
            return self.get_dbus_property(self, "lasterror")

#        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='as')
#        def backup_paths(self):
#            return self.get_dbus_property(self, "backup_paths")

#        @backup_paths.setter
#        @dbus_handle_exceptions
#        def backup_paths(self, new_value):
#            new_value = dbus_to_python(new_value)
#            self._check_string_array(new_value)
#            self._settings["backup_paths"] = new_value
#            self._settings.write()
#            self.PropertiesChanged(DBUS_INTERFACE_ROLE_INSTANCE,
#                                   { "backup_paths": new_value }, [ ])

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
            for name in self._exported_ro_properties + self._exported_rw_properties:
                ret[name] = self.get_dbus_property(self, name)
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

            if property_name in self._exported_rw_properties:
                if not hasattr(self, "__check_%s", property_name):
                    raise RolekitError(MISSING_CHECK, property_name)
                x = getattr(self, "__check_%s", property_name)
                x(new_value)
                self._settings.set(property_name, new_value)
                self._settings.write()
                self.PropertiesChanged(interface_name,
                                       { property_name: new_value }, [ ])
            elif property_name in self._exported_ro_properties:
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

    @handle_exceptions
    def get_name(self):
        return self._name

    @handle_exceptions
    def get_state(self):
        if "state" in self._settings:
            return self._settings["state"]
        return ""

    @handle_exceptions
    def installPackages(self):
        """install packages"""
        log.debug1("%s.installPackages()", self._log_prefix)
        raise NotImplementedError()

    @handle_exceptions
    def startServices(self):
        """start services"""
        log.debug1("%s.startServices()", self._log_prefix)
        raise NotImplementedError()

    @handle_exceptions
    def restartServices(self):
        """restart services"""
        log.debug1("%s.restartServices()", self._log_prefix)
        raise NotImplementedError()

    @handle_exceptions
    def stopServices(self):
        """stopServices"""
        log.debug1("%s.stopServices()", self._log_prefix)
        raise NotImplementedError()

    @handle_exceptions
    def installFirewall(self):
        """install firewall"""
        log.debug1("%s.installFirewall()", self._log_prefix)
        raise NotImplementedError()

    @handle_exceptions
    def updateFirewall(self):
        """update firewall"""
        log.debug1("%s.updateFirewall()", self._log_prefix)
        raise NotImplementedError()

    @handle_exceptions
    def uninstallFirewall(self):
        """uninstall firewall"""
        log.debug1("%s.uninstallFirewall()", self._log_prefix)
        raise NotImplementedError()

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # Public methods

    @dbus.service.signal(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
    @dbus_handle_exceptions
    def StateChanged(self, state):
        log.debug1("%s.StateChanged('%s')", self._log_prefix, state)


    @dbus_service_method(DBUS_INTERFACE_ROLE_INSTANCE, out_signature='')
    @dbus_handle_exceptions
    def start(self, sender=None):
        """start role"""
        log.debug1("%s.start()", self._log_prefix)
        raise NotImplementedError()


    @dbus_service_method(DBUS_INTERFACE_ROLE_INSTANCE, out_signature='')
    @dbus_handle_exceptions
    def stop(self, sender=None):
        """stop role"""
        log.debug1("%s.stop()", self._log_prefix)
        raise NotImplementedError()


    @dbus_service_method(DBUS_INTERFACE_ROLE_INSTANCE, out_signature='')
    @dbus_handle_exceptions
    def restart(self, sender=None):
        """restart role"""
        log.debug1("%s.restart()", self._log_prefix)
        raise NotImplementedError()


    @dbus_service_method(DBUS_INTERFACE_ROLE_INSTANCE, in_signature='a{sv}',
                         out_signature='')
    @dbus_handle_exceptions
    def deploy(self, values, sender=None):
        """deploy role"""
        values = dbus_to_python(values)
        log.debug1("%s.deploy(%s)", self._log_prefix, values)
        for x in self._DEFAULTS:
            self._settings[x] = self._DEFAULTS[x]

        self._settings["new"] = values
        self._settings.write()


    @dbus_service_method(DBUS_INTERFACE_ROLE_INSTANCE, out_signature='')
    @dbus_handle_exceptions
    def decommission(self, sender=None):
        """decommission role"""
        log.debug1("%s.decommission()", self._log_prefix)
        self._settings.remove()
        self.remove_from_connection()
        self._parent.remove_instance(self)


    @dbus_service_method(DBUS_INTERFACE_ROLE_INSTANCE, out_signature='')
    @dbus_handle_exceptions
    def update(self, sender=None):
        """update role"""
        log.debug1("%s.update()", self._log_prefix)
        raise NotImplementedError()
