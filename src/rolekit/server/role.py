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
import types

from rolekit.config import *
from rolekit.config.dbus import *
from rolekit.logger import log
from rolekit.server.decorators import *
#from rolekit.server.io.rolesettings import RoleSettings
from rolekit.dbus_utils import dbus_to_python
from rolekit.errors import *

############################################################################
#
# class RoleBase
#
############################################################################

class RoleBase(slip.dbus.service.Object):
    """Role class"""

#    persistent = True
    """ Make RolekitD persistent. """
    default_polkit_auth_required = PK_ACTION_ALL
    """ Use PK_ACTION_ALL as a default """

    @handle_exceptions
    def __init__(self, name, directory, *args, **kwargs):
        super(RoleBase, self).__init__(*args, **kwargs)
        self._path = args[0]
        self._name = name
        self._directory = directory
        self._version = 0
        self._state = NASCENT
        self._packages = [ ]
        self._services = [ ]
        self._firewall = { "ports": [ ], "services": [ ] } 
        self._firewall_zones = [ ]
        self._custom_firewall = False
        self._lasterror = ""
#        self._backup_paths = [ ]
#        self._settings = RoleSettings()
        self._settings = { }
        if not hasattr(dbus.service, "property"):
            self._exported_ro_properties = [ "name", "version", "state",
                                             "packages", "services", "firewall",
                                             "lasterror" ]
            self._exported_rw_properties = [
                "firewall_zones", "custom_firewall",
                # "backup_paths",
            ]

    @handle_exceptions
    def __del__(self):
        self.remove_from_connection()

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # property check methods

    @handle_exceptions
    def __check_firewall_zones(self, new_value):
        self._check_string_aray(new_value)

    @handle_exceptions
    def __check_custom_firewall(self, value):
        if type(value) is not bool:
            raise RolekitError(INVALID_VALUE, x)

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

    if hasattr(dbus.service, "property"):
        # property support in dbus.service

        @dbus.service.property(DBUS_INTERFACE_ROLES, signature='s')
        @dbus_handle_exceptions
        def name(self):
            return self._name

        @dbus.service.property(DBUS_INTERFACE_ROLES, signature='ao')
        @dbus_handle_exceptions
        def version(self):
            return self._version

        @dbus.service.property(DBUS_INTERFACE_ROLES, signature='s')
        @dbus_handle_exceptions
        def state(self):
            return self._state

        @dbus.service.property(DBUS_INTERFACE_ROLES, signature='as')
        @dbus_handle_exceptions
        def packages(self):
            return dbus.Array(self._packages, "s")

        @dbus.service.property(DBUS_INTERFACE_ROLES, signature='as')
        @dbus_handle_exceptions
        def services(self):
            return dbus.Array(self._services, "s")

        @dbus.service.property(DBUS_INTERFACE_ROLES, signature='a{sas}')
        @dbus_handle_exceptions
        def firewall(self):
            return dbus.Dictionary(self._firewall, "sas")

        @dbus.service.property(DBUS_INTERFACE_ROLES, signature='as')
        @dbus_handle_exceptions
        def firewall_zones(self):
            if "firewall_zones" in self._settings:
                return dbus.Array(self._settings["firewall_zones"], "s")
            return dbus.Array(self._firewall_zones, "s")

        @firewall_zones.setter
        @dbus_handle_exceptions
        def firewall_zones(self, new_value):
            new_value = dbus_to_python(new_value)
            self._check_string_array(new_value)
            self._settings["firewall_zones"] = new_value
            #self._settings.write()
            self.PropertiesChanged(DBUS_INTERFACE_ROLES,
                                   { "firewall_zones": new_value }, [ ])

        @dbus.service.property(DBUS_INTERFACE_ROLES, signature='b')
        @dbus_handle_exceptions
        def custom_firewall(self):
            if "custom_firewall" in self._settings:
                return self._settings["custom_firewall"]
            return self._custom_firewall

        @custom_firewall.setter
        @dbus_handle_exceptions
        def custom_firewall(self, new_value):
            new_value = dbus_to_python(new_value)
            self._check_bool(new_value)
            self._settings["custom_firewall"] = new_value
            #self._settings.write()
            self.PropertiesChanged(DBUS_INTERFACE_ROLES,
                                   { "custom_firewall": new_value }, [ ])

        @dbus.service.property(DBUS_INTERFACE_ROLES, signature='s')
        @dbus_handle_exceptions
        def lasterror(self):
            return self._lasterror

#        @dbus.service.property(DBUS_INTERFACE_ROLES, signature='as')
#        def backup_paths(self):
#            if "backup_paths" in self._settings:
#                return dbus.Array(self._settings["backup_paths"], "s")
#            return dbus.Array(self._backup_paths, "s")

#        @backup_paths.setter
#        @dbus_handle_exceptions
#        def backup_paths(self, new_value):
#            new_value = dbus_to_python(new_value)
#            self._check_string_array(new_value)
#            self._settings["backup_paths"] = new_value
#            #self._settings.write()
#            self.PropertiesChanged(DBUS_INTERFACE_ROLES,
#                                   { "backup_paths": new_value }, [ ])

    else:
        # no property support in dbus.service

        @dbus_handle_exceptions
        def _get_property(self, prop):
            if prop in self._exported_ro_properties or \
               prop in self._exported_rw_properties:
                if prop == "name":
                    return self._name
                elif prop == "version":
                    return self._version
                elif prop == "state":
                    return self._state
                elif prop == "packages":
                    return dbus.Array(self._packages, "s")
                elif prop == "services":
                    return dbus.Array(self._services, "s")
                elif prop == "firewall":
                    return dbus.Dictionary(self._firewall, "sas")
                elif prop == "firewall_zones":
                    if "firewall_zones" in self._settings:
                        return dbus.Array(self._settings["firewall_zones"], "s")
                    return dbus.Array(self._firewall_zones, "s")
                elif prop == "custom_firewall":
                    if "custom_firewall" in self._settings:
                        return self._settings["custom_firewall"]
                    return self._custom_firewall
                elif prop == "lasterror":
                    return self._lasterror
#                elif prop == "backup_paths":
#                    if "backup_paths" in self._settings:
#                        return dbus.Array(self._settings["backup_paths"], "s")
#                    return dbus.Array(self._backup_paths, "s")

            raise dbus.exceptions.BusException(
                "org.freedesktop.DBus.Error.AccessDenied: "
                "Property '%s' isn't exported (or may not exist)" % prop)

        @dbus_service_method(dbus.PROPERTIES_IFACE, in_signature='ss',
                             out_signature='v')
        @dbus_handle_exceptions
        def Get(self, interface_name, property_name, sender=None):
            # get a property
            interface_name = dbus_to_python(interface_name)
            property_name = dbus_to_python(property_name)
            log.debug1("config.Get('%s', '%s')", interface_name, property_name)

            if interface_name != DBUS_INTERFACE_ROLES:
                raise dbus.exceptions.DBusException(
                    "org.freedesktop.DBus.Error.UnknownInterface: "
                    "RolekitD does not implement %s" % interface_name)

            return self._get_property(property_name)

        @dbus_service_method(dbus.PROPERTIES_IFACE, in_signature='s',
                             out_signature='a{sv}')
        @dbus_handle_exceptions
        def GetAll(self, interface_name, sender=None):
            interface_name = dbus_to_python(interface_name)
            log.debug1("config.GetAll('%s')", interface_name)

            if interface_name != DBUS_INTERFACE_ROLES:
                raise dbus.exceptions.DBusException(
                    "org.freedesktop.DBus.Error.UnknownInterface: "
                    "RolekitD does not implement %s" % interface_name)

            ret = { }
            for name in self._exported_ro_properties + self._exported_rw_properties:
                ret[name] = self._get_property(name)
            return ret

        @dbus_service_method(dbus.PROPERTIES_IFACE, in_signature='ssv')
        @dbus_handle_exceptions
        def Set(self, interface_name, property_name, new_value, sender=None):
            interface_name = dbus_to_python(interface_name)
            property_name = dbus_to_python(property_name)
            new_value = dbus_to_python(new_value)
            log.debug1("config.Set('%s', '%s', '%s')", interface_name,
                       property_name, new_value)

            if interface_name != DBUS_INTERFACE_ROLES:
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
    def installPackages(self):
        """install packages"""
        log.debug1("roles.%s.installPackages()", self._name)
        raise NotImplementedError()

    @handle_exceptions
    def startServices(self):
        """start services"""
        log.debug1("roles.%s.startServices()", self._name)
        raise NotImplementedError()
        
    @handle_exceptions
    def restartServices(self):
        """restart services"""
        log.debug1("roles.%s.restartServices()", self._name)
        raise NotImplementedError()

    @handle_exceptions
    def stopServices(self):
        """stopServices"""
        log.debug1("roles.%s.stopServices()", self._name)
        raise NotImplementedError()

    @handle_exceptions
    def installFirewall(self):
        """install firewall"""
        log.debug1("roles.%s.installFirewall()", self._name)
        raise NotImplementedError()

    @handle_exceptions
    def updateFirewall(self):
        """update firewall"""
        log.debug1("roles.%s.updateFirewall()", self._name)
        raise NotImplementedError()

    @handle_exceptions
    def uninstallFirewall(self):
        """uninstall firewall"""
        log.debug1("roles.%s.uninstallFirewall()", self._name)
        raise NotImplementedError()

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # Public methods

    @dbus_service_method(DBUS_INTERFACE_ROLES, out_signature='')
    @dbus_handle_exceptions
    def start(self, sender=None):
        """start role"""
        log.debug1("roles.%s.start()", self._name)
        raise NotImplementedError()


    @dbus_service_method(DBUS_INTERFACE_ROLES, out_signature='')
    @dbus_handle_exceptions
    def stop(self, sender=None):
        """stop role"""
        log.debug1("roles.%s.stop()", self._name)
        raise NotImplementedError()


    @dbus_service_method(DBUS_INTERFACE_ROLES, out_signature='')
    @dbus_handle_exceptions
    def restart(self, sender=None):
        """restart role"""
        log.debug1("roles.%s.restart()", self._name)
        raise NotImplementedError()


    @dbus_service_method(DBUS_INTERFACE_ROLES, in_signature='a{sv}',
                         out_signature='')
    @dbus_handle_exceptions
    def deploy(self, values, sender=None):
        """deploy role"""
        values = dbus_to_python(values)
        log.debug1("roles.%s.deploy(%s)", values, self._name)
        raise NotImplementedError()


    @dbus_service_method(DBUS_INTERFACE_ROLES, out_signature='')
    @dbus_handle_exceptions
    def decommission(self, sender=None):
        """decommission role"""
        log.debug1("roles.%s.decommission()", self._name)
        raise NotImplementedError()


    @dbus_service_method(DBUS_INTERFACE_ROLES, out_signature='')
    @dbus_handle_exceptions
    def update(self, sender=None):
        """update role"""
        log.debug1("roles.%s.update()", self._name)
        raise NotImplementedError()
