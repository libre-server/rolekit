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
        self.name = name
        self.directory = directory
        self.version = 0
        self.state = NASCENT
        self.packages = [ ]
        self.services = [ ]
        self.firewall = { "ports": [ ], "services": [ ] } 
        self.firewall_zones = [ ]
        self.custom_firewall = False
        self.lasterror = ""
        self.backup_paths = [ ]
#        self.settings = RoleSettings()
        self.settings = { }
        self._exported_ro_properties = [ "name", "version", "state",
                                         "packages", "services", "firewall",
                                         "lasterror", "backup_paths" ]
        self._exported_rw_properties = [ "firewall_zones", "custom_firewall" ]

    @handle_exceptions
    def __del__(self):
        self.remove_from_connection()

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # property check methods

    @handle_exceptions
    def __check_firewall_zones(self, value):
        if type(new_value) is not list:
            raise RolekitError(INVALID_VALUE, new_value)
        for x in new_value:
            if type(x) is not str:
                raise RolekitError(INVALID_VALUE, x)

    def __check_custom_firewall(self, value):
        if type(value) is not bool:
            raise RolekitError(INVALID_VALUE, x)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # Property handling

    @dbus_handle_exceptions
    def _get_property(self, prop):
        if prop in self._exported_ro_properties or \
           prop in self._exported_rw_properties:
            if prop == "name":
                return self.name
            elif prop == "version":
                return self.version

            if prop in self.settings:
                return self.settings[prop]
            else:
                return getattr(self, prop)

        raise dbus.exceptions.DBusException(
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
#        for name in self._exported_ro_properties + self._exported_rw_properties:
#            ret[name] = self._get_property(name)
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
            self.settings.set(property_name, new_value)
            self.settings.write()
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
        log.debug1("config.PropertiesChanged('%s', '%s', '%s')", interface_name,
                   changed_properties, invalidated_properties)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # 

    @dbus_service_method(DBUS_INTERFACE_ROLES, out_signature='')
    @dbus_handle_exceptions
    def start(self, sender=None):
        """start role"""
        log.debug1("roles.%s.start()", self.name)
        raise NotImplementedError()


    @dbus_service_method(DBUS_INTERFACE_ROLES, out_signature='')
    @dbus_handle_exceptions
    def stop(self, sender=None):
        """stop role"""
        log.debug1("roles.%s.stop()", self.name)
        raise NotImplementedError()


    @dbus_service_method(DBUS_INTERFACE_ROLES, out_signature='')
    @dbus_handle_exceptions
    def restart(self, sender=None):
        """restart role"""
        log.debug1("roles.%s.restart()", self.name)
        raise NotImplementedError()


    @dbus_service_method(DBUS_INTERFACE_ROLES, in_signature='a{sv}',
                         out_signature='')
    @dbus_handle_exceptions
    def deploy(self, values, sender=None):
        """deploy role"""
        values = dbus_to_python(values)
        log.debug1("roles.%s.deploy(%s)", values, self.name)
        raise NotImplementedError()


    @dbus_service_method(DBUS_INTERFACE_ROLES, out_signature='')
    @dbus_handle_exceptions
    def decommission(self, sender=None):
        """decommission role"""
        log.debug1("roles.%s.decommission()", self.name)
        raise NotImplementedError()


    @dbus_service_method(DBUS_INTERFACE_ROLES, out_signature='')
    @dbus_handle_exceptions
    def update(self, sender=None):
        """update role"""
        log.debug1("roles.%s.update()", self.name)
        raise NotImplementedError()
