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

import os
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
# class DBus Role
#
############################################################################

class DBusRole(slip.dbus.service.Object):
    """Role class"""

    default_polkit_auth_required = PK_ACTION_ALL
    """ Use PK_ACTION_ALL as a default """

    @handle_exceptions
    def __init__(self, role, name, directory, *args, **kwargs):
        super(DBusRole, self).__init__(*args, **kwargs)
        self._path = args[0]
        self._role = role
        self._name = name
        self._escaped_name = dbus_label_escape(name)
        self._directory = directory
        self._instances = { }

        # create instances for stored instance settings

        path = "%s/%s" % (ETC_ROLEKIT_ROLES, self._name)
        if os.path.exists(path) and os.path.isdir(path):
            for name in sorted(os.listdir(path)):
                if not name.endswith(".json"):
                    continue
                instance = name[:-5]
                log.debug1("Loading '%s' instance '%s'", self._name, instance)

                settings = RoleSettings(self._name, instance)
                try:
                    settings.read()
                except ValueError as e:
                    log.error("Failed to load '%s' instance '%s': %s",
                              self._name, instance, e)
                    continue

                instance_escaped_name = dbus_label_escape(instance)
                if instance_escaped_name in self._instances:
                    raise RolekitError(NAME_CONFLICT, instance_escaped_name)

                role = self._role(self, instance, self._name, self._directory,
                                  settings, self._path,
                                  "%s/%s/%s" % (DBUS_PATH_ROLES,
                                                self._escaped_name,
                                                instance_escaped_name))
                self._instances[instance_escaped_name] = role

    @handle_exceptions
    def __del__(self):
        self.remove_from_connection()

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # Property handling

    if hasattr(dbus.service, "property"):
    # property support in dbus.service

        @dbus.service.property(DBUS_INTERFACE_ROLE, signature='s')
        @dbus_handle_exceptions
        def name(self):
            return dbus.String(self._name)

        @dbus.service.property(DBUS_INTERFACE_ROLE, signature='a{sv}')
        @dbus_handle_exceptions
        def DEFAULTS(self):
            ret = dbus.Dictionary(signature = "sv")
            for x in self._role._DEFAULTS:
                try:
                    ret[x] = self._role.get_dbus_property(self._role, x)
                except Exception as e:
                    log.error("role.%s.DEFAULTS(): Failed to get/convert property '%s'", self._escaped_name, x)
                    pass
            return ret

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

            if interface_name != DBUS_INTERFACE_ROLE:
                raise dbus.exceptions.DBusException(
                    "org.freedesktop.DBus.Error.UnknownInterface: "
                    "RolekitD does not implement %s" % interface_name)

            return self._role.get_dbus_property(self._role, property_name)

        @dbus_service_method(dbus.PROPERTIES_IFACE, in_signature='s',
                             out_signature='a{sv}')
        @dbus_handle_exceptions
        def GetAll(self, interface_name, sender=None):
            interface_name = dbus_to_python(interface_name)
            log.debug1("config.GetAll('%s')", interface_name)

            if interface_name != DBUS_INTERFACE_ROLE:
                raise dbus.exceptions.DBusException(
                    "org.freedesktop.DBus.Error.UnknownInterface: "
                    "RolekitD does not implement %s" % interface_name)

            ret = dbus.Dictionary(signature = "sv")
            for x in self._role._DEFAULTS:
                try:
                    ret[x] = self._role.get_dbus_property(self._role, x)
                except Exception as e:
                    log.error("role.%s.DEFAULTS(): Failed to get/convert property '%s'", self._escaped_name, x)
                    pass
            return ret

        @dbus_service_method(dbus.PROPERTIES_IFACE, in_signature='ssv')
        @dbus_handle_exceptions
        def Set(self, interface_name, property_name, new_value, sender=None):
            interface_name = dbus_to_python(interface_name)
            property_name = dbus_to_python(property_name)
            new_value = dbus_to_python(new_value)
            log.debug1("config.Set('%s', '%s', '%s')", interface_name,
                       property_name, new_value)

            if interface_name != DBUS_INTERFACE_ROLE:
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
    def get_instances(self):
        return self._instances

    @handle_exceptions
    def remove_instance(self, instance):
        name = instance.get_name()
        escaped_name = dbus_label_escape(name)

        if name in self._instances:
            del self._instances[name]
            self.InstanceRemoved(escaped_name)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # Public methods

    @dbus_service_method(DBUS_INTERFACE_ROLE, in_signature='',
                         out_signature='ao')
    @dbus_handle_exceptions
    def getInstances(self, sender=None):
        """get role instances"""
        log.debug1("role.%s.getInstances()", self._escaped_name)

        return self._instances.values()

    @dbus_service_method(DBUS_INTERFACE_ROLE, in_signature='s',
                         out_signature='o')
    @dbus_handle_exceptions
    def getNamedInstance(self, name, sender=None):
        """ return the role with the name, otherwise raise error """
        name = dbus_to_python(name)
        log.debug1("role.%s.getNamedInstance('%s')", self._escaped_name, name)
        if name in self._instances:
            return self._instances[name]
        raise RolekitError(INVALID_ROLE, name)

    @dbus.service.signal(DBUS_INTERFACE_ROLE, signature='s')
    @dbus_handle_exceptions
    def InstanceAdded(self, name):
        log.debug1("role.%s.InstanceAdded('%s')", self._escaped_name, name)

    @dbus.service.signal(DBUS_INTERFACE_ROLE, signature='s')
    @dbus_handle_exceptions
    def InstanceRemoved(self, name):
        log.debug1("role.%s.InstanceRemoved('%s')", self._escaped_name, name)

    # deploy: create new instance and deploy

    @dbus_service_method(DBUS_INTERFACE_ROLE, in_signature='sa{sv}',
                         out_signature='')
    @dbus_handle_exceptions
    def deploy(self, name, values, sender=None):
        """deploy role"""

        values = dbus_to_python(values)
        name = dbus_to_python(name)
        log.debug1("role.%s.deploy('%s', %s)", self._escaped_name, name, values)

        # limit role instances to 1 for now
        if len(self._instances) >= MAX_INSTANCES:
            raise RolekitError(TOO_MANY_INSTANCES, "> 1")

        # TODO: lock

        # create name if empty
        if not name:
            id = 1
            while str(id) in self._instances:
                id += 1
            name = str(id)

        # create escaped name and check if it is already in use
        instance_escaped_name = dbus_label_escape(name)
        if instance_escaped_name in self._instances:
            raise RolekitError(NAME_CONFLICT, instance_escaped_name)

        settings = RoleSettings(self._name, name)
        try:
            settings.read()
        except ValueError as e:
            raise RolekitError(NAME_CONFLICT, settings.filename)
        except IOError as e:
            pass
        else:
            raise RolekitError(NAME_CONFLICT, settings.filename)

        # create role
        role = self._role(self, name, self._name, self._directory, settings,
                          self._path,
                          "%s/%s/%s" % (DBUS_PATH_ROLES, self._escaped_name,
                                        instance_escaped_name))
        self._instances[instance_escaped_name] = role
        self.InstanceAdded(instance_escaped_name)

        # TODO: unlock

        # deploy role, lock in role now
        role.deploy(values)

        return role

