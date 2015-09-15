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

from rolekit import async
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
        """The DBUS_INTERFACE_ROLE implementation

        :param role: RoleBase descendant
        :param name: Role name
        :param directory: FIXME: unused???
        :param path: (Implicit in *args) FIXME: unused???
        """
        super(DBusRole, self).__init__(*args, **kwargs)
        self.busname = args[0]
        self.path = args[1]
        self._role = role
        self._name = name
        self._escaped_name = dbus_label_escape(name)
        self._log_prefix = "role.%s" % self._escaped_name
        self._directory = directory
        self._instances = { }

        # create instances for stored instance settings

        path = "%s/%s" % (ETC_ROLEKIT_ROLES, self.get_name())
        if os.path.exists(path) and os.path.isdir(path):
            for name in sorted(os.listdir(path)):
                if not name.endswith(".json"):
                    continue
                instance = name[:-5]
                log.debug1("Loading '%s' instance '%s'", self.get_name(),
                           instance)

                settings = RoleSettings(self.get_name(), instance)
                try:
                    settings.read()
                except ValueError as e:
                    log.error("Failed to load '%s' instance '%s': %s",
                              self.get_name(), instance, e)
                    continue

                instance_escaped_name = dbus_label_escape(instance)
                if instance_escaped_name in self._instances:
                    raise RolekitError(NAME_CONFLICT, instance_escaped_name)

                role = self._role(self, instance, self.get_name(),
                                  self._directory, settings, self.busname,
                                  "%s/%s/%s" % (DBUS_PATH_ROLES,
                                                self._escaped_name,
                                                instance_escaped_name),
                                  persistent=self.persistent)
                self._instances[instance_escaped_name] = role

        self.timeout_restart()

    @handle_exceptions
    def __del__(self):
        self.remove_from_connection()

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # Property handling

    def get_property(self, prop):
        if prop == "name":
            return self.get_name()
        elif prop == "DEFAULTS":
            return self._role._DEFAULTS

        raise RolekitError(UNKNOWN_SETTING, prop)

    def get_dbus_property(self, prop):
        if prop == "name":
            return dbus.String(self.get_property(prop))
        elif prop == "DEFAULTS":
            ret = dbus.Dictionary(signature = "sv")
            for x in self._role._DEFAULTS:
                try:
                    ret[x] = self._role.get_dbus_property(self._role, x)
                except Exception as e:
                    log.error("%s.DEFAULTS: Failed to get/convert property '%s'", self._log_prefix, x)
                    pass
            return ret

        raise dbus.exceptions.DBusException(
            "org.freedesktop.DBus.Error.AccessDenied: "
            "Property '%s' isn't exported (or may not exist)" % prop)


    # property methods

    @dbus_service_method(dbus.PROPERTIES_IFACE, in_signature='ss',
                         out_signature='v')
    @dbus_handle_exceptions
    def Get(self, interface_name, property_name, sender=None):
        # get a property
        interface_name = dbus_to_python(interface_name)
        property_name = dbus_to_python(property_name)
        log.debug1("%s.Get('%s', '%s')", self._log_prefix,
                   interface_name, property_name)

        if interface_name != DBUS_INTERFACE_ROLE:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.UnknownInterface: "
                "RolekitD does not implement %s" % interface_name)

        return self.get_dbus_property(property_name)

    @dbus_service_method(dbus.PROPERTIES_IFACE, in_signature='s',
                         out_signature='a{sv}')
    @dbus_handle_exceptions
    def GetAll(self, interface_name, sender=None):
        interface_name = dbus_to_python(interface_name)
        log.debug1("%s.GetAll('%s')", self._log_prefix, interface_name)

        if interface_name != DBUS_INTERFACE_ROLE:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.UnknownInterface: "
                "RolekitD does not implement %s" % interface_name)

        ret = dbus.Dictionary(signature = "sv")
        for x in [ "name", "DEFAULTS" ]:
            ret[x] = self.get_dbus_property(x)
        return ret

    @dbus_service_method(dbus.PROPERTIES_IFACE, in_signature='ssv')
    @dbus_handle_exceptions
    def Set(self, interface_name, property_name, new_value, sender=None):
        interface_name = dbus_to_python(interface_name)
        property_name = dbus_to_python(property_name)
        new_value = dbus_to_python(new_value)
        log.debug1("%s.Set('%s', '%s', '%s')", self._log_prefix,
                   interface_name, property_name, new_value)

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
        interface_name = dbus_to_python(interface_name)
        changed_properties = dbus_to_python(changed_properties)
        invalidated_properties = dbus_to_python(invalidated_properties)
        log.debug1("%s.PropertiesChanged('%s', '%s', '%s')",
                   self._log_prefix, interface_name, changed_properties,
                   invalidated_properties)

    @dbus_service_method(dbus.INTROSPECTABLE_IFACE, out_signature='s')
    @dbus_handle_exceptions
    def Introspect(self, sender=None):
        log.debug1("%s.Introspect()" % self._log_prefix)

        data = super(DBusRole, self).Introspect(self.path,
                                                self.busname.get_bus())
        return dbus_introspection_add_properties(self, data,
                                                 DBUS_INTERFACE_ROLE)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # Methods

    def get_name(self):
        return self._name

    def get_instances(self):
        return self._instances

    def remove_instance(self, instance):
        """Remove an instance from our list.

        Note that this neither undeploys it nor deletes the settings file.
        """
        name = instance.get_name()
        escaped_name = dbus_label_escape(name)

        if escaped_name in self._instances:
            del self._instances[escaped_name]
            self.InstanceRemoved(escaped_name)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # D-Bus methods

    @dbus_service_method(DBUS_INTERFACE_ROLE, in_signature='',
                         out_signature='ao')
    @dbus_handle_exceptions
    def getInstances(self, sender=None):
        """get role instances"""
        log.debug1("%s.getInstances()", self._log_prefix)

        return self._instances.values()

    @dbus_service_method(DBUS_INTERFACE_ROLE, in_signature='s',
                         out_signature='o')
    @dbus_handle_exceptions
    def getNamedInstance(self, name, sender=None):
        """ return the role with the name, otherwise raise error """
        name = dbus_to_python(name)
        log.debug1("%s.getNamedInstance('%s')", self._log_prefix, name)
        instance_escaped_name = dbus_label_escape(name)
        if instance_escaped_name in self._instances:
            return self._instances[instance_escaped_name]
        raise RolekitError(INVALID_INSTANCE, name)

    @dbus.service.signal(DBUS_INTERFACE_ROLE, signature='s')
    @dbus_handle_exceptions
    def InstanceAdded(self, name):
        log.debug1("%s.InstanceAdded('%s')", self._log_prefix, name)

    @dbus.service.signal(DBUS_INTERFACE_ROLE, signature='s')
    @dbus_handle_exceptions
    def InstanceRemoved(self, name):
        log.debug1("%s.InstanceRemoved('%s')", self._log_prefix, name)

    # deploy: create new instance and deploy

    @dbus_service_method(DBUS_INTERFACE_ROLE, in_signature='sa{sv}',
                         out_signature='',
                         async_callbacks=('reply_handler', 'error_handler'))
    @dbus_handle_exceptions
    def deploy(self, name, values,
               reply_handler, error_handler,
               sender=None):
        """deploy role"""
        async.start_with_dbus_callbacks(self.__deploy_async(name, values),
                                        reply_handler, error_handler)

    def __deploy_async(self, name, values):
        values = dbus_to_python(values)
        name = dbus_to_python(name)
        log.debug1("%s.deploy('%s', %s)", self._log_prefix, name, values)

        # limit role instances to max instances per role
        if len(self._instances) >= self._role._MAX_INSTANCES:
            raise RolekitError(TOO_MANY_INSTANCES, "> %d" % \
                               self._role._MAX_INSTANCES)

        # TODO: lock

        # Create the settings object. If no name has been passed in,
        # this function will create one from the next available value.
        # Note: this isn't protected by a lock, so name-generation
        # might be racy.
        settings = RoleSettings(self.get_name(), name)

        # create escaped name and check if it is already in use
        instance_escaped_name = dbus_label_escape(settings.get_name())
        if instance_escaped_name in self._instances:
            raise RolekitError(NAME_CONFLICT, instance_escaped_name)

        try:
            settings.read()
        except ValueError as e:
            raise RolekitError(NAME_CONFLICT, settings.filename)
        except IOError as e:
            pass
        else:
            raise RolekitError(NAME_CONFLICT, settings.filename)

        # create role
        role = self._role(self, settings.get_name(), self.get_name(),
                          self._directory, settings, self.busname,
                          "%s/%s/%s" % (DBUS_PATH_ROLES, self._escaped_name,
                                        instance_escaped_name),
                          persistent=self.persistent)
        self._instances[instance_escaped_name] = role
        self.InstanceAdded(instance_escaped_name)

        # TODO: unlock

        # deploy role, lock in role now
        result = yield async.call_future(role.deploy_async(values))
        yield result
