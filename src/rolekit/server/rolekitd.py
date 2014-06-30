# -*- coding: utf-8 -*-
#
# Copyright (C) 2010-2014 Red Hat, Inc.
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

from gi.repository import GLib, GObject

# force use of pygobject3 in python-slip
import sys
sys.modules['gobject'] = GObject

import os
import imp

import dbus
import dbus.service
import slip.dbus
import slip.dbus.service

from rolekit.config import *
from rolekit.config.dbus import *
from rolekit.logger import log
from rolekit.server.decorators import *
from rolekit.dbus_utils import dbus_to_python
from rolekit.errors import *

############################################################################
#
# class RolekitD
#
############################################################################

class RolekitD(slip.dbus.service.Object):
    """RolekitD main class"""

#    persistent = True
    """ Make RolekitD persistent. """
    default_polkit_auth_required = PK_ACTION_ALL
    """ Use PK_ACTION_ALL as a default """

    @handle_exceptions
    def __init__(self, *args, **kwargs):
        super(RolekitD, self).__init__(*args, **kwargs)
        self.roles = [ ]
        self._path = args[0]
        self.version = ROLEKIT_VERSION
        self.start()

    def __del__(self):
        self.stop()

    @handle_exceptions
    def start(self):
        """ starts rolekit """
        log.debug1("start()")


        role_name = "role"
        path = ROLEKIT_ROLES

        for name in sorted(os.listdir(path)):
            directory = "%s/%s" % (path, name)
            if not os.path.isdir(directory):
                continue

            if not os.path.exists(os.path.join(directory, "role.py")):
                continue

            log.debug1("Loading role '%s'", name)
            try:
                if os.path.exists(os.path.join(directory, "role.pyc")):
                    mod = imp.load_compiled(name, "%s/role.pyc" % directory)
                elif os.path.exists(os.path.join(directory, "role.py")):
                    mod = imp.load_source(name, "%s/role.py" % directory)

                obj = getattr(mod, "Role")(name, directory, self._path,
                                           "%s/%s" % (DBUS_PATH_ROLES, name))

                if obj.name in self.roles:
                    log.error("Duplicate name for role '%s'", obj.name)
                else:
                    self.roles.append(obj)
            except RolekitError as msg:
                log.error("Failed to load role '%s': %s", name, msg)
                continue
            except Exception as msg:
                log.error("Failed to load role '%s':", name)
                log.exception()
                continue

#        for role in self.roles:
#            if role.auto_start == True:
#                try:
#                    role.start()
#                except RolekitError as msg:
#                    log.error("Failed to auto start role %s '%s': %s",
#                              role.name, msg)

    @handle_exceptions
    def suspend(self):
        """ suspend rolekit """
        # save states
        raise NotImplementedError()

    @handle_exceptions
    def wakeup(self):
        """ wakeup rolekit """
        # reload states
        raise NotImplementedError()

    @handle_exceptions
    def stop(self):
        """ stops rolekit """
        log.debug1("stop()")

    # Property handling

    @dbus_handle_exceptions
    def _get_property(self, prop):
        if prop == "version":
            return ROLEKIT_VERSION
        elif prop == "roles":
            return self.roles
        else:
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
        log.debug1("Get('%s', '%s')", interface_name, property_name)

        if interface_name != DBUS_INTERFACE:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.UnknownInterface: "
                "rolekitd does not implement %s" % interface_name)

        return self._get_property(property_name)

    @dbus_service_method(dbus.PROPERTIES_IFACE, in_signature='s',
                         out_signature='a{sv}')
    @dbus_handle_exceptions
    def GetAll(self, interface_name, sender=None):
        interface_name = dbus_to_python(interface_name)
        log.debug1("GetAll('%s')", interface_name)

        if interface_name != DBUS_INTERFACE:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.UnknownInterface: "
                "rolekitd does not implement %s" % interface_name)

        return {
            'version': self._get_property("version"),
            'roles': self._get_property("roles"),
        }
        

    @dbus_service_method(dbus.PROPERTIES_IFACE, in_signature='ssv')
    @dbus_handle_exceptions
    def Set(self, interface_name, property_name, new_value, sender=None):
        interface_name = dbus_to_python(interface_name)
        property_name = dbus_to_python(property_name)
        new_value = dbus_to_python(new_value)
        log.debug1("Set('%s', '%s', '%s')", interface_name, property_name,
                   new_value)
        self.accessCheck(sender)

        if interface_name != DBUS_INTERFACE:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.UnknownInterface: "
                "rolekitd does not implement %s" % interface_name)

        raise dbus.exceptions.DBusException(
            "org.freedesktop.DBus.Error.AccessDenied: "
            "Property '%s' is not settable" % property_name)

    @dbus.service.signal(dbus.PROPERTIES_IFACE, signature='sa{sv}as')
    def PropertiesChanged(self, interface_name, changed_properties,
                          invalidated_properties):
        pass

    # Role methods

    @dbus_service_method(DBUS_INTERFACE, in_signature='s',
                         out_signature='o')
    @dbus_handle_exceptions
    def getNamedRole(self, name, sender=None):
        """ return the role with the name, otherwise raise error """
        name = dbus_to_python(name)
        log.debug1("getNamedRole('%s')", name)
        for obj in self.roles:
            if obj.name == name:
                return obj
        raise RoleKitError(INVALID_ROLE, name)

    @dbus_service_method(DBUS_INTERFACE, in_signature='s',
                         out_signature='o')
    @dbus_handle_exceptions
    def getRolesByState(self, state, sender=None):
        """ return the list of roles that are in the state i """
        state = dbus_to_python(state)
        log.debug1("getRolesByState('%s')", state)
        ret_list = [ ]
        for obj in self.roles:
            if obj.state == state:
                ret_list.append(obj)
        return ret_list
