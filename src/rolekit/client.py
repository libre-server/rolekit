# -*- coding: utf-8 -*-
#
# Copyright (C) 2009-2014 Red Hat, Inc.
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
#

from gi.repository import GLib, GObject

# force use of pygobject3 in python-slip
import sys
sys.modules['gobject'] = GObject

import dbus
import dbus.mainloop.glib
import slip.dbus

from rolekit.config import *
from rolekit.config.dbus import *
from rolekit.dbus_utils import dbus_to_python
from decorator import decorator

exception_handler = None
not_authorized_loop = False

# exception handler

@decorator
def handle_exceptions(func, *args, **kwargs):
    """Decorator to handle exceptions
    """
    global exception_handler
    global not_authorized_loop
    authorized = False
    while not authorized:
        try:
            return func(*args, **kwargs)
        except dbus.exceptions.DBusException as e:
            dbus_message = e.get_dbus_message() # returns unicode
            dbus_name = e.get_dbus_name()
            if not exception_handler:
                raise
            if "NotAuthorizedException" in dbus_name:
                authorized = False
                exception_handler("NotAuthorizedException")
            else:
                authorized = True
                if dbus_message:
                    exception_handler(dbus_message)
                else:
                    exception_handler(b2u(str(e)))
        except Exception as e:
            if not exception_handler:
                raise
            else:
                exception_handler(b2u(str(e)))
        if not not_authorized_loop:
            break

# rolekit client role

class RolekitClientRole(object):
    @handle_exceptions
    def __init__(self, bus, path):
        self.bus = bus
        self.path = path
        self.dbus_obj = self.bus.get_object(DBUS_INTERFACE, path)
        self.role = dbus.Interface(self.dbus_obj,
                                   dbus_interface=DBUS_INTERFACE_ROLE)
        self.properties = dbus.Interface(
            self.dbus_obj, dbus_interface='org.freedesktop.DBus.Properties')

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def get_property(self, prop):
        return dbus_to_python(self.properties.Get(DBUS_INTERFACE_ROLE, prop))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def get_properties(self):
        return dbus_to_python(self.properties.GetAll(DBUS_INTERFACE_ROLE))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def set_property(self, prop, value):
        self.properties.Set(DBUS_INTERFACE_ROLE, prop, value)

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def start(self):
        self.role.start()

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def stop(self):
        self.role.stop()

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def restart(self):
        self.role.restart()

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def deploy(self):
        self.role.deploy()

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def decomission(self):
        self.role.decomission()

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def updateRole(self):
        self.role.updateRole()

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getFirewallZones(self):
        self.role.getFirewallZones()

# rolekit client

class RolekitClient(object):
    @handle_exceptions
    def __init__(self, bus=None, wait=0, quiet=True):
        if not bus:
            dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
            try:
                self.bus = slip.dbus.SystemBus()
                self.bus.default_timeout = None
            except:
                print("Not using slip")
                self.bus = dbus.SystemBus()
        else:
            self.bus = bus

        self.bus.add_signal_receiver(
            handler_function=self._dbus_connection_changed,
            signal_name="NameOwnerChanged",
            dbus_interface="org.freedesktop.DBus")

        for interface in [ DBUS_INTERFACE,
                           DBUS_INTERFACE_ROLE ]:
            self.bus.add_signal_receiver(self._signal_receiver,
                                         dbus_interface=interface,
                                         interface_keyword='interface',
                                         member_keyword='member',
                                         path_keyword='path')

        # callbacks
        self._callback = { }
        self._callbacks = {
            # client callbacks
            "connection-changed": "connection-changed",
            "connection-established": "connection-established",
            "connection-lost": "connection-lost",
            # rolekit callbacks
            # rolekit.role callbacks
            "role:StateChanged": "role:StateChanged",
            }

        # initialize variables used for connection
        self._init_vars()

        self.quiet = quiet

        if wait > 0:
            # connect in one second
            GLib.timeout_add_seconds(wait, self._connection_established)
        else:
            self._connection_established()

    @handle_exceptions
    def _init_vars(self):
        self.rk = None
        self.rK-roles = None
        self.connected = False

    @handle_exceptions
    def getExceptionHandler(self):
        global exception_handler
        return exception_handler

    @handle_exceptions
    def setExceptionHandler(self, handler):
        global exception_handler
        exception_handler = handler

    @handle_exceptions
    def connect(self, name, callback, *args):
        if name in self._callbacks:
            self._callback[self._callbacks[name]] = (callback, args)
        else:
            raise ValueError("Unknown callback name '%s'" % name)

    @handle_exceptions
    def _dbus_connection_changed(self, name, old_owner, new_owner):
        if name != DBUS_INTERFACE:
            return

        if new_owner:
            # connection established
            self._connection_established()
        else:
            # connection lost
            self._connection_lost()

    @handle_exceptions
    def _connection_established(self):
        try:
            self.dbus_obj = self.bus.get_object(DBUS_INTERFACE, DBUS_PATH)
            self.rk = dbus.Interface(self.dbus_obj,
                                     dbus_interface=DBUS_INTERFACE)
            self.properties = dbus.Interface(
                self.dbus_obj, dbus_interface='org.freedesktop.DBus.Properties')
        except dbus.exceptions.DBusException as e:
            # ignore dbus errors
            if not self.quiet:
                print ("DBusException", e.get_dbus_message())
            return
        except Exception as e:
            if not self.quiet:
                print ("Exception", e)
            return
        self.connected = True
        self._signal_receiver(member="connection-established",
                              interface=DBUS_INTERFACE)
        self._signal_receiver(member="connection-changed",
                              interface=DBUS_INTERFACE)

    @handle_exceptions
    def _connection_lost(self):
        self._init_vars()
        self._signal_receiver(member="connection-lost",
                              interface=DBUS_INTERFACE)
        self._signal_receiver(member="connection-changed",
                              interface=DBUS_INTERFACE)

    @handle_exceptions
    def _signal_receiver(self, *args, **kwargs):
        _args = [ ]
        for arg in args:
            _args.append(dbus_to_python(arg))
        args = _args
        if not "member" in kwargs:
            return
        signal = kwargs["member"]
        interface = kwargs["interface"]

        cb = None
        cb_args = [ ]

        # config signals need special treatment
        # pimp signal name
        if interface.startswith(DBUS_INTERFACE_ROLE):
            signal = "config:Role" + signal

        for callback in self._callbacks:
            if self._callbacks[callback] == signal and \
                    self._callbacks[callback] in self._callback:
                cb = self._callback[self._callbacks[callback]]
        if not cb:
            return

        cb_args.extend(args)

        # call back ...
        try:
            if cb[1]:
                # add call data
                cb_args.extend(cb[1])
            # call back
            cb[0](*cb_args)
        except Exception as msg:
            print(msg)

    # properties

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def get_property(self, prop):
        return dbus_to_python(self.properties.Get(DBUS_INTERFACE, prop))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def get_properties(self):
        return dbus_to_python(self.properties.GetAll(DBUS_INTERFACE))

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def set_property(self, prop, value):
        self.properties.Set(DBUS_INTERFACE, prop, value)

    # getNamedRole

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getNamedRole(self, name):
        return self.rk.getNamedRole(name)

    @slip.dbus.polkit.enable_proxy
    @handle_exceptions
    def getRolesByState(self, state):
        self.rk.getRolesByState(state)
