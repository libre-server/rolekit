# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Red Hat, Inc.
#
# Authors:
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

import dbus
import dbus.mainloop.glib
import slip.dbus
from concurrent.futures import Future

HOSTNAME_BUS_NAME = "org.freedesktop.hostname1"
HOSTNAME_INTERFACE = "org.freedesktop.hostname1"
HOSTNAME_PATH = "/org/freedesktop/hostname1"

def set_hostname(hostname):
    f = Future()

    def reply_handler():
        f.set_result(True)

    def exception_handler(e):
        f.set_exception(e)

    try:
        bus = slip.dbus.SystemBus()
        bus.default_timeout = None
    except:
        print("Not using slip")
        bus = dbus.SystemBus()

    hostname_proxy = bus.get_object(bus_name=HOSTNAME_BUS_NAME,
                                    object_path=HOSTNAME_PATH)
    hostname_proxy.SetStaticHostname(hostname, False,
                                     dbus_interface=HOSTNAME_INTERFACE,
                                     reply_handler = reply_handler,
                                     error_handler = exception_handler)

    return f
