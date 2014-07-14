# -*- coding: utf-8 -*-
#
# Copyright (C) 2014 Red Hat, Inc.
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

import dbus
import dbus.service
import slip.dbus
import slip.dbus.service

from rolekit.config import *
from rolekit.config.dbus import *
from rolekit.logger import log
from rolekit.server.decorators import *
from rolekit.server.rolebase import RoleBase
from rolekit.dbus_utils import *
from rolekit.errors import *

class Role(RoleBase):
    _DEFAULTS = {
        "version": 1,
        "services": [ "service1" ],
        "packages": [ "package1", "@group1" ],
        "firewall": { "ports": [ "69/tcp" ], "services": [ "service1" ] },
        "firewall_zones": [ ],
        "custom_firewall": False,
        "myownsetting": "something",
        "failonthis": 123,
    }

    @handle_exceptions
    def __init__(self, name, directory, *args, **kwargs):
        super(Role, self).__init__(name, directory, *args, **kwargs)

    @dbus_service_method(DBUS_INTERFACE_ROLE_INSTANCE, in_signature='a{sv}')
    @dbus_handle_exceptions
    def deploy(self, values, sender=None):
        # Call deploy in parent class first, the values are written to
        # self_settings["new"].
        super(Role, self).deploy(values)

        # Then do the magic and use the new values.
        # After successful deployment, move the values from self_settings["new"]
        # to self_settings["deployed"] and call self._settings.write() to save
        # this change.

    # The definition of decommision is only needed if there are additional
    # steps needed
    @dbus_service_method(DBUS_INTERFACE_ROLE_INSTANCE, out_signature='')
    @dbus_handle_exceptions
    def decommission(self, sender=None):
        # Do some magic here if needed, then call decommission of parent class
        # for cleanup: remove settings file, remove from dbus connection and
        # destroy instance
        super(Role, self).decommission()

    # If there are additional _DEFAULTS, then the definition of
    # get_dbus_properties is needed to cover them.
    @staticmethod
    @dbus_handle_exceptions
    def get_dbus_property(x, prop):
        # At first cover the additional settings and return dbus types.
        # Then return the result of the call to get_dbus_property of the
        # parent class.
        if prop == "myownsetting":
            return dbus.String(x._DEFAULTS["myownsetting"])
        return super(Role, x).get_dbus_property(x, prop)
