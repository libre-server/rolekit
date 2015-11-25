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

from rolekit.server.rolebase import RoleBase
from rolekit.server.rolebase import RoleDeploymentValues
from rolekit.errors import INVALID_PROPERTY, RolekitError

# Some example imports:
# from rolekit.dbus_utils import SystemdJobHandler
# from rolekit import async
# from rolekit.config import SYSTEMD_UNITS
# from rolekit.errors import COMMAND_FAILED, INVALID_VALUE, INVALID_PROPERTY
# from rolekit.errors import RolekitError
# from rolekit.logger import log
# from rolekit.server.io.systemd import enable_units
# from rolekit.server.io.systemd import SystemdContainerServiceUnit

class Role(RoleBase):
    # Use _DEFAULTS from RoleBase and overwrite settings or add new if needed.
    # Without overwrites or new settings, this can be omitted.
    _DEFAULTS = dict(RoleBase._DEFAULTS, **{
        "version": 1,
        "services": [ "service1" ],
        "packages": [ "tftp-server", "@c-development" ],
        "firewall": { "ports": [ "69/tcp" ], "services": [ "tftp" ] },
        "myownsetting": "something",
    })

    # Use _READONLY_SETTINGS from RoleBase and add new if needed.
    # Without new readonly settings, this can be omitted.
    _READONLY_SETTINGS = RoleBase._READONLY_SETTINGS + [
        "myownsetting"
    ]

    # maximum number of instances of this role
    _MAX_INSTANCES = 5


    # Initialize role
    def __init__(self, name, directory, *args, **kwargs):
        super(Role, self).__init__(name, directory, *args, **kwargs)


    # Deploy code
    def do_deploy_async(self, values, sender=None):
        # Do the magic
        #
        # In case of error raise an exception
        target = RoleDeploymentValues(self.get_type(), self.get_name(),
                                      "Test Role")
        target.add_required_units(['rolekit.socket'])

        yield target


    # Redeploy code
    def do_redeploy_async(self, values, sender=None):
        # Do the magic
        #
        # In case of error raise an exception
        yield None


    # Decommission code
    def do_decommission_async(self, force=False, sender=None):
        # Do the magic
        #
        # In case of error raise an exception
        yield None


    # Update code
    def do_update_async(self, sender=None):
        # Do the magic
        #
        # In case of error raise an exception
        yield None


    # Check own properties
    def do_check_property(self, prop, value):
        if prop == "myownsetting":
            return self.check_type_string(value)
        return False


    # Static method for use in roles and instances
    #
    # Usage in roles: <class>.do_get_dbus_property(<class>, key)
    #   Returns settings as dbus types
    #
    # Usage in instances: role.do_get_dbus_property(role, key)
    #   Uses role.get_property(role, key)
    #
    # Without additional properties, this can be omitted.
    @staticmethod
    def do_get_dbus_property(x, prop):
        # Cover additional settings and return a proper dbus type.
        if prop == "myownsetting":
            return dbus.String(x.get_property(x, prop))
        raise RolekitError(INVALID_PROPERTY, prop)
