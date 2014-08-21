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
from rolekit.server.rolebase import *
from rolekit.dbus_utils import *
from rolekit.errors import *

class Role(RoleBase):
    # Use _DEFAULTS from RoleBase and overwrite settings or add new if needed.
    # Without overwrites or new settings, this can be omitted.
    _DEFAULTS = dict(RoleBase._DEFAULTS, **{
        "version": 1,
        "services": [ "postgresql.service" ],
        "packages": [ "postgresql-server", "postgresql-contrib" ],
        "firewall": { "ports": [], "services": [ "postgresql" ] },
#        "myownsetting": "something",
#        "failonthis": 123,
    })

    # Use _READONLY_SETTINGS from RoleBase and add new if needed.
    # Without new readonly settings, this can be omitted.
#    _READONLY_SETTINGS = RoleBase._READONLY_SETTINGS + [
#        "myownsetting"
#    ]


    # Initialize role
    def __init__(self, name, directory, *args, **kwargs):
        super(Role, self).__init__(name, directory, *args, **kwargs)

    def do_start_async(self, sender=None):
        yield async.call_future(self.start_services_async())

    def do_stop_async(self, sender=None):
        yield async.call_future(self.stop_services_async())


    # Deploy code
    def do_deploy_async(self, values, sender=None):
        # Do the magic
        #
        # In case of error raise an exception
        # FIXME: install packages, run initdb, enable services
        raise NotImplementedError()


    # Redeploy code
    def do_redeploy(self, values, sender=None):
        # Do the magic
        #
        # In case of error raise an exception
        # FIXME: should just chain to parent for the common fields?
        raise NotImplementedError()


    # Decommission code
    def do_decommission_async(self, sender=None):
        # Do the magic
        #
        # In case of error raise an exception
        # FIXME: disable services
        raise NotImplementedError() # FIXME: what about the data?


    # Update code
    def do_update(self, sender=None):
        # Do the magic
        #
        # In case of error raise an exception
        # FIXME: should just chain to parent for the common fields?
        raise NotImplementedError()


    # Static method for use in roles and instances
    #
    # Usage in roles: <class>.get_property(<class>, key)
    #   Returns values from _DEFAULTS as dbus types
    #
    # Usage in instances: role.get_property(role, key)
    #   Returns values from instance _settings if set, otherwise from _DEFAULTS
    #
    # This method needs to be extended for new role settings.
    # Without additional properties, this can be omitted.
#   @staticmethod
#   def get_property(x, prop):
#       # At first cover additional settings.
#       # Then return the result of the call to get_property of the
#       # parent class.
#       if hasattr(x, "_settings") and prop in x._settings:
#           return x._settings[prop]
#       if prop == "myownsetting":
#           return x._name
#
#       return super(Role, x).get_property(x, prop)


    # Static method for use in roles and instances
    #
    # Usage in roles: <class>.get_dbus_property(<class>, key)
    #   Returns settings as dbus types
    #
    # Usage in instances: role.get_dbus_property(role, key)
    #   Uses role.get_property(role, key)
    #
    # This method needs to be extended for new role settings.
    # Without additional properties, this can be omitted.
#   @staticmethod
#   def get_dbus_property(x, prop):
#       # At first cover additional settings and return a proper dbus type.
#       # Then return the result of the call to get_dbus_property of the
#       # parent class.
#       if prop == "myownsetting":
#           return dbus.String(x.get_property(x, prop))
#       return super(Role, x).get_dbus_property(x, prop)
