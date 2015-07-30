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

import dbus.service
from rolekit.server.rolebase import *
from rolekit.dbus_utils import *
from rolekit.errors import *

class Role(RoleBase):
    # Use _DEFAULTS from RoleBase and overwrite settings or add new if needed.
    # Without overwrites or new settings, this can be omitted.
    _DEFAULTS = dict(RoleBase._DEFAULTS, **{
        # All roles must provide the following four options:
        # version, services, packages and firewall

        # Version of the *role* (not the services it provides)
        "version": 1,

        # A list of systemd services that must be started with
        # this role.
        "services": [ "emptyservice.service" ],

        # A list of packages that must be installed by the
        # package manager to be able to deploy and run this
        # role. These will be installed before the deploy()
        # routine is invoked, so it can contain packages
        # needed for deployment as well as runtime.
        "packages": [ "emptypkg" ],

        # The ports or "services" that need to be available
        # in the firewall.
        # These will be opened automatically as part of
        # deployment and associated with the default
        # firewall zone of the system.
        "firewall": { "ports": [ '3/tcp' ],
                     "services": [ "myfirewallservice"] },


        # Role-specific settings belong here, with their defaults
        # Roles that have no default should be specified here, with
        # 'None' as their default
        # Examples:
        "string1": None,
        "string2": None,
        "bool1": False,
        "bool2": True,
        "int1": 0,
        "int2": 1000,
        "dict1": {
            "key1": ["val1a", "val1b"],
            "key2": ["val2a", "val2b"]
        }
    })

    # Maximum number of instances of this role that can be instantiated
    # on a single host.
    _MAX_INSTANCES = 1


    # Initialize role
    def __init__(self, name, directory, *args, **kwargs):
        # Get the default initialization from the RoleBase class
        # Always use this.
        super(Role, self).__init__(name, directory, *args, **kwargs)

        # Role-specific initialization goes here, if any


    # Deploy code
    def do_deploy_async(self, values, sender=None):
        log.debug9("TRACE: do_deploy_async")
        # Run whatever series of actions are needed to deploy
        # this role in a meaningful way.
        #
        # Return a dictionary with the following structure:
        # target = {'Role': 'emptyrole',
        #           'Instance': self.get_name(),
        #           'Description': Empty Example Role - %s" %
        #                          self.get_name(),
        #           'Wants': ['wanted.service'],
        #           'Requires': ['required.service']
        #           'After': ['syslog.target', 'network.target']}
        # the 'Wants', 'Requires', etc. are systemd unit file directives
        # See http://www.freedesktop.org/software/systemd/man/systemd.unit.html#%5BUnit%5D%20Section%20Options
        #
        # In case of error raise an appropriate RolekitError exception

        # If you need to call out to a long-running routine, use an asynchronous function
        # and yield until it returns.
        # Example:
        # result = yield async.subprocess_future(forked_process_args)

        # We're done!
        # Since this is an asynchronous function, we need to 'yield' the final
        # result.
        #yield target

        # Remove this line for real roles
        raise NotImplementedError()


    # Redeploy code
    def do_redeploy(self, values, sender=None):
        # Run whaever series of actions are needed to update the
        # role with a new high-level configuration.
        # Note: This should be configuration of the role itself,
        # not configuration of data held by the role. That should
        # be managed by the standard tools for interacting with
        # the role.
        #
        # In case of error raise a RolekitError exception

        # Remove this line for real roles
        raise NotImplementedError()


    # Decommission code
    def do_decommission_async(self, force=False, sender=None):
        # Run whatever series of actions are needed to completely
        # remove this role and restore the system state to its
        # original configuration.

        # If you need to call out to a long-running routine, use an asynchronous function
        # and yield until it returns.
        # Example:
        # result = yield async.subprocess_future(forked_process_args)

        # Always yield None at the end or return a RolekitError exception
        # yield None

        # Remove this line for real roles
        raise NotImplementedError()


    # Update code
    def do_update_async(self, sender=None):
        # If this role requires any special processing during an
        # update (other than simply updating the packages),
        # run them here.
        #
        # Always yield None at the end or return a RolekitError exception
        # yield None

        # Remove this line for real roles
        raise NotImplementedError()



    # Check own properties
    def do_check_property(self, prop, value):
        # All options passed to the role must be validated
        # At minimum, this routine should call one of the
        # following routines for all known settings:
        #  * self.check_type_bool(value)
        #  * self.check_type_dict(value)
        #  * self.check_type_int(value)
        #  * self.check_type_list(value)
        #  * self.check_type_string(value)
        #  * self.check_type_string_list(value)
        # Each of these routines will return True if
        # the value is appropriate or raise a
        # RolekitError if it is not.
        # If you wish to add your own checks, this
        # function must return as follows:
        # * True: The value passes all validation
        # * False: The setting was unknown to this role
        # * RolekitError: The value failed to pass validation
        # In the case of RolekitError, it is recommended to
        # provide an explanation of the failure as the msg
        # field of the exception.
        # Example:
        #   raise RolekitError(INVALID_VALUE,
        #                      "{0} must be at least eight characters"
        #                      .format(prop))

        # We didn't recognize this argument
        return False


    @staticmethod
    def do_get_dbus_property(x, prop):
        # This method tells rolekit what D-BUS type to use for each
        # of this role's custom settings.
        #
        # Examples:
        if prop in [ "string1",
                     "string2" ]:
            return dbus.String(x.get_property(x, prop))
        elif prop in [ "array1",
                       "array2"]:
            # This assumes array1 and array2 are arrays of
            # strings.
            return dbus.Array(x.get_property(x, prop), "s")
        elif prop in [ "bool1",
                       "bool2"]:
            return dbus.Boolean(x.get_property(x, prop))
        elif prop in [ "int1",
                       "int2" ]:
            return dbus.Int32(x.get_property(x, prop))
        elif prop in [ "dict1" ]:
            # This example dictionary is a string key with
            # an array of strings as the value
            return dbus.Dictionary(x.get_property(x, prop), "sas")

        # If you have any arguments that should be "write-only"
        # (such as passwords used only for the initial deployment),
        # include them here and raise a RolekitError:
        # if prop in [ "password" ]:
        #    raise RolekitError(UNKNOWN_SETTING, prop)

        # Lastly, always fall through to INVALID_PROPERTY if
        # the setting is unknown.
        raise RolekitError(INVALID_PROPERTY, prop)



    # D-Bus Property handling
    # Create a decorated function to return the value of any of
    # this role's custom settings.
    # Note the use of self.get_dbus_property(), *NOT*
    # self.do_get_dbus_property()

    @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
    @dbus_handle_exceptions
    def string1(self):
        return self.get_dbus_property(self, "string1")

    @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
    @dbus_handle_exceptions
    def string2(self):
        return self.get_dbus_property(self, "string2")

    @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
    @dbus_handle_exceptions
    def bool1(self):
        return self.get_dbus_property(self, "bool1")

    @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
    @dbus_handle_exceptions
    def bool2(self):
        return self.get_dbus_property(self, "bool2")

    @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
    @dbus_handle_exceptions
    def int1(self):
        return self.get_dbus_property(self, "int1")

    @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
    @dbus_handle_exceptions
    def int2(self):
        return self.get_dbus_property(self, "int2")

    @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
    @dbus_handle_exceptions
    def dict1(self):
        return self.get_dbus_property(self, "dict2")
