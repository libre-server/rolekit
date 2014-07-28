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
import subprocess
import socket
import copy

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
        "services": [ "freeipa" ],
        "packages": [ "@freeipa-server" ],
        "firewall": { "ports": [ ],
                     "services": [ "freeipa-ldap",
                                   "freeipa-ldaps",
                                   "dns" ] },
        # Default domain name will be autodetected in __init__()
        "domain_name": None,

        # do_deploy_async() will check whether this is set and make it
        # the upper-case version of domain_name if not.
        "realm_name": None,

        # Must be supplied
        "admin_password": None,

        # If not supplied, do_deploy_async() will make this the same
        # as admin_password
        "dm_password": None,

        # Starting ID value for the domain
        # If unset, will be assigned randomly
        "id_start": None,

        # Maximum ID value in the domain
        # This is an offset from id_start
        "id_max": 199999,

        # Path to a root CA certificate
        # If not specified, one will be generated
        "root_ca_file": None,

        # Install DNS Server
        "setup_dns": True,

        # Set up the DNS reverse zone
        "setup_reverse_dns": False,

        # DNS Forwarders
        # If unspecified, installation will default to root servers
        # Otherwise, it should be a dictionary of lists of IP Addresses
        # as below:
        # "dns_forwarders": {"ipv4": [
        #                            "198.41.0.4",  # a.root-servers.net
        #                            "192.228.79.201",  # b.root-servers.net
        #                            "192.33.4.12"],  # c.root-servers.net
        #                   "ipv6": [
        #                            "2001:500:2d::d",  # d.root-servers.net
        #                            "2001:500:2f::f",  # f.root-servers.net
        #                            "2001:500:1::803f:235",  # h.root-servers.net
        #                           ]
        #                  },
        "dns_forwarders": None,

        # TODO: There are many less-common options to ipa-server-install.
        # The API should support them.
    })

    # Use _READONLY_SETTINGS from RoleBase and add new if needed.
    # Without new readonly settings, this can be omitted.
    # _READONLY_SETTINGS = RoleBase._READONLY_SETTINGS + []


    # Initialize role
    def __init__(self, name, directory, *args, **kwargs):
        super(Role, self).__init__(name, directory, *args, **kwargs)
        self._DEFAULTS["domain_name"] = self._get_domain()


    # Start code
    def do_start_async(self, sender=None):
        # Do the magic
        #
        # In case of error raise an exception
        yield None


    # Stop code
    def do_stop_async(self, sender=None):
        # Do the magic
        #
        # In case of error raise an exception
        yield None


    # Deploy code
    def do_deploy_async(self, values, sender=None):
        # Do the magic
        #
        # In case of error raise an exception
        props = copy.deepcopy(self._DEFAULTS)
        props.update(values)

        # If left unspecified, default the realm to the
        # upper-case version of the domain name
        if not props['realm_name']:
            props['realm_name'] = props['domain_name'].upper()

        # If left unspecified, default the directory manager
        # password to the admin password
        if not props['dm_password']:
            props['dm_password'] = props['admin_password']

        # TODO: If the user has requested the DNS server,
        # set up the argument to ipa-server-install

        # TODO: If the user has requested the reverse zone,
        # set up the argument to ipa-server-install

        # TODO: If the user has provided DNS forwarders,
        # set up the argument to ipa-server-install

        # TODO: If the user has requested an ID range offset,
        # set up the argument to ipa-server-install

        # TODO: If the user has specified a root CA file,
        # set up the argument to ipa-server-install

        # Call ipa-server-install with the requested arguments
        subprocess.check_call(
                ['ipa-server-install', '-U',
                 '--setup-dns',
                 '--no-forwarders',
                 '-r', props['realm_name'],
                 '-d', props['domain_name'],
                 '-p', props['dm_password'],
                 '-a', props['admin_password'],
                 ])
        yield None


    # Redeploy code
    def do_redeploy(self, values, sender=None):
        # Do the magic
        #
        # In case of error raise an exception
        pass


    # Decommission code
    def do_decommission(self, sender=None):
        # Do the magic
        #
        # In case of error raise an exception
        pass


    # Update code
    def do_update(self, sender=None):
        # Do the magic
        #
        # In case of error raise an exception
        pass


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
    @staticmethod
    def get_property(x, prop):
        # At first cover additional settings.
        # Then return the result of the call to get_property of the
        # parent class.
        if hasattr(x, "_settings") and prop in x._settings:
            return x._settings[prop]
        if prop == "myownsetting":
            return x._name

        return super(Role, x).get_property(x, prop)


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
    @staticmethod
    def get_dbus_property(x, prop):
        # At first cover additional settings and return a proper dbus type.
        # Then return the result of the call to get_dbus_property of the
        # parent class.
        if prop in [ "domain_name",
                     "realm_name",
                     "admin_password",
                     "dm_password",
                     "root_ca_file" ]:
            return dbus.String(x.get_property(x, prop))
        elif prop in [ "setup_dns",
                       "setup_reverse_dns" ]:
            return dbus.Boolean(x.get_property(x, prop))
        elif prop in [ "id_start",
                       "id_max" ]:
            return dbus.Int32(x.get_property(x, prop))
        elif prop in [ "dns_forwarders" ]:
            return dbus.Dictionary(x.get_property(x, prop), "sas")

        return super(Role, x).get_dbus_property(x, prop)


    # Helper Routines
    def _get_domain(self):
        # First, look up this machine's FQDN
        fqdn = socket.getfqdn()
        # Get everything after the first dot as the domain
        return fqdn[fqdn.find(".") + 1:]

    # Check Domain Controller-specific properties
    def _check_property(self, prop, value):
        try:
            super(Role, self)._check_property(prop, value)
        except RolekitError as e:
            if e.code == MISSING_CHECK:
                log.debug1("Unvalidated property: %s" % prop)
                pass
            else:
                log.debug1("Property %s did not validate" % prop)
                raise

        # TODO validate arguments
