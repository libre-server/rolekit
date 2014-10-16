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
import string
import os
import random

from concurrent.futures import Future

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
        # Default domain name will be autodetected if not specified
        "domain_name": None,

        # do_deploy_async() will check whether this is set and make it
        # the upper-case version of domain_name if not.
        "realm_name": None,

        # Must be supplied
        "admin_password": None,

        # If not supplied, do_deploy_async() will generate a
        # random password
        "dm_password": None,

        # Starting ID value for the domain
        # If unset, will be assigned randomly
        # If set, id_max must also be set
        "id_start": None,

        # Highest ID value for the domain
        # If unset, the domain will have space
        # for 200,000 IDs (FreeIPA default).
        # If set, id_start must also be set
        "id_max": None,

        # Path to a root CA certificate
        # If not specified, one will be generated
        "root_ca_file": None,

        # Install DNS Server
        "serve_dns": True,

        # Set up the DNS reverse zone
        "reverse_zone": None,

        # Primary IP address of the machine
        # This is necessary when setting up DNS
        # to work around
        # https://fedorahosted.org/freeipa/ticket/3575
        "primary_ip": None,

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


    # Deploy code
    def do_deploy_async(self, values, sender=None):
        log.debug9("TRACE: do_deploy_async")
        # Do the magic
        #
        # In case of error raise an exception

        # TODO: Much better input validation

        # Ensure we have all the mandatory arguments
        if 'admin_password' not in values:
            raise RolekitError(INVALID_VALUE, "admin_password unset")

        if 'domain_name' not in values:
            values['domain_name'] = self._get_domain()

        # If left unspecified, default the realm to the
        # upper-case version of the domain name
        if 'realm_name' not in values:
            values['realm_name'] = values['domain_name'].upper()

        # If left unspecified, assign a random password for
        # the directory manager
        if 'dm_password' not in values:
            # Generate a random password
            rpass = ''.join(random.choice(string.ascii_letters + string.digits)
                             for _ in range(16))
            values['dm_password'] = rpass

        # Call ipa-server-install with the requested arguments
        ipa_install_args = [
            'ipa-server-install', '-U',
                '-r', values['realm_name'],
                '-d', values['domain_name'],
                '-p', values['dm_password'],
                '-a', values['admin_password'],
            ]

        # If the user has requested the DNS server, enable it
        if 'serve_dns' not in values:
            values['serve_dns'] = self._settings['serve_dns']

        if values['serve_dns']:
            ipa_install_args.append('--setup-dns')

            # Pass the primary IP address
            if 'primary_ip' not in values:
                raise RolekitError(INVALID_VALUE, "No primary IP address set")

            ipa_install_args.append('--ip-address=%s' % values['primary_ip'])

            # if the user has requested DNS forwarders, add them
            if 'dns_forwarders' in values:
                [ipa_install_args.append("--forwarder=%s" % x)
                     for x in values['dns_forwarders']['ipv4']]
                [ipa_install_args.append("--forwarder=%s" % x)
                     for x in values['dns_forwarders']['ipv6']]
                pass
            else:
                ipa_install_args.append('--no-forwarders')

            # If the user has requested the reverse zone add it
            if 'reverse_zone' in values:
                ipa_install_args.append('--reverse-zone=%s'
                                        % values['reverse_zone'])
            else:
                ipa_install_args.append('--no-reverse')

        # If the user has requested a specified ID range,
        # set up the argument to ipa-server-install
        if 'id_start' in values or 'id_max' in values:
            if ('id_start' not in values or
                'id_max' not in values or
                not values['id_start'] or
                not values['id_max']):

                raise RolekitError(INVALID_VALUE,
                                   "Must specify id_start and id_max together")

            if (values['id_start'] and values['id_max'] <= values['id_start']):
                raise RolekitError(INVALID_VALUE,
                                   "id_max must be greater than id_start")

            ipa_install_args.append('--idstart=%d' % values['id_start'])
            ipa_install_args.append('--idmax=%d' % values['id_max'])

        # TODO: If the user has specified a root CA file,
        # set up the argument to ipa-server-install

        # Remove the admin_password from the values so
        # it won't be saved to the settings
        values.pop('admin_password', None)

        result = yield async.subprocess_future(ipa_install_args)

        if result.status:
            # If the subprocess returned non-zero, raise an exception
            raise RolekitError(COMMAND_FAILED, "%d" % result.status)

        # Create the systemd target definition
        target = {'Role': 'domaincontroller',
                  'Instance': self.get_name(),
                  'Description': "Domain Controller Role - %s" %
                                 self.get_name(),
                  'Wants': ['ipa.service'],
                  'After': ['syslog.target', 'network.target']}

        # We're done!
        yield target


    # Redeploy code
    def do_redeploy(self, values, sender=None):
        # Do the magic
        #
        # In case of error raise an exception
        pass


    # Decommission code
    def do_decommission_async(self, sender=None):
        # We need to run the FreeIPA uninstallation
        result = yield async.subprocess_future(['ipa-server-install',
                                                '-U', '--uninstall'])
        if result.status:
            # Something went wrong with the uninstall
            raise RolekitError(COMMAND_FAILED, "%d" % result.status)

        yield None


    # Update code
    def do_update(self, sender=None):
        # Do the magic
        #
        # In case of error raise an exception
        pass


    # Check own properties
    def do_check_property(self, prop, value):
        if prop in [ "domain_name",
                     "realm_name",
                     "dm_password",
                     "root_ca_file",
                     "primary_ip",
                     "reverse_zone",
                     "admin_password"]:
            return self.check_type_string(value)
        elif prop in [ "serve_dns" ]:
            return self.check_type_bool(value)
        elif prop in [ "id_start",
                       "id_max" ]:
            return self.check_type_int(value)
        elif prop in [ "dns_forwarders" ]:
            self.check_type_dict(value)
            for x in value.keys():
                self.check_type_string(x)
                self.check_type_string_list(value[x])
            return True
        return False


    # Static method for use in roles and instances
    #
    # Usage in roles: <class>.do_get_dbus_property(<class>, key)
    #   Returns settings as dbus types
    #
    # Usage in instances: role.do_get_dbus_property(role, key)
    #   Uses role.get_property(role, key)
    #
    # This method needs to be extended for new role settings.
    # Without additional properties, this can be omitted.
    @staticmethod
    def do_get_dbus_property(x, prop):
        # Cover additional settings and return a proper dbus type.
        if prop in [ "domain_name",
                     "realm_name",
                     "dm_password",
                     "root_ca_file",
                     "primary_ip",
                     "reverse_zone" ]:
            return dbus.String(x.get_property(x, prop))
        elif prop in [ "serve_dns" ]:
            return dbus.Boolean(x.get_property(x, prop))
        elif prop in [ "id_start",
                       "id_max" ]:
            return dbus.Int32(x.get_property(x, prop))
        elif prop in [ "dns_forwarders" ]:
            return dbus.Dictionary(x.get_property(x, prop), "sas")

        # Do not export the admin_password as that is a user account
        # and may have been changed.
        # We have to export the dm_password as it may be the only
        # way to recover it, if it was generated randomly.
        elif prop in [ "admin_password" ]:
            raise RolekitError(UNKNOWN_SETTING, prop)

        raise RolekitError(INVALID_PROPERTY, prop)


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


    # D-Bus Property handling
    if hasattr(dbus.service, "property"):
        # property support in dbus.service

        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
        @dbus_handle_exceptions
        def domain_name(self):
            return self.get_dbus_property(self, "domain_name")


        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
        @dbus_handle_exceptions
        def realm_name(self):
            return self.get_dbus_property(self, "realm_name")


        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
        @dbus_handle_exceptions
        def dm_password(self):
            return self.get_dbus_property(self, "dm_password")


        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
        @dbus_handle_exceptions
        def id_start(self):
            return self.get_dbus_property(self, "id_start")


        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
        @dbus_handle_exceptions
        def id_max(self):
            return self.get_dbus_property(self, "id_max")


        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
        @dbus_handle_exceptions
        def root_ca_file(self):
            return self.get_dbus_property(self, "root_ca_file")


        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
        @dbus_handle_exceptions
        def serve_dns(self):
            return self.get_dbus_property(self, "serve_dns")


        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
        @dbus_handle_exceptions
        def reverse_zone(self):
            return self.get_dbus_property(self, "reverse_zone")


        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
        @dbus_handle_exceptions
        def reverse_zone(self):
            return self.get_dbus_property(self, "reverse_zone")


        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
        @dbus_handle_exceptions
        def primary_ip(self):
            return self.get_dbus_property(self, "primary_ip")


        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
        @dbus_handle_exceptions
        def dns_forwarders(self):
            return self.get_dbus_property(self, "dns_forwarders")
