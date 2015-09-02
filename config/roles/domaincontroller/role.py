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
import re

from concurrent.futures import Future

from rolekit.config import *
from rolekit.config.dbus import *
from rolekit.logger import log
from rolekit.server.decorators import *
from rolekit.server.rolebase import *
from rolekit.server.io.hostname import set_hostname
from rolekit.dbus_utils import *
from rolekit.errors import *
from rolekit.util import generate_password
from IPy import IP

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

        # Host name will use the current system name if unspecified
        # If the system name starts with "localhost" it will be changed to
        # DC-<UUID>
        "host_name": None,

        # Default domain name will be autodetected if not specified
        "domain_name": None,

        # do_deploy_async() will check whether this is set and make it
        # the upper-case version of domain_name if not.
        "realm_name": None,

        # If not supplied, do_deploy_async() will generate a
        # random password
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

    # maximum number of instances of this role
    _MAX_INSTANCES = 1


    # Initialize role
    def __init__(self, name, directory, *args, **kwargs):
        super(Role, self).__init__(name, directory, *args, **kwargs)

        # Add a compiled regular expression for testing domain validity
        self.allowed_fqdn = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)


    # Deploy code
    def do_deploy_async(self, values, sender=None):
        log.debug9("TRACE: do_deploy_async")
        # Do the magic
        #
        # In case of error raise an exception

        # Get the domain name from the passed-in settings
        # or set it to the instance name if ommitted

        if 'domain_name' not in values:
            values['domain_name'] = self.get_name()

        if not self._valid_fqdn(values['domain_name']):
            raise RolekitError(INVALID_VALUE,
                               "Invalid domain name: %s" % values['domain_name'])

        if "host_name" not in values:
            # Let's construct a new host name.
            host_part = self._get_hostname()
            if host_part.startswith("localhost"):
                # We'll assign a random hostname starting with "dc-"
                random_part = ''.join(random.choice(string.ascii_lowercase)
                                      for _ in range(16))
                host_part = "dc-%s" % random_part

            values['host_name'] = "%s.%s" % (host_part, values['domain_name'])

        if not self._valid_fqdn(values['host_name']):
            raise RolekitError(INVALID_VALUE,
                               "Invalid host name: %s" % values['host_name'])

        # Change the hostname with the hostnamectl API
        yield set_hostname(values['host_name'])

        # If left unspecified, default the realm to the
        # upper-case version of the domain name
        if 'realm_name' not in values:
            values['realm_name'] = values['domain_name'].upper()

        # If left unspecified, assign a random password for
        # the administrative user
        if 'admin_password' not in values:
            admin_pw_provided = False
            values['admin_password'] = generate_password()
        else:
            admin_pw_provided = True

        # If left unspecified, assign a random password for
        # the directory manager
        if 'dm_password' not in values:
            dm_pw_provided = False
            values['dm_password'] = generate_password()
        else:
            dm_pw_provided = True

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
            if 'primary_ip' in values:
                ipa_install_args.append('--ip-address=%s' %
                                        values['primary_ip'])

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
                for zone in values['reverse_zone']:
                    ipa_install_args.append('--reverse-zone=%s' % zone)
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

        # Remove the passwords from the values so
        # they won't be saved to the settings
        if admin_pw_provided:
            values.pop('admin_password', None)
        if dm_pw_provided:
            values.pop('dm_password', None)

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
    def do_redeploy_async(self, values, sender=None):
        # Do the magic
        #
        # In case of error raise an exception
        raise NotImplementedError("Redeploy not supported yet")


    # Decommission code
    def do_decommission_async(self, force=False, sender=None):
        # We need to run the FreeIPA uninstallation
        result = yield async.subprocess_future(['ipa-server-install',
                                                '-U', '--uninstall'])
        if result.status:
            # Something went wrong with the uninstall
            raise RolekitError(COMMAND_FAILED, "%d" % result.status)

        yield None


    # Update code
    def do_update_async(self, sender=None):
        # Do the magic
        #
        # In case of error raise an exception
        raise NotImplementedError()


    # Check own properties
    def do_check_property(self, prop, value):
        if prop in [ "realm_name" ]:
            return self.check_type_string(value)

        elif prop in [ "admin_password",
                       "dm_password" ]:
            self.check_type_string(value)

            if len(value) < 8:
                raise RolekitError(INVALID_VALUE,
                                   "{0} must be at least eight characters"
                                   .format(prop))
            return True

        elif prop in [ "host_name" ]:
            self.check_type_string(value)

            if not self._valid_fqdn(value):
                raise RolekitError(INVALID_VALUE,
                                   "Invalid hostname: %s" % value)

            return True

        elif prop in [ "domain_name" ]:
            self.check_type_string(value)

            if not self._valid_fqdn(value):
                raise RolekitError(INVALID_VALUE,
                                   "Invalid domain name: %s" % value)

            return True

        elif prop in [ "root_ca_file" ]:
            self.check_type_string(value)

            if not os.path.isfile(value):
                raise RolekitError(INVALID_VALUE,
                                   "{0} is not a valid CA file"
                                   .format(value))
            return True

        if prop in [ "reverse_zone" ]:
            # TODO: properly parse reverse zones here
            # Getting this right is very complex and
            # FreeIPA already does it internally.
            return self.check_type_string_list(value)

        elif prop in [ "serve_dns" ]:
            return self.check_type_bool(value)

        elif prop in [ "id_start",
                       "id_max" ]:
            return self.check_type_int(value)

        elif prop in [ "dns_forwarders" ]:
            self.check_type_dict(value)
            for family in value.keys():
                self.check_type_string(family)

                if family not in [ "ipv4", "ipv6" ]:
                    raise RolekitError(INVALID_VALUE,
                                       "{0} is not a supported IP family"
                                       .format(family))

                self.check_type_string_list(value[family])

                for address in value[family]:
                    try:
                        IP(address)
                    except ValueError as ve:
                        raise RolekitError(INVALID_VALUE,
                                           "{0} is not a valid IP address"
                                           .format(address))
            return True

        elif prop in [ "primary_ip" ]:
            try:
                IP(value)
            except ValueError as ve:
                raise RolekitError(INVALID_VALUE,
                                   "{0} is not a valid IP address"
                                   .format(value))
            return True

        # We didn't recognize this argument
        return False


    # Sanitize settings
    def do_sanitize(self):
        """Sanitize settings"""
        self._settings['admin_password'] = None
        self._settings['dm_password'] = None


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
                     "host_name",
                     "admin_password",
                     "dm_password",
                     "root_ca_file",
                     "primary_ip" ]:
            return dbus.String(x.get_property(x, prop))
        elif prop in [ "reverse_zone" ]:
            return dbus.Array(x.get_property(x, prop), "s")
        elif prop in [ "serve_dns" ]:
            return dbus.Boolean(x.get_property(x, prop))
        elif prop in [ "id_start",
                       "id_max" ]:
            return dbus.Int32(x.get_property(x, prop))
        elif prop in [ "dns_forwarders" ]:
            return dbus.Dictionary(x.get_property(x, prop), "sas")

        raise RolekitError(INVALID_PROPERTY, prop)

    # Helper Routines
    def _get_hostname(self):
        # First, look up this machine's hostname
        # We don't need the FQDN because we're only interested
        # in the first part anyway.
        host = socket.gethostname()

        # Get everything up to the first dot as the hostname
        return host.split(".")[0]


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

    def _valid_fqdn(self, fqdn):
        # Most parts taken from
        # http://stackoverflow.com/questions/2532053/validate-a-hostname-string
        # This function will also work for either domain or hostname-only
        # portions of a hostname
        if len(fqdn) > 255:
            return False

        # Disallow the autogenerated instance names (names that are nothing but
        # a number)
        if fqdn.isdigit():
            return False

        if fqdn[-1] == ".":
            fqdn = fqdn[:-1] # strip exactly one dot from the right, if present

        return all(self.allowed_fqdn.match(x) for x in fqdn.split("."))

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
        def host_name(self):
            return self.get_dbus_property(self, "host_name")

        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
        @dbus_handle_exceptions
        def admin_password(self):
            return self.get_dbus_property(self, "admin_password")

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
