# -*- coding: utf-8 -*-
#
# Copyright (C) 2014-2015 Red Hat, Inc.
#
# Authors:
# Thomas Woerner <twoerner@redhat.com>
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
import dbus.service
import slip.dbus
import slip.dbus.service
import pwd
import grp
import os

from rolekit.config import ROLEKIT_ROLES
from rolekit.config.dbus import *
from rolekit.logger import log
from rolekit.server.decorators import *
from rolekit.server.rolebase import *
from rolekit.dbus_utils import *
from rolekit.errors import *
from rolekit.util import generate_password

class Role(RoleBase):
    # Use _DEFAULTS from RoleBase and overwrite settings or add new if needed.
    # Without overwrites or new settings, this can be omitted.
    _DEFAULTS = dict(RoleBase._DEFAULTS, **{
        "version": 1,
        "services": [ "postgresql.service" ],
        "packages": [ "postgresql-server",
                      "postgresql-contrib",
                      "python-psycopg2" ], # Needed for role deployment
        "firewall": { "ports": [],
                      "services": [ "postgresql" ] },

        # Database to create
        "database": None, # Mandatory

        # Name of the database owner
        "owner": None, # Mandatory

        # Password for the database owner
        "password": None, # Auto-generated if unspecified

        # Paths to configuration files
        "postgresql_conf": "/var/lib/pgsql/data/postgresql.conf",
        "pg_hba_conf": "/var/lib/pgsql/data/pg_hba.conf"
    })

    # Use _READONLY_SETTINGS from RoleBase and add new if needed.
    # Without new readonly settings, this can be omitted.
#    _READONLY_SETTINGS = RoleBase._READONLY_SETTINGS + [
#        "myownsetting"
#    ]

    # maximum number of instances of this role
    _MAX_INSTANCES = 1


    # Initialize role
    def __init__(self, name, directory, *args, **kwargs):
        super(Role, self).__init__(name, directory, *args, **kwargs)

    def do_start_async(self, sender=None):
        yield async.call_future(self.start_services_async())

    def do_stop_async(self, sender=None):
        yield async.call_future(self.stop_services_async())


    # Deploy code
    def do_deploy_async(self, values, sender=None):
        log.debug9("TRACE do_deploy_async(databaseserver)")
        # Do the magic
        #
        # In case of error raise an exception

        # TODO: handle cases where more than one database is
        # running on this system. For now, we'll assume a
        # pristine environment.

        # First, check for all mandatory arguments
        if 'database' not in values:
            raise RolekitError(INVALID_VALUE, "Database name unset")

        if 'owner' not in values:
            raise RolekitError(INVALID_VALUE, "Database owner unset")

        if 'password' not in values:
            values['password'] = generate_password()

        if 'postgresql_conf' not in values:
            values['postgresql_conf'] = self._settings['postgresql_conf']

        if 'pg_hba_conf' not in values:
            values['pg_hba_conf'] = self._settings['pg_hba_conf']

        # Get the UID and GID of the 'postgres' user
        self.pg_uid = pwd.getpwnam('postgres').pw_uid
        self.pg_gid = grp.getgrnam('postgres').gr_gid

        # Initialize the database on the filesystem
        initdb_args = ["/usr/bin/postgresql-setup", "initdb"]

        result = yield async.subprocess_future(initdb_args)
        if result.status:
            # If this fails, it may be just that the filesystem
            # has already been initialized. We'll log the message
            # and continue.
            log.debug1("INITDB: %s" % result.stdout)

        # Now we have to start the service to set everything else up
        with SystemdJobHandler() as job_handler:
            job_path = job_handler.manager.StartUnit("postgresql.service", "replace")
            job_handler.register_job(job_path)

            job_results = yield job_handler.all_jobs_done_future()
            if any([x for x in job_results.itervalues() if x not in ("skipped", "done")]):
                details = ", ".join(["%s: %s" % item for item in job_results.iteritems()])
                raise RolekitError(COMMAND_FAILED, "Starting services failed: %s" % details)


        # Next we create the owner
        createuser_args = ["/usr/bin/createuser", values['owner']]
        result = yield async.subprocess_future(createuser_args,
                                               uid=self.pg_uid,
                                               gid=self.pg_gid)

        if result.status:
            # If the subprocess returned non-zero, raise an exception
            raise RolekitError(COMMAND_FAILED,
                               "Creating user failed: %d" % result.status)


        createdb_args = ["/usr/bin/createdb", values['database'],
                         "-O", values['owner']]
        result = yield async.subprocess_future(createdb_args,
                                               uid=self.pg_uid,
                                               gid=self.pg_gid)
        if result.status:
            # If the subprocess returned non-zero, raise an exception
            raise RolekitError(COMMAND_FAILED,
                               "Creating database failed: %d" % result.status)

        # Next, set the password on the owner
        pwd_args = [ROLEKIT_ROLES + "/databaseserver/tools/rk_db_setpwd.py",
                    "--database", values['database'],
                    "--user", values['owner']]
        result = yield async.subprocess_future(pwd_args,
                                               stdin=values['password'],
                                               uid=self.pg_uid,
                                               gid=self.pg_gid)

        if result.status:
            # If the subprocess returned non-zero, raise an exception
            raise RolekitError(COMMAND_FAILED,
                               "Setting owner password failed: %d" %
                               result.status)

        # Remove the password from the values so
        # it won't be saved to the settings
        values.pop("password")

        # Then update the server configuration to accept network
        # connections.
        # edit postgresql.conf to add listen_addresses = '*'
        sed_args = [ "/bin/sed",
                     "-e", "s@^[#]listen_addresses\W*=\W*'.*'@listen_addresses = '\*'@",
                     "-i.rksave", values['postgresql_conf'] ]
        result = yield async.subprocess_future(sed_args)

        if result.status:
            # If the subprocess returned non-zero, raise an exception
            raise RolekitError(COMMAND_FAILED,
                               "Changing listen_addresses in '%s' failed: %d" %
                               (values['postgresql_conf'], result.status))

        # Edit pg_hba.conf to allow 'md5' auth on IPv4 and
        # IPv6 interfaces.
        sed_args = [ "/bin/sed",
                     "-e", "s@^host@#host@",
                     "-e", '/^local/a # Use md5 method for all connections',
                     "-e", '/^local/a host    all             all             all                     md5',
                     "-i.rksave", values['pg_hba_conf'] ]

        result = yield async.subprocess_future(sed_args)

        if result.status:
            # If the subprocess returned non-zero, raise an exception
            raise RolekitError(COMMAND_FAILED,
                               "Changing all connections to use md5 method in '%s' failed: %d" %
                               (values['pg_hba_conf'], result.status))

        # Restart the postgresql server to accept the new configuration
        # TODO

        # Create the systemd target definition
        target = {'Role': 'databaseserver',
                  'Instance': self.get_name(),
                  'Description': "Database Server Role - %s" %
                                 self.get_name(),
                  'Wants': ['postgresql.service'],
                  'After': ['syslog.target', 'network.target']}

        yield target

    # Redeploy code
    def do_redeploy(self, values, sender=None):
        # Do the magic
        #
        # In case of error raise an exception
        # FIXME: should just chain to parent for the common fields?
        raise NotImplementedError()


    # Decommission code
    def do_decommission_async(self, force=False, sender=None):
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


    # Check own properties
    def do_check_property(self, prop, value):
        if prop in [ "database",
                     "owner"]:
            return self.check_type_string(value)

        elif prop in [ "password" ]:
            self.check_type_string(value)

            if len(value) < 8:
                raise RolekitError(INVALID_VALUE,
                                   "{0} must be at least eight characters"
                                   .format(prop))
            return True

        elif prop in [ "postgresql_conf",
                       "pg_hba_conf" ]:
            self.check_type_string(value)

            if not os.path.isfile(value):
                raise RolekitError(INVALID_VALUE,
                                   "{0} is not a valid configuration file"
                                   .format(value))
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
        if prop in [ "database",
                     "owner",
                     "postgresql_conf",
                     "pg_hba_conf" ]:
            return dbus.String(x.get_property(x, prop))

        # Do not export the password as that is a user account
        # and may have been changed.
        elif prop in [ "password" ]:
            raise RolekitError(UNKNOWN_SETTING, prop)

        raise RolekitError(INVALID_PROPERTY, prop)


    # D-Bus Property handling
    if hasattr(dbus.service, "property"):
        # property support in dbus.service

        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
        @dbus_handle_exceptions
        def database(self):
            return self.get_dbus_property(self, "database")

        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
        @dbus_handle_exceptions
        def owner(self):
            return self.get_dbus_property(self, "owner")

        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
        @dbus_handle_exceptions
        def postgresql_conf(self):
            return self.get_dbus_property(self, "postgresql_conf")

        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
        @dbus_handle_exceptions
        def pg_hba_conf(self):
            return self.get_dbus_property(self, "pg_hba_conf")
