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

from rolekit.config import ROLEKIT_ROLES, READY_TO_START, RUNNING, DEPLOYING, \
    REDEPLOYING, DECOMMISSIONING, STARTING, STOPPING, UPDATING

from rolekit.config.dbus import *
from rolekit.logger import log
from rolekit.server.decorators import *
from rolekit.server.rolebase import *
from rolekit.dbus_utils import *
from rolekit.errors import *
from rolekit.util import generate_password

# A list of states that may indicate that another instance of the DB
# Role is already available on this system. It expressly ignores
# NASCENT and ERROR, since those may be due to a failed earlier
# deployment that didn't have the initialization run.
deployed_states = (READY_TO_START, RUNNING, DEPLOYING, REDEPLOYING,
                   DECOMMISSIONING, STARTING, STOPPING, UPDATING)

class Role(RoleBase):
    # Use _DEFAULTS from RoleBase and overwrite settings or add new if needed.
    # Without overwrites or new settings, this can be omitted.
    _DEFAULTS = dict(RoleBase._DEFAULTS, **{
        "version": 1,
        "services": [ "postgresql.service" ],
        "packages": [ "postgresql-server",
                      "postgresql-contrib",
                      "python3-psycopg2" ], # Needed for role deployment
        "firewall": { "ports": [],
                      "services": [ "postgresql" ] },

        # Database to create
        "database": None, # Mandatory

        # Name of the database owner
        "owner": None,  # Defaults to db_owner

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
    # We'll pick an arbitrarily large number. It's
    # unlikely that any system will ever have so many
    _MAX_INSTANCES = 1000


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

        first_instance = True

        # Check whether this is the first instance of the database
        for value in self._parent.get_instances().values():
            if ('databaseserver' == value._type and
                        self._name != value._name and
                        self.get_state() in deployed_states):
                first_instance = False
                break

        # First, check for all mandatory arguments
        if 'database' not in values:
            raise RolekitError(INVALID_VALUE, "Database name unset")

        if 'owner' not in values:
            # We'll default to db_owner
            values['owner'] = "db_owner"

        # We will assume the owner is new until adding them fails
        new_owner = True

        # Determine if a password was passed in, so we know whether to
        # suppress it from the settings list later.
        if 'password' in values:
            password_provided = True
        else:
            password_provided = False

        if 'postgresql_conf' not in values:
            values['postgresql_conf'] = self._settings['postgresql_conf']

        if 'pg_hba_conf' not in values:
            values['pg_hba_conf'] = self._settings['pg_hba_conf']

        # Get the UID and GID of the 'postgres' user
        try:
            self.pg_uid = pwd.getpwnam('postgres').pw_uid
        except KeyError:
            raise RolekitError(MISSING_ID, "Could not retrieve UID for postgress user")

        try:
            self.pg_gid = grp.getgrnam('postgres').gr_gid
        except KeyError:
            raise RolekitError(MISSING_ID, "Could not retrieve GID for postgress group")

        if first_instance:
            # Initialize the database on the filesystem
            initdb_args = ["/usr/bin/postgresql-setup", "--initdb"]

            log.debug2("TRACE: Initializing database")
            result = yield async.subprocess_future(initdb_args)
            if result.status:
                # If this fails, it may be just that the filesystem
                # has already been initialized. We'll log the message
                # and continue.
                log.debug1("INITDB: %s" % result.stdout)

        # Now we have to start the service to set everything else up
        # It's safe to start an already-running service, so we'll
        # just always make this call, particularly in case other instances
        # exist but aren't running.
        log.debug2("TRACE: Starting postgresql.service unit")
        try:
            with SystemdJobHandler() as job_handler:
                job_path = job_handler.manager.StartUnit("postgresql.service", "replace")
                job_handler.register_job(job_path)
                log.debug2("TRACE: unit start job registered")


                job_results = yield job_handler.all_jobs_done_future()

                log.debug2("TRACE: unit start job concluded")

                if any([x for x in job_results.values() if x not in ("skipped", "done")]):
                    details = ", ".join(["%s: %s" % item for item in job_results.items()])
                    log.error("Starting services failed: {}".format(details))
                    raise RolekitError(COMMAND_FAILED, "Starting services failed: %s" % details)
        except Exception as e:
            log.error("Error received starting unit: {}".format(e))
            raise


        # Next we create the owner
        log.debug2("TRACE: Creating owner of new database")
        createuser_args = ["/usr/bin/createuser", values['owner']]
        result = yield async.subprocess_future(createuser_args,
                                               uid=self.pg_uid,
                                               gid=self.pg_gid)

        if result.status:
            # If the subprocess returned non-zero, the user probably already exists
            # (such as when we're using db_owner). If the caller was trying to set
            # a password, they probably didn't realize this, so we need to throw
            # an exception.
            log.info1("User {} already exists in the database".format(
                      values['owner']))

            if password_provided:
                raise RolekitError(INVALID_SETTING,
                                   "Cannot set password on pre-existing user")

            # If no password was specified, we'll continue
            new_owner = False


        # If no password was requested, generate a random one here
        if not password_provided:
            values['password'] = generate_password()

        log.debug2("TRACE: Creating new database")
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
        # We'll skip this phase if the the user already existed
        if new_owner:
            log.debug2("TRACE: Setting password for database owner")
            pwd_args = [ROLEKIT_ROLES + "/databaseserver/tools/rk_db_setpwd.py",
                        "--database", values['database'],
                        "--user", values['owner']]
            result = yield async.subprocess_future(pwd_args,
                                                   stdin=values['password'],
                                                   uid=self.pg_uid,
                                                   gid=self.pg_gid)

            if result.status:
                # If the subprocess returned non-zero, raise an exception
                log.error("Setting owner password failed: {}".format(result.status))
                raise RolekitError(COMMAND_FAILED,
                                   "Setting owner password failed: %d" %
                                   result.status)

            # If this password was provided by the user, don't save it to
            # the settings for later retrieval. That could be a security
            # issue
            if password_provided:
                values.pop("password", None)
        else: # Not a new owner
            # Never save the password to settings for an existing owner
            log.debug2("TRACE: Owner already exists, not setting password")
            values.pop("password", None)

        if first_instance:
            # Then update the server configuration to accept network
            # connections.
            # edit postgresql.conf to add listen_addresses = '*'
            log.debug2("TRACE: Opening access to external addresses")
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
            log.debug2("TRACE: Restarting postgresql.service unit")
            with SystemdJobHandler() as job_handler:
                job_path = job_handler.manager.RestartUnit("postgresql.service", "replace")
                job_handler.register_job(job_path)

                job_results = yield job_handler.all_jobs_done_future()
                if any([x for x in job_results.values() if x not in ("skipped", "done")]):
                    details = ", ".join(["%s: %s" % item for item in job_results.items()])
                    raise RolekitError(COMMAND_FAILED, "Restarting service failed: %s" % details)

        # Create the systemd target definition
        #
        # We use all of BindsTo, Requires and RequiredBy so we can ensure that
        # all database instances are started and stopped together, since
        # they're really all a single daemon service.
        #
        # The intention here is that starting or stopping any role instance or
        # the main postgresql server will result in the same action happening
        # to all roles. This way, rolekit maintains an accurate view of what
        # instances are running and can communicate that to anyone registered
        # to listen for notifications.

        target = {'Role': 'databaseserver',
                  'Instance': self.get_name(),
                  'Description': "Database Server Role - %s" %
                                 self.get_name(),
                  'BindsTo': ['postgresql.service'],
                  'Requires': ['postgresql.service'],
                  'RequiredBy': ['postgresql.service'],
                  'After': ['syslog.target', 'network.target']}

        log.debug2("TRACE: Database server deployed")

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

        # Get the UID and GID of the 'postgres' user
        try:
            self.pg_uid = pwd.getpwnam('postgres').pw_uid
        except KeyError:
            raise RolekitError(MISSING_ID, "Could not retrieve UID for postgress user")

        try:
            self.pg_gid = grp.getgrnam('postgres').gr_gid
        except KeyError:
            raise RolekitError(MISSING_ID, "Could not retrieve GID for postgress group")

        # Check whether this is the last instance of the database
        last_instance = True
        for value in self._parent.get_instances().values():
            # Check if there are any other instances of databaseserver
            # We have to exclude our own instance name since it hasn't
            # been removed yet.
            if 'databaseserver' == value._type and self._name != value._name:
                last_instance = False
                break

        # The postgresql service must be running to remove
        # the database and owner
        with SystemdJobHandler() as job_handler:
            job_path = job_handler.manager.StartUnit("postgresql.service", "replace")
            job_handler.register_job(job_path)

            job_results = yield job_handler.all_jobs_done_future()
            if any([x for x in job_results.values() if x not in ("skipped", "done")]):
                details = ", ".join(["%s: %s" % item for item in job_results.items()])
                raise RolekitError(COMMAND_FAILED, "Starting services failed: %s" % details)

        # Drop the database
        dropdb_args = ["/usr/bin/dropdb",
                       "-w", "--if-exists",
                       self._settings['database']]
        result = yield async.subprocess_future(dropdb_args,
                                               uid=self.pg_uid,
                                               gid=self.pg_gid)
        if result.status:
            # If the subprocess returned non-zero, raise an exception
            raise RolekitError(COMMAND_FAILED,
                               "Dropping database failed: %d" % result.status)

        # Drop the owner
        dropuser_args = ["/usr/bin/dropuser",
                         "-w", "--if-exists",
                         self._settings['owner']]
        result = yield async.subprocess_future(dropuser_args,
                                               uid=self.pg_uid,
                                               gid=self.pg_gid)
        if result.status:
            # If the subprocess returned non-zero, the user may
            # still be there. This is probably due to the owner
            # having privileges on other instances. This is non-fatal.
            log.error("Dropping owner failed: %d" % result.status)

        # If this is the last instance, restore the configuration
        if last_instance:
            try:
                os.rename("%s.rksave" % self._settings['pg_hba_conf'],
                          self._settings['pg_hba_conf'])
                os.rename("%s.rksave" % self._settings['postgresql_conf'],
                          self._settings['postgresql_conf'])
            except:
                log.error("Could not restore pg_hba.conf and/or postgresql.conf. "
                          "Manual intervention required")
                # Not worth stopping here.

            # Since this is the last instance, turn off the postgresql service
            with SystemdJobHandler() as job_handler:
                job_path = job_handler.manager.StopUnit("postgresql.service", "replace")
                job_handler.register_job(job_path)

                job_results = yield job_handler.all_jobs_done_future()
                if any([x for x in job_results.values() if x not in ("skipped", "done")]):
                    details = ", ".join(["%s: %s" % item for item in job_results.items()])
                    raise RolekitError(COMMAND_FAILED, "Stopping services failed: %s" % details)

        # Decommissioning complete
        yield None

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
                     "password",
                     "postgresql_conf",
                     "pg_hba_conf" ]:
            return dbus.String(x.get_property(x, prop))

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

        @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
        @dbus_handle_exceptions
        def password(self):
            return self.get_dbus_property(self, "password")
