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

# This role provides a memory object caching service
# It is deployed inside of a Docker container

import os
import shutil
import dbus.service
from rolekit.server.rolebase import *
from rolekit.dbus_utils import *
from rolekit.errors import *
from rolekit.server.io.systemd import enable_units
from rolekit.server.io.systemd import SystemdContainerServiceUnit

MEMCACHED_DOCKER_IMAGE = "fedora/memcached"

MEMCACHED_ENVIRONMENT_FILE = "/etc/sysconfig/memcached"
MEMCACHED_DEFAULT_PORT = 11211

MiB_SIZE = 1024 * 1024
GiB_SIZE = MiB_SIZE * 1024


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
        "services": [ ],

        # A list of packages that must be installed by the
        # package manager to be able to deploy and run this
        # role. These will be installed before the deploy()
        # routine is invoked, so it can contain packages
        # needed for deployment as well as runtime.
        "packages": [ "memcached",
                      "docker",
                      "python3-docker-py",
                      "python3-psutil" ],

        # The ports or "services" that need to be available
        # in the firewall.
        # These will be opened automatically as part of
        # deployment and associated with the default
        # firewall zone of the system.

        "firewall": { "ports": [ '%s/tcp' % MEMCACHED_DEFAULT_PORT,
                                 '%s/udp' % MEMCACHED_DEFAULT_PORT],
                      "services": [ ] },


        # Role-specific settings belong here, with their defaults
        # Roles that have no default should be specified here, with
        # 'None' as their default

        # How many megabytes to allocate for the cache
        # If this is unspecified, the default will be 1 GB or
        # 25% of the total RAM on the system, whichever is smaller
        "cache_size": GiB_SIZE / MiB_SIZE,

        # How many concurrent connections are allowed?
        # Default: 1024 (from upstream recommendations)
        "connections": 1024,

        # How many threads should memcache run?
        # Upstream does not recommend changing this value from the
        # default.
        "threads": 4,
    })

    # Maximum number of instances of this role that can be instantiated
    # on a single host.

    # Until we work out how to set multiple firewall ports, this will
    # provide a single instance.
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
        import docker

        # Get the default cache size
        # Find out how much RAM is available on the system
        if 'cache_size' not in values:
            # Do a late import of psutil. This will only get
            # used during a deployment, so we don't need to
            # have it as a dependency for rolekit itself
            import psutil

            # Get the total number of bytes in local system memory
            total_ram = psutil.virtual_memory().total

            # If 25% of the available memory is less than 1GB, use
            # that for the cache.
            if total_ram / 4 < GiB_SIZE:
                # Set cache_size in MiB
                values['cache_size'] = int(total_ram / 4 / MiB_SIZE)
            else:
                # Cap the default size at 1 GB in MiB
                values['cache_size'] = int(GiB_SIZE / MiB_SIZE)

        # Set defaults
        if "connections" not in values:
            values["connections"] = self._DEFAULTS["connections"]

        if "threads" not in values:
            values["threads"] = self._DEFAULTS["threads"]

        # Create a container for memcached and launch that
        log.debug2("Enabling the Docker container manager")

        # Enable and start the docker service
        enable_units(['docker.service'])

        log.debug2("Starting the Docker container manager")
        with SystemdJobHandler() as job_handler:
            job_path = job_handler.manager.StartUnit("docker.service", "replace")
            job_handler.register_job(job_path)

            job_results = yield job_handler.all_jobs_done_future()
            if any([x for x in job_results.values() if x not in ("skipped", "done")]):
                details = ", ".join(["%s: %s" % item for item in job_results.items()])
                raise RolekitError(COMMAND_FAILED, "Starting docker.service failed: %s" % details)

        log.debug2("Pulling %s image from Docker Hub" % MEMCACHED_DOCKER_IMAGE)
        dockerclient = docker.Client(base_url=docker.utils.utils.DEFAULT_UNIX_SOCKET,
                                     version='auto')

        # First, pull down the latest version of the memcached container
        dockerclient.pull(MEMCACHED_DOCKER_IMAGE, tag="latest")

        log.debug2("Creating systemd service unit")
        # Generate a systemd service unit for this container
        container_unit = SystemdContainerServiceUnit(
            image_name = MEMCACHED_DOCKER_IMAGE,
            container_name = "memcached_%s" % self.get_name(),
            desc="memcached docker container - %s" % self.get_name(),
            env = {
                "MEMCACHED_CACHE_SIZE": str(values['cache_size']),
                "MEMCACHED_CONNECTIONS": str(values['connections']),
                "MEMCACHED_THREADS": str(values['threads'])
            },
            ports = ("{0}:{0}/tcp".format(MEMCACHED_DEFAULT_PORT),
                     "{0}:{0}/udp".format(MEMCACHED_DEFAULT_PORT))
        )
        container_unit.write()

        # Make systemd load this new unit file
        log.debug2("Running systemd daemon-reload")
        with SystemdJobHandler() as job_handler:
            job_handler.manager.Reload()

        # Return the target dictionary
        target = {'Role': 'memcache',
                  'Instance': self.get_name(),
                  'Description': "Memory Cache Role - %s" %
                                 self.get_name(),
                  'Wants': ['memcached_%s.service' % self.get_name()],
                  'After': ['network.target']}
        log.debug9("TRACE: exiting do_deploy_async")
        yield target

    # Redeploy code
    def do_redeploy_async(self, values, sender=None):
        # Run whatever series of actions are needed to update the
        # role with a new high-level configuration.
        # Note: This should be configuration of the role itself,
        # not configuration of data held by the role. That should
        # be managed by the standard tools for interacting with
        # the role.
        #

        # For this role, we can just run the decommission routine
        # and then the deploy routine again.
        yield async.call_future(self.do_decommission_async(values, sender))

        # Invoke the deploy routine again
        # Discard the target return; we don't need it
        yield async.call_future(self.do_deploy_async(values, sender))

        # Success
        yield None


    # Decommission code
    def do_decommission_async(self, force=False, sender=None):
        # Remove the container unit
        # Nothing else needs to happen here; the image is
        # removed as part of the role stop() operation
        path = "%s/memcached_%s.service" % (SYSTEMD_UNITS, self.get_name())
        try:
            os.unlink(path)
        except FileNotFoundError:
            # If the file wasn't there, this is probably part of a
            # redeploy fixing a failed initial deployment.
            pass

        yield None


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

        if prop in [ "cache_size" ]:
            import psutil

            self.check_type_int(value)
            if value > psutil.virtual_memory().total / MiB_SIZE:
                raise RolekitError(INVALID_VALUE,
                                   "Cache size exceeds physical memory")
            return True

        elif prop in [ "connections" ]:
            return self.check_type_int(value)

        elif prop in [ "threads" ]:
            self.check_type_int(value)
            # Up to four threads should be safe on any platform
            # More than that should be limited by the available CPUs
            if value <= 4:
                return True
            elif value > os.cpu_count():
                raise RolekitError(INVALID_VALUE,
                                   "Number of threads exceeds available CPUs")
            return True

        # We didn't recognize this argument
        return False


    @staticmethod
    def do_get_dbus_property(x, prop):
        # This method tells rolekit what D-BUS type to use for each
        # of this role's custom settings.

        if prop in [ "connections",
                     "threads" ]:
            return dbus.Int32(x.get_property(x, prop))
        elif prop in [ "cache_size" ]:
            return dbus.Int64(x.get_property(x, prop))

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
    def cache_size(self):
        return self.get_dbus_property(self, "cache_size")

    @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
    @dbus_handle_exceptions
    def connections(self):
        return self.get_dbus_property(self, "connections")

    @dbus.service.property(DBUS_INTERFACE_ROLE_INSTANCE, signature='s')
    @dbus_handle_exceptions
    def threads(self):
        return self.get_dbus_property(self, "threads")
