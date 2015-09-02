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
#

from rolekit.server.io.systemd import SystemdUnitParser
from rolekit.config import ETC_ROLEKIT_ROLES, SYSTEMD_UNITS
from rolekit.dbus_utils import SystemdJobHandler
import subprocess

def generate_nextboot_unit(type_name, instance_name, settings_file):
    # Create a oneshot systemd service
    # This service will invoke rolectl and pass it the defferedrole
    # settings-file to deploy the role. rolectl will be expected to
    # delete this unit and the settings once the deployment succeeds.
    config = SystemdUnitParser()

    # == Create the [Unit] section == #
    config['Unit'] = {}
    config['Unit']['Description'] = "Deploy {0} role - {1}".format(type_name, instance_name)
    config['Unit']['Wants'] = "network-online.target"
    config['Unit']['After'] = "network-online.target"

    # Ensure that this runs only once, so if it fails we don't keep trying to deploy on
    # subsequent boots.
    config['Unit']['ConditionPathExists'] = "!{0}/{1}/{2}.json".format(ETC_ROLEKIT_ROLES, type_name, instance_name)

    # == Create the [Service] section == #
    config['Service'] = {}
    config['Service']['Type'] = "oneshot"
    config['Service']['RemainAfterExit'] = "no"
    config['Service']['ExecStart'] = "/usr/bin/rolectl deploy --name={0} --settings-file={1} {2}".format(
        instance_name, settings_file, type_name
    )

    # == Create the [Install] section == #
    config['Install'] = {}
    config['Install']['WantedBy'] = "multi-user.target"

    servicename = "deferred-role-deployment-{0}-{1}.service".format(
                  type_name, instance_name)
    with open("{0}/{1}".format(SYSTEMD_UNITS, servicename), 'w') as configfile:
        config.write(configfile)

    # Enable this unit to start at boot
    # In installation environments such as Anaconda's kickstart, the
    # systemd API isn't yet running, so we need to call
    # 'systemctl enable <blah>.service' through exec().
    subprocess.call(['/usr/bin/systemctl',
                     'enable',
                     "{0}".format(servicename),
                     '--quiet'])
