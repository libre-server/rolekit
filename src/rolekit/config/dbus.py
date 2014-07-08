# -*- coding: utf-8 -*-
#
# Copyright (C) 2011-2014 Red Hat, Inc.
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
#

DBUS_INTERFACE_VERSION = 1
DBUS_INTERFACE_REVISION = 1

DBUS_INTERFACE = "org.fedoraproject.rolekit%d" % DBUS_INTERFACE_VERSION
DBUS_INTERFACE_ROLES = DBUS_INTERFACE+".roles"

DBUS_PATH = "/org/fedoraproject/rolekit%d" % DBUS_INTERFACE_VERSION
DBUS_PATH_ROLES = DBUS_PATH + "/roles"

# Polkit actions
_PK_ACTION = "org.fedoraproject.rolekit%d" % DBUS_INTERFACE_VERSION
PK_ACTION_ALL = _PK_ACTION+".all"
