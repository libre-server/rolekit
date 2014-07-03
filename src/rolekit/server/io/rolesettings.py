# -*- coding: utf-8 -*-
#
# Copyright (C) 2011-2012 Red Hat, Inc.
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

import os, io
import shutil
import sys
import json

from rolekit.config import *
from rolekit.errors import *
from rolekit.functions import b2u

PY2 = sys.version < '3'

class RoleSettings(dict):
    """ Rolesettings store """

    def __init__(self, name, *args, **kwargs):
        super(RoleSettings, self).__init__(*args, **kwargs)
        self.name = name
        self.path = ETC_ROLEKIT_ROLES
        self.filename = "%s.json" % name
        self.read()
        
    def read(self):
        name = "%s/%s" % (self.path, self.filename)

        if not os.path.exists(name):
            return

        with open(name, "r") as f:
            data = f.read()
        imported = json.loads(data)
        del data
        if type(imported) is not dict:
            return

        for key,value in imported.items():
            self[key] = value
        del imported

    def write(self):
        name = "%s/%s" % (self.path, self.filename)

        if os.path.exists(name):
            try:
                shutil.copy2(name, "%s.old" % name)
            except Exception as msg:
                raise IOError("Backup of '%s' failed: %s" % (name, msg))

        d = json.dumps(self)
        with open(name, "w") as f:
            f.write(d)

