# -*- coding: utf-8 -*-
#
# Copyright (C) 2010-2012 Red Hat, Inc.
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

ALREADY_STARTED     =   11
NOT_STARTED         =   12
TOO_MANY_INSTANCES  =   13
NAME_CONFLICT       =   14

COMMAND_FAILED      =   99

INVALID_ROLE        =  100
INVALID_PROPERTY    =  101
INVALID_VALUE       =  102
INVALID_OBJECT      =  103
INVALID_NAME        =  104
INVALID_SETTING     =  105
INVALID_LOG_LEVEL   =  106

MISSING_ROLE        =  200
MISSING_CHECK       =  201

NOT_RUNNING         =  252
NOT_AUTHORIZED      =  253
UNKNOWN_ERROR       =  254

import sys

class RolekitError(Exception):
    def __init__(self, code, msg=None):
        self.code = code
        self.msg = msg

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__, self.code, self.msg)

    def __str__(self):
        if self.msg:
            return "%s: %s" % (self.errors[self.code], self.msg)
        return self.errors[self.code]

    def get_code(msg):
        if ":" in msg:
            idx = msg.index(":")
            ecode = msg[:idx]
        else:
            ecode = msg

        try:
            code = RolekitError.codes[ecode]
        except KeyError:
            code = UNKNOWN_ERROR

        return code

    get_code = staticmethod(get_code)

mod = sys.modules[RolekitError.__module__]
RolekitError.errors = { getattr(mod,varname) : varname
                         for varname in dir(mod)
                         if not varname.startswith("_") and \
                         type(getattr(mod,varname)) == int }
RolekitError.codes =  { RolekitError.errors[code] : code
                         for code in RolekitError.errors }
