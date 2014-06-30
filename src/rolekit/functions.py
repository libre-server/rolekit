# -*- coding: utf-8 -*-
#
# Copyright (C) 2007,2008,2011,2012 Red Hat, Inc.
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

import socket
import os.path
import shlex, pipes
import string
import sys
from rolekit.logger import log

PY2 = sys.version < '3'

def rolekitd_is_active():
    """ Check if rolekitd is active

    @return True if there is a rolekitd pid file and the pid is used by rolekitd
    """

    if not os.path.exists("/var/run/rolekitd.pid"):
        return False

    try:
        with open("/var/run/rolekitd.pid", "r") as fd:
            pid = fd.readline()
    except:
        return False

    if not os.path.exists("/proc/%s" % pid):
        return False

    try:
        with open("/proc/%s/cmdline" % pid, "r") as fd:
            cmdline = fd.readline()
    except:
        return False

    if "rolekitd" in cmdline:
        return True

    return False

def readfile(filename):
    try:
        with open(filename, "r") as f:
            line = "".join(f.readlines())
    except Exception as e:
        log.error('Failed to read file "%s": %s' % (filename, e))
        return None
    return line

def writefile(filename, line):
    try:
        with open(filename, "w") as f:
            f.write(line)
    except Exception as e:
        log.error('Failed to write to file "%s": %s' % (filename, e))
        return False
    return True

def joinArgs(args):
    if "quote" in dir(shlex):
        return " ".join(shlex.quote(a) for a in args)
    else:
        return " ".join(pipes.quote(a) for a in args)

def splitArgs(string):
    if PY2 and isinstance(string, unicode):
        # Python2's shlex doesn't like unicode
        string = u2b(string)
        splits = shlex.split(string)
        return map (b2u, splits)
    else:
        return shlex.split(string)

def b2u(string):
    """ bytes to unicode """
    if isinstance(string, bytes):
        return string.decode('UTF-8', 'replace')
    return string

def u2b(string):
    """ unicode to bytes """
    if not isinstance(string, bytes):
        return string.encode('UTF-8', 'replace')
    return string

def u2b_if_py2(string):
    """ unicode to bytes only if Python 2"""
    if PY2 and isinstance(string, unicode):
            return string.encode('UTF-8', 'replace')
    return string
