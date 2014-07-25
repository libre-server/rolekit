# -*- coding: utf-8 -*-
#
# Copyright (C) 2011,2012 Red Hat, Inc.
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

import dbus
import pwd
import slip.dbus
import sys
import urllib

from concurrent.futures import Future
from rolekit.logger import log

PY2 = sys.version < '3'

SYSTEMD_MANAGER_INTERFACE = "org.freedesktop.systemd1.Manager"
SYSTEMD_MANAGER_NAME = "org.freedesktop.systemd1"
SYSTEMD_MANAGER_PATH = "/org/freedesktop/systemd1"

def command_of_pid(pid):
    """ Get command for pid from /proc """
    try:
        with open("/proc/%d/cmdline" % pid, "r") as f:
            cmd = f.readlines()[0].replace('\0', " ").strip()
    except:
        return None
    return cmd

def pid_of_sender(bus, sender):
    """ Get pid from sender string using
    org.freedesktop.DBus.GetConnectionUnixProcessID """

    dbus_obj = bus.get_object('org.freedesktop.DBus', '/org/freedesktop/DBus')
    dbus_iface = dbus.Interface(dbus_obj, 'org.freedesktop.DBus')

    try:
        pid = int(dbus_iface.GetConnectionUnixProcessID(sender))
    except:
        return None
    return pid

def uid_of_sender(bus, sender):
    """ Get user id from sender string using
    org.freedesktop.DBus.GetConnectionUnixUser """

    dbus_obj = bus.get_object('org.freedesktop.DBus', '/org/freedesktop/DBus')
    dbus_iface = dbus.Interface(dbus_obj, 'org.freedesktop.DBus')

    try:
        uid = int(dbus_iface.GetConnectionUnixUser(sender))
    except:
        return None
    return uid

def user_of_uid(uid):
    """ Get user for uid from pwd """

    try:
        pws = pwd.getpwuid(uid)
    except Exception as msg:
        return None
    return pws[0]

def context_of_sender(bus, sender):
    """ Get SELinux context from sender string using
    org.freedesktop.DBus.GetConnectionSELinuxSecurityContext """

    dbus_obj = bus.get_object('org.freedesktop.DBus', '/org/freedesktop/DBus')
    dbus_iface = dbus.Interface(dbus_obj, 'org.freedesktop.DBus')

    try:
        context =  dbus_iface.GetConnectionSELinuxSecurityContext(sender)
    except:
        return None

    return "".join(map(chr, dbus_to_python(context)))

def command_of_sender(bus, sender):
    """ Return command of D-Bus sender """

    return command_of_pid(pid_of_sender(bus, sender))

def user_of_sender(bus, sender):
    return user_of_uid(uid_of_sender(bus, sender))

def dbus_to_python(obj):
    if obj == None:
        return obj
    elif isinstance(obj, dbus.Boolean):
        return obj == True
    elif isinstance(obj, dbus.String):
        return obj.encode('utf-8') if PY2 else str(obj)
    elif PY2 and isinstance(obj, dbus.UTF8String): # Python3 has no UTF8String
        return str(obj)
    elif isinstance(obj, dbus.ObjectPath):
        return str(obj)
    elif isinstance(obj, dbus.Byte) or \
            isinstance(obj, dbus.Int16) or \
            isinstance(obj, dbus.Int32) or \
            isinstance(obj, dbus.Int64) or \
            isinstance(obj, dbus.UInt16) or \
            isinstance(obj, dbus.UInt32) or \
            isinstance(obj, dbus.UInt64):
        return int(obj)
    elif isinstance(obj, dbus.Double):
        return float(obj)
    elif isinstance(obj, dbus.Array):
        return [dbus_to_python(x) for x in obj]
    elif isinstance(obj, dbus.Struct):
        return tuple([dbus_to_python(x) for x in obj])
    elif isinstance(obj, dbus.Dictionary):
        return {dbus_to_python(k):dbus_to_python(v) for k,v in obj.items()}
    elif isinstance(obj, bool) or \
         isinstance(obj, str) or isinstance(obj, bytes) or \
         isinstance(obj, int) or isinstance(obj, float) or \
         isinstance(obj, list) or isinstance(obj, tuple) or \
         isinstance(obj, dict):
        return obj
    else:
        raise TypeError("Unhandled %s" % obj)

def dbus_label_escape(label):
    # Escape labels to only contain characters dbus is able to handle.
    # The empty string is a special case and returns '_'.

    # Derived from systemd
    # Copyright (C) 2013 Lennard Poettering

    if len(label) < 0:
        return "_"

    ret = ""
    for x in label:
        if (x >= "a" and x <= "z") or (x >= "A" and x <= "Z") \
           or (x >= "0" and x <= "9"):
            ret += x
        else:
            # add hex repressentation of the char and replace 0x by _
            ret += hex(ord(x)).replace("0x", "_")

    return ret


# FIXME: Is it possible to write a reasonably stand-alone test for this?
class SystemdJobHandler(object):
    """An utility for waiting for one or more systemd jobs.

    Usage:

    with SystemdJobHandler() as job_handler:
        job_path = job_handler.manager.$do_something_to_create_a_job
        job_handler.register_job(job_path)
        # Can register more parallel jobs like this

        job_results = yield job_handler.all_jobs_done_future()

    job_results will be a dictionary, in SYSTEMD_MANAGER_INTERFACE.JobRemoved
    terms job_results[unit] = result
    """

    def __init__(self):
        self.__future = Future()
        self.__pending_jobs = set()
        self.__job_results = {}
        self.__signal_match = None

        bus = slip.dbus.SystemBus()
        manager_object = bus.get_object(SYSTEMD_MANAGER_NAME,
                                        SYSTEMD_MANAGER_PATH)
        self.__manager = dbus.Interface(manager_object,
                                         SYSTEMD_MANAGER_INTERFACE)

    def __job_removed_handler(self, job_id, job_path, unit, result):
        """SYSTEMD_MANAGER_INTERFACE.JobRemoved signal handler"""
        log.debug1("systemd JobRemoved signal: %s" %
                   repr((job_id, job_path, unit, result)))
        if job_path in self.__pending_jobs:
            self.__job_results[unit] = result
            self.__pending_jobs.remove(job_path)
            if len(self.__pending_jobs) == 0:
                self.__future.set_result(self.__job_results)

    # We use the context manager protocol to ensure the signal registration is
    # correctly removed.
    def __enter__(self):
        assert self.__signal_match is None, "Recursive use of SystemdJobProcessor"
        assert not self.__future.done(), "Repeated use of SystemdJobProcessor"
        self.__signal_match = self.__manager.connect_to_signal("JobRemoved", self.__job_removed_handler)
        return self # To allow “with SystemdJobHandler as job_handler:”…

    def __exit__(self, *args):
        self.__signal_match.remove()
        self.__signal_match = None
        return False

    # This is not strictly speaking a necessary part of the API, but since we
    # need the interface object for ourselves and the caller needs it as well,
    # let’s make it available.
    @property
    def manager(self):
        """A dbus.Interface object for SYSTEMD_MANAGER_INTERFACE."""
        return self.__manager

    def register_job(self, job_path):
        """Register a job to be followed to completion.

        :param job_path: A path of the job object.  Make sure to provide the
        path soon after receiving it (in particular before allowing any D-Bus
        signals to be processed).
        """
        assert self.__signal_match is not None, \
            "Registering for jobs when not watching for results"
        self.__pending_jobs.add(job_path)

    def all_jobs_done_future(self):
        """Return a future for results of registered jobs.

        :returns: a future.  The value eventually set as a result is
        a dictionary of unit name -> job result string.
        """
        assert self.__signal_match is not None and len(self.__pending_jobs) != 0
        return self.__future
