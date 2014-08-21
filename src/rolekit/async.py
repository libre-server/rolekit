# -*- coding: utf-8 -*-
#
# Copyright (C) 2014 Red Hat, Inc.
#
# Authors:
# Miloslav Trmač <mitr@redhat.com>
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
"""Helpers for writing asynchronous code in a more natural way.

Instead of a callback hell, an asynchronous function can be linear
and handle exceptions naturally.  The differences from an ordinary synchronous
code are:
* Blocking operations need to be converted into use/activation of a Future,
  and that Future must be yielded from the asynchronous function.
* An asynchronous function can call synchronous function (which will block)
  directly; calling other asynchronous functions needs to happen through
  the async.call_future() helper.
* Instead of returning a value, the function must yield it.   (Falling off
  the end of a method, or a plain return without a value, is still equivalent
  to returning None, but your function does need to contain at least one
  “yield” command to be considered a generator.  return with a value is invalid
  in a generator, so Python won’t let you use it as long as there is at least
  one yield expression within the function.)

Due to use of generators, an asynchronous function can’t be directly called
synchronously (the call of a generator function just creates a generator
object); asynchronous methods will therefore be conventionally marked with an
"_async" suffix.

As a related convention, functions that _return_ (not yield) a future should
have a "_future" suffix.

Example asynchronous method:

def do_something_async(param):
    # Blocking operations look like usual
    var = blocking_call(param)

    # The generic case of a blocking operation:
    f = Future()
    # cause f.set_result() or f.set_exception() to be somehow called later
    result = yield f

    # A blocking operation with a helper function to set up the future.
    result = yield async.subprocess_future(["/bin/true"])

    # Asynchronous subroutine calls:
    yield async.call_future(subroutine_async(param))

    # Return a value; also terminates execution of the async method
    yield 42
"""

import collections
import fcntl
import os
import subprocess
import types

from concurrent.futures import Future
from dbus.exceptions import DBusException
from gi.repository import GLib

from rolekit.logger import log


# Always import the module and refer to functions with an async. prefix;
# “import *” and “from async import …” are discouraged.
__all__ = ()

def start_with_callbacks(generator, result_handler, error_handler):
    """Set up generator as an async coroutine, calling a handler when done.

    :param generator: A generator object (result of calling a generator
    function); instead of blocking, this generator should repeatedly
    yield concurrent.futures.Future objects (and configure them to be
    resolved somehow to prevent a hang), and finally yield a value that
    is not a concurrent.futures.Future.  Returning without yielding a value
    is equivalent to yielding None.
    :param result_handler: A function to be called with the final yielded
    value of generator.
    :param error_handler: A function to be called on error, with an exception
    object.

    The requirement to yield the final return value instead of just returning
    could go away with PEP 380 (i.e. requiring Python 3.3).
    """
    if type(generator) is not types.GeneratorType:
        raise TypeError("A generator object expected")

    # Perform one synchronous step of the generator.
    #
    # This inner function closes over the parameters of setup_async, but is
    # not actually called recursively, so the overall memory usage is constant.
    def async_step(future):
        try:
            if future is None:
                value = None
                exception = None
            else:
                assert future.done() and not future.cancelled()
                try:
                    value = future.result(0)
                    exception = None
                except Exception as exception:
                    value = None

            # Call into the generator to perform a part of its work until it
            # wants to give up the CPU.  The generator can return to us a value
            # through yield (either a Future or a return value, as documented
            # above, received as async_result), simply return (which we see as
            # StopIteration), or raise an exception (caught by the outer
            # try/except block).
            try:
                if exception is not None:
                    async_result = generator.throw(exception)
                else:
                    async_result = generator.send(value)
            except StopIteration:
                async_result = None

            if isinstance(async_result, Future):
                # The generator asks to be reactivated after this Future is
                # done, so arrange for that.
                async_result.add_done_callback(async_step)
            else:
                result_handler(async_result)
        except Exception as e:
            error_handler(e)

    async_step(None)

def start_with_dbus_callbacks(generator, result_handler, error_handler):
    """Set up generator as an async D-Bus-responding coroutine, calling a handler when done.

    :param generator: A generator object (result of calling a generator
    function); instead of blocking, this generator should repeatedly
    yield concurrent.futures.Future objects (and configure them to be
    resolved somehow to prevent a hang), and finally yield a value that
    is not a concurrent.futures.Future.  Returning without yielding a value
    is equivalent to yielding None.
    :param result_handler: A function to be called with the final yielded
    value of generator.
    :param error_handler: A function to be called on error, with an exception
    object.

    The requirement to yield the final return value instead of just returning
    could go away with PEP 380 (i.e. requiring Python 3.3).
    """
    # Keep this in sync with decorators.dbus_handle_exceptions()
    def error_handler_with_conversion(e):
        # We can’t use log.exception() because the traceback is no longer available.
        # So the three cases in dbus_handle_exceptions amount to just this.
        if not isinstance(e, DBusException):
            log.error("{0}: {1}".format(type(e), str(e)))
            e = DBusException(str(e))
        error_handler(e)

    return start_with_callbacks(generator, result_handler,
                                error_handler_with_conversion)


def call_future(generator):
    """Return a future used to record output of generator

    :param generator: A generator object (result of calling a generator
    function); instead of blocking, this generator should repeatedly
    yield concurrent.futures.Future objects (and configure them to be
    resolved somehow to prevent a hang), and finally yield a value that
    is not a concurrent.futures.Future.  Returning without yielding a value
    is equivalent to yielding None.
    :return: a future
    """
    if type(generator) is not types.GeneratorType:
        raise TypeError("A generator object expected")

    f = Future()
    def result_handler(result):
        f.set_result(result)
    def error_handler(exception):
        f.set_exception(exception)
    start_with_callbacks(generator, result_handler, error_handler)
    return f


def _fd_output_future(fd, log_fn):
    """Return a future for all output on fd.

    :param fd: A Python file object to collect output from and close.  The
    caller should not touch it in any way after calling this function.
    """
    output_chunks = [] # A list of strings to avoid an O(N^2) behavior

    # A string holding output data for logging
    # Needs to be stored as a one-item array because strings
    # are immutable and it would otherwise be overwritten by
    # input_handler below
    linebuf = ['']
    future = Future()

    def input_handler(unused_fd, condition, unused_data):
        finished = True
        if (condition & (GLib.IOCondition.ERR | GLib.IOCondition.NVAL)) != 0:
            log.error("Unexpected input handler state %s" % condition)
        else:
            assert (condition & (GLib.IOCondition.IN | GLib.IOCondition.HUP)) != 0
            # Note that HUP and IN can happen at the same time, so don’t
            # explicitly test for HUP.
            try:
                chunk = fd.read()
            except IOError, e:
                log.error("Error reading subprocess output: %s" % e)
            else:
                if len(chunk) > 0:
                    output_chunks.append(chunk)

                    # Log the input at the requested level
                    lines = (linebuf[0] + chunk).split('\n')
                    for line in lines[:-1]:
                        if line.find('\0'):
                            # It's unsafe for us to try to handle
                            # a line with a NULL-terminator in it.
                            log_fn('<suppressed line with NUL>');
                        log_fn(line)
                    linebuf[0] = lines[-1];

                    # Continue until there's no more data to be had
                    finished = False

        if finished:
            fd.close()
            future.set_result("".join(output_chunks))
            return False
        return True

    fcntl.fcntl(fd, fcntl.F_SETFL,
                fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK)
    condition = (GLib.IOCondition.IN | GLib.IOCondition.ERR |
                 GLib.IOCondition.HUP | GLib.IOCondition.NVAL)
    GLib.unix_fd_add_full(GLib.PRIORITY_DEFAULT, fd.fileno(), condition,
                          input_handler, None)

    return future

# An internal type for the result of subprocess_future.  There’s no point in
# exporting this name.
_AsyncSubprocessResult = collections.namedtuple("_AsyncSubprocessResult",
                                               ["status", "stdout", "stderr"])

def subprocess_future(args):
    """Start a subprocess and return a future used to wait for it to finish.

    :param args: A sequence of program arguments (see subprocess.Popen())
    :return: a future for an object with the members status, stdout and stderr,
    representing waitpid()-like status, stdout output and stderr output,
    respectively.
    """
    log.debug9("subprocess: {0}".format(args))
    process = subprocess.Popen(args, close_fds=True,
                               stdin=open("/dev/null", "r"),
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)

    # The three partial results.
    stdout_future = _fd_output_future(process.stdout, log.debug1)
    stderr_future = _fd_output_future(process.stderr, log.error)
    waitpid_future = Future()

    def child_exited(unused_pid, status):
        waitpid_future.set_result(status)
        # GLib has retrieved the process status and freed the PID. Ask the
        # subprocess.Popen object to wait for the process as well; we know this
        # will fail, but it prevents the subprocess module from calling
        # waitpid() on that freed PID in some indeterminate time in the future,
        # where it might take over an unrelated process.  At this point we are
        # technically calling waitpid() on an unallocated PID, which is
        # generally racy, but we don’t have any concurrently running threads
        # creating subprocesses under our hands, so we should be OK.
        process.wait()
    GLib.child_watch_add(GLib.PRIORITY_DEFAULT, process.pid, child_exited)

    # Resolve the returned future when all partial results are resolved.
    future = Future()
    def check_if_done(unused_future):
        if (waitpid_future.done() and stdout_future.done() and
            stderr_future.done()):
            r = _AsyncSubprocessResult(status=waitpid_future.result(),
                                       stdout=stdout_future.result(),
                                       stderr=stderr_future.result())
            future.set_result(r)
    for f in (waitpid_future, stdout_future, stderr_future):
        f.add_done_callback(check_if_done)

    return future
