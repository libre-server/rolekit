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
from rolekit.logger import log
from dbus.exceptions import DBusException

"""Helpers for writing asynchronous code in a more natural way.

Instead of a callback hell, an asynchronous function can be linear
and handle exceptions naturally.  The differences from an ordinary synchronous
code are:
* Blocking operations need to be converted into use/activation of a Future,
  and that Future must be yielded from the asynchronous function.
* An asynchronous function can call synchronous function (which will block)
  directly; calling other asynchronous functions needs to happen through
  the async_call() helper.
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

Example asynchronous method:

def do_something_async(param):
    # Blocking operations look like usual
    var = blocking_call(param)

    # The generic case of a blocking operation:
    f = Future()
    # cause f.set_result() or f.set_exception to be somehow called later
    result = yield f

    # Asynchronous subroutine calls:
    yield async.async_call(subroutine_async(param))

    # Return a value; also terminates execution of the async method
    yield 42
"""

import types

from concurrent.futures import Future


__all__ = ("start_async_with_callbacks", "async_call")

def start_async_with_callbacks(generator, result_handler, error_handler):
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

def start_async_with_dbus_callbacks(generator, result_handler, error_handler):
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
            log.error(str(e))
            e = DBusException(str(e))
        error_handler(e)

    return start_async_with_callbacks(generator, result_handler,
                                      error_handler_with_conversion)


def async_call(generator):
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
    start_async_with_callbacks(generator, result_handler, error_handler)
    return f
