# coding=utf-8

import logging
import unittest

from concurrent.futures import Future
from gi.repository import GLib

from rolekit import async


DELAY = 0 # Increase this for debugging

class TestAsyncInfrastructure(unittest.TestCase):
    def __sub_async(self, multiplier):
        """Demonstrating/testing use of yield for async waiting and returning values."""
        logging.debug("sub: starting")
        f1 = Future()
        def fn1():
            logging.debug("sub: async event 1")
            f1.set_exception(ValueError(4))
            return False
        GLib.timeout_add_seconds(DELAY, fn1)
        logging.debug("sub: before first yield")
        try:
            v2 = yield f1
        except Exception as e:
            logging.debug("sub: after first yield: %s", repr(e))
            assert type(e) is ValueError and e.args == (4,)
        else:
            raise AssertionError("sub: expected exception, got %s" % v2)

        f2 = Future()
        def fn2():
            logging.debug("sub: async event 2")
            f2.set_result(2)
            return False
        GLib.timeout_add_seconds(DELAY, fn2)
        logging.debug("sub: before second yield")
        v = yield f2
        logging.debug("sub: after second yield: %s", repr(v))
        assert v == 2

        logging.debug("sub: yielding result")
        yield 37 * multiplier

        logging.debug("sub: reached only on cleanup")

    class __sub_exception_unique_error(Exception):
        pass
    def __sub_exception_async(self, unused_multiplier):
        """Demonstrating/testing raising unhandled exceptions from async subroutines."""
        raise self.__sub_exception_unique_error()

    def __toplevel_async(self, subroutine):
        """Demonstrating use of yield for async waiting and calling async subroutines."""
        logging.debug("top: starting")
        f1 = Future()
        def fn1():
            logging.debug("top: async event 1")
            f1.set_result(1)
            return False
        GLib.timeout_add_seconds(DELAY, fn1)
        logging.debug("top: before first yield")
        v = yield f1
        logging.debug("top: after first yield: %s", repr(v))
        assert v == 1

        logging.debug("top: before yield to subroutine")
        subroutine_result = yield async.async_call(subroutine(10))
        logging.debug("top: after sub yield: %s", repr(v))

        f3 = Future()
        def fn2():
            logging.debug("top: async event 2")
            f3.set_exception(ValueError(2))
            return False
        GLib.timeout_add_seconds(DELAY, fn2)
        logging.debug("top: before second yield")
        try:
            v = yield f3
        except Exception as e:
            logging.debug("top: after second yield: %s", repr(e))
            assert type(e) is ValueError and e.args == (2,)
        else:
            raise AssertionError(v2)

        logging.debug("top: yielding result")
        yield 42 * subroutine_result

        logging.debug("top: reached only on cleanup")

    def __run_in_mainloop(self, callable):
        loop = GLib.MainLoop()
        result = []
        exception = []

        def reply_handler(x):
            logging.debug("reply_handler %s" % repr(x))
            loop.quit()
            result.append(x)
        def error_handler(x):
            logging.debug("error_handler %s" % repr(x))
            loop.quit()
            exception.append(x)

        def init():
            logging.debug("Will start top async")
            try:
                async.start_async_with_callbacks(callable(), reply_handler, error_handler)
            except Exception as e:
                logging.debug("Exception in init %s" % repr(e))
                loop.quit()
                exception.append(e)
            logging.debug("Started top async")
            return False
        GLib.idle_add(init)

        loop.run()

        assert len(result) == 0 or len(exception) == 0
        if len(exception) != 0:
            raise exception[0]
        return result[0]

    def test_async_in_mainloop(self):
        self.assertEqual(self.__run_in_mainloop(lambda: self.__toplevel_async(self.__sub_async)), 42 * 37 * 10)

    def test_async_exception_in_mainloop(self):
        self.assertRaises(self.__sub_exception_unique_error, self.__run_in_mainloop, lambda: self.__toplevel_async(self.__sub_exception_async))

    def __chained_return_sub_async(self):
        """Demonstrating/testing chaining of async return values in the callee."""
        yield 42

    def __chained_return_top_async(self):
        """Demonstrating/testing chaining of async return values in the caller."""
        v = yield async.async_call(self.__chained_return_sub_async())
        yield v

    def test_async_chained_return_in_mainloop(self):
        self.assertEqual(self.__run_in_mainloop(lambda: self.__chained_return_top_async()), 42)

    def __no_return_value_async(self):
        """Demonstrating/testing functions that don’t explicitly return a value."""
        f = Future()
        def fn():
            f.set_result(1)
            return False
        GLib.timeout_add_seconds(DELAY, fn)
        yield f
        pass

    def test_async_StopIteration_in_mainloop(self):
        self.assertIs(self.__run_in_mainloop(lambda: self.__no_return_value_async()), None)

    def __not_a_coroutine_pass(self):
        """Demonstrating/testing handling of functions that aren’t asynchronous."""
        pass

    def __not_a_coroutine_int(self):
        """Demonstrating/testing handling of functions that aren’t asynchronous."""
        return 37

    def test_not_a_coroutine_in_mainloop(self):
        self.assertRaises(TypeError, self.__run_in_mainloop, lambda: self.__not_a_coroutine_pass())
        self.assertRaises(TypeError, self.__run_in_mainloop, lambda: self.__not_a_coroutine_int())

    def test_not_a_coroutine_async_call(self):
        self.assertRaises(TypeError, async.async_call, self.__not_a_coroutine_pass())
        self.assertRaises(TypeError, async.async_call, self.__not_a_coroutine_int())

if __name__ == '__main__':
    #logging.basicConfig(level=logging.DEBUG)
    unittest.main()