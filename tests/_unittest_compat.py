# coding: utf-8

import asyncio
import inspect
import sys
import unittest
import re
from unittest import TestCase

_non_local = {'patched': False}


# Note: this code is copied from cPython, used under the PSL
# as a polyfill for Python 3.7 compatibility in the tests
# Source: https://github.com/python/cpython/blob/94b462686b7dfabbd69cc9401037d736d71c4dc2/Lib/unittest/async_case.py
# License: https://github.com/python/cpython/blob/94b462686b7dfabbd69cc9401037d736d71c4dc2/LICENSE
# Copyright (c) 2021 Python Software Foundation

class _IsolatedAsyncioTestCase(TestCase):

    def __init__(self, methodName='runTest'):
        super().__init__(methodName)
        self._asyncioTestLoop = None
        self._asyncioCallsQueue = None

    async def asyncSetUp(self):
        pass

    async def asyncTearDown(self):
        pass

    def addAsyncCleanup(self, func, *args, **kwargs):
        # A trivial trampoline to addCleanup()
        # the function exists because it has a different semantics
        # and signature:
        # addCleanup() accepts regular functions
        # but addAsyncCleanup() accepts coroutines
        #
        # We intentionally don't add inspect.iscoroutinefunction() check
        # for func argument because there is no way
        # to check for async function reliably:
        # 1. It can be "async def func()" iself
        # 2. Class can implement "async def __call__()" method
        # 3. Regular "def func()" that returns awaitable object
        self.addCleanup(*(func, *args), **kwargs)

    def _callSetUp(self):
        self.setUp()
        self._callAsync(self.asyncSetUp)

    def _callTestMethod(self, method):
        self._callMaybeAsync(method)

    def _callTearDown(self):
        self._callAsync(self.asyncTearDown)
        self.tearDown()

    def _callCleanup(self, function, *args, **kwargs):
        self._callMaybeAsync(function, *args, **kwargs)

    def _callAsync(self, func, *args, **kwargs):
        assert self._asyncioTestLoop is not None
        ret = func(*args, **kwargs)
        assert inspect.isawaitable(ret)
        fut = self._asyncioTestLoop.create_future()
        self._asyncioCallsQueue.put_nowait((fut, ret))
        return self._asyncioTestLoop.run_until_complete(fut)

    def _callMaybeAsync(self, func, *args, **kwargs):
        assert self._asyncioTestLoop is not None
        ret = func(*args, **kwargs)
        if inspect.isawaitable(ret):
            fut = self._asyncioTestLoop.create_future()
            self._asyncioCallsQueue.put_nowait((fut, ret))
            return self._asyncioTestLoop.run_until_complete(fut)
        else:
            return ret

    async def _asyncioLoopRunner(self, fut):
        self._asyncioCallsQueue = queue = asyncio.Queue()
        fut.set_result(None)
        while True:
            query = await queue.get()
            queue.task_done()
            if query is None:
                return
            fut, awaitable = query
            try:
                ret = await awaitable
                if not fut.cancelled():
                    fut.set_result(ret)
            except (SystemExit, KeyboardInterrupt):
                raise
            except (BaseException, asyncio.CancelledError) as ex:
                if not fut.cancelled():
                    fut.set_exception(ex)

    def _setupAsyncioLoop(self):
        assert self._asyncioTestLoop is None
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.set_debug(True)
        self._asyncioTestLoop = loop
        fut = loop.create_future()
        self._asyncioCallsTask = loop.create_task(self._asyncioLoopRunner(fut))
        loop.run_until_complete(fut)

    def _tearDownAsyncioLoop(self):
        assert self._asyncioTestLoop is not None
        loop = self._asyncioTestLoop
        self._asyncioTestLoop = None
        self._asyncioCallsQueue.put_nowait(None)
        loop.run_until_complete(self._asyncioCallsQueue.join())

        try:
            # cancel all tasks
            to_cancel = asyncio.all_tasks(loop)
            if not to_cancel:
                return

            for task in to_cancel:
                task.cancel()

            loop.run_until_complete(
                asyncio.gather(*to_cancel, loop=loop, return_exceptions=True))

            for task in to_cancel:
                if task.cancelled():
                    continue
                if task.exception() is not None:
                    loop.call_exception_handler({
                        'message': 'unhandled exception during test shutdown',
                        'exception': task.exception(),
                        'task': task,
                    })
            # shutdown asyncgens
            loop.run_until_complete(loop.shutdown_asyncgens())
        finally:
            asyncio.set_event_loop(None)
            loop.close()

    def run(self, result=None):
        self._setupAsyncioLoop()
        try:
            return super().run(result)
        finally:
            self._tearDownAsyncioLoop()


def patch():
    if sys.version_info >= (3, 8):
        return

    if _non_local['patched']:
        return

    if sys.version_info < (3, 8):
        # patch IsolatedAsyncioTestCase
        unittest.IsolatedAsyncioTestCase = _IsolatedAsyncioTestCase

    if sys.version_info >= (3, 0):
        return

    if sys.version_info < (2, 7):
        unittest.TestCase.assertIsInstance = _assert_is_instance
        unittest.TestCase.assertRegex = _assert_regex
        unittest.TestCase.assertRaises = _assert_raises
        unittest.TestCase.assertRaisesRegex = _assert_raises_regex
        unittest.TestCase.assertGreaterEqual = _assert_greater_equal
        unittest.TestCase.assertLess = _assert_less
        unittest.TestCase.assertLessEqual = _assert_less_equal
        unittest.TestCase.assertIn = _assert_in
        unittest.TestCase.assertNotIn = _assert_not_in
    else:
        unittest.TestCase.assertRegex = unittest.TestCase.assertRegexpMatches
        unittest.TestCase.assertRaisesRegex = unittest.TestCase.assertRaisesRegexp
    _non_local['patched'] = True


def _safe_repr(obj):
    try:
        return repr(obj)
    except Exception:
        return object.__repr__(obj)


def _format_message(msg, standard_msg):
    return msg or standard_msg


def _assert_greater_equal(self, a, b, msg=None):
    if not a >= b:
        standard_msg = '%s not greater than or equal to %s' % (_safe_repr(a), _safe_repr(b))
        self.fail(_format_message(msg, standard_msg))


def _assert_less(self, a, b, msg=None):
    if not a < b:
        standard_msg = '%s not less than %s' % (_safe_repr(a), _safe_repr(b))
        self.fail(_format_message(msg, standard_msg))


def _assert_less_equal(self, a, b, msg=None):
    if not a <= b:
        standard_msg = '%s not less than or equal to %s' % (_safe_repr(a), _safe_repr(b))
        self.fail(_format_message(msg, standard_msg))


def _assert_is_instance(self, obj, cls, msg=None):
    if not isinstance(obj, cls):
        if not msg:
            msg = '%s is not an instance of %r' % (obj, cls)
        self.fail(msg)


def _assert_in(self, member, container, msg=None):
    if member not in container:
        standard_msg = '%s not found in %s' % (_safe_repr(member), _safe_repr(container))
        self.fail(_format_message(msg, standard_msg))


def _assert_not_in(self, member, container, msg=None):
    if member in container:
        standard_msg = '%s found in %s' % (_safe_repr(member), _safe_repr(container))
        self.fail(_format_message(msg, standard_msg))


def _assert_regex(self, text, expected_regexp, msg=None):
    """Fail the test unless the text matches the regular expression."""
    if isinstance(expected_regexp, str):
        expected_regexp = re.compile(expected_regexp)
    if not expected_regexp.search(text):
        msg = msg or "Regexp didn't match"
        msg = '%s: %r not found in %r' % (msg, expected_regexp.pattern, text)
        self.fail(msg)


def _assert_raises(self, excClass, callableObj=None, *args, **kwargs):  # noqa
    context = _AssertRaisesContext(excClass, self)
    if callableObj is None:
        return context
    with context:
        callableObj(*args, **kwargs)


def _assert_raises_regex(self, expected_exception, expected_regexp, callable_obj=None, *args, **kwargs):
    if expected_regexp is not None:
        expected_regexp = re.compile(expected_regexp)
    context = _AssertRaisesContext(expected_exception, self, expected_regexp)
    if callable_obj is None:
        return context
    with context:
        callable_obj(*args, **kwargs)


class _AssertRaisesContext(object):
    def __init__(self, expected, test_case, expected_regexp=None):
        self.expected = expected
        self.failureException = test_case.failureException
        self.expected_regexp = expected_regexp

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        if exc_type is None:
            try:
                exc_name = self.expected.__name__
            except AttributeError:
                exc_name = str(self.expected)
            raise self.failureException(
                "{0} not raised".format(exc_name))
        if not issubclass(exc_type, self.expected):
            # let unexpected exceptions pass through
            return False
        self.exception = exc_value  # store for later retrieval
        if self.expected_regexp is None:
            return True

        expected_regexp = self.expected_regexp
        if not expected_regexp.search(str(exc_value)):
            raise self.failureException(
                '"%s" does not match "%s"' %
                (expected_regexp.pattern, str(exc_value))
            )
        return True
