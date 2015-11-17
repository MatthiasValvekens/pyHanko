# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys
import unittest
import re


_non_local = {'patched': False}


def patch():
    if not sys.version_info < (2, 7):
        return

    if _non_local['patched']:
        return

    unittest.TestCase.assertIsInstance = _assert_is_instance
    unittest.TestCase.assertRaises = _assert_raises
    unittest.TestCase.assertRaisesRegexp = _assert_raises_regexp
    unittest.TestCase.assertLess = _assert_less
    unittest.TestCase.assertIn = _assert_in
    _non_local['patched'] = True


def _assert_less(self, a, b, msg=None):
    if not a < b:
        standard_msg = '%s not less than %s' % (unittest.util.safe_repr(a), unittest.util.safe_repr(b))
        self.fail(self._formatMessage(msg, standard_msg))


def _assert_is_instance(self, obj, cls, msg=None):
    if not isinstance(obj, cls):
        if not msg:
            msg = '%s is not an instance of %r' % (obj, cls)
        self.fail(msg)


def _assert_in(self, member, container, msg=None):
    if member not in container:
        standard_msg = '%s not found in %s' % (unittest.util.safe_repr(member), unittest.util.safe_repr(container))
        self.fail(self._formatMessage(msg, standard_msg))


def _assert_raises(self, excClass, callableObj=None, *args, **kwargs):  # noqa
    context = _AssertRaisesContext(excClass, self)
    if callableObj is None:
        return context
    with context:
        callableObj(*args, **kwargs)


def _assert_raises_regexp(self, expected_exception, expected_regexp, callable_obj=None, *args, **kwargs):
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
