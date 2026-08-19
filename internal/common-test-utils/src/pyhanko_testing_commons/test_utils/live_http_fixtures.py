"""Pytest plugin exposing the ambient PKI service server as a fixture.

Register with ``pytest_plugins = ["pyhanko_testing_commons.test_utils.
live_http_fixtures"]`` in a ``conftest.py``.
"""

from collections.abc import Iterator

import pytest

from pyhanko_testing_commons.test_utils.live_http import (
    PKIServiceRegistry,
    live_pki_services,
)


@pytest.fixture
def pki_services() -> Iterator[PKIServiceRegistry]:
    """Serve certomancer PKI services over an in-process HTTP server."""

    with live_pki_services() as registry:
        yield registry
