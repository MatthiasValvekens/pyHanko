from importlib.util import find_spec

import pytest
import pytest_asyncio
from pyhanko_certvalidator.fetchers.aiohttp_fetchers import (
    AIOHttpFetcherBackend,
)

pytest_plugins = [
    "pyhanko_testing_commons.test_utils.pkcs11_utils.fixtures",
    "pyhanko_testing_commons.test_utils.live_http_fixtures",
]


@pytest.fixture
def expect_deprecation():
    with pytest.warns(DeprecationWarning):
        yield


FETCHER_BACKENDS = (
    ('requests', 'aiohttp')
    if find_spec('requests') is not None
    else ('aiohttp',)
)


@pytest.fixture(scope="module", params=FETCHER_BACKENDS)
def fetcher_backend_type(request) -> str:
    return request.param


@pytest_asyncio.fixture
async def fetchers(fetcher_backend_type):
    """A set of fetchers to share between several validation contexts."""

    if fetcher_backend_type == 'aiohttp':
        backend = AIOHttpFetcherBackend()
    else:
        from pyhanko_certvalidator.fetchers.requests_fetchers import (
            RequestsFetcherBackend,
        )

        backend = RequestsFetcherBackend()
    try:
        yield backend.get_fetchers()
    finally:
        await backend.close()
