import pytest
import pytest_asyncio
from pyhanko_certvalidator.fetchers.aiohttp_fetchers import (
    AIOHttpFetcherBackend,
)
from pyhanko_certvalidator.fetchers.requests_fetchers import (
    RequestsFetcherBackend,
)

pytest_plugins = [
    "pyhanko_testing_commons.test_utils.pkcs11_utils.fixtures",
    "pyhanko_testing_commons.test_utils.live_http_fixtures",
]


@pytest.fixture
def expect_deprecation():
    with pytest.warns(DeprecationWarning):
        yield


FETCHER_BACKENDS = ('requests', 'aiohttp')


@pytest.fixture(scope="module", params=FETCHER_BACKENDS)
def fetcher_backend_type(request) -> str:
    return request.param


@pytest_asyncio.fixture
async def fetchers(fetcher_backend_type):
    """A set of fetchers to share between several validation contexts."""

    backend = (
        AIOHttpFetcherBackend()
        if fetcher_backend_type == 'aiohttp'
        else RequestsFetcherBackend()
    )
    try:
        yield backend.get_fetchers()
    finally:
        await backend.close()
