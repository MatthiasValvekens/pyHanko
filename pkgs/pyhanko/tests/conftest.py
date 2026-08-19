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


@pytest_asyncio.fixture
async def fetchers():
    """A set of fetchers to share between several validation contexts."""

    backend = AIOHttpFetcherBackend()
    try:
        yield backend.get_fetchers()
    finally:
        await backend.close()
