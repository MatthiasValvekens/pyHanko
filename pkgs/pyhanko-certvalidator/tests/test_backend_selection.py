"""
Tests for :func:`pyhanko_certvalidator.fetchers._default_fetcher_backend`'s
preference-ordered HTTP backend selection.
"""

import pytest
from pyhanko_certvalidator import fetchers
from pyhanko_certvalidator.context import (
    ValidationContext,
    bootstrap_validation_data_handlers,
)


def _find_spec_stub(available):
    def _find_spec(name, *args, **kwargs):
        return object() if name in available else None

    return _find_spec


@pytest.mark.nosmoke
def test_prefers_aiohttp_when_available(monkeypatch):
    from pyhanko_certvalidator.fetchers.aiohttp_fetchers import (
        AIOHttpFetcherBackend,
    )

    monkeypatch.setattr(
        fetchers, 'find_spec', _find_spec_stub({'aiohttp', 'requests'})
    )
    vc = ValidationContext(allow_fetching=True, trust_roots=[])
    assert isinstance(vc._owned_fetcher_backend, AIOHttpFetcherBackend)


@pytest.mark.nosmoke
def test_falls_back_to_requests_when_aiohttp_unavailable(monkeypatch):
    from pyhanko_certvalidator.fetchers.requests_fetchers import (
        RequestsFetcherBackend,
    )

    monkeypatch.setattr(fetchers, 'find_spec', _find_spec_stub({'requests'}))
    handlers = bootstrap_validation_data_handlers()
    assert isinstance(handlers.owned_fetcher_backend, RequestsFetcherBackend)


def test_raises_informative_error_when_no_backend_available(monkeypatch):
    monkeypatch.setattr(fetchers, 'find_spec', _find_spec_stub(set()))
    with pytest.raises(ImportError, match=r'\[async-http\]'):
        ValidationContext(allow_fetching=True)


def test_bootstrap_raises_informative_error_when_no_backend_available(
    monkeypatch,
):
    monkeypatch.setattr(fetchers, 'find_spec', _find_spec_stub(set()))
    with pytest.raises(ImportError, match=r'\[async-http\]'):
        bootstrap_validation_data_handlers()
