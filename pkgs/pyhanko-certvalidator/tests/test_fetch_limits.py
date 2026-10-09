import logging
from types import SimpleNamespace

import aiohttp
import pytest
import requests
from pyhanko_certvalidator import authority
from pyhanko_certvalidator.errors import (
    CertificateFetchError,
    CRLFetchError,
    OCSPFetchError,
)
from pyhanko_certvalidator.fetchers.aiohttp_fetchers import (
    AIOHttpFetcherBackend,
)
from pyhanko_certvalidator.fetchers.api import FetchLimits
from pyhanko_certvalidator.fetchers.common_utils import (
    FetchBudget,
    FetchKind,
    cap_aia_urls,
)
from pyhanko_certvalidator.fetchers.requests_fetchers import (
    RequestsFetcherBackend,
)

from .common import load_cert_object

UNLIMITED = FetchLimits(None, None, None)


class FailingSession:
    """Session whose requests always fail, while counting them."""

    def __init__(self):
        self.request_count = 0

    def _fail(self, **kwargs):
        self.request_count += 1
        raise aiohttp.ClientError("no network")

    get = post = _fail


class Network:
    def __init__(self, backend_factory, request_count):
        self.backend_factory = backend_factory
        self._request_count = request_count

    @property
    def request_count(self):
        return self._request_count()


@pytest.fixture(params=['aiohttp', 'requests'])
def network(request, monkeypatch):
    if request.param == 'aiohttp':
        session = FailingSession()
        return Network(
            lambda limits: AIOHttpFetcherBackend(session, limits=limits),
            lambda: session.request_count,
        )

    calls = []

    def fail(**kwargs):
        calls.append(kwargs)
        raise requests.RequestException("no network")

    monkeypatch.setattr(requests, 'get', fail)
    monkeypatch.setattr(requests, 'post', fail)
    return Network(
        lambda limits: RequestsFetcherBackend(limits=limits),
        lambda: len(calls),
    )


async def _fetch_crl(fetchers, url):
    crl_fetcher = fetchers.crl_fetcher
    single = (
        getattr(crl_fetcher, '_single_fetch', None) or crl_fetcher._fetch_single
    )
    return await single(url)


@pytest.mark.asyncio
async def test_cert_requests_beyond_total_limit_are_refused(network):
    fetchers = network.backend_factory(
        FetchLimits(max_requests=2)
    ).get_fetchers()
    cert_fetcher = fetchers.cert_fetcher
    for i in range(2):
        with pytest.raises(CertificateFetchError, match="Failed to fetch"):
            await cert_fetcher.fetch_certs(f'http://x/{i}', 'certificate')
    with pytest.raises(CertificateFetchError, match="limit of 2 requests"):
        await cert_fetcher.fetch_certs('http://x/2', 'certificate')
    assert network.request_count == 2


@pytest.mark.asyncio
async def test_cached_results_do_not_consume_budget(network):
    fetchers = network.backend_factory(
        FetchLimits(max_requests=1)
    ).get_fetchers()
    for _ in range(3):
        with pytest.raises(CertificateFetchError, match="Failed to fetch"):
            await fetchers.cert_fetcher.fetch_certs('http://x', 'certificate')
    assert network.request_count == 1


@pytest.mark.asyncio
async def test_cert_limit_does_not_block_other_fetch_types(network):
    fetchers = network.backend_factory(
        FetchLimits(max_cert_requests=1)
    ).get_fetchers()
    for i in range(3):
        with pytest.raises(CRLFetchError, match="Failure to fetch"):
            await _fetch_crl(fetchers, f'http://x/{i}')
    with pytest.raises(CertificateFetchError, match="Failed to fetch"):
        await fetchers.cert_fetcher.fetch_certs('http://x', 'certificate')
    with pytest.raises(CertificateFetchError, match="1 certificate requests"):
        await fetchers.cert_fetcher.fetch_certs('http://y', 'certificate')
    assert network.request_count == 4


@pytest.mark.asyncio
async def test_total_limit_is_shared_between_fetchers(network):
    fetchers = network.backend_factory(
        FetchLimits(max_requests=1)
    ).get_fetchers()
    with pytest.raises(CRLFetchError, match="Failure to fetch"):
        await _fetch_crl(fetchers, 'http://x/crl')
    with pytest.raises(CertificateFetchError, match="limit of 1 requests"):
        await fetchers.cert_fetcher.fetch_certs('http://x', 'certificate')
    with pytest.raises(CRLFetchError, match="limit of 1 requests"):
        await _fetch_crl(fetchers, 'http://x/crl2')
    assert network.request_count == 1


@pytest.mark.asyncio
async def test_ocsp_requests_are_limited(network):
    leaf = load_cert_object('ades', 'time-slide', 'certs', 'alice.crt')
    interm = load_cert_object('ades', 'time-slide', 'certs', 'interm.crt')
    root = load_cert_object('ades', 'time-slide', 'certs', 'root.crt')
    issuer = authority.CertTrustAnchor(interm).authority
    other_issuer = authority.CertTrustAnchor(root).authority
    fetchers = network.backend_factory(
        FetchLimits(max_requests=1)
    ).get_fetchers()
    with pytest.raises(OCSPFetchError, match="Failed to fetch"):
        await fetchers.ocsp_fetcher.fetch(leaf, issuer)
    with pytest.raises(OCSPFetchError, match="limit of 1 requests"):
        await fetchers.ocsp_fetcher.fetch(leaf, other_issuer)
    assert network.request_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['certificate', 'crl'])
async def test_aia_urls_per_object_are_capped(network, monkeypatch, kind):
    urls = [f'http://x/{i}' for i in range(5)]
    for module in ('aiohttp_fetchers', 'requests_fetchers'):
        monkeypatch.setattr(
            f'pyhanko_certvalidator.fetchers.{module}.cert_fetch_client.'
            'gather_aia_issuer_urls',
            lambda cert: iter(urls),
        )
    fetchers = network.backend_factory(
        FetchLimits(max_aia_urls_per_object=2)
    ).get_fetchers()
    cert_fetcher = fetchers.cert_fetcher
    if kind == 'certificate':
        results = cert_fetcher.fetch_cert_issuers(None)
    else:
        results = cert_fetcher.fetch_crl_issuers(
            SimpleNamespace(issuer_cert_urls=urls)
        )
    assert [c async for c in results] == []
    assert network.request_count == 2


def test_aia_urls_are_not_capped_without_a_budget_or_limit(caplog):
    urls = [f'http://x/{i}' for i in range(30)]
    assert cap_aia_urls(None, urls) == urls
    assert cap_aia_urls(FetchBudget(UNLIMITED), iter(urls)) == urls
    assert not caplog.records


def test_aia_cap_logs_a_warning_when_truncating(caplog):
    budget = FetchBudget(FetchLimits(max_aia_urls_per_object=1))
    with caplog.at_level(logging.WARNING):
        assert cap_aia_urls(budget, ['a', 'b']) == ['a']
        assert cap_aia_urls(budget, ['a']) == ['a']
    assert len(caplog.records) == 1


def test_exhaustion_warns_once_then_logs_at_debug(caplog):
    budget = FetchBudget(FetchLimits(max_requests=0))
    with caplog.at_level(logging.DEBUG):
        for _ in range(3):
            with pytest.raises(OCSPFetchError):
                budget.charge(FetchKind.OCSP)
    levels = [r.levelno for r in caplog.records]
    assert levels == [logging.WARNING, logging.DEBUG, logging.DEBUG]


def test_unlimited_budget_never_refuses():
    budget = FetchBudget(UNLIMITED)
    for kind in FetchKind:
        for _ in range(50):
            budget.charge(kind)


@pytest.mark.parametrize(
    'backend_cls', [AIOHttpFetcherBackend, RequestsFetcherBackend]
)
def test_backend_limits_default_and_propagation(backend_cls):
    assert backend_cls().limits == FetchLimits()
    custom = FetchLimits(max_requests=5)
    backend = backend_cls(limits=custom)
    assert backend.limits is custom

    first, second = backend.get_fetchers(), backend.get_fetchers()
    budgets = {
        id(f._budget)
        for f in (
            first.ocsp_fetcher,
            first.crl_fetcher,
            first.cert_fetcher,
        )
    }
    assert len(budgets) == 1
    assert first.cert_fetcher._budget is not second.cert_fetcher._budget
    assert first.cert_fetcher._budget.limits is custom
