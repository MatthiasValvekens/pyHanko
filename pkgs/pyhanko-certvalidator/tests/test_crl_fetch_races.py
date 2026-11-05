import asyncio
import contextlib
import enum
from types import SimpleNamespace

import aiohttp
import pytest
import requests
from asn1crypto import x509
from pyhanko_certvalidator.errors import CRLFetchError
from pyhanko_certvalidator.fetchers.aiohttp_fetchers import (
    AIOHttpFetcherBackend,
)
from pyhanko_certvalidator.fetchers.common_utils import (
    FetchKind,
    crl_fetch_url_groups,
    first_successful_fetch,
)
from pyhanko_certvalidator.fetchers.requests_fetchers import (
    RequestsFetcherBackend,
)

from .common import load_cert_object, load_crl
from .test_common_utils import ATTRIBUTE_CERT

BASE_CERT = load_cert_object('testing-aia', 'with-ldap-urls.der')
CRL_BYTES = load_crl('freshness', 'root-2020-10-01.crl').dump()
SOME_NAME = BASE_CERT.issuer


def _dp(*urls, reasons=None, crl_issuer=False):
    dp = {}
    if urls:
        dp['distribution_point'] = x509.DistributionPointName(
            name='full_name',
            value=[
                x509.GeneralName(name='uniform_resource_identifier', value=u)
                for u in urls
            ],
        )
    if reasons:
        dp['reasons'] = x509.ReasonFlags(set(reasons))
    if crl_issuer:
        dp['crl_issuer'] = [
            x509.GeneralName(name='directory_name', value=SOME_NAME)
        ]
    return x509.DistributionPoint(dp)


def _cert_with_dps(dps=(), delta_dps=(), serial=1) -> x509.Certificate:
    cert = x509.Certificate.load(BASE_CERT.dump())
    tbs = cert['tbs_certificate']
    exts = [
        ext
        for ext in tbs['extensions']
        if ext['extn_id'].native
        not in ('crl_distribution_points', 'freshest_crl')
    ]
    for ext_id, value in (
        ('crl_distribution_points', dps),
        ('freshest_crl', delta_dps),
    ):
        if value:
            exts.append(
                x509.Extension({'extn_id': ext_id, 'extn_value': list(value)})
            )
    tbs['extensions'] = x509.Extensions(exts)
    tbs['serial_number'] = serial
    return x509.Certificate.load(cert.dump(force=True))


@pytest.mark.parametrize(
    'dps,expected',
    [
        # mirrors published as separate DPs
        ([_dp('http://a'), _dp('http://b')], [['http://a', 'http://b']]),
        # a DP with several URLs must only be enumerated once
        ([_dp('http://a', 'http://b')], [['http://a', 'http://b']]),
        (
            [_dp('http://a'), _dp('http://a', 'http://b')],
            [['http://a', 'http://b']],
        ),
        (
            [
                _dp('http://a'),
                _dp('http://b', 'http://c', reasons={'key_compromise'}),
                _dp('http://d'),
            ],
            [['http://a', 'http://d'], ['http://b', 'http://c']],
        ),
        (
            [_dp('http://a', crl_issuer=True), _dp('http://b')],
            [['http://b'], ['http://a']],
        ),
        (
            [
                _dp('http://a', crl_issuer=True),
                _dp('http://b', crl_issuer=True),
            ],
            [['http://a'], ['http://b']],
        ),
        # nothing we can fetch
        ([_dp(crl_issuer=True), _dp('ldap://a')], []),
        ([], []),
    ],
)
def test_crl_fetch_url_groups(dps, expected):
    cert = _cert_with_dps(dps)
    assert crl_fetch_url_groups(cert, use_deltas=True) == expected


@pytest.mark.parametrize(
    'use_deltas,expected',
    [
        (True, [['http://a'], ['http://d1', 'http://d2']]),
        (False, [['http://a']]),
    ],
)
def test_crl_fetch_url_groups_deltas_separate(use_deltas, expected):
    cert = _cert_with_dps(
        [_dp('http://a')], delta_dps=[_dp('http://d1'), _dp('http://d2')]
    )
    assert crl_fetch_url_groups(cert, use_deltas=use_deltas) == expected


def test_crl_fetch_url_groups_attribute_cert():
    assert crl_fetch_url_groups(ATTRIBUTE_CERT, use_deltas=True) == [
        ['http://localhost:9000/basic-aa/crls/role-aa/latest.crl']
    ]


async def _fail(msg):
    raise CRLFetchError(msg)


async def _succeed_after(event: asyncio.Event, value):
    await event.wait()
    return value


@pytest.mark.asyncio
async def test_first_successful_fetch_survives_earlier_failures():
    go = asyncio.Event()

    async def fail_then_release():
        go.set()
        raise CRLFetchError("first")

    result = await first_successful_fetch(
        [fail_then_release(), _succeed_after(go, 'ok')], FetchKind.CRL
    )
    assert result == 'ok'


@pytest.mark.asyncio
async def test_first_successful_fetch_cancels_losers():
    cancelled = asyncio.Event()

    async def hang():
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise

    async def win():
        return 'ok'

    result = await first_successful_fetch([hang(), win()], FetchKind.CRL)
    assert result == 'ok'
    assert cancelled.is_set()


@pytest.mark.asyncio
async def test_first_successful_fetch_all_fail():
    with pytest.raises(CRLFetchError, match="nope"):
        await first_successful_fetch(
            [_fail("nope"), _fail("nope")], FetchKind.CRL
        )


@pytest.mark.asyncio
async def test_first_successful_fetch_no_jobs():
    with pytest.raises(CRLFetchError, match="No CRL results"):
        await first_successful_fetch([], FetchKind.CRL)


class Behaviour(enum.Enum):
    OK = enum.auto()
    FAIL = enum.auto()
    HANG = enum.auto()


class FakeNetwork:
    def __init__(self):
        self.behaviour: dict[str, Behaviour] = {}
        self.requested: list[str] = []
        self.cancelled: list[str] = []

    async def serve_async(self, url):
        self.requested.append(url)
        behaviour = self.behaviour[url]
        if behaviour is Behaviour.HANG:
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.cancelled.append(url)
                raise
        if behaviour is Behaviour.FAIL:
            raise aiohttp.ClientError("down")
        return CRL_BYTES

    def serve_sync(self, *, url, **_kwargs):
        self.requested.append(url)
        if self.behaviour[url] is Behaviour.FAIL:
            raise requests.RequestException("down")
        return SimpleNamespace(status_code=200, content=CRL_BYTES)


class FakeSession:
    def __init__(self, network: FakeNetwork):
        self.network = network

    @contextlib.asynccontextmanager
    async def get(self, *, url, **_kwargs):
        data = await self.network.serve_async(url)
        yield SimpleNamespace(read=lambda: asyncio.sleep(0, data))


@pytest.fixture
def network():
    return FakeNetwork()


@pytest.fixture
def aiohttp_crl_fetcher(network):
    backend = AIOHttpFetcherBackend(FakeSession(network))
    return backend.get_fetchers().crl_fetcher


@pytest.fixture(params=['aiohttp', 'requests'])
def crl_fetcher(request, network, monkeypatch):
    if request.param == 'aiohttp':
        return request.getfixturevalue('aiohttp_crl_fetcher')
    monkeypatch.setattr(requests, 'get', network.serve_sync)
    return RequestsFetcherBackend().get_fetchers().crl_fetcher


MIRRORS = [_dp('http://a'), _dp('http://b')]


@pytest.mark.asyncio
async def test_mirror_failure_does_not_fail_fetch(network, crl_fetcher):
    network.behaviour = {'http://a': Behaviour.FAIL, 'http://b': Behaviour.OK}
    result = await crl_fetcher.fetch(_cert_with_dps(MIRRORS))
    assert len(result) == 1


@pytest.mark.asyncio
async def test_all_mirrors_failing_fails_fetch(network, crl_fetcher):
    network.behaviour = {'http://a': Behaviour.FAIL, 'http://b': Behaviour.FAIL}
    with pytest.raises(CRLFetchError):
        await crl_fetcher.fetch(_cert_with_dps(MIRRORS))


@pytest.mark.asyncio
async def test_scoped_dps_are_not_raced(network, crl_fetcher):
    network.behaviour = {'http://a': Behaviour.OK, 'http://b': Behaviour.OK}
    cert = _cert_with_dps(
        [_dp('http://a'), _dp('http://b', reasons={'key_compromise'})]
    )
    result = await crl_fetcher.fetch(cert)
    assert len(result) == 2
    assert sorted(network.requested) == ['http://a', 'http://b']


@pytest.mark.asyncio
async def test_cached_mirror_result_is_reused(network, crl_fetcher):
    network.behaviour = {'http://a': Behaviour.FAIL, 'http://b': Behaviour.OK}
    await crl_fetcher.fetch(_cert_with_dps(MIRRORS, serial=1))
    result = await crl_fetcher.fetch(_cert_with_dps(MIRRORS, serial=2))
    assert len(result) == 1
    assert sorted(network.requested) == ['http://a', 'http://b']


@pytest.mark.asyncio
async def test_no_dps_no_fetch(network, crl_fetcher):
    assert await crl_fetcher.fetch(_cert_with_dps()) == []
    assert network.requested == []


@pytest.mark.asyncio
async def test_slow_mirror_is_abandoned(network, aiohttp_crl_fetcher):
    network.behaviour = {'http://a': Behaviour.HANG, 'http://b': Behaviour.OK}
    result = await asyncio.wait_for(
        aiohttp_crl_fetcher.fetch(_cert_with_dps(MIRRORS, serial=1)), 1
    )
    assert len(result) == 1
    assert network.cancelled == ['http://a']

    # a cancelled fetch neither poisons the cache nor leaves waiters hanging
    network.behaviour['http://a'] = Behaviour.OK
    result = await asyncio.wait_for(
        aiohttp_crl_fetcher.fetch(_cert_with_dps([_dp('http://a')], serial=2)),
        1,
    )
    assert len(result) == 1
    assert network.requested.count('http://a') == 2
