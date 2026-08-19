"""Tests for the ownership rules around implicitly provisioned fetchers."""

import pytest
from pyhanko_certvalidator.context import (
    USE_DEFAULT_FETCHERS,
    CertValidationPolicySpec,
    ValidationContext,
    ValidationDataHandlers,
    bootstrap_validation_data_handlers,
)
from pyhanko_certvalidator.fetchers import (
    FetcherBackend,
    Fetchers,
    OwnedFetcherBackend,
)
from pyhanko_certvalidator.fetchers.aiohttp_fetchers import (
    AIOHttpFetcherBackend,
)
from pyhanko_certvalidator.fetchers.aiohttp_fetchers.util import LazySession
from pyhanko_certvalidator.ltv.poe import POEManager
from pyhanko_certvalidator.ltv.types import ValidationTimingInfo
from pyhanko_certvalidator.policy_decl import (
    CertRevTrustPolicy,
    RevocationCheckingPolicy,
)
from pyhanko_certvalidator.registry import (
    CertificateRegistry,
    SimpleTrustManager,
)
from pyhanko_certvalidator.revinfo.manager import RevinfoManager


class RecordingBackend(FetcherBackend):
    """A backend that only remembers whether it was closed."""

    def __init__(self):
        self.closed = 0
        self._delegate = AIOHttpFetcherBackend()

    def get_fetchers(self) -> Fetchers:
        return self._delegate.get_fetchers()

    async def close(self):
        self.closed += 1


def _handlers_only() -> tuple[RevinfoManager, CertificateRegistry]:
    registry = CertificateRegistry()
    return (
        RevinfoManager(
            certificate_registry=registry,
            poe_manager=POEManager(),
            crls=[],
            ocsps=[],
        ),
        registry,
    )


@pytest.mark.asyncio
async def test_context_provisions_and_owns_a_backend():
    vc = ValidationContext(trust_roots=[], allow_fetching=True)
    backend = vc._owned_fetcher_backend
    assert isinstance(backend, AIOHttpFetcherBackend)
    # closing the context releases what it provisioned...
    await vc.aclose()
    # ...and is repeatable, since a context outlives any single operation
    await vc.aclose()


@pytest.mark.asyncio
async def test_context_leaves_a_supplied_backend_alone():
    backend = RecordingBackend()
    vc = ValidationContext(
        trust_roots=[], allow_fetching=True, fetcher_backend=backend
    )
    assert vc._owned_fetcher_backend is None
    await vc.aclose()
    assert backend.closed == 0


@pytest.mark.asyncio
async def test_context_leaves_supplied_fetchers_alone():
    backend = RecordingBackend()
    vc = ValidationContext(
        trust_roots=[],
        allow_fetching=True,
        fetchers=backend.get_fetchers(),
    )
    assert vc._owned_fetcher_backend is None
    await vc.aclose()
    assert backend.closed == 0


@pytest.mark.asyncio
async def test_context_adopts_an_owned_backend():
    backend = RecordingBackend()
    vc = ValidationContext(
        trust_roots=[],
        allow_fetching=True,
        fetcher_backend=OwnedFetcherBackend(backend),
    )
    assert vc._owned_fetcher_backend is backend
    await vc.aclose()
    assert backend.closed == 1


@pytest.mark.asyncio
async def test_no_backend_without_fetching():
    vc = ValidationContext(trust_roots=[], allow_fetching=False)
    assert vc._owned_fetcher_backend is None
    await vc.aclose()


def test_no_backend_when_fetchers_are_unreachable():
    # both the revinfo manager and the registry come from the caller, so
    # anything provisioned here would be discarded unused
    revinfo_manager, registry = _handlers_only()
    vc = ValidationContext(
        trust_roots=[],
        allow_fetching=True,
        revinfo_manager=revinfo_manager,
        certificate_registry=registry,
    )
    assert vc._owned_fetcher_backend is None


@pytest.mark.asyncio
async def test_unreachable_fetchers_still_adopt_an_owned_backend():
    backend = RecordingBackend()
    revinfo_manager, registry = _handlers_only()
    vc = ValidationContext(
        trust_roots=[],
        allow_fetching=True,
        revinfo_manager=revinfo_manager,
        certificate_registry=registry,
        fetcher_backend=OwnedFetcherBackend(backend),
    )
    await vc.aclose()
    assert backend.closed == 1


@pytest.mark.asyncio
async def test_bootstrap_owns_the_default_backend():
    handlers = bootstrap_validation_data_handlers()
    assert isinstance(handlers.owned_fetcher_backend, AIOHttpFetcherBackend)
    await handlers.aclose()


@pytest.mark.asyncio
async def test_bootstrap_owns_the_default_backend_explicitly():
    handlers = bootstrap_validation_data_handlers(fetchers=USE_DEFAULT_FETCHERS)
    assert handlers.owned_fetcher_backend is not None
    await handlers.aclose()


@pytest.mark.asyncio
async def test_bootstrap_without_fetching_owns_nothing():
    handlers = bootstrap_validation_data_handlers(fetchers=None)
    assert handlers.owned_fetcher_backend is None
    assert not handlers.revinfo_manager.fetching_allowed
    await handlers.aclose()


@pytest.mark.asyncio
async def test_bootstrap_leaves_a_supplied_backend_alone():
    backend = RecordingBackend()
    handlers = bootstrap_validation_data_handlers(fetchers=backend)
    assert handlers.owned_fetcher_backend is None
    await handlers.aclose()
    assert backend.closed == 0


@pytest.mark.asyncio
async def test_bootstrap_leaves_supplied_fetchers_alone():
    backend = RecordingBackend()
    handlers = bootstrap_validation_data_handlers(
        fetchers=backend.get_fetchers()
    )
    assert handlers.owned_fetcher_backend is None
    await handlers.aclose()
    assert backend.closed == 0


@pytest.mark.asyncio
async def test_policy_hands_ownership_to_the_context():
    backend = RecordingBackend()
    revinfo_manager, registry = _handlers_only()
    handlers = ValidationDataHandlers(
        revinfo_manager=revinfo_manager,
        poe_manager=POEManager(),
        cert_registry=registry,
        owned_fetcher_backend=backend,
    )
    kwargs = CertValidationPolicySpec(
        trust_manager=SimpleTrustManager.build(trust_roots=[]),
        revinfo_policy=CertRevTrustPolicy(
            RevocationCheckingPolicy.from_legacy("soft-fail")
        ),
    ).build_validation_context_kwargs(
        timing_info=ValidationTimingInfo.now(), handlers=handlers
    )
    assert isinstance(kwargs['fetcher_backend'], OwnedFetcherBackend)
    vc = ValidationContext(trust_roots=[], **kwargs)
    await vc.aclose()
    assert backend.closed == 1


def test_policy_without_handlers_hands_over_nothing():
    kwargs = CertValidationPolicySpec(
        trust_manager=SimpleTrustManager.build(trust_roots=[]),
        revinfo_policy=CertRevTrustPolicy(
            RevocationCheckingPolicy.from_legacy("soft-fail")
        ),
    ).build_validation_context_kwargs(
        timing_info=ValidationTimingInfo.now(), handlers=None
    )
    assert 'fetcher_backend' not in kwargs


@pytest.mark.asyncio
async def test_lazy_session_is_reusable_after_closing():
    lazy = LazySession()
    first = lazy.get_session()
    await lazy.close()
    assert first.closed
    # a fresh session, because the loop that owned the first one is gone by
    # the time a second top-level operation runs
    second = lazy.get_session()
    assert second is not first
    await lazy.close()


@pytest.mark.asyncio
async def test_lazy_session_close_without_a_session():
    await LazySession().close()
