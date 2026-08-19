"""Support framework for the executable documentation samples (doctests).

This module exposes a single declarative entry point, :func:`make_doc_env`,
which takes a :class:`DocEnvSpec` parameter object and returns a mapping of
names to inject into a document's doctest globals. It is responsible for all
the boilerplate the samples themselves should not have to show:

* an isolated working directory, so literal ``open('document.pdf', 'rb')``
  calls in the samples resolve against real files;
* materialised input files (sample PDFs) and signer key material (PEM and
  PKCS#12) written to the placeholder paths the samples reference;
* network mocking for timestamping and revocation info, so samples that talk
  to ``http://tsa.example.com`` or fetch OCSP/CRLs simply work;
* a bundle of injected helper symbols (test signers, timestampers and the
  stand-in "remote service" callables used by the interrupted-signing
  examples).

Everything is built on top of the existing test utilities
(:mod:`pyhanko_testing_commons.test_utils.signing_commons` and
:mod:`pyhanko_testing_commons.test_data.samples`), so the certomancer PKI,
canonical sample PDFs and key material are reused verbatim.
"""

import asyncio
import enum
import os
import tempfile
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from typing import (
    Any,
)

import aiohttp
import aiohttp.web
import tzlocal
from asn1crypto import pem, tsp
from certomancer import PKIArchitecture
from certomancer.integrations.aiohttp_illusionist import AsyncIllusionist
from certomancer.registry import (
    ArchLabel,
    CertLabel,
    EntityLabel,
    KeyLabel,
    ServiceLabel,
)
from cryptography.hazmat.primitives import serialization
from freezegun import freeze_time
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers, timestamps
from pyhanko.sign.signers.pdf_cms import ExternalSigner, SimpleSigner
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.registry import SimpleCertificateStore

from pyhanko_testing_commons.test_data import samples
from pyhanko_testing_commons.test_data.certomancer_trust_lists import (
    certomancer_pki_as_trusted_list,
)
from pyhanko_testing_commons.test_utils import signing_commons
from pyhanko_testing_commons.test_utils.live_http import live_pki_services

__all__ = [
    'EXAMPLE_DOMAIN',
    'FREEZE_DT',
    'DocEnv',
    'DocEnvSpec',
    'SignatureProfile',
    'SignedDocSpec',
    'SignerProvisioning',
    'SignerSpec',
    'TimestampSpec',
    'TrustListSpec',
    'TrustSpec',
    'make_doc_env',
    'run_with_seeded_lotl',
    'seed_lotl_cache',
    'teardown_doc_env',
]


#: Single canonical domain from which every example URL is derived. The
#: samples display URLs under this domain, and the network mocks key off it.
EXAMPLE_DOMAIN = 'pyhanko.tests'

#: Fixed point in time at which the doctests run. Chosen to fall within the
#: validity window of the certomancer ``testing-ca`` material.
FREEZE_DT = datetime(2020, 8, 1, tzinfo=timezone.utc).astimezone(
    tz=tzlocal.get_localzone()
)

#: Point in time at which samples that consume the *real* bundled EU trusted
#: lists run. Those are signed by actual EU trust service providers, whose
#: certificates postdate :data:`FREEZE_DT` by years; this instant sits within
#: their validity window instead. Refreshing the bundled lists may require
#: moving it.
REAL_TL_DT = datetime(2026, 3, 1, tzinfo=timezone.utc).astimezone(
    tz=tzlocal.get_localzone()
)


class SignerProvisioning(enum.Enum):
    """Ways in which signer key material is made available to a sample."""

    PEM = 'pem'
    """Separate ``key.pem`` + ``cert.pem`` (+ a CA chain file)."""

    PKCS12 = 'pkcs12'
    """A single bundled ``.pfx`` file."""


@dataclass(frozen=True)
class SignerSpec:
    """Describes the signer key material to materialise on disk."""

    cert: CertLabel = CertLabel('signer1')
    """The certomancer certificate (and matching key) to provision."""

    provisioning: SignerProvisioning = SignerProvisioning.PEM
    """How the key material is laid out on disk."""

    key_passphrase: bytes = b'secret'
    """Passphrase protecting the private key / PKCS#12 bundle."""

    key_path: str = 'path/to/signer/key.pem'
    """Destination for the PEM-encoded private key."""

    cert_path: str = 'path/to/signer/cert.pem'
    """Destination for the PEM-encoded signer certificate."""

    chain_path: str | None = 'path/to/relevant/certs.pem'
    """Destination for the PEM-encoded CA chain, or ``None`` to skip it."""

    pfx_path: str = 'signer.pfx'
    """Destination for the PKCS#12 bundle."""


@dataclass(frozen=True)
class TrustSpec:
    """Chain-of-trust configuration for validation samples."""

    trust_root: CertLabel = CertLabel('root')
    """Trust anchor used to validate signatures produced in the sample."""

    fetch_revocation: bool = False
    """Whether to register OCSP/CRL responders for live revocation fetching."""

    cert_path: str | None = 'path/to/certfile'
    """Destination for the PEM-encoded trust root, or ``None`` to skip it.
    Samples that call ``load_cert_from_pemder('path/to/certfile')`` read it."""


@dataclass(frozen=True)
class TrustListSpec:
    """ETSI trusted-list configuration for qualified-signature samples.

    When present, a signed trusted list covering the architecture's PKI is
    written to disk so a sample can build a
    :class:`~pyhanko.sign.validation.qualified.tsp.TSPRegistry` from it, exactly
    as it would from a real national trusted list.
    """

    tlso_entity: EntityLabel = EntityLabel('root')
    """Entity in the test PKI that acts as trusted-list scheme operator and
    signs the list."""

    xml_path: str = 'trusted-list.xml'
    """Destination for the signed trusted-list XML."""


@dataclass(frozen=True)
class TimestampSpec:
    """Timestamping configuration for samples that embed timestamp tokens."""

    service: ServiceLabel = ServiceLabel('tsa')
    """Which TSA in the test PKI backs the mocked :data:`TSA_URL`."""


class SignatureProfile(enum.Enum):
    """Profile of a pre-signed document materialised for validation samples."""

    PLAIN = 'plain'
    """A single, plain approval signature."""

    PADES = 'pades'
    """A PAdES baseline (B-B) signature, without embedded revocation info or a
    timestamp (suitable for qualified-signature samples that fetch revocation
    info live)."""

    PADES_LTA = 'pades_lta'
    """A PAdES B-LTA signature with embedded revocation info and a document
    timestamp (suitable for long-term validation samples)."""


@dataclass(frozen=True)
class SignedDocSpec:
    """Describes a pre-signed document to materialise for validation samples."""

    path: str = 'document.pdf'
    """Destination for the signed document."""

    base_file: str = 'MINIMAL_ONE_FIELD'
    """Source identifier for the unsigned base document (see
    :func:`_resolve_source`); must contain an empty signature field."""

    field_name: str = 'Sig1'
    """Name of the signature field to fill."""

    profile: SignatureProfile = SignatureProfile.PLAIN
    """Which :class:`SignatureProfile` to produce."""

    signer_cert: CertLabel = CertLabel('signer1')
    """Certificate (within the architecture) of the signer."""

    signer_key: KeyLabel = KeyLabel('signer1')
    """Private key (within the architecture) used to sign."""

    signer_chain: tuple[CertLabel, ...] = (
        CertLabel('root'),
        CertLabel('interm'),
    )
    """CA certificates to embed alongside the signature."""


@dataclass(frozen=True)
class DocEnvSpec:
    """Declarative description of the environment a document's samples need.

    Every field has a sane default, so ``DocEnvSpec()`` yields an isolated
    working directory containing ``document.pdf`` plus PEM signer material for
    the RSA ``testing-ca`` architecture.
    """

    certomancer_config: str = samples.CERTOMANCER_CONFIG_PATH
    """Path to the certomancer configuration to load architectures from."""

    arch: ArchLabel = ArchLabel('testing-ca')
    """Architecture within that configuration to wire up."""

    files: Mapping[str, str] = field(
        default_factory=lambda: {'document.pdf': 'MINIMAL'}
    )
    """Maps destination file names to a source identifier (see
    :func:`_resolve_source`)."""

    signers: tuple[SignerSpec, ...] = (SignerSpec(),)
    """Signer key material to provision. A document may need several layouts
    (e.g. both PEM files and a PKCS#12 bundle); pass an empty tuple for none."""

    signed_documents: tuple[SignedDocSpec, ...] = ()
    """Pre-signed documents to materialise (for validation samples)."""

    trust: TrustSpec | None = None
    """Chain-of-trust configuration, or ``None``."""

    trust_list: TrustListSpec | None = None
    """ETSI trusted-list configuration for qualified-signature samples, or
    ``None``."""

    timestamping: TimestampSpec = TimestampSpec()
    """Timestamping configuration, or ``None``."""


# Logical source names that resolve to asset files shipped with the test data,
# in addition to the byte constants exposed by the samples module.
_ASSET_SOURCES = {
    'NotoSans-Regular.ttf': samples.PDF_DATA_DIR
    + '/../fonts/NotoSans-Regular.ttf',
    'stamp.png': samples.PDF_DATA_DIR + '/../img/stamp.png',
}


def _resolve_source(name: str) -> bytes:
    """Resolve a ``files`` source identifier to raw bytes.

    The identifier is looked up first as a ``bytes`` constant on the samples
    module (e.g. ``'MINIMAL'``), then as a named asset file.
    """
    value = getattr(samples, name, None)
    if isinstance(value, bytes):
        return value
    if name in _ASSET_SOURCES:
        return samples.read_all(_ASSET_SOURCES[name])
    raise KeyError(f"Unknown doctest file source: {name!r}")


@dataclass
class DocEnv:
    """Live handle on a materialised doctest environment.

    Held onto by the generated globals so that :func:`teardown_doc_env` can
    restore the working directory and tear down the active mocks.
    """

    workdir: str
    prev_cwd: str
    globals: dict[str, Any]
    _closers: list[Any]


def _write_file(path: str, data: bytes) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, 'wb') as outf:
        outf.write(data)


def _provision_signer(arch: PKIArchitecture, spec: SignerSpec) -> None:
    cert = arch.get_cert(spec.cert)
    if spec.provisioning == SignerProvisioning.PKCS12:
        p12 = arch.package_pkcs12(spec.cert, password=spec.key_passphrase)
        _write_file(spec.pfx_path, p12)
        return

    key_info = arch.key_set.get_private_key(KeyLabel(str(spec.cert)))
    private_key = serialization.load_der_private_key(
        key_info.dump(), password=None
    )
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            spec.key_passphrase
        ),
    )
    _write_file(spec.key_path, key_pem)
    _write_file(spec.cert_path, pem.armor('CERTIFICATE', cert.dump()))
    if spec.chain_path is not None:
        chain = b''.join(
            pem.armor('CERTIFICATE', arch.get_cert(CertLabel(label)).dump())
            for label in ('root', 'interm')
        )
        _write_file(spec.chain_path, chain)


def _build_signer(arch: PKIArchitecture, spec: SignedDocSpec) -> SimpleSigner:
    return SimpleSigner(
        signing_cert=arch.get_cert(spec.signer_cert),
        signing_key=arch.key_set.get_private_key(spec.signer_key),
        cert_registry=SimpleCertificateStore.from_certs(
            arch.get_cert(label) for label in spec.signer_chain
        ),
    )


def _generate_signed_doc(
    arch: PKIArchitecture, spec: SignedDocSpec, ts_spec: TimestampSpec | None
) -> None:
    """Produce a signed PDF and write it to ``spec.path``.

    Must be called while the timestamp/revocation mocks and ``freeze_time`` are
    active, since the B-LTA profile fetches revocation info and a timestamp.
    """
    base = _resolve_source(spec.base_file)
    writer = IncrementalPdfFileWriter(BytesIO(base))
    signer = _build_signer(arch, spec)
    if spec.profile == SignatureProfile.PADES_LTA:
        if not ts_spec:
            raise ValueError("ts_spec must not be None")
        root = arch.get_cert(CertLabel('root'))
        meta = signers.PdfSignatureMetadata(
            field_name=spec.field_name,
            md_algorithm='sha256',
            subfilter=fields.SigSeedSubFilter.PADES,
            validation_context=ValidationContext(
                trust_roots=[root], allow_fetching=True, other_certs=[]
            ),
            embed_validation_info=True,
            use_pades_lta=True,
        )
        out = signers.sign_pdf(
            writer,
            meta,
            signer=signer,
            timestamper=timestamps.HTTPTimeStamper(
                arch.service_registry.get_tsa_info(ts_spec.service).url
            ),
            existing_fields_only=True,
        )
    elif spec.profile == SignatureProfile.PADES:
        out = signers.sign_pdf(
            writer,
            signers.PdfSignatureMetadata(
                field_name=spec.field_name,
                subfilter=fields.SigSeedSubFilter.PADES,
            ),
            signer=signer,
            existing_fields_only=True,
        )
    else:
        out = signers.sign_pdf(
            writer,
            signers.PdfSignatureMetadata(field_name=spec.field_name),
            signer=signer,
            existing_fields_only=True,
        )
    _write_file(spec.path, out.getvalue())


def _tsa_callback(request_body: bytes) -> bytes:
    req = tsp.TimeStampReq.load(request_body)
    return signing_commons.DUMMY_TS.request_tsa_response(req=req).dump()


def _make_async_runner(
    arch: PKIArchitecture,
) -> Callable[[Callable[[aiohttp.ClientSession], Awaitable[None]]], None]:
    """Build the ``run_async_signing`` helper injected into the doctest globals.

    The ``aiohttp`` sample factors its logic into a coroutine that performs
    PAdES-LTA signing given an :class:`aiohttp.ClientSession`. The helper runs
    that coroutine against a certomancer
    :class:`~certomancer.integrations.aiohttp_illusionist.AsyncIllusionist`,
    whose served session transparently answers the OCSP/CRL fetches and the
    timestamp request the sample makes, so the example runs end to end.
    """
    illusionist = AsyncIllusionist(arch, at_time=FREEZE_DT)

    def run_async_signing(
        body: Callable[[aiohttp.ClientSession], Awaitable[None]],
    ) -> None:
        async def _main() -> None:
            app = illusionist.build_app()
            async with illusionist.serving_session(app=app) as session:
                await body(session)

        asyncio.run(_main())

    return run_async_signing


def _make_standins(signer: SimpleSigner) -> dict:
    """Build the stand-in "remote service" helpers used by the
    interrupted-signing examples.

    These mimic an external signing service by routing the cryptographic work
    through the in-process ``testing-ca`` key material, so the visible samples
    can keep referring to opaque ``call_external_service`` /
    ``instantiate_external_signer`` helpers while still running end to end.
    """

    cert = signer.signing_cert
    registry = signer.cert_registry

    # A non-signing ExternalSigner for size estimation / signed-attr assembly,
    # standing in for a remote signer whose certificate is known up front.
    ext_signer = ExternalSigner(
        signing_cert=cert,
        cert_registry=registry,
        signature_value=bytes(256),
    )

    async def sign_remotely(signed_attrs_data: bytes) -> bytes:
        # The "remote service" signs the prepared signed attributes with the
        # real private key, yielding a value the caller can plug back in.
        return await signer.async_sign_raw(signed_attrs_data, 'sha256')

    def instantiate_external_signer(sig_value: bytes) -> ExternalSigner:
        return ExternalSigner(
            signing_cert=cert,
            cert_registry=registry,
            signature_value=sig_value,
        )

    async def call_external_service(document_digest: bytes):
        # Stand-in for a service that provisions a short-lived certificate and
        # returns a complete CMS container given a document digest.
        return await signer.async_sign(
            document_digest,
            digest_algorithm='sha256',
        )

    return {
        'ext_signer': ext_signer,
        'sign_remotely': sign_remotely,
        'instantiate_external_signer': instantiate_external_signer,
        'call_external_service': call_external_service,
    }


def make_doc_env(spec: DocEnvSpec = DocEnvSpec()) -> dict:
    """Materialise a doctest environment and return the doctest globals.

    The returned mapping is meant to be fed to ``globals().update(...)`` in a
    document's hidden ``.. testsetup:: *`` block. It contains the injected
    helper symbols *and* a ``_doc_env`` handle consumed by
    :func:`teardown_doc_env`.

    :param spec:
        Declarative description of the environment; see :class:`DocEnvSpec`.
    :return:
        A mapping of names to inject into the doctest globals.
    """

    arch = samples.CERTOMANCER.get_pki_arch(spec.arch)

    prev_cwd = os.getcwd()
    workdir = tempfile.mkdtemp(prefix='pyhanko-doctest-')
    os.chdir(workdir)

    closers: list[Any] = []
    try:
        freezer = freeze_time(FREEZE_DT)
        freezer.start()
        closers.append(freezer.stop)

        needs_pades = any(
            doc.profile == SignatureProfile.PADES_LTA
            for doc in spec.signed_documents
        )
        register_services = (
            spec.trust is not None and spec.trust.fetch_revocation
        ) or needs_pades

        services_cm = live_pki_services()
        services = services_cm.__enter__()
        closers.append(lambda: services_cm.__exit__(None, None, None))
        services.post(
            arch.service_registry.get_tsa_info(spec.timestamping.service).url,
            content=_tsa_callback,
            content_type='application/timestamp-reply',
        )
        if register_services:
            services.register(arch)

        for dest, source in spec.files.items():
            _write_file(dest, _resolve_source(source))

        for signer_spec in spec.signers:
            _provision_signer(arch, signer_spec)

        if spec.trust is not None and spec.trust.cert_path is not None:
            trust_cert = arch.get_cert(spec.trust.trust_root)
            _write_file(
                spec.trust.cert_path,
                pem.armor('CERTIFICATE', trust_cert.dump()),
            )

        if spec.trust_list is not None:
            tl_xml = certomancer_pki_as_trusted_list(
                arch, spec.trust_list.tlso_entity
            )
            _write_file(spec.trust_list.xml_path, tl_xml.encode('utf-8'))

        for doc_spec in spec.signed_documents:
            _generate_signed_doc(arch, doc_spec, spec.timestamping)

        injected: dict[str, Any] = {
            'run_async_signing': _make_async_runner(arch),
            'run_with_seeded_lotl': run_with_seeded_lotl,
            'TSA_URL': arch.service_registry.get_tsa_info(
                spec.timestamping.service
            ).url,
        }
        injected.update(_make_standins(signing_commons.FROM_CA))
    except Exception:
        # Make sure a partially constructed environment doesn't leak the cwd
        # change or any started mocks.
        for closer in reversed(closers):
            closer()
        os.chdir(prev_cwd)
        raise

    env = DocEnv(
        workdir=workdir,
        prev_cwd=prev_cwd,
        globals=injected,
        _closers=closers,
    )
    injected['_doc_env'] = env
    return injected


def teardown_doc_env(env: DocEnv) -> None:
    """Tear down an environment produced by :func:`make_doc_env`.

    Restores the previous working directory and stops the timestamp/revocation
    mocks. Safe to call once per document in a ``.. testcleanup::`` block.

    :param env:
        The :class:`DocEnv` handle (typically referenced as ``_doc_env`` in the
        doctest globals).
    """
    for closer in reversed(env._closers):
        closer()
    env._closers.clear()
    os.chdir(env.prev_cwd)


def seed_lotl_cache(cache_dir: str | os.PathLike) -> str:
    """Pre-seed a :class:`FileSystemTLCache` directory with the bundled EU
    list-of-the-lists and the Belgian national trusted list.

    This lets the live-bootstrap sample in the qualified-validation guide run
    without touching the network: every download
    :func:`~.pyhanko.sign.validation.qualified.eutl_fetch.lotl_to_registry`
    would otherwise perform becomes a cache hit. Restricting the sample to a
    single member state (``only_territories={'be'}``) keeps it fast and means
    only the Belgian list has to be seeded alongside the LOTL itself.

    :param cache_dir:
        Directory to populate; created if it does not yet exist.
    :return:
        The cache directory as a string, handy for feeding straight back into
        the sample.
    """
    from pyhanko.sign.validation.qualified.eutl_fetch import (
        EU_LOTL_LOCATION,
        FileSystemTLCache,
    )

    tl_dir = Path(samples.TEST_DIR) / 'data' / 'tl'
    cache = FileSystemTLCache(
        Path(cache_dir), expire_after=timedelta(days=3650)
    )
    cache[EU_LOTL_LOCATION] = (tl_dir / 'eu-lotl.xml').read_text(
        encoding='utf8'
    )
    # The Belgian list's location as advertised in the bundled LOTL.
    cache['https://tsl.belgium.be/tsl-be-v6.xml'] = (
        tl_dir / 'tsl-be-v6.xml'
    ).read_text(encoding='utf8')
    return str(cache_dir)


def run_with_seeded_lotl(
    body: Callable[[str], Awaitable[Any]], cache_dir: str = 'lotl-cache'
) -> Any:
    """Run a coroutine that bootstraps from the EU list-of-the-lists.

    Seeds ``cache_dir`` through :func:`seed_lotl_cache` and runs ``body``
    against it at :data:`REAL_TL_DT`, overriding the document's usual frozen
    clock for the duration.

    :param body:
        Callable taking the cache directory and returning the coroutine to run.
    :param cache_dir:
        Directory to seed and hand to ``body``.
    :return:
        Whatever the coroutine returns.
    """
    with freeze_time(REAL_TL_DT):
        seed_lotl_cache(cache_dir)
        return asyncio.run(body(cache_dir))
