import asyncio
import logging
import os
from io import BytesIO

import aiohttp
import pytest
from asn1crypto import x509
from click.testing import CliRunner
from cryptography.hazmat.primitives.serialization import pkcs12
from pyhanko.cli import cli_root

from pyhanko.keys.internal import (
    translate_pyca_cryptography_cert_to_asn1,
    translate_pyca_cryptography_key_to_asn1,
)
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import SimpleSigner, signers
from pyhanko.sign.diff_analysis import ModificationLevel
from pyhanko.sign.fields import SigSeedSubFilter
from pyhanko.sign.timestamps import HTTPTimeStamper
from pyhanko.sign.timestamps.aiohttp_client import AIOHttpTimeStamper
from pyhanko.sign.validation import (
    DocumentSecurityStore,
    RevocationInfoValidationType,
    async_validate_pdf_ltv_signature,
)
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.fetchers import Fetchers
from pyhanko_certvalidator.fetchers.aiohttp_fetchers import (
    AIOHttpCertificateFetcher,
    AIOHttpCRLFetcher,
    AIOHttpFetcherBackend,
    AIOHttpOCSPFetcher,
    LazySession,
)
from pyhanko_certvalidator.fetchers.requests_fetchers import (
    RequestsCertificateFetcher,
    RequestsCRLFetcher,
    RequestsOCSPFetcher,
)
from pyhanko_certvalidator.registry import SimpleCertificateStore
from test_data.samples import MINIMAL_ONE_FIELD

logger = logging.getLogger(__name__)

SKIP_LIVE = False
CERTOMANCER_HOST_URL = os.environ.get('LIVE_CERTOMANCER_HOST_URL', None)
if not CERTOMANCER_HOST_URL:
    logger.warning("Skipping live tests -- no Certomancer host")
    SKIP_LIVE = True

TEST_PASSPHRASE = b"secret"
TIMEOUT = 5

run_if_live = pytest.mark.skipif(
    SKIP_LIVE, reason="no Certomancer instance available"
)


async def _retrieve_credentials(
    session: aiohttp.ClientSession, arch, cert_label
) -> bytes:
    url = f"{CERTOMANCER_HOST_URL}/_certomancer/pfx-download/{arch}"
    data = {"cert": cert_label, "passphrase": TEST_PASSPHRASE.decode("ascii")}
    async with session.post(
        url=url, data=data, raise_for_status=True, timeout=TIMEOUT
    ) as response:
        pfx_bytes = await response.read()
    return pfx_bytes


async def _retrieve_and_decode_credentials(
    session: aiohttp.ClientSession,
    arch,
    cert_label,
    *,
    skip_other_certs=False,
    **kwargs,
):
    pfx_bytes = await _retrieve_credentials(session, arch, cert_label)
    (private_key, cert, other_certs_pkcs12) = pkcs12.load_key_and_certificates(
        pfx_bytes, TEST_PASSPHRASE
    )

    kinfo = translate_pyca_cryptography_key_to_asn1(private_key)
    cert = translate_pyca_cryptography_cert_to_asn1(cert)
    other_certs_pkcs12 = set(
        map(translate_pyca_cryptography_cert_to_asn1, other_certs_pkcs12)
    )

    cs = SimpleCertificateStore()
    if not skip_other_certs:
        cs.register_multiple(other_certs_pkcs12)
    return SimpleSigner(
        signing_key=kinfo, signing_cert=cert, cert_registry=cs, **kwargs
    )


async def _retrieve_cert(session, arch, cert):
    url = f"{CERTOMANCER_HOST_URL}/_certomancer/any-cert/{arch}/{cert}.crt"
    async with session.get(
        url=url, raise_for_status=True, timeout=TIMEOUT
    ) as response:
        cert_bytes = await response.read()
    return x509.Certificate.load(cert_bytes)


def _fetcher_backend(session):
    return AIOHttpFetcherBackend(session, per_request_timeout=TIMEOUT)


async def _init_validation_context(session, arch, *, backend=None, **kwargs):
    root = await _retrieve_cert(session, arch, "root")
    backend = backend or _fetcher_backend(session)
    kwargs.setdefault("revocation_mode", "require")
    vc = ValidationContext(
        trust_roots=[root],
        fetcher_backend=backend,
        allow_fetching=True,
        **kwargs,
    )
    return vc, root


async def _check_pades_result(out, roots, session, rivt_pades):
    r = PdfFileReader(out)
    status = await async_validate_pdf_ltv_signature(
        r.embedded_signatures[0],
        rivt_pades,
        {'trust_roots': roots, 'fetcher_backend': _fetcher_backend(session)},
    )
    assert status.valid and status.trusted
    assert status.modification_level == ModificationLevel.LTA_UPDATES


@run_if_live
@pytest.mark.asyncio
@pytest.mark.parametrize('start_with_full_chain', [True, False])
async def test_pades_lt_live(start_with_full_chain):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    arch = "testing-ca"

    async with aiohttp.ClientSession() as session:
        signer = await _retrieve_and_decode_credentials(
            session,
            arch,
            "signer1-long",
            skip_other_certs=start_with_full_chain,
        )

        vc, root = await _init_validation_context(session, arch)
        out = await signers.async_sign_pdf(
            w,
            signers.PdfSignatureMetadata(
                field_name='Sig1',
                validation_context=vc,
                subfilter=SigSeedSubFilter.PADES,
                embed_validation_info=True,
            ),
            signer=signer,
            timestamper=AIOHttpTimeStamper(
                f"{CERTOMANCER_HOST_URL}/{arch}/tsa/tsa", session=session
            ),
        )
        await _check_pades_result(
            out, [root], session, RevocationInfoValidationType.PADES_LT
        )


@run_if_live
@pytest.mark.asyncio
@pytest.mark.parametrize('start_with_full_chain', [True, False])
async def test_pades_lta_live(start_with_full_chain):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    arch = "testing-ca"

    async with aiohttp.ClientSession() as session:
        signer = await _retrieve_and_decode_credentials(
            session,
            arch,
            "signer1-long",
            skip_other_certs=not start_with_full_chain,
        )

        vc, root = await _init_validation_context(session, arch)
        out = await signers.async_sign_pdf(
            w,
            signers.PdfSignatureMetadata(
                field_name='Sig1',
                validation_context=vc,
                subfilter=SigSeedSubFilter.PADES,
                embed_validation_info=True,
                use_pades_lta=True,
            ),
            signer=signer,
            timestamper=AIOHttpTimeStamper(
                f"{CERTOMANCER_HOST_URL}/{arch}/tsa/tsa", session=session
            ),
        )
        await _check_pades_result(
            out, [root], session, RevocationInfoValidationType.PADES_LTA
        )


@run_if_live
@pytest.mark.asyncio
async def test_async_sign_many_concurrent():
    arch = "testing-ca"
    concurrent_count = 10

    async with aiohttp.ClientSession() as session:
        signer = await _retrieve_and_decode_credentials(
            session, arch, "signer1-long"
        )

        vc, root = await _init_validation_context(session, arch)

        timestamper = AIOHttpTimeStamper(
            f"{CERTOMANCER_HOST_URL}/{arch}/tsa/tsa", session=session
        )

        async def _job(_i):
            w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
            meta = signers.PdfSignatureMetadata(
                field_name='Sig1',
                validation_context=vc,
                subfilter=SigSeedSubFilter.PADES,
                embed_validation_info=True,
                use_pades_lta=True,
                reason=f"Live revinfo concurrency test #{_i}!",
            )
            pdf_signer = signers.PdfSigner(
                meta, signer, timestamper=timestamper
            )
            sig_result = await pdf_signer.async_sign_pdf(w, in_place=True)
            return _i, sig_result

        jobs = asyncio.as_completed(map(_job, range(1, concurrent_count + 1)))
        for finished_job in jobs:
            i, out = await finished_job
            r = PdfFileReader(out)
            emb = r.embedded_signatures[0]
            assert emb.field_name == 'Sig1'
            assert emb.sig_object['/Reason'].endswith(f"#{i}!")
            await _check_pades_result(
                out, [root], session, RevocationInfoValidationType.PADES_LTA
            )


@run_if_live
@pytest.mark.asyncio
async def test_async_lazy_session():
    # explicitly validate the lazy session usage that is used as a fallback in some places

    arch = "testing-ca"
    async with aiohttp.ClientSession() as session:
        signer = await _retrieve_and_decode_credentials(
            session, arch, "signer1-long", skip_other_certs=True
        )

        vc, root = await _init_validation_context(
            session, arch, backend=AIOHttpFetcherBackend(session=None)
        )

    timestamper = AIOHttpTimeStamper(
        f"{CERTOMANCER_HOST_URL}/{arch}/tsa/tsa", session=LazySession()
    )

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1',
        validation_context=vc,
        subfilter=SigSeedSubFilter.PADES,
        embed_validation_info=True,
        use_pades_lta=True,
    )
    pdf_signer = signers.PdfSigner(meta, signer, timestamper=timestamper)
    out = await pdf_signer.async_sign_pdf(w, in_place=True)
    async with aiohttp.ClientSession() as session:
        await _check_pades_result(
            out, [root], session, RevocationInfoValidationType.PADES_LTA
        )


@run_if_live
@pytest.mark.asyncio
async def test_async_strict_cert_fetchers_happy_path():
    arch = "testing-ca"
    async with aiohttp.ClientSession() as session:
        signer = await _retrieve_and_decode_credentials(
            session, arch, "signer1-long", skip_other_certs=True
        )
        fetchers = Fetchers(
            ocsp_fetcher=AIOHttpOCSPFetcher(session, per_request_timeout=10),
            crl_fetcher=AIOHttpCRLFetcher(session, per_request_timeout=10),
            cert_fetcher=AIOHttpCertificateFetcher(
                session, per_request_timeout=10, permit_pem=False
            ),
        )
        vc, root = await _init_validation_context(
            session, arch, backend=None, fetchers=fetchers
        )

        timestamper = AIOHttpTimeStamper(
            f"{CERTOMANCER_HOST_URL}/{arch}/tsa/tsa", session=session
        )

        w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
        meta = signers.PdfSignatureMetadata(
            field_name='Sig1',
            validation_context=vc,
            subfilter=SigSeedSubFilter.PADES,
            embed_validation_info=True,
            use_pades_lta=True,
        )
        pdf_signer = signers.PdfSigner(meta, signer, timestamper=timestamper)
        out = await pdf_signer.async_sign_pdf(w, in_place=True)
        await _check_pades_result(
            out, [root], session, RevocationInfoValidationType.PADES_LTA
        )


@run_if_live
@pytest.mark.asyncio
@pytest.mark.parametrize('strict', [True, False])
async def test_requests_fetchers_happy_path(strict):
    arch = "testing-ca"
    async with aiohttp.ClientSession() as session:
        signer = await _retrieve_and_decode_credentials(
            session, arch, "signer1-long", skip_other_certs=True
        )
        fetchers = Fetchers(
            ocsp_fetcher=RequestsOCSPFetcher(per_request_timeout=10),
            crl_fetcher=RequestsCRLFetcher(per_request_timeout=10),
            cert_fetcher=RequestsCertificateFetcher(
                per_request_timeout=10, permit_pem=strict
            ),
        )
        vc, root = await _init_validation_context(
            session, arch, backend=None, fetchers=fetchers
        )

    timestamper = HTTPTimeStamper(f"{CERTOMANCER_HOST_URL}/{arch}/tsa/tsa")

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1',
        validation_context=vc,
        subfilter=SigSeedSubFilter.PADES,
        embed_validation_info=True,
        use_pades_lta=True,
    )
    pdf_signer = signers.PdfSigner(meta, signer, timestamper=timestamper)
    out = await pdf_signer.async_sign_pdf(w, in_place=True)
    async with aiohttp.ClientSession() as session:
        await _check_pades_result(
            out, [root], session, RevocationInfoValidationType.PADES_LTA
        )


async def _retrieve_and_save_credentials(fname, session, arch, label):
    result = await _retrieve_credentials(session, arch, label)
    with open(fname, 'wb') as credf:
        credf.write(result)


# TODO this should go into a separate integration testing package


@run_if_live
def test_pades_lta_live_with_cli():
    arch = "testing-ca"
    infile = 'in.pdf'
    outfile = 'out.pdf'
    cred_file = 'credential.p12'
    root_file = 'root.crt'
    cli_runner = CliRunner()

    cfg = f"""
   pkcs12-setups:
       test:
           pfx-file: {cred_file}
           pfx-passphrase: {TEST_PASSPHRASE.decode('ascii')}
   validation-contexts:
       default:
           trust: {root_file}
   """

    async def _env_setup():
        async with aiohttp.ClientSession() as session:
            await _retrieve_and_save_credentials(
                cred_file, session, arch, "signer1-long"
            )
            root = await _retrieve_cert(session, arch, "root")
        with open(root_file, 'wb') as f:
            f.write(root.dump())
        with open(infile, 'wb') as f:
            f.write(MINIMAL_ONE_FIELD)
        with open('pyhanko.yml', 'w') as f:
            f.write(cfg)

    async def _check():
        async with aiohttp.ClientSession() as session:
            with open(outfile, 'rb') as f:
                root = await _retrieve_cert(session, arch, "root")
                await _check_pades_result(
                    f, [root], session, RevocationInfoValidationType.PADES_LTA
                )
                r = PdfFileReader(f)
                dss = DocumentSecurityStore.read_dss(r)
                assert len(dss.crls) == 1
                assert len(dss.ocsps) == 1

    with cli_runner.isolated_filesystem():
        asyncio.run(_env_setup())

        result = cli_runner.invoke(
            cli_root,
            [
                'sign',
                'addsig',
                '--with-validation-info',
                '--use-pades-lta',
                '--timestamp-url',
                f"{CERTOMANCER_HOST_URL}/{arch}/tsa/tsa",
                'pkcs12',
                '--p12-setup',
                'test',
                infile,
                outfile,
                cred_file,
            ],
        )
        assert not result.exception, result.output
        asyncio.run(_check())
