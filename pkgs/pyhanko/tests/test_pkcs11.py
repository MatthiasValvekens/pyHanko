"""
Tests for PKCS#11 functionality.

NOTE: these are not run in CI, due to lack of testing setup.
"""

import asyncio
import binascii
from io import BytesIO
from typing import Optional

import pytest
from asn1crypto import algos
from asn1crypto.algos import SignedDigestAlgorithm
from certomancer.registry import CertLabel
from freezegun import freeze_time
from pkcs11 import Mechanism, NoSuchKey, PKCS11Error
from pkcs11 import types as p11_types
from pyhanko.config.pkcs11 import PKCS11PinEntryMode, PKCS11SignatureConfig
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import general, pkcs11, signers
from pyhanko.sign.general import SigningError
from pyhanko.sign.pkcs11 import (
    PKCS11Signer,
    PKCS11SigningContext,
    TokenCriteria,
    criteria_satisfied_by,
    find_token,
)

from pyhanko_certvalidator.registry import SimpleCertificateStore

from .samples import MINIMAL, TESTING_CA
from .signing_commons import (
    SIMPLE_DSA_V_CONTEXT,
    SIMPLE_ECC_V_CONTEXT,
    SIMPLE_ED448_V_CONTEXT,
    SIMPLE_ED25519_V_CONTEXT,
    SOFTHSM,
    async_val_trusted,
    pkcs11_only,
    pkcs11_test_module,
    val_trusted,
)

pytestmark = pkcs11_only


def _simple_sess(token='testrsa'):
    return pkcs11.open_pkcs11_session(
        pkcs11_test_module,
        user_pin='1234',
        token_criteria=TokenCriteria(label=token),
    )


default_other_certs = ('root', 'interm')
SIGNER_LABEL = 'signer1'


@pytest.mark.parametrize('bulk_fetch', [True, False])
@freeze_time('2020-11-01')
def test_simple_sign(bulk_fetch):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    with _simple_sess() as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            SIGNER_LABEL,
            other_certs_to_pull=default_other_certs,
            bulk_fetch=bulk_fetch,
        )
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_trusted(emb)


@freeze_time('2020-11-01')
def test_simple_sign_with_rsassa_pss():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    with _simple_sess(token='testrsa') as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            SIGNER_LABEL,
            other_certs_to_pull=default_other_certs,
            prefer_pss=True,
        )
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    algo = emb.signer_info['signature_algorithm']['algorithm'].native
    assert algo == 'rsassa_pss'
    assert emb.field_name == 'Sig1'
    val_trusted(emb)


@freeze_time('2020-11-01')
def test_simple_sign_with_rsassa_pss_custom_parameters():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')

    pss_params = algos.RSASSAPSSParams(
        {
            'hash_algorithm': algos.DigestAlgorithm({'algorithm': 'sha256'}),
            'mask_gen_algorithm': algos.MaskGenAlgorithm(
                {
                    'algorithm': 'mgf1',
                    'parameters': algos.DigestAlgorithm(
                        {'algorithm': 'sha256'}
                    ),
                }
            ),
            'salt_length': 32,
        }
    )
    with _simple_sess(token='testrsa') as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            SIGNER_LABEL,
            other_certs_to_pull=default_other_certs,
            prefer_pss=True,
            signature_mechanism=algos.SignedDigestAlgorithm(
                {'algorithm': 'rsassa_pss', 'parameters': pss_params},
            ),
        )
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    algo = emb.signer_info['signature_algorithm']['algorithm'].native
    params = emb.signer_info['signature_algorithm']['parameters']
    assert algo == 'rsassa_pss'
    assert params.dump() == pss_params.dump()
    assert emb.field_name == 'Sig1'
    val_trusted(emb)


@freeze_time('2020-11-01')
def test_simple_sign_legacy_open_session_by_token_label():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    with pytest.deprecated_call():
        with pkcs11.open_pkcs11_session(
            pkcs11_test_module, user_pin='1234', token_label='testrsa'
        ) as sess:
            signer = pkcs11.PKCS11Signer(
                sess,
                SIGNER_LABEL,
                other_certs_to_pull=default_other_certs,
            )
            out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_trusted(emb)


@pytest.mark.parametrize('bulk_fetch', [True, False])
@freeze_time('2020-11-01')
def test_sign_external_certs(bulk_fetch):
    # Test to see if unnecessary fetches for intermediate certs are skipped

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    with _simple_sess() as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            SIGNER_LABEL,
            ca_chain=(TESTING_CA.get_cert(CertLabel('interm')),),
            bulk_fetch=bulk_fetch,
        )
        orig_fetcher = pkcs11._pull_cert
        try:

            def _trap_pull(session, *, label=None, cert_id=None):
                if label != SIGNER_LABEL:
                    raise RuntimeError
                return orig_fetcher(session, label=label, cert_id=cert_id)

            pkcs11._pull_cert = _trap_pull
            assert isinstance(signer.cert_registry, SimpleCertificateStore)
            assert len(list(signer.cert_registry)) == 1
            out = signers.sign_pdf(w, meta, signer=signer)
        finally:
            pkcs11._pull_cert = orig_fetcher

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_trusted(emb)


@pytest.mark.parametrize('bulk_fetch', [True, False])
@freeze_time('2020-11-01')
def test_sign_multiple_cert_sources(bulk_fetch):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    with _simple_sess() as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            SIGNER_LABEL,
            other_certs_to_pull=('root',),
            ca_chain=(TESTING_CA.get_cert(CertLabel('interm')),),
            bulk_fetch=bulk_fetch,
        )
        assert isinstance(signer.cert_registry, SimpleCertificateStore)
        assert len(list(signer.cert_registry)) == 2
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_trusted(emb)


@pytest.mark.parametrize('bulk_fetch', [True, False])
@freeze_time('2020-11-01')
def test_wrong_key_label(bulk_fetch):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    with _simple_sess() as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            SIGNER_LABEL,
            other_certs_to_pull=default_other_certs,
            bulk_fetch=bulk_fetch,
            key_label='NoSuchKeyExists',
        )
        with pytest.raises(NoSuchKey):
            signers.sign_pdf(w, meta, signer=signer)


@pytest.mark.parametrize('bulk_fetch', [True, False])
@freeze_time('2020-11-01')
def test_wrong_cert(bulk_fetch):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    with _simple_sess() as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            key_label=SIGNER_LABEL,
            other_certs_to_pull=default_other_certs,
            bulk_fetch=bulk_fetch,
            cert_id=binascii.unhexlify(b'deadbeef'),
        )
        with pytest.raises(PKCS11Error, match='Could not find cert'):
            signers.sign_pdf(w, meta, signer=signer)


@freeze_time('2020-11-01')
def test_provided_certs():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    signer_cert = TESTING_CA.get_cert(CertLabel('signer1'))
    with _simple_sess() as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            key_label=SIGNER_LABEL,
            signing_cert=signer_cert,
            ca_chain={
                TESTING_CA.get_cert(CertLabel('root')),
                TESTING_CA.get_cert(CertLabel('interm')),
            },
        )
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    assert emb.signer_cert.dump() == signer_cert.dump()
    # this will fail if the intermediate cert is not present
    val_trusted(emb)


@pytest.mark.parametrize('bulk_fetch', [True, False])
@freeze_time('2020-11-01')
def test_signer_provided_others_pulled(bulk_fetch):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    with _simple_sess() as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            SIGNER_LABEL,
            ca_chain={
                TESTING_CA.get_cert(CertLabel('root')),
                TESTING_CA.get_cert(CertLabel('interm')),
            },
        )
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_trusted(emb)


@pytest.mark.parametrize('bulk_fetch', [True, False])
@freeze_time('2020-11-01')
def test_signer_pulled_others_provided(bulk_fetch):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    signer_cert = TESTING_CA.get_cert(CertLabel('signer1'))
    with _simple_sess() as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            key_label=SIGNER_LABEL,
            signing_cert=signer_cert,
            bulk_fetch=bulk_fetch,
            other_certs_to_pull=default_other_certs,
        )
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    assert emb.signer_cert.dump() == signer_cert.dump()
    # this will fail if the intermediate cert is not present
    val_trusted(emb)


@freeze_time('2020-11-01')
def test_unclear_key_label_and_cert():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    with _simple_sess() as sess:
        with pytest.raises(PKCS11Error, match='Found more than one'):
            signer = pkcs11.PKCS11Signer(sess)
            signers.sign_pdf(w, meta, signer=signer)


@freeze_time('2020-11-01')
def test_auto_use_only_key_if_cert_is_known():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    signer_cert = TESTING_CA.get_cert(CertLabel('signer1'))
    with _simple_sess() as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            signing_cert=signer_cert,
            other_certs_to_pull=default_other_certs,
        )
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    val_trusted(emb)


@pytest.mark.parametrize('bulk_fetch', [True, False])
@freeze_time('2020-11-01')
def test_simple_sign_dsa(bulk_fetch):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1', md_algorithm='sha256'
    )
    with _simple_sess(token='testdsa') as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            SIGNER_LABEL,
            other_certs_to_pull=default_other_certs,
            bulk_fetch=bulk_fetch,
        )
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_trusted(emb, vc=SIMPLE_DSA_V_CONTEXT())


@pytest.mark.parametrize('bulk_fetch', [True, False])
@freeze_time('2020-11-01')
def test_simple_sign_ecdsa(bulk_fetch):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1', md_algorithm='sha256'
    )
    with _simple_sess(token='testecdsa') as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            SIGNER_LABEL,
            other_certs_to_pull=default_other_certs,
            bulk_fetch=bulk_fetch,
            use_raw_mechanism=True,
        )
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_trusted(emb, vc=SIMPLE_ECC_V_CONTEXT())


@pytest.mark.parametrize('bulk_fetch', [True, False])
@freeze_time('2020-11-01')
def test_simple_sign_ed25519(bulk_fetch):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    with _simple_sess(token='tested25519') as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            SIGNER_LABEL,
            other_certs_to_pull=default_other_certs,
            bulk_fetch=bulk_fetch,
        )
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_trusted(emb, vc=SIMPLE_ED25519_V_CONTEXT())


@pytest.mark.parametrize('bulk_fetch', [True, False])
@freeze_time('2020-11-01')
def test_simple_sign_ed448(bulk_fetch):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    with _simple_sess(token='tested448') as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            SIGNER_LABEL,
            other_certs_to_pull=default_other_certs,
            bulk_fetch=bulk_fetch,
        )
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_trusted(emb, vc=SIMPLE_ED448_V_CONTEXT())


@freeze_time('2020-11-01')
def test_simple_sign_from_config():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    config = PKCS11SignatureConfig(
        module_path=pkcs11_test_module,
        token_criteria=TokenCriteria('testrsa'),
        cert_label=SIGNER_LABEL,
        user_pin='1234',
        other_certs_to_pull=None,
    )

    with PKCS11SigningContext(config) as signer:
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_trusted(emb)


def test_config_init_failure_signing_error():
    config = PKCS11SignatureConfig(
        module_path='.',
        token_criteria=TokenCriteria('testrsa'),
        cert_label=SIGNER_LABEL,
        user_pin='1234',
        other_certs_to_pull=None,
    )

    with pytest.raises(SigningError, match='error while opening session'):
        with PKCS11SigningContext(config):
            pass


@freeze_time('2020-11-01')
def test_sign_skip_login_fail():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    config = PKCS11SignatureConfig(
        module_path=pkcs11_test_module,
        token_criteria=TokenCriteria(label='testrsa'),
        cert_label=SIGNER_LABEL,
        prompt_pin=PKCS11PinEntryMode.SKIP,
    )

    # no key will be found, since we didn't bother logging in
    with pytest.raises(NoSuchKey):
        with PKCS11SigningContext(config) as signer:
            signers.sign_pdf(w, meta, signer=signer)


@pytest.mark.skipif(
    not SOFTHSM,
    reason=(
        "this test relies on SoftHSM not supporting the "
        "PROTECTED_AUTHENTICATION_PATH flag, and is disabled when running "
        "against other PKCS#11 implementations."
    ),
)
@freeze_time('2020-11-01')
def test_sign_deferred_auth():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    config = PKCS11SignatureConfig(
        module_path=pkcs11_test_module,
        token_criteria=TokenCriteria('testrsa'),
        cert_label=SIGNER_LABEL,
        prompt_pin=PKCS11PinEntryMode.DEFER,
    )

    # no key will be found, since we didn't bother logging in
    with pytest.raises(
        SigningError, match="Protected auth.*not supported by loaded module"
    ):
        with PKCS11SigningContext(config) as signer:
            signers.sign_pdf(w, meta, signer=signer)


@freeze_time('2020-11-01')
def test_simple_sign_with_raw_rsa():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    config = PKCS11SignatureConfig(
        module_path=pkcs11_test_module,
        token_criteria=TokenCriteria('testrsa'),
        cert_label=SIGNER_LABEL,
        user_pin='1234',
        other_certs_to_pull=None,
        raw_mechanism=True,
    )

    with PKCS11SigningContext(config) as signer:
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_trusted(emb)


@pytest.mark.parametrize('bulk_fetch', [True, False])
@freeze_time('2020-11-01')
def test_simple_sign_with_raw_dsa(bulk_fetch):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1', md_algorithm='sha256'
    )
    with _simple_sess(token='testdsa') as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            SIGNER_LABEL,
            other_certs_to_pull=default_other_certs,
            bulk_fetch=bulk_fetch,
            use_raw_mechanism=True,
        )
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_trusted(emb, vc=SIMPLE_DSA_V_CONTEXT())


def test_no_raw_pss():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1', md_algorithm='sha256'
    )
    with _simple_sess(token='testrsa') as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            SIGNER_LABEL,
            other_certs_to_pull=default_other_certs,
            use_raw_mechanism=True,
            prefer_pss=True,
        )
        with pytest.raises(NotImplementedError, match='PSS not available'):
            signers.sign_pdf(w, meta, signer=signer)


def test_unsupported_algo():
    with pytest.raises(NotImplementedError, match="2.999"):
        pkcs11.select_pkcs11_signing_params(
            algos.SignedDigestAlgorithm({'algorithm': '2.999'}),
            digest_algorithm='sha256',
            use_raw_mechanism=False,
        )


@pytest.mark.parametrize('md', ['sha256', 'sha384'])
def test_select_ecdsa_mech(md):
    # can't do a round-trip test since softhsm doesn't support these, but
    # we can at least verify that the selection works
    algo = f'{md}_ecdsa'
    result = pkcs11.select_pkcs11_signing_params(
        algos.SignedDigestAlgorithm({'algorithm': algo}),
        digest_algorithm=md,
        use_raw_mechanism=False,
    )
    assert result.sign_kwargs['mechanism'] == getattr(
        Mechanism, f"ECDSA_{md.upper()}"
    )


@pytest.mark.parametrize(
    'label,cert_id,no_results,exp_err',
    [
        (
            'foo',
            b'foo',
            True,
            "Could not find cert with label 'foo', ID '666f6f'.",
        ),
        ('foo', None, True, "Could not find cert with label 'foo'."),
        (None, b'foo', True, "Could not find cert with ID '666f6f'."),
        ('foo', None, False, "Found more than one cert with label 'foo'."),
    ],
)
def test_pull_err_fmt(label, cert_id, no_results, exp_err):
    err = pkcs11._format_pull_err_msg(
        no_results=no_results, label=label, cert_id=cert_id
    )
    assert err == exp_err


@pytest.mark.parametrize(
    'bulk_fetch,pss',
    [(True, True), (False, False), (True, False), (True, True)],
)
@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_simple_sign_from_config_async(bulk_fetch, pss):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    config = PKCS11SignatureConfig(
        module_path=pkcs11_test_module,
        token_criteria=TokenCriteria('testrsa'),
        other_certs_to_pull=default_other_certs,
        bulk_fetch=bulk_fetch,
        prefer_pss=pss,
        cert_label=SIGNER_LABEL,
        user_pin='1234',
    )
    async with PKCS11SigningContext(config=config) as signer:
        pdf_signer = signers.PdfSigner(meta, signer)
        out = await pdf_signer.async_sign_pdf(w)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    await async_val_trusted(emb)


@pytest.mark.skip  # FIXME flaky test, sometimes coredumps with SoftHSM
@pytest.mark.parametrize(
    'bulk_fetch,pss',
    [(True, True), (False, False), (True, False), (True, True)],
)
@pytest.mark.asyncio
async def test_async_sign_many_concurrent(bulk_fetch, pss):
    concurrent_count = 10
    config = PKCS11SignatureConfig(
        module_path=pkcs11_test_module,
        token_criteria=TokenCriteria(label='testrsa'),
        other_certs_to_pull=default_other_certs,
        bulk_fetch=bulk_fetch,
        prefer_pss=pss,
        cert_label=SIGNER_LABEL,
        user_pin='1234',
    )
    async with PKCS11SigningContext(config=config) as signer:

        async def _job(_i):
            w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
            meta = signers.PdfSignatureMetadata(
                field_name='Sig1', reason=f"PKCS#11 concurrency test #{_i}!"
            )
            pdf_signer = signers.PdfSigner(meta, signer)
            sig_result = await pdf_signer.async_sign_pdf(w, in_place=True)
            await asyncio.sleep(2)
            return _i, sig_result

        jobs = asyncio.as_completed(map(_job, range(1, concurrent_count + 1)))
        for finished_job in jobs:
            i, out = await finished_job
            r = PdfFileReader(out)
            emb = r.embedded_signatures[0]
            assert emb.field_name == 'Sig1'
            assert emb.sig_object['/Reason'].endswith(f"#{i}!")
            with freeze_time("2020-11-01"):
                await async_val_trusted(emb)


@pytest.mark.skip  # FIXME flaky test, sometimes coredumps with SoftHSM
@pytest.mark.parametrize(
    'bulk_fetch,pss',
    [(True, True), (False, False), (True, False), (True, True)],
)
@pytest.mark.asyncio
async def test_async_sign_raw_many_concurrent_no_preload_objs(bulk_fetch, pss):
    concurrent_count = 10

    # don't instantiate through PKCS11SigningContext
    # also, just sign raw strings, we want to exercise the correctness of
    # the awaiting logic in sign_raw for object loading
    with _simple_sess() as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            SIGNER_LABEL,
            other_certs_to_pull=default_other_certs,
            bulk_fetch=bulk_fetch,
        )

        async def _job(_i):
            payload = f"PKCS#11 concurrency test #{_i}!".encode('utf8')
            sig_result = await signer.async_sign_raw(payload, 'sha256')
            await asyncio.sleep(2)
            return _i, sig_result

        jobs = asyncio.as_completed(map(_job, range(1, concurrent_count + 1)))
        for finished_job in jobs:
            i, sig = await finished_job
            general.validate_raw(
                signature=sig,
                signed_data=f"PKCS#11 concurrency test #{i}!".encode('utf8'),
                cert=signer.signing_cert,
                md_algorithm='sha256',
                signature_algorithm=SignedDigestAlgorithm(
                    {'algorithm': 'sha256_rsa'}
                ),
            )


def test_token_does_not_exist():
    with pytest.raises(PKCS11Error, match='No token matching criteria'):
        _simple_sess(token='aintnosuchtoken')


def test_token_unclear():
    with pytest.raises(PKCS11Error, match='more than 1'):
        return pkcs11.open_pkcs11_session(
            pkcs11_test_module, user_pin='1234', token_label=None
        )


DUMMY_VER = {'major': 0, 'minor': 0}
DUMMY_ARGS = dict(
    slotDescription=b'',
    manufacturerID=b'',
    hardwareVersion=DUMMY_VER,
    firmwareVersion=DUMMY_VER,
)


class DummyToken(p11_types.Token):
    def open(self, rw=False, user_pin=None, so_pin=None):
        raise NotImplementedError


class DummySlot(p11_types.Slot):
    def __init__(self, lbl: Optional[str]):
        self.lbl = lbl

        super().__init__(
            "dummy.so.0",
            slot_id=0xDEADBEEF,
            flags=(
                p11_types.SlotFlag(0)
                if lbl is None
                else p11_types.SlotFlag.TOKEN_PRESENT
            ),
            **DUMMY_ARGS,
        )

    def get_token(self):
        if self.lbl is not None:
            lbl = self.lbl.encode('utf8')
            return DummyToken(
                self,
                label=lbl,
                model=b'DummyToken',
                flags=p11_types.TokenFlag(0),
                serialNumber=lbl + b'-\xde\xad\xbe\xef',
                **DUMMY_ARGS,
            )
        else:
            raise PKCS11Error("No token in slot")

    def get_mechanisms(self):
        return []

    def get_mechanism_info(self, mechanism):
        raise NotImplementedError


@pytest.mark.parametrize(
    'slot_list,slot_no_query,token_criteria',
    [
        (('foo',), None, None),
        (('foo', 'bar'), 0, TokenCriteria(label='foo')),
        (('foo', None, 'bar'), 0, TokenCriteria(label='foo')),
        (('foo', None, 'bar'), None, TokenCriteria(label='foo')),
        (
            ('foo', None, 'bar'),
            None,
            TokenCriteria(label='foo', serial=b'foo-\xde\xad\xbe\xef'),
        ),
        (
            ('foo', None, 'bar'),
            None,
            TokenCriteria(serial=b'foo-\xde\xad\xbe\xef'),
        ),
        (
            ('foo', None, 'bar'),
            None,
            TokenCriteria(serial=b'bar-\xde\xad\xbe\xef'),
        ),
        # skip over empty slots when doing this scan
        ((None, 'foo', None, 'bar'), None, TokenCriteria(label='foo')),
        ((None, 'foo', None), 1, None),
    ],
)
def test_find_token(slot_list, slot_no_query, token_criteria):
    tok = find_token(
        [DummySlot(lbl) for lbl in slot_list],
        slot_no=slot_no_query,
        token_criteria=token_criteria,
    )
    assert tok is not None
    criteria_satisfied_by(token_criteria, tok)


@pytest.mark.parametrize(
    'slot_list,slot_no_query,criteria,err',
    [
        (('foo', 'bar'), 2, TokenCriteria(label='foo'), 'too large'),
        (('foo', 'bar'), 1, TokenCriteria(label='foo'), 'label is not \'foo\''),
        (
            ('foo', 'bar'),
            1,
            TokenCriteria(serial=b'foo-\xde\xad\xbe\xef'),
            'serial is not \'666f6f2ddeadbeef\'',
        ),
        # when querying by slot, we want the error to be passed on
        ((None, 'bar'), 0, None, 'No token in'),
        (('foo', 'bar'), None, None, 'more than 1'),
        # right now, we don't care about the status of the slot in any way
        (('foo', None), None, None, 'more than 1'),
    ],
)
def test_find_token_error(slot_list, slot_no_query, criteria, err):
    with pytest.raises(PKCS11Error, match=err):
        find_token(
            [DummySlot(lbl) for lbl in slot_list],
            slot_no=slot_no_query,
            token_criteria=criteria,
        )


@pytest.mark.parametrize(
    'slot_list,token_lbl_query',
    [
        ((None, 'bar'), 'foo'),
        (('foo', 'bar'), 'baz'),
        ((None, None), 'foo'),
        ((), 'foo'),
    ],
)
def test_token_not_found(slot_list, token_lbl_query):
    tok = find_token(
        [DummySlot(lbl) for lbl in slot_list],
        slot_no=None,
        token_criteria=TokenCriteria(label=token_lbl_query),
    )
    assert tok is None


def _mirror(*cfgs):
    for cfg in cfgs:
        a = cfg
        b = cfg[1], cfg[0], cfg[3], cfg[2]
        yield a
        if a != b:
            yield b


@pytest.mark.parametrize(
    'key_in,cert_in,key_prop,cert_prop',
    [
        *_mirror(
            ((None, None), (None, None), (None, None), (None, None)),
            (('a', b"a"), (None, None), ('a', b"a"), ('a', b"a")),
            (('a', None), (None, None), ('a', None), ('a', None)),
            ((None, b"a"), (None, None), (None, b"a"), (None, b"a")),
            (('a', None), (None, b"a"), ('a', None), (None, b"a")),
        )
    ],
)
def test_config_fallbacks(key_in, cert_in, key_prop, cert_prop):
    # noinspection PyTypeChecker
    signer = PKCS11Signer(
        pkcs11_session=None,
        cert_label=cert_in[0],
        cert_id=cert_in[1],
        key_label=key_in[0],
        key_id=key_in[1],
    )
    actual_key_prop = signer.key_label, signer.key_id
    actual_cert_prop = signer.cert_label, signer.cert_id
    assert (actual_key_prop, actual_cert_prop) == (key_prop, cert_prop)
