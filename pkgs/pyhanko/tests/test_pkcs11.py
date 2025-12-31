"""
Tests for PKCS#11 functionality.

NOTE: these are not run in CI, due to lack of testing setup.
"""

import binascii
from io import BytesIO
from typing import Optional

import pytest
from asn1crypto import algos
from certomancer.registry import CertLabel
from pkcs11 import Mechanism, PKCS11Error
from pkcs11 import types as p11_types
from pyhanko.config.pkcs11 import PKCS11PinEntryMode, PKCS11SignatureConfig
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import pkcs11, signers
from pyhanko.sign.general import SigningError
from pyhanko.sign.pkcs11 import (
    PKCS11Signer,
    PKCS11SigningContext,
    TokenCriteria,
    criteria_satisfied_by,
    find_token,
)
from pyhanko_certvalidator.registry import SimpleCertificateStore
from test_data.samples import MINIMAL, TESTING_CA
from test_utils.signing_commons import (
    async_val_trusted,
    val_trusted,
)


@pytest.mark.parametrize('bulk_fetch', [True, False])
@pytest.mark.hsm(platform='all')
def test_simple_sign(bulk_fetch, p11_config, any_algo, platform):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    with p11_config.session as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            p11_config.cert_label,
            key_label=p11_config.key_label,
            other_certs_to_pull=p11_config.cert_chain_labels,
            bulk_fetch=bulk_fetch,
            use_raw_mechanism=platform == "softhsm"
            and p11_config.algo == "ecdsa",
        )
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_trusted(emb, vc=p11_config.validation_context)


@pytest.mark.algo('rsa')
@pytest.mark.hsm(platform='all')
def test_simple_sign_with_rsassa_pss(p11_config):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    with p11_config.session as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            p11_config.cert_label,
            key_label=p11_config.key_label,
            other_certs_to_pull=p11_config.cert_chain_labels,
            prefer_pss=True,
        )
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    sig_algo = emb.signer_info['signature_algorithm']['algorithm'].native
    assert sig_algo == 'rsassa_pss'
    assert emb.field_name == 'Sig1'
    val_trusted(emb, vc=p11_config.validation_context)


@pytest.mark.algo('rsa')
@pytest.mark.hsm(platform='all')
def test_simple_sign_with_rsassa_pss_custom_parameters(p11_config):
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
    with p11_config.session as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            p11_config.cert_label,
            key_label=p11_config.key_label,
            other_certs_to_pull=p11_config.cert_chain_labels,
            prefer_pss=True,
            signature_mechanism=algos.SignedDigestAlgorithm(
                {'algorithm': 'rsassa_pss', 'parameters': pss_params},
            ),
        )
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    sig_algo = emb.signer_info['signature_algorithm']['algorithm'].native
    params = emb.signer_info['signature_algorithm']['parameters']
    assert sig_algo == 'rsassa_pss'
    assert params.dump() == pss_params.dump()
    assert emb.field_name == 'Sig1'
    val_trusted(emb, vc=p11_config.validation_context)


@pytest.mark.hsm(platform='softhsm')
def test_simple_sign_legacy_open_session_by_token_label(p11_config):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    with pytest.deprecated_call():
        with pkcs11.open_pkcs11_session(
            p11_config.module,
            user_pin=p11_config.user_pin,
            token_label=p11_config.token_label,
        ) as sess:
            signer = pkcs11.PKCS11Signer(
                sess,
                p11_config.cert_label,
                key_label=p11_config.key_label,
                other_certs_to_pull=p11_config.cert_chain_labels,
            )
            out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_trusted(emb, vc=p11_config.validation_context)


@pytest.mark.parametrize('bulk_fetch', [True, False])
@pytest.mark.hsm(platform='all')
def test_sign_external_certs(bulk_fetch, p11_config):
    # Test to see if unnecessary fetches for intermediate certs are skipped

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    with p11_config.session as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            p11_config.cert_label,
            key_label=p11_config.key_label,
            ca_chain=(p11_config.cert_chain[1],),
            bulk_fetch=bulk_fetch,
        )
        orig_fetcher = signer._pull_single_cert

        def _trap_pull(*, label=None, cert_id=None):
            if label != p11_config.cert_label:
                raise RuntimeError
            return orig_fetcher(label=label, cert_id=cert_id)

        signer._pull_cert = _trap_pull
        assert isinstance(signer.cert_registry, SimpleCertificateStore)
        assert len(list(signer.cert_registry)) == 1
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_trusted(emb, vc=p11_config.validation_context)


@pytest.mark.parametrize('bulk_fetch', [True, False])
@pytest.mark.hsm(platform='softhsm,yubihsm')
def test_sign_multiple_cert_sources(bulk_fetch, p11_config):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    with p11_config.session as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            p11_config.cert_label,
            key_label=p11_config.key_label,
            other_certs_to_pull=(p11_config.cert_chain_labels[0],),
            ca_chain=(p11_config.cert_chain[1],),
            bulk_fetch=bulk_fetch,
        )
        assert isinstance(signer.cert_registry, SimpleCertificateStore)
        assert len(list(signer.cert_registry)) == 2
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_trusted(emb, vc=p11_config.validation_context)


@pytest.mark.parametrize('bulk_fetch', [True, False])
@pytest.mark.hsm(platform='softhsm')
def test_wrong_key_label(bulk_fetch, p11_config):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    with p11_config.session as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            cert_label=p11_config.cert_label,
            other_certs_to_pull=p11_config.cert_chain_labels,
            bulk_fetch=bulk_fetch,
            key_label='NoSuchKeyExists',
        )
        with pytest.raises(PKCS11Error, match="Could not find private key"):
            signers.sign_pdf(w, meta, signer=signer)


@pytest.mark.parametrize('bulk_fetch', [True, False])
@pytest.mark.hsm(platform='softhsm')
def test_wrong_key_id(bulk_fetch, p11_config):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    with p11_config.session as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            p11_config.cert_label,
            key_label=p11_config.key_label,
            other_certs_to_pull=p11_config.cert_chain_labels,
            bulk_fetch=bulk_fetch,
            key_id=binascii.unhexlify(b'deadbeef'),
        )
        with pytest.raises(PKCS11Error, match="Could not find private key"):
            signers.sign_pdf(w, meta, signer=signer)


@pytest.mark.parametrize('bulk_fetch', [True, False])
@pytest.mark.hsm(platform='softhsm')
def test_wrong_cert(bulk_fetch, p11_config):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    with p11_config.session as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            key_label=p11_config.cert_label,
            other_certs_to_pull=p11_config.cert_chain_labels,
            bulk_fetch=bulk_fetch,
            cert_id=binascii.unhexlify(b'deadbeef'),
        )
        with pytest.raises(PKCS11Error, match='Could not find cert'):
            signers.sign_pdf(w, meta, signer=signer)


def test_provided_certs(p11_config):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    signer_cert = TESTING_CA.get_cert(CertLabel('signer1'))
    with p11_config.session as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            cert_label=p11_config.cert_label,
            signing_cert=signer_cert,
            ca_chain=list(p11_config.cert_chain),
        )
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    assert emb.signer_cert.dump() == signer_cert.dump()
    # this will fail if the intermediate cert is not present
    val_trusted(emb, vc=p11_config.validation_context)


@pytest.mark.parametrize('bulk_fetch', [True, False])
@pytest.mark.hsm(platform='softhsm')
def test_signer_provided_others_pulled(bulk_fetch, p11_config):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    with p11_config.session as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            p11_config.cert_label,
            ca_chain=list(p11_config.cert_chain),
        )
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_trusted(emb, vc=p11_config.validation_context)


@pytest.mark.parametrize('bulk_fetch', [True, False])
@pytest.mark.hsm(platform='softhsm')
def test_signer_pulled_others_provided(bulk_fetch, p11_config):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    signer_cert = TESTING_CA.get_cert(CertLabel('signer1'))
    with p11_config.session as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            key_label=p11_config.cert_label,
            other_certs_to_pull=p11_config.cert_chain_labels,
            signing_cert=signer_cert,
            bulk_fetch=bulk_fetch,
        )
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    assert emb.signer_cert.dump() == signer_cert.dump()
    # this will fail if the intermediate cert is not present
    val_trusted(emb, vc=p11_config.validation_context)


@pytest.mark.hsm(platform='softhsm')
def test_unclear_key_label_and_cert(p11_config):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    with p11_config.session as sess:
        with pytest.raises(PKCS11Error, match='Found more than one'):
            signer = pkcs11.PKCS11Signer(sess)
            signers.sign_pdf(w, meta, signer=signer)


@pytest.mark.hsm(platform='softhsm')
def test_auto_use_only_key_if_cert_is_known(p11_config):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    signer_cert = TESTING_CA.get_cert(CertLabel('signer1'))
    with p11_config.session as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            signing_cert=signer_cert,
            other_certs_to_pull=p11_config.cert_chain_labels,
        )
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    val_trusted(emb, vc=p11_config.validation_context)


@pytest.mark.hsm(platform='all')
def test_simple_sign_from_config(p11_config):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    config = PKCS11SignatureConfig(
        module_path=p11_config.module,
        token_criteria=TokenCriteria(p11_config.token_label),
        cert_label=p11_config.cert_label,
        key_label=p11_config.key_label,
        user_pin=p11_config.user_pin,
        other_certs_to_pull=None,
        only_resident_certs=True,
    )

    with PKCS11SigningContext(config) as signer:
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_trusted(emb, vc=p11_config.validation_context)


@pytest.mark.hsm(platform='softhsm')
def test_config_init_failure_signing_error(p11_config):
    config = PKCS11SignatureConfig(
        module_path='.',
        token_criteria=TokenCriteria(p11_config.token_label),
        cert_label=p11_config.cert_label,
        user_pin=p11_config.user_pin,
        other_certs_to_pull=None,
    )

    with pytest.raises(SigningError, match='error while opening session'):
        with PKCS11SigningContext(config):
            pass


@pytest.mark.hsm(platform='softhsm')
def test_sign_skip_login_fail(p11_config):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    config = PKCS11SignatureConfig(
        module_path=p11_config.module,
        token_criteria=TokenCriteria(label=p11_config.token_label),
        cert_label=p11_config.cert_label,
        prompt_pin=PKCS11PinEntryMode.SKIP,
    )

    # no key will be found, since we didn't bother logging in
    with pytest.raises(PKCS11Error, match="Could not find private key"):
        with PKCS11SigningContext(config) as signer:
            signers.sign_pdf(w, meta, signer=signer)


# this test relies on SoftHSM not supporting the
# PROTECTED_AUTHENTICATION_PATH flag, and is disabled when running
# against other PKCS#11 implementations.
@pytest.mark.hsm(platform='softhsm')
def test_sign_deferred_auth(p11_config):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    config = PKCS11SignatureConfig(
        module_path=p11_config.module,
        token_criteria=TokenCriteria(p11_config.token_label),
        cert_label=p11_config.cert_label,
        prompt_pin=PKCS11PinEntryMode.DEFER,
    )

    # no key will be found, since we didn't bother logging in
    with pytest.raises(
        SigningError, match="Protected auth.*not supported by loaded module"
    ):
        with PKCS11SigningContext(config) as signer:
            signers.sign_pdf(w, meta, signer=signer)


@pytest.mark.algo('rsa')
@pytest.mark.hsm(platform='all')
def test_simple_sign_with_raw_rsa(p11_config):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    config = PKCS11SignatureConfig(
        module_path=p11_config.module,
        token_criteria=TokenCriteria(p11_config.token_label),
        cert_label=p11_config.cert_label,
        key_label=p11_config.key_label,
        user_pin=p11_config.user_pin,
        other_certs_to_pull=None,
        raw_mechanism=True,
    )

    with PKCS11SigningContext(config) as signer:
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_trusted(emb, vc=p11_config.validation_context)


@pytest.mark.algo('dsa')
@pytest.mark.hsm(platform='softhsm')
def test_simple_sign_with_raw_dsa(p11_config):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1', md_algorithm='sha256'
    )
    with p11_config.session as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            p11_config.cert_label,
            key_label=p11_config.key_label,
            other_certs_to_pull=p11_config.cert_chain_labels,
            use_raw_mechanism=True,
        )
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_trusted(emb, vc=p11_config.validation_context)


@pytest.mark.algo('rsa')
@pytest.mark.hsm(platform='softhsm')
def test_no_raw_pss(p11_config):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1', md_algorithm='sha256'
    )
    with p11_config.session as sess:
        signer = pkcs11.PKCS11Signer(
            sess,
            p11_config.cert_label,
            key_label=p11_config.key_label,
            other_certs_to_pull=p11_config.cert_chain_labels,
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
            sign_kwargs={},
        )


def test_unsupported_algo_mech_specified_in_kwargs():
    # this should be allowed
    result = pkcs11.select_pkcs11_signing_params(
        algos.SignedDigestAlgorithm({'algorithm': '2.999'}),
        digest_algorithm='sha256',
        use_raw_mechanism=False,
        sign_kwargs={'mechanism': 0xDEADBEEF},
    )
    assert result.sign_kwargs['mechanism'] == 0xDEADBEEF


@pytest.mark.parametrize('md', ['sha256', 'sha384'])
def test_select_ecdsa_mech(md):
    # can't do a round-trip test since softhsm doesn't support these, but
    # we can at least verify that the selection works
    algo = f'{md}_ecdsa'
    result = pkcs11.select_pkcs11_signing_params(
        algos.SignedDigestAlgorithm({'algorithm': algo}),
        digest_algorithm=md,
        use_raw_mechanism=False,
        sign_kwargs={},
    )
    assert result.sign_kwargs['mechanism'] == getattr(
        Mechanism, f"ECDSA_{md.upper()}"
    )


def test_select_sign_kwargs_priority():
    result = pkcs11.select_pkcs11_signing_params(
        algos.SignedDigestAlgorithm({'algorithm': 'sha256_ecdsa'}),
        digest_algorithm='sha256',
        use_raw_mechanism=False,
        sign_kwargs={'mechanism': 0xDEADBEEF},
    )
    assert result.sign_kwargs['mechanism'] == 0xDEADBEEF


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
        "cert", no_results=no_results, label=label, id_value=cert_id
    )
    assert err == exp_err


@pytest.mark.asyncio
@pytest.mark.hsm(platform='all')
async def test_simple_sign_from_config_async(any_algo, p11_config, platform):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    config = PKCS11SignatureConfig(
        module_path=p11_config.module,
        token_criteria=TokenCriteria(p11_config.token_label),
        other_certs_to_pull=p11_config.cert_chain_labels,
        cert_label=p11_config.cert_label,
        key_label=p11_config.key_label,
        user_pin=p11_config.user_pin,
        raw_mechanism=platform == 'softhsm' and p11_config.algo == 'ecdsa',
    )
    async with PKCS11SigningContext(config=config) as signer:
        pdf_signer = signers.PdfSigner(meta, signer)
        out = await pdf_signer.async_sign_pdf(w)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    await async_val_trusted(emb, vc=p11_config.validation_context)


@pytest.mark.asyncio
@pytest.mark.algo('rsa')
@pytest.mark.hsm(platform='all')
async def test_simple_sign_from_config_async_pss(p11_config):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    config = PKCS11SignatureConfig(
        module_path=p11_config.module,
        token_criteria=TokenCriteria(p11_config.token_label),
        other_certs_to_pull=p11_config.cert_chain_labels,
        prefer_pss=True,
        cert_label=p11_config.cert_label,
        key_label=p11_config.key_label,
        user_pin=p11_config.user_pin,
    )
    async with PKCS11SigningContext(config=config) as signer:
        pdf_signer = signers.PdfSigner(meta, signer)
        out = await pdf_signer.async_sign_pdf(w)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    await async_val_trusted(emb, vc=p11_config.validation_context)


@pytest.mark.hsm(platform='all')
def test_token_does_not_exist(p11_config):
    with pytest.raises(PKCS11Error, match='No token matching criteria'):
        pkcs11.open_pkcs11_session(
            p11_config.module,
            user_pin=p11_config.user_pin,
            token_criteria=TokenCriteria(label='aintnosuchtoken'),
        )


@pytest.mark.hsm(platform='softhsm')
def test_token_unclear(p11_config):
    with pytest.raises(PKCS11Error, match='more than 1'):
        pkcs11.open_pkcs11_session(
            p11_config.module, user_pin=p11_config.user_pin, token_criteria=None
        )


DUMMY_VER = {'major': 0, 'minor': 0}
DUMMY_ARGS = dict(
    slotDescription=b'',
    manufacturerID=b'',
    hardwareVersion=DUMMY_VER,
    firmwareVersion=DUMMY_VER,
)


class DummyToken(p11_types.Token):
    label = None
    serial = None

    def __init__(self, label, serial):
        self.label = label
        self.serial = serial
        super().__init__()

    def open(self, **kwargs):
        raise NotImplementedError


class DummySlot(p11_types.Slot):
    def __init__(self, lbl: Optional[str]):
        self.lbl = lbl
        super().__init__()

    def get_token(self):
        if self.lbl is not None:
            lbl = self.lbl
            serial = b"-".join((lbl.encode('utf8'), b"\xde\xad\xbe\xef"))
            return DummyToken(lbl, serial)
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
