"""
Tests for PKCS#11 functionality.

NOTE: these are not run in CI, due to lack of testing setup.
"""

import os
from io import BytesIO

import pytest
import logging

from certomancer.registry import CertLabel
from freezegun import freeze_time
from pkcs11 import PKCS11Error

from pyhanko.config import PKCS11SignatureConfig
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers, pkcs11
from pyhanko.sign.general import SigningError
from pyhanko.sign.pkcs11 import PKCS11SigningContext
from pyhanko_tests.samples import MINIMAL, TESTING_CA
from pyhanko_tests.test_signing import val_trusted, SIMPLE_ECC_V_CONTEXT

logger = logging.getLogger(__name__)

SKIP_PKCS11 = False
pkcs11_test_module = os.environ.get('PKCS11_TEST_MODULE', None)
if not pkcs11_test_module:
    logger.warning("Skipping PKCS#11 tests --- no PCKS#11 module specified")
    SKIP_PKCS11 = True


def _simple_sess(token='testrsa'):
    return pkcs11.open_pkcs11_session(
        pkcs11_test_module, user_pin='1234', token_label=token
    )


default_other_certs = ('root', 'intermediate')


@pytest.mark.skipif(SKIP_PKCS11, reason="no PKCS#11 module")
@pytest.mark.parametrize('bulk_fetch,pss', [(True, True), (False, False),
                                            (True, False), (True, True)])
@freeze_time('2020-11-01')
def test_simple_sign(bulk_fetch, pss):

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    with _simple_sess() as sess:
        signer = pkcs11.PKCS11Signer(
            sess, 'signer', other_certs_to_pull=default_other_certs,
            bulk_fetch=bulk_fetch, prefer_pss=pss
        )
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_trusted(emb)


@pytest.mark.skipif(SKIP_PKCS11, reason="no PKCS#11 module")
@pytest.mark.parametrize('bulk_fetch', [True, False])
@freeze_time('2020-11-01')
def test_wrong_key_label(bulk_fetch):

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    with _simple_sess() as sess:
        signer = pkcs11.PKCS11Signer(
            sess, 'signer', other_certs_to_pull=default_other_certs,
            bulk_fetch=bulk_fetch, key_label='NoSuchKeyExists'
        )
        with pytest.raises(PKCS11Error, match='.*private key handle.*'):
            signers.sign_pdf(w, meta, signer=signer)


@pytest.mark.skipif(SKIP_PKCS11, reason="no PKCS#11 module")
@freeze_time('2020-11-01')
def test_provided_certs():

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    signer_cert = TESTING_CA.get_cert(CertLabel('signer1'))
    with _simple_sess() as sess:
        signer = pkcs11.PKCS11Signer(
            sess, key_label='signer',
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


@pytest.mark.skipif(SKIP_PKCS11, reason="no PKCS#11 module")
@pytest.mark.parametrize('bulk_fetch', [True, False])
@freeze_time('2020-11-01')
def test_signer_provided_others_pulled(bulk_fetch):

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    with _simple_sess() as sess:
        signer = pkcs11.PKCS11Signer(
            sess, 'signer',
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


@pytest.mark.skipif(SKIP_PKCS11, reason="no PKCS#11 module")
@pytest.mark.parametrize('bulk_fetch', [True, False])
@freeze_time('2020-11-01')
def test_signer_pulled_others_provided(bulk_fetch):

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    signer_cert = TESTING_CA.get_cert(CertLabel('signer1'))
    with _simple_sess() as sess:
        signer = pkcs11.PKCS11Signer(
            sess, key_label='signer',
            signing_cert=signer_cert, bulk_fetch=bulk_fetch,
            other_certs_to_pull=default_other_certs
        )
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    assert emb.signer_cert.dump() == signer_cert.dump()
    # this will fail if the intermediate cert is not present
    val_trusted(emb)

@pytest.mark.skipif(SKIP_PKCS11, reason="no PKCS#11 module")
@freeze_time('2020-11-01')
def test_unclear_key_label():
    signer_cert = TESTING_CA.get_cert(CertLabel('signer1'))
    with _simple_sess() as sess:
        with pytest.raises(SigningError, match='\'key_label\'.*mandatory'):
            pkcs11.PKCS11Signer(
                sess, signing_cert=signer_cert,
                other_certs_to_pull=default_other_certs,
            )


@pytest.mark.skipif(SKIP_PKCS11, reason="no PKCS#11 module")
@freeze_time('2020-11-01')
def test_unclear_signer_cert():
    with _simple_sess() as sess:
        with pytest.raises(SigningError, match='Either.*must be provided'):
            pkcs11.PKCS11Signer(
                sess, other_certs_to_pull=default_other_certs,
            )


@pytest.mark.xfail  # fails due to lack of (proper) support in SoftHSMv2
@pytest.mark.parametrize('bulk_fetch', [True, False])
@freeze_time('2020-11-01')
def test_simple_sign_ecdsa(bulk_fetch):

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1', md_algorithm='sha1')
    with _simple_sess(token='testecdsa') as sess:
        signer = pkcs11.PKCS11Signer(
            sess, 'signer', other_certs_to_pull=default_other_certs,
            bulk_fetch=bulk_fetch
        )
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_trusted(emb, vc=SIMPLE_ECC_V_CONTEXT())


@pytest.mark.skipif(SKIP_PKCS11, reason="no PKCS#11 module")
def test_simple_sign_from_config():

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    config = PKCS11SignatureConfig(
        module_path=pkcs11_test_module, token_label='testrsa',
        cert_label='signer', user_pin='1234', other_certs_to_pull=None
    )

    with PKCS11SigningContext(config) as signer:
        out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_trusted(emb)
