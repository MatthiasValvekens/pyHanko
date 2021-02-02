"""
Tests for PKCS#11 functionality.

NOTE: these are not run in CI, due to lack of testing setup.
"""

import os
from io import BytesIO

import pytest
from freezegun import freeze_time

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers, pkcs11
from pyhanko_tests.samples import MINIMAL
from pyhanko_tests.test_signing import val_trusted, SIMPLE_ECC_V_CONTEXT

pkcs11_test_module = os.environ.get('PKCS11_TEST_MODULE', None)
if not pkcs11_test_module:
    raise RuntimeError("No path to PKCS#11 specified in PKCS11_TEST_MODULE")


def _simple_sess(token='testrsa'):
    return pkcs11.open_pkcs11_session(
        pkcs11_test_module, user_pin='1234', token_label=token
    )


default_other_certs = ('root', 'intermediate')


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

