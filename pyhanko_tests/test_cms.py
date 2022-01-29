import hashlib
import itertools
import os
from datetime import datetime
from io import BytesIO

import pytest
import pytz
import tzlocal
from asn1crypto import cms, core
from asn1crypto.algos import (
    DigestAlgorithm,
    MaskGenAlgorithm,
    RSASSAPSSParams,
    SignedDigestAlgorithm,
)
from certomancer.registry import ArchLabel, CertLabel, KeyLabel
from freezegun import freeze_time
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.registry import SimpleCertificateStore

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, signers, timestamps
from pyhanko.sign.ades.api import CAdESSignedAttrSpec
from pyhanko.sign.ades.report import AdESIndeterminate, AdESStatus
from pyhanko.sign.attributes import CMSAttributeProvider, TSTProvider
from pyhanko.sign.general import (
    CMSExtractionError,
    SigningError,
    as_signing_certificate,
    as_signing_certificate_v2,
    find_cms_attribute,
)
from pyhanko.sign.signers import cms_embedder
from pyhanko.sign.signers.pdf_cms import PdfCMSSignedAttributes
from pyhanko.sign.validation import (
    DocumentSecurityStore,
    async_validate_cms_signature,
    async_validate_detached_cms,
    async_validate_pdf_ltv_signature,
    async_validate_pdf_signature,
    collect_validation_info,
    validate_cms_signature,
)
from pyhanko.sign.validation.errors import (
    SignatureValidationError,
    WeakHashAlgorithmError,
)
from pyhanko.sign.validation.generic_cms import validate_sig_integrity
from pyhanko_tests.samples import (
    CERTOMANCER,
    CRYPTO_DATA_DIR,
    MINIMAL,
    PDF_DATA_DIR,
    TESTING_CA,
    TESTING_CA_DSA,
    TESTING_CA_ECDSA,
)
from pyhanko_tests.signing_commons import (
    DSA_INTERM_CERT,
    DSA_ROOT_CERT,
    DUMMY_TS,
    ECC_INTERM_CERT,
    ECC_ROOT_CERT,
    FIXED_OCSP,
    FROM_CA,
    FROM_DSA_CA,
    FROM_ECC_CA,
    INTERM_CERT,
    ROOT_CERT,
    SIMPLE_DSA_V_CONTEXT,
    SIMPLE_ECC_V_CONTEXT,
    SIMPLE_V_CONTEXT,
    async_val_trusted,
    live_ac_vcs,
    val_trusted,
    val_untrusted,
)


def test_generic_data_sign_legacy():
    input_data = b'Hello world!'
    with pytest.deprecated_call():
        # noinspection PyDeprecation
        signature = FROM_CA.sign_general_data(
            input_data, 'sha256', detached=False
        )

    # reset the stream
    if isinstance(input_data, BytesIO):
        input_data.seek(0)

    # re-parse just to make sure we're starting fresh
    signature = cms.ContentInfo.load(signature.dump())

    raw_digest = hashlib.sha256(b'Hello world!').digest()
    content = signature['content']
    assert content['version'].native == 'v1'
    assert isinstance(content, cms.SignedData)

    with pytest.deprecated_call():
        # noinspection PyDeprecation

        # noinspection PyDeprecation
        status = validate_cms_signature(content, raw_digest=raw_digest)
    assert status.valid
    assert status.intact

    eci = content['encap_content_info']
    assert eci['content_type'].native == 'data'
    assert eci['content'].native == b'Hello world!'

    assert status.valid
    assert status.intact


@pytest.mark.parametrize('input_data, detached', list(itertools.product(
        [
            b'Hello world!', BytesIO(b'Hello world!'),
            # v1 CMS -> PKCS#7 compatible -> use cms.ContentInfo
            cms.ContentInfo({
                'content_type': 'data',
                'content': b'Hello world!'
            })
        ],
        [True, False]
    ))
)
async def test_generic_data_sign(input_data, detached):

    signature = await FROM_CA.async_sign_general_data(
        input_data, 'sha256', detached=detached
    )

    # reset the stream
    if isinstance(input_data, BytesIO):
        input_data.seek(0)

    # re-parse just to make sure we're starting fresh
    signature = cms.ContentInfo.load(signature.dump())

    raw_digest = hashlib.sha256(b'Hello world!').digest() if detached else None
    content = signature['content']
    assert content['version'].native == 'v1'
    assert isinstance(content, cms.SignedData)
    status = await async_validate_cms_signature(content, raw_digest=raw_digest)
    assert status.valid
    assert status.intact

    eci = content['encap_content_info']
    if detached:
        assert eci['content_type'].native == 'data'
        assert eci['content'].native is None

        status = await async_validate_detached_cms(input_data, content)
        assert status.valid
        assert status.intact
        assert 'No available information about the signing time.' \
               in status.pretty_print_details()
        if isinstance(input_data, BytesIO):
            input_data.seek(0)
    else:
        assert eci['content_type'].native == 'data'
        assert eci['content'].native == b'Hello world!'

    assert status.valid
    assert status.intact

    assert content['signer_infos'][0]['unsigned_attrs'].native is None


@pytest.mark.parametrize('detached', [True, False])
async def test_cms_v3_sign(detached):
    inner_obj = await FROM_CA.async_sign_general_data(
        b'Hello world!', 'sha256', detached=False
    )

    signature = await FROM_CA.async_sign_general_data(
        cms.EncapsulatedContentInfo({
            'content_type': 'signed_data',
            'content': inner_obj['content'].untag()
        }),
        'sha256',
        detached=detached
    )

    # re-parse just to make sure we're starting fresh
    signature = cms.ContentInfo.load(signature.dump())

    content = signature['content']
    assert content['version'].native == 'v3'
    assert isinstance(content, cms.SignedData)
    eci = content['encap_content_info']
    assert eci['content_type'].native == 'signed_data'
    if detached:
        raw_digest = hashlib.sha256(
            inner_obj['content'].untag().dump()
        ).digest()
    else:
        raw_digest = None
        inner_eci = eci['content'].parsed['encap_content_info']
        assert inner_eci['content'].native == b'Hello world!'
    status = await async_validate_cms_signature(
        content, raw_digest=raw_digest
    )
    assert status.valid
    assert status.intact


async def test_detached_cms_with_self_reported_timestamp():
    dt = datetime.fromisoformat('2020-11-01T05:00:00+00:00')
    signature = await FROM_CA.async_sign_general_data(
        b'Hello world!', 'sha256', detached=False,
        signed_attr_settings=PdfCMSSignedAttributes(signing_time=dt)
    )
    signature = cms.ContentInfo.load(signature.dump())
    status = await async_validate_detached_cms(
        b'Hello world!', signature['content']
    )
    assert status.signer_reported_dt == dt
    assert status.timestamp_validity is None
    assert 'reported by signer' in status.pretty_print_details()
    assert status.valid
    assert status.intact


@freeze_time('2020-11-01')
async def test_detached_cms_with_tst():
    signature = await FROM_CA.async_sign_general_data(
        b'Hello world!', 'sha256', detached=False, timestamper=DUMMY_TS
    )
    signature = cms.ContentInfo.load(signature.dump())
    status = await async_validate_detached_cms(
        b'Hello world!', signature['content']
    )
    assert status.signer_reported_dt is None
    assert status.timestamp_validity.intact
    assert status.timestamp_validity.valid
    assert status.timestamp_validity.timestamp == datetime.now(tz=pytz.utc)
    assert 'The TSA certificate is untrusted' in status.pretty_print_details()
    assert status.valid
    assert status.intact


@freeze_time('2020-11-01')
async def test_detached_cms_with_content_tst():
    signed_attr_settings = PdfCMSSignedAttributes(
        cades_signed_attrs=CAdESSignedAttrSpec(timestamp_content=True)
    )
    signature = await FROM_CA.async_sign_general_data(
        b'Hello world!', 'sha256', detached=False, timestamper=DUMMY_TS,
        signed_attr_settings=signed_attr_settings
    )
    signature = cms.ContentInfo.load(signature.dump())
    status = await async_validate_detached_cms(
        b'Hello world!', signature['content']
    )
    assert status.signer_reported_dt is None
    assert status.timestamp_validity.intact
    assert status.timestamp_validity.valid
    assert status.timestamp_validity.timestamp == datetime.now(tz=pytz.utc)
    assert status.content_timestamp_validity
    assert status.content_timestamp_validity.intact
    assert status.content_timestamp_validity.valid
    assert status.content_timestamp_validity.timestamp == datetime.now(tz=pytz.utc)
    pretty_print = status.pretty_print_details()
    assert 'The TSA certificate is untrusted' in pretty_print
    assert 'Content timestamp' in pretty_print
    assert 'Signature timestamp' in pretty_print
    assert status.valid
    assert status.intact
    assert 'CONTENT_TIMESTAMP_TOKEN<INTACT:UNTRUSTED>' in status.summary()
    assert ',TIMESTAMP_TOKEN<INTACT:UNTRUSTED>' in status.summary()


@freeze_time('2020-11-01')
async def test_detached_cms_with_wrong_content_tst():
    class CustomSigner(signers.SimpleSigner):
        def _signed_attr_providers(self, *args, **kwargs):
            yield from super()._signed_attr_providers(*args, **kwargs)
            yield TSTProvider(
                digest_algorithm='sha256', data_to_ts=b'\xde\xad\xbe\xef',
                timestamper=DUMMY_TS, attr_type='content_time_stamp',
            )

    signer = CustomSigner(
        signing_cert=FROM_CA.signing_cert,
        signing_key=FROM_CA.signing_key,
        cert_registry=FROM_CA.cert_registry
    )
    signature = await signer.async_sign_general_data(
        b'Hello world!', 'sha256', detached=False, timestamper=DUMMY_TS,
    )
    signature = cms.ContentInfo.load(signature.dump())
    status = await async_validate_detached_cms(
        b'Hello world!', signature['content']
    )
    assert status.signer_reported_dt is None
    assert status.timestamp_validity.intact
    assert status.timestamp_validity.valid
    assert status.timestamp_validity.timestamp == datetime.now(tz=pytz.utc)
    assert status.content_timestamp_validity
    assert not status.content_timestamp_validity.intact
    assert not status.content_timestamp_validity.valid
    assert status.content_timestamp_validity.timestamp == datetime.now(tz=pytz.utc)
    pretty_print = status.pretty_print_details()
    assert 'The TSA certificate is untrusted' in pretty_print
    assert 'Content timestamp' in pretty_print
    assert 'Signature timestamp' in pretty_print
    assert status.valid
    assert status.intact
    assert 'CONTENT_TIMESTAMP_TOKEN<INVALID>' in status.summary()
    assert 'TIMESTAMP_TOKEN<INTACT:UNTRUSTED>' in status.summary()


@freeze_time('2020-11-01')
@pytest.mark.parametrize('content,detach', [
    (b'This is not a TST!', True),
    (b'This is not a TST!', False),
    (cms.ContentInfo({
        'content_type': 'data', 'content': b'This is not a TST!'
    }), False),
    (cms.EncapsulatedContentInfo({
        'content_type': '2.999',
        'content': core.ParsableOctetString(
            core.OctetString(b'This is not a TST!').dump()
        )
    }), False),
    (cms.ContentInfo({'content_type': '2.999',}), True),
])
async def test_detached_with_malformed_content_tst(content, detach):
    class CustomProvider(CMSAttributeProvider):
        attribute_type = 'content_time_stamp'

        async def build_attr_value(self, dry_run=False):
            attr_value = await FROM_CA.async_sign_general_data(
                content, 'sha256',
                detached=detach,
            )
            return attr_value

    class CustomSigner(signers.SimpleSigner):
        def _signed_attr_providers(self, *args, **kwargs):
            yield from super()._signed_attr_providers(*args, **kwargs)
            yield CustomProvider()

    signer = CustomSigner(
        signing_cert=FROM_CA.signing_cert,
        signing_key=FROM_CA.signing_key,
        cert_registry=FROM_CA.cert_registry
    )
    signature = await signer.async_sign_general_data(
        b'Hello world!', 'sha256', detached=False,
        timestamper=DUMMY_TS,
    )
    signature = cms.ContentInfo.load(signature.dump())
    with pytest.raises(SignatureValidationError,
                       match="does not encapsulate TSTInfo"):
        await async_validate_detached_cms(
            b'Hello world!', signature['content']
        )


@freeze_time('2020-11-01')
def test_overspecify_cms_digest_algo():
    # TODO this behaviour is not ideal, but at least this test documents it

    signer = signers.SimpleSigner.load(
        CRYPTO_DATA_DIR + '/selfsigned.key.pem',
        CRYPTO_DATA_DIR + '/selfsigned.cert.pem',
        ca_chain_files=(CRYPTO_DATA_DIR + '/selfsigned.cert.pem',),
        key_passphrase=b'secret',
        # specify an algorithm object that also mandates a specific
        # message digest
        signature_mechanism=SignedDigestAlgorithm(
            {'algorithm': 'sha256_rsa'}
        )
    )
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    # digest methods agree, so that should be OK
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(field_name='Sig1', md_algorithm='sha256'),
        signer=signer

    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    val_untrusted(s)

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    with pytest.raises(SigningError):
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(
                field_name='Sig1', md_algorithm='sha512'
            ), signer=signer
        )


def _tamper_with_signed_attrs(attr_name, *, duplicate=False, delete=False,
                              replace_with=None, resign=False):
    input_buf = BytesIO(MINIMAL)
    w = IncrementalPdfFileWriter(input_buf)
    md_algorithm = 'sha256'

    cms_writer = cms_embedder.PdfCMSEmbedder().write_cms(
        field_name='Signature', writer=w
    )
    next(cms_writer)
    sig_obj = signers.SignatureObject(bytes_reserved=8192)

    cms_writer.send(cms_embedder.SigObjSetup(sig_placeholder=sig_obj))

    prep_digest, output = cms_writer.send(
        cms_embedder.SigIOSetup(md_algorithm=md_algorithm, in_place=True)
    )

    signer: signers.SimpleSigner = signers.SimpleSigner(
        signing_cert=FROM_CA.signing_cert, signing_key=FROM_CA.signing_key,
        cert_registry=FROM_CA.cert_registry,
        signature_mechanism=SignedDigestAlgorithm({
            'algorithm': 'rsassa_pkcs1v15'
        })
    )
    with pytest.deprecated_call():
        # noinspection PyDeprecation
        cms_obj = signer.sign(
            data_digest=prep_digest.document_digest,
            digest_algorithm=md_algorithm,
        )
    sd = cms_obj['content']
    si, = sd['signer_infos']
    signed_attrs = si['signed_attrs']
    ix = next(
        ix for ix, attr in enumerate(signed_attrs)
        if attr['type'].native == attr_name
    )

    # mess with the attribute in the requested way
    if delete:
        del signed_attrs[ix]
    elif duplicate:
        vals = signed_attrs[ix]['values']
        vals.append(vals[0])
    else:
        vals = signed_attrs[ix]['values']
        vals[0] = replace_with

    # ... and replace the signature if requested
    if resign:
        si['signature'] = \
            signer.sign_raw(si['signed_attrs'].untag().dump(), md_algorithm)
    cms_writer.send(cms_obj)
    return output


@pytest.mark.parametrize('replacement_value', [
    cms.CMSAlgorithmProtection({
        'digest_algorithm': DigestAlgorithm({'algorithm': 'sha1'}),
        'signature_algorithm': SignedDigestAlgorithm(
            {'algorithm': 'rsassa_pkcs1v15'}
        )
    }),
    cms.CMSAlgorithmProtection({
        'digest_algorithm': DigestAlgorithm({'algorithm': 'sha256'}),
        'signature_algorithm': SignedDigestAlgorithm(
            {'algorithm': 'sha512_rsa'}
        )
    }),
    cms.CMSAlgorithmProtection({
        'digest_algorithm': DigestAlgorithm({'algorithm': 'sha256'}),
    }),
    None
])
def test_cms_algorithm_protection(replacement_value):
    output = _tamper_with_signed_attrs(
        'cms_algorithm_protection', duplicate=replacement_value is None,
        replace_with=replacement_value, resign=True
    )

    r = PdfFileReader(output)
    emb = r.embedded_signatures[0]
    digest = emb.compute_digest()
    with pytest.raises(SignatureValidationError, match='.*CMS.*'):
        validate_sig_integrity(
            emb.signer_info, emb.signer_cert, 'data', digest
        )


def test_signed_attrs_tampering():
    # delete the (signed) CMSAlgorithmProtection attribute
    # this should invalidate the signature

    output = _tamper_with_signed_attrs('cms_algorithm_protection', delete=True)

    r = PdfFileReader(output)
    emb = r.embedded_signatures[0]
    digest = emb.compute_digest()

    intact, valid = validate_sig_integrity(
        emb.signer_info, emb.signer_cert, 'data', digest
    )
    # "intact" refers to the messageDigest attribute, which we didn't touch
    assert intact and not valid


def test_no_message_digest():
    output = _tamper_with_signed_attrs(
        'message_digest', delete=True, resign=True
    )

    r = PdfFileReader(output)
    emb = r.embedded_signatures[0]
    digest = emb.compute_digest()

    with pytest.raises(SignatureValidationError):
        validate_sig_integrity(
            emb.signer_info, emb.signer_cert, 'data', digest
        )


def test_duplicate_content_type():
    output = _tamper_with_signed_attrs(
        'content_type', duplicate=True, resign=True
    )

    r = PdfFileReader(output)
    emb = r.embedded_signatures[0]
    digest = emb.compute_digest()

    with pytest.raises(SignatureValidationError):
        validate_sig_integrity(
            emb.signer_info, emb.signer_cert, 'data', digest
        )


def test_no_content_type():
    output = _tamper_with_signed_attrs('content_type', delete=True, resign=True)

    r = PdfFileReader(output)
    emb = r.embedded_signatures[0]
    digest = emb.compute_digest()

    with pytest.raises(SignatureValidationError):
        validate_sig_integrity(
            emb.signer_info, emb.signer_cert, 'data', digest
        )


def test_wrong_content_type():
    # delete the (signed) CMSAlgorithmProtection attribute
    # this should invalidate the signature

    output = _tamper_with_signed_attrs(
        'content_type', replace_with='enveloped_data', resign=True
    )

    r = PdfFileReader(output)
    emb = r.embedded_signatures[0]
    digest = emb.compute_digest()

    with pytest.raises(SignatureValidationError):
        validate_sig_integrity(
            emb.signer_info, emb.signer_cert, 'data', digest
        )


@freeze_time('2020-11-01')
def test_sign_weak_digest():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1', md_algorithm='md5')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    with pytest.raises(WeakHashAlgorithmError):
        val_trusted(emb)

    lenient_vc = ValidationContext(
        trust_roots=[ROOT_CERT], weak_hash_algos=set()
    )
    val_trusted(emb, vc=lenient_vc)


@freeze_time('2020-11-01')
def test_sign_weak_digest_prevention():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1', md_algorithm='md5',
        validation_context=SIMPLE_V_CONTEXT()
    )
    with pytest.raises(SigningError, match='.*weak.*'):
        signers.sign_pdf(w, meta, signer=FROM_CA)


@freeze_time('2020-11-01')
async def test_sign_weak_sig_digest():
    # We have to jump through some hoops to put together a signature
    # where the signing method's digest is not the same as the "external"
    # digest. This is intentional, since it's bad practice.

    input_buf = BytesIO(MINIMAL)
    w = IncrementalPdfFileWriter(input_buf)

    cms_writer = cms_embedder.PdfCMSEmbedder().write_cms(
        field_name='Signature', writer=w
    )
    next(cms_writer)

    timestamp = datetime.now(tz=tzlocal.get_localzone())
    sig_obj = signers.SignatureObject(timestamp=timestamp, bytes_reserved=8192)

    external_md_algorithm = 'sha256'
    cms_writer.send(cms_embedder.SigObjSetup(sig_placeholder=sig_obj))

    prep_digest, output = cms_writer.send(
        cms_embedder.SigIOSetup(md_algorithm=external_md_algorithm, in_place=True)
    )
    signer = signers.SimpleSigner(
        signing_cert=TESTING_CA.get_cert(CertLabel('signer1')),
        signing_key=TESTING_CA.key_set.get_private_key(KeyLabel('signer1')),
        cert_registry=SimpleCertificateStore.from_certs([ROOT_CERT,
                                                         INTERM_CERT])
    )
    cms_obj = await signer.async_sign(
        data_digest=prep_digest.document_digest,
        digest_algorithm=external_md_algorithm,
        signed_attr_settings=PdfCMSSignedAttributes(signing_time=timestamp)
    )
    si_obj: cms.SignerInfo = cms_obj['content']['signer_infos'][0]
    bad_algo = SignedDigestAlgorithm({'algorithm': 'md5_rsa'})
    si_obj['signature_algorithm'] = signer.signature_mechanism = bad_algo
    attrs = si_obj['signed_attrs']
    cms_prot = find_cms_attribute(attrs, 'cms_algorithm_protection')[0]
    cms_prot['signature_algorithm'] = bad_algo
    # recompute the signature
    si_obj['signature'] = signer.sign_raw(attrs.untag().dump(), 'md5')
    sig_contents = cms_writer.send(cms_obj)

    # we requested in-place output
    assert output is input_buf

    r = PdfFileReader(input_buf)
    emb = r.embedded_signatures[0]
    with pytest.raises(WeakHashAlgorithmError):
        await async_val_trusted(emb)

    lenient_vc = ValidationContext(
        trust_roots=[ROOT_CERT], weak_hash_algos=set()
    )
    await async_val_trusted(emb, vc=lenient_vc)


@pytest.mark.parametrize("with_issser", [False, True])
@freeze_time('2020-11-01')
def test_old_style_signing_cert_attr_ok(with_issser):
    if with_issser:
        fname = 'pades-with-old-style-signing-cert-attr-issser.pdf'
    else:
        # this file has an old-style signing cert attr without issuerSerial
        fname = 'pades-with-old-style-signing-cert-attr.pdf'
    with open(os.path.join(PDF_DATA_DIR, fname), 'rb') as f:
        r = PdfFileReader(f)
        s = r.embedded_signatures[0]
        assert s.field_name == 'Sig1'
        val_trusted(s)


@pytest.mark.parametrize("with_issser", [False, True])
@freeze_time('2020-11-01')
def test_old_style_signing_cert_attr_mismatch(with_issser):

    if with_issser:
        # this file has an old-style signing cert attr with issuerSerial
        fname = 'pades-with-old-style-signing-cert-attr-issser.pdf'
    else:
        fname = 'pades-with-old-style-signing-cert-attr.pdf'
    with open(os.path.join(PDF_DATA_DIR, fname), 'rb') as f:
        r = PdfFileReader(f)
        s = r.embedded_signatures[0]
        signer_info = s.signer_info
        digest = s.compute_digest()
    # signer1-long has the same key as signer1
    alt_cert = TESTING_CA.get_cert(CertLabel('signer1-long'))
    signer_info['sid'] = {
        'issuer_and_serial_number': cms.IssuerAndSerialNumber({
            'issuer': alt_cert.issuer,
            'serial_number': alt_cert.serial_number
        })
    }
    with pytest.raises(
            SignatureValidationError,
            match="Signing certificate attribute does not match ") as exc_info:
        validate_sig_integrity(
            signer_info, alt_cert, expected_content_type='data',
            actual_digest=digest
        )

    assert exc_info.value.ades_status == AdESStatus.INDETERMINATE
    assert exc_info.value.ades_subindication \
           == AdESIndeterminate.NO_SIGNING_CERTIFICATE_FOUND


def test_old_style_signing_cert_attr_get():
    cert = TESTING_CA.get_cert(CertLabel('signer1'))
    v2 = as_signing_certificate_v2(cert, 'sha1')['certs'][0]
    v1 = as_signing_certificate(cert)['certs'][0]
    assert v1['issuer_serial'].dump() == v2['issuer_serial'].dump()
    assert v1['cert_hash'].dump() == v2['cert_hash'].dump()


def test_signing_cert_attr_malformed_issuer():
    from asn1crypto import x509
    cert = TESTING_CA.get_cert(CertLabel('signer1'))
    bogus_attr = as_signing_certificate_v2(cert)
    bogus_attr['certs'][0]['issuer_serial']['issuer'][0] = x509.GeneralName(
        {'dns_name': 'www.example.com'}
    )
    output = _tamper_with_signed_attrs(
        'signing_certificate_v2', resign=True,
        replace_with=bogus_attr
    )
    r = PdfFileReader(output)
    emb = r.embedded_signatures[0]
    digest = emb.compute_digest()
    with pytest.raises(
            SignatureValidationError,
            match="Signing certificate attribute does not match ") as exc_info:
        validate_sig_integrity(
            emb.signer_info, emb.signer_cert, 'data', digest
        )
    assert exc_info.value.ades_status == AdESStatus.INDETERMINATE
    assert exc_info.value.ades_subindication \
           == AdESIndeterminate.NO_SIGNING_CERTIFICATE_FOUND


def test_signing_cert_attr_duplicated():
    output = _tamper_with_signed_attrs(
        'signing_certificate_v2', resign=True, duplicate=True
    )
    r = PdfFileReader(output)
    emb = r.embedded_signatures[0]
    digest = emb.compute_digest()
    with pytest.raises(SignatureValidationError,
                       match="Wrong cardinality for signing cert"):
        validate_sig_integrity(
            emb.signer_info, emb.signer_cert, 'data', digest
        )


def test_verify_sig_without_signed_attrs():
    # pyHanko never produces signatures of this type, but we should be able
    # to validate them (this file was created using a modified version of
    # pyHanko's signing code, which will never see the light of day)

    with open(PDF_DATA_DIR + '/sig-no-signed-attrs.pdf', 'rb') as f:
        r = PdfFileReader(f)
        s = r.embedded_signatures[0]
        assert s.field_name == 'Sig1'
        val_untrusted(s)


def test_verify_sig_with_ski_sid():
    with open(PDF_DATA_DIR + '/sig-with-ski-sid.pdf', 'rb') as f:
        r = PdfFileReader(f)
        s = r.embedded_signatures[0]
        assert s.field_name == 'Sig1'
        val_untrusted(s)


@freeze_time('2020-11-01')
def test_sign_with_ecdsa_trust():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1'), signer=FROM_ECC_CA
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    si = s.signer_info
    assert si['signature_algorithm']['algorithm'].native == 'sha384_ecdsa'
    val_trusted(s, vc=SIMPLE_ECC_V_CONTEXT())


@freeze_time('2020-11-01')
def test_sign_with_dsa_trust():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1'), signer=FROM_DSA_CA
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    si = s.signer_info
    assert si['signature_algorithm']['algorithm'].native == 'sha256_dsa'
    val_trusted(s, vc=SIMPLE_DSA_V_CONTEXT())


@freeze_time('2020-11-01')
def test_sign_with_explicit_ecdsa_implied_hash():
    signer = signers.SimpleSigner(
        signing_cert=TESTING_CA_ECDSA.get_cert(CertLabel('signer1')),
        signing_key=TESTING_CA_ECDSA.key_set.get_private_key(
            KeyLabel('signer1')),
        cert_registry=SimpleCertificateStore.from_certs(
            [ECC_ROOT_CERT, ECC_INTERM_CERT]
        ),
        # this is not allowed, but the validator should accept it anyway
        signature_mechanism=SignedDigestAlgorithm({'algorithm': 'ecdsa'})
    )
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1'),
        signer=signer
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    si = s.signer_info
    assert si['signature_algorithm']['algorithm'].native == 'ecdsa'
    assert si['digest_algorithm']['algorithm'].native == 'sha384'
    assert s.field_name == 'Sig1'
    val_trusted(s, vc=SIMPLE_ECC_V_CONTEXT())


@freeze_time('2020-11-01')
def test_sign_with_explicit_dsa_implied_hash():
    signer = signers.SimpleSigner(
        signing_cert=TESTING_CA_DSA.get_cert(CertLabel('signer1')),
        signing_key=TESTING_CA_DSA.key_set.get_private_key(KeyLabel('signer1')),
        cert_registry=SimpleCertificateStore.from_certs(
            [DSA_ROOT_CERT, DSA_INTERM_CERT]
        ),
        # this is not allowed, but the validator should accept it anyway
        signature_mechanism=SignedDigestAlgorithm({'algorithm': 'dsa'})
    )
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1'),
        signer=signer
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    si = s.signer_info
    assert si['signature_algorithm']['algorithm'].native == 'dsa'
    assert s.field_name == 'Sig1'
    val_trusted(s, vc=SIMPLE_DSA_V_CONTEXT())


def test_sign_pss():
    signer = signers.SimpleSigner.load(
        CRYPTO_DATA_DIR + '/selfsigned.key.pem',
        CRYPTO_DATA_DIR + '/selfsigned.cert.pem',
        ca_chain_files=(CRYPTO_DATA_DIR + '/selfsigned.cert.pem',),
        key_passphrase=b'secret', prefer_pss=True
    )
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    sda: SignedDigestAlgorithm = emb.signer_info['signature_algorithm']
    assert sda.signature_algo == 'rsassa_pss'
    val_untrusted(emb)


def test_sign_pss_md_discrepancy():
    # Acrobat refuses to validate PSS signatures where the internal
    # hash functions disagree, but mathematically speaking, that shouldn't
    # be an issue.
    signer = signers.SimpleSigner.load(
        CRYPTO_DATA_DIR + '/selfsigned.key.pem',
        CRYPTO_DATA_DIR + '/selfsigned.cert.pem',
        ca_chain_files=(CRYPTO_DATA_DIR + '/selfsigned.cert.pem',),
        key_passphrase=b'secret', signature_mechanism=SignedDigestAlgorithm({
            'algorithm': 'rsassa_pss',
            'parameters': RSASSAPSSParams({
                'mask_gen_algorithm': MaskGenAlgorithm({
                    'algorithm': 'mgf1',
                    'parameters': DigestAlgorithm({'algorithm': 'sha512'})
                }),
                'hash_algorithm': DigestAlgorithm({'algorithm': 'sha256'}),
                'salt_length': 478
            })
        })
    )
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=signer)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    sda: SignedDigestAlgorithm = emb.signer_info['signature_algorithm']
    assert sda.signature_algo == 'rsassa_pss'
    val_untrusted(emb)


@freeze_time('2020-11-01')
def test_direct_pdfcmsembedder_usage():
    # CMS-agnostic signing example
    #
    # write an in-place certification signature using the PdfCMSEmbedder
    # low-level API directly.

    input_buf = BytesIO(MINIMAL)
    w = IncrementalPdfFileWriter(input_buf)

    # Phase 1: coroutine sets up the form field
    cms_writer = cms_embedder.PdfCMSEmbedder().write_cms(
        field_name='Signature', writer=w
    )
    sig_field_ref = next(cms_writer)

    # just for kicks, let's check
    assert sig_field_ref.get_object()['/T'] == 'Signature'

    # Phase 2: make a placeholder signature object,
    # wrap it up together with the MDP config we want, and send that
    # on to cms_writer
    timestamp = datetime.now(tz=tzlocal.get_localzone())
    sig_obj = signers.SignatureObject(timestamp=timestamp, bytes_reserved=8192)

    md_algorithm = 'sha256'
    cms_writer.send(
        cms_embedder.SigObjSetup(
            sig_placeholder=sig_obj,
            mdp_setup=cms_embedder.SigMDPSetup(
                md_algorithm=md_algorithm, certify=True,
                docmdp_perms=fields.MDPPerm.NO_CHANGES
            )
        )
    )

    # Phase 3: write & hash the document (with placeholder)
    prep_digest, output = cms_writer.send(
        cms_embedder.SigIOSetup(md_algorithm=md_algorithm, in_place=True)
    )

    # Phase 4: construct CMS signature object, and pass it on to cms_writer

    # NOTE: I'm using a regular SimpleSigner here, but you can substitute
    # whatever CMS supplier you want.

    signer: signers.SimpleSigner = FROM_CA
    # let's supply the CMS object as a raw bytestring
    with pytest.deprecated_call():
        # noinspection PyDeprecation
        cms_bytes = signer.sign(
            data_digest=prep_digest.document_digest,
            digest_algorithm=md_algorithm, timestamp=timestamp
        ).dump()
    sig_contents = cms_writer.send(cms_bytes)

    # we requested in-place output
    assert output is input_buf

    r = PdfFileReader(input_buf)
    val_trusted(r.embedded_signatures[0])

    # add some stuff to the DSS for kicks
    DocumentSecurityStore.add_dss(
        output, sig_contents, certs=FROM_CA.cert_registry, ocsps=(FIXED_OCSP,)
    )
    r = PdfFileReader(input_buf)
    dss = DocumentSecurityStore.read_dss(handler=r)
    val_trusted(r.embedded_signatures[0], extd=True)
    assert dss is not None
    assert len(dss.certs) == 3
    assert len(dss.ocsps) == 1


@freeze_time('2020-11-01')
async def test_no_embed_root():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    cr = SimpleCertificateStore()
    cr.register_multiple(FROM_CA.cert_registry)
    no_embed_root_signer = signers.SimpleSigner(
        signing_cert=FROM_CA.signing_cert, signing_key=FROM_CA.signing_key,
        cert_registry=cr, embed_roots=False
    )
    out = await signers.async_sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1'),
        signer=no_embed_root_signer
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    assert '/AP' not in s.sig_field
    assert len(s.signed_data['certificates']) == 2
    await async_val_trusted(s)


@freeze_time('2020-11-01')
async def test_noop_attribute_prov():
    class NoopProv(CMSAttributeProvider):
        async def build_attr_value(self, dry_run=False):
            return None

    class CustomSigner(signers.SimpleSigner):
        def _signed_attr_providers(self, *args, **kwargs):
            yield from super()._signed_attr_providers(*args, **kwargs)
            yield NoopProv()

    signer = CustomSigner(
        signing_cert=FROM_CA.signing_cert, signing_key=FROM_CA.signing_key,
        cert_registry=FROM_CA.cert_registry
    )
    input_data = b'Hello world!'
    signature = await signer.async_sign_general_data(input_data, 'sha256')

    # re-parse just to make sure we're starting fresh
    signature = cms.ContentInfo.load(signature.dump())

    raw_digest = hashlib.sha256(input_data).digest()
    content = signature['content']
    status = await async_validate_cms_signature(content, raw_digest=raw_digest)
    assert status.valid
    assert status.intact


@pytest.mark.parametrize('delete', [True, False])
async def test_no_certificates(delete):
    input_buf = BytesIO(MINIMAL)
    w = IncrementalPdfFileWriter(input_buf)
    md_algorithm = 'sha256'

    cms_writer = cms_embedder.PdfCMSEmbedder().write_cms(
        field_name='Signature', writer=w
    )
    next(cms_writer)
    sig_obj = signers.SignatureObject(bytes_reserved=8192)

    cms_writer.send(cms_embedder.SigObjSetup(sig_placeholder=sig_obj))

    prep_digest, output = cms_writer.send(
        cms_embedder.SigIOSetup(md_algorithm=md_algorithm, in_place=True)
    )

    signer: signers.SimpleSigner = signers.SimpleSigner(
        signing_cert=FROM_CA.signing_cert, signing_key=FROM_CA.signing_key,
        cert_registry=FROM_CA.cert_registry,
        signature_mechanism=SignedDigestAlgorithm({
            'algorithm': 'rsassa_pkcs1v15'
        })
    )
    cms_obj = await signer.async_sign(
        data_digest=prep_digest.document_digest,
        digest_algorithm=md_algorithm,
    )
    sd = cms_obj['content']
    if delete:
        del sd['certificates']
    else:
        sd['certificates'] = cms.CertificateSet([])
    cms_writer.send(cms_obj)

    r = PdfFileReader(output)
    with pytest.raises(CMSExtractionError, match='signer cert.*includ'):
        emb = r.embedded_signatures[0]
        await collect_validation_info(
            embedded_sig=emb, validation_context=ValidationContext()
        )


async def test_two_signer_infos():
    input_buf = BytesIO(MINIMAL)
    w = IncrementalPdfFileWriter(input_buf)
    md_algorithm = 'sha256'

    cms_writer = cms_embedder.PdfCMSEmbedder().write_cms(
        field_name='Signature', writer=w
    )
    next(cms_writer)
    sig_obj = signers.SignatureObject(bytes_reserved=8192)

    cms_writer.send(cms_embedder.SigObjSetup(sig_placeholder=sig_obj))

    prep_digest, output = cms_writer.send(
        cms_embedder.SigIOSetup(md_algorithm=md_algorithm, in_place=True)
    )

    signer: signers.SimpleSigner = signers.SimpleSigner(
        signing_cert=FROM_CA.signing_cert, signing_key=FROM_CA.signing_key,
        cert_registry=SimpleCertificateStore(),
        signature_mechanism=SignedDigestAlgorithm({
            'algorithm': 'rsassa_pkcs1v15'
        })
    )
    cms_obj = await signer.async_sign(
        data_digest=prep_digest.document_digest,
        digest_algorithm=md_algorithm,
    )
    sd = cms_obj['content']
    si = sd['signer_infos'][0]
    sd['signer_infos'] = [si, si]
    cms_writer.send(cms_obj)

    r = PdfFileReader(output)
    with pytest.raises(CMSExtractionError, match='exactly one'):
        emb = r.embedded_signatures[0]
        await collect_validation_info(
            embedded_sig=emb, validation_context=ValidationContext()
        )


def get_ac_aware_signer(actual_signer='signer1'):
    pki_arch = CERTOMANCER.get_pki_arch(ArchLabel('testing-ca-with-aa'))
    signer = signers.SimpleSigner(
        signing_cert=pki_arch.get_cert(CertLabel(actual_signer)),
        signing_key=pki_arch.key_set.get_private_key(KeyLabel(actual_signer)),
        cert_registry=SimpleCertificateStore.from_certs(
            [
                pki_arch.get_cert('root'), pki_arch.get_cert('interm'),
                pki_arch.get_cert('root-aa'), pki_arch.get_cert('interm-aa'),
                pki_arch.get_cert('leaf-aa')
            ]
        ),
        attribute_certs=[
            pki_arch.get_attr_cert(CertLabel('alice-role-with-rev'))
        ]
    )
    return signer


@freeze_time('2020-11-01')
async def test_embed_ac(requests_mock):
    signer = get_ac_aware_signer()
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = await signers.async_sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1'),
        signer=signer
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.signed_data['version'].native == 'v4'
    # 4 CA certs, 1 AA certs, 1 AC, 1 signer cert -> 7 certs
    assert len(s.other_embedded_certs) == 5  # signer cert is excluded
    assert len(s.embedded_attr_certs) == 1
    main_vc, ac_vc = live_ac_vcs(requests_mock)
    status = await async_validate_pdf_signature(
        s, signer_validation_context=main_vc, ac_validation_context=ac_vc
    )
    assert status.bottom_line
    roles = list(status.ac_attrs['role'].attr_values)
    role = roles[0]
    assert isinstance(role, cms.RoleSyntax)
    assert role['role_name'].native == 'bigboss@example.com'


@freeze_time('2020-11-01')
async def test_embed_ac_revinfo_adobe_style(requests_mock):
    signer = get_ac_aware_signer()
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    pki_arch = CERTOMANCER.get_pki_arch(ArchLabel('testing-ca-with-aa'))
    dummy_ts = timestamps.DummyTimeStamper(
        tsa_cert=pki_arch.get_cert(CertLabel('tsa')),
        tsa_key=pki_arch.key_set.get_private_key(KeyLabel('tsa')),
        certs_to_embed=SimpleCertificateStore.from_certs(
            [pki_arch.get_cert('root')]
        )
    )
    from certomancer.integrations.illusionist import Illusionist
    from pyhanko_certvalidator.fetchers.requests_fetchers import (
        RequestsFetcherBackend,
    )
    fetchers = RequestsFetcherBackend().get_fetchers()
    main_vc = ValidationContext(
        trust_roots=[pki_arch.get_cert('root')], allow_fetching=True,
        other_certs=signer.cert_registry, fetchers=fetchers,
        revocation_mode='require'
    )
    ac_vc = ValidationContext(
        trust_roots=[pki_arch.get_cert('root-aa')], allow_fetching=True,
        other_certs=signer.cert_registry, fetchers=fetchers,
        revocation_mode='require'
    )
    Illusionist(pki_arch).register(requests_mock)
    out = await signers.async_sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1',
            embed_validation_info=True,
            validation_context=main_vc,
            ac_validation_context=ac_vc
        ),
        timestamper=dummy_ts,
        signer=signer
    )

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    # 4 CA certs, 1 AA certs, 1 AC, 1 signer cert -> 7 certs
    assert len(s.other_embedded_certs) == 5  # signer cert is excluded
    assert len(s.embedded_attr_certs) == 1
    from pyhanko.sign.validation import RevocationInfoValidationType
    status = await async_validate_pdf_ltv_signature(
        s, RevocationInfoValidationType.ADOBE_STYLE,
        validation_context_kwargs={
            'trust_roots': [pki_arch.get_cert('root')]
        },
        ac_validation_context_kwargs={
            'trust_roots': [pki_arch.get_cert('root-aa')]
        }
    )
    assert status.bottom_line
    roles = list(status.ac_attrs['role'].attr_values)
    role = roles[0]
    assert isinstance(role, cms.RoleSyntax)
    assert role['role_name'].native == 'bigboss@example.com'


@freeze_time('2020-11-01')
async def test_ac_detached(requests_mock):
    input_data = b'Hello world!'
    signer = get_ac_aware_signer()
    output = await signer.async_sign_general_data(input_data, 'sha256')
    assert output['content']['version'].native == 'v4'
    main_vc, ac_vc = live_ac_vcs(requests_mock)
    status = await async_validate_detached_cms(
        input_data, output['content'],
        signer_validation_context=main_vc, ac_validation_context=ac_vc
    )
    assert status.bottom_line
    roles = list(status.ac_attrs['role'].attr_values)
    role = roles[0]
    assert isinstance(role, cms.RoleSyntax)
    assert len(list(status.ac_attrs)) == 1
    assert role['role_name'].native == 'bigboss@example.com'


@freeze_time('2020-11-01')
async def test_ac_attr_validation_fail(requests_mock):
    input_data = b'Hello world!'
    signer = get_ac_aware_signer()
    output = await signer.async_sign_general_data(input_data, 'sha256')
    main_vc, ac_vc = live_ac_vcs(requests_mock)
    status = await async_validate_detached_cms(
        input_data, output['content'],
        signer_validation_context=main_vc,
        ac_validation_context=main_vc  # pass in the wrong VC on purpose
    )
    assert status.bottom_line  # this should still be OK
    assert len(list(status.ac_attrs)) == 0
    assert 'role' not in status.ac_attrs  # ...but the attribute check fails


@freeze_time('2020-11-01')
async def test_ac_attr_validation_holder_mismatch(requests_mock):
    input_data = b'Hello world!'
    # sign with a key pair that's not the same as the holder of the AC
    # that we're embedding
    signer = get_ac_aware_signer('signer2')
    output = await signer.async_sign_general_data(input_data, 'sha256')
    main_vc, ac_vc = live_ac_vcs(requests_mock)
    status = await async_validate_detached_cms(
        input_data, output['content'],
        signer_validation_context=main_vc,
        ac_validation_context=ac_vc
    )
    assert status.bottom_line  # this should still be OK
    assert len(list(status.ac_attrs)) == 0
    assert 'role' not in status.ac_attrs  # ...but the attribute check fails


@freeze_time('2020-11-01')
async def test_detached_cades_cms_with_tst():
    signature = await FROM_CA.async_sign_general_data(
        b'Hello world!', 'sha256', detached=False, timestamper=DUMMY_TS,
        use_cades=True
    )
    signature = cms.ContentInfo.load(signature.dump())
    status = await async_validate_detached_cms(
        b'Hello world!', signature['content']
    )
    assert status.signer_reported_dt == datetime.now(tz=pytz.utc)
    assert status.timestamp_validity.intact
    assert status.timestamp_validity.valid
    assert status.timestamp_validity.timestamp == datetime.now(tz=pytz.utc)
    assert 'The TSA certificate is untrusted' in status.pretty_print_details()
    assert status.valid
    assert status.intact
