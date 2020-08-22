import hashlib
import os
from dataclasses import dataclass
from datetime import datetime
from typing import TypeVar, Type, Optional

from asn1crypto import cms, tsp
from certvalidator import ValidationContext, CertificateValidator
from oscrypto import asymmetric
from oscrypto.errors import SignatureError

from pdf_utils import generic, misc
from pdf_utils.reader import PdfFileReader
from .general import SignatureStatus, find_cms_attribute
from .timestamps import TimestampSignatureStatus

__all__ = [
    'PDFSignatureStatus', 'validate_pdf_signature', 'validate_cms_signature',
]


def partition_certs(certs, signer_info):
    # The 'certificates' entry is defined as a set in PCKS#7.
    # In particular, we cannot make any assumptions about the order.
    # This means that we have to manually dig through the list to find
    # the actual signer
    iss_sn = signer_info['sid']
    # TODO Figure out how the subject key identifier thing works
    if iss_sn.name != 'issuer_and_serial_number':
        raise ValueError(
            'Can only look up certificates by issuer and serial number'
        )
    issuer = iss_sn.chosen['issuer']
    serial_number = iss_sn.chosen['serial_number'].native
    cert = None
    ca_chain = []
    for c in certs:
        if c.issuer == issuer and c.serial_number == serial_number:
            cert = c
        else:
            ca_chain.append(c)
    if cert is None:
        raise ValueError('signer certificate not included in signature')
    return cert, ca_chain


StatusType = TypeVar('StatusType', bound=SignatureStatus)


def validate_cms_signature(signed_data: cms.SignedData,
                           status_cls: Type[StatusType] = SignatureStatus,
                           raw_digest: bytes = None,
                           validation_context: ValidationContext = None,
                           status_kwargs: dict = None):
    """
    Validate CMS and PKCS#7 signatures.
    """

    certs = [c.parse() for c in signed_data['certificates']]

    try:
        signer_info, = signed_data['signer_infos']
    except ValueError:
        raise ValueError('signer_infos should contain exactly one entry')

    cert, ca_chain = partition_certs(certs, signer_info)

    mechanism = \
        signer_info['signature_algorithm']['algorithm'].native.lower()
    md_algorithm = \
        signer_info['digest_algorithm']['algorithm'].native.lower()
    signature = signer_info['signature'].native
    signed_attrs = signer_info['signed_attrs']

    # TODO What to do if signed_attrs is absent?
    # I guess I'll wait until someone complains that a valid signature
    # isn't being validated correctly
    if raw_digest is None:
        # this means that there should be encapsulated data
        # TODO Carefully read § 5.2.1 in RFC 5652, and compare with
        #  the implementation in asn1crypto.
        raw = signed_data['encap_content_info']['content'].parsed.dump()
        raw_digest = getattr(hashlib, md_algorithm)(raw).digest()

    # XXX for some reason, these values are sometimes set wrongly
    # when asn1crypto loads things. No clue why, but they mess up
    # the header byte (and hence the signature) of the DER-encoded
    # message object. Needs investigation.
    signed_attrs.class_ = 0
    signed_attrs.tag = 17
    signed_blob = signed_attrs.dump(force=True)
    try:
        embedded_digest = find_cms_attribute(signed_attrs, 'message_digest')
    except KeyError:
        raise ValueError('Message digest not found in signature')
    intact = raw_digest == embedded_digest[0].native

    # finally validate the signature
    if mechanism not in MECHANISMS:
        raise NotImplementedError(
            'Signature mechanism %s is not currently supported'
            % mechanism
        )

    valid = False
    if intact:
        try:
            asymmetric.rsa_pkcs1v15_verify(
                asymmetric.load_public_key(cert.public_key), signature,
                signed_blob, hash_algorithm=md_algorithm
            )
            valid = True
        except SignatureError:
            valid = False

    trusted = revoked = usage_ok = False
    if valid:
        validator = CertificateValidator(
            cert, intermediate_certs=ca_chain,
            validation_context=validation_context
        )
        trusted, revoked, usage_ok = status_cls.validate_cert_usage(validator)
    return status_cls(
        intact=intact, ca_chain=ca_chain, valid=valid, signing_cert=cert,
        md_algorithm=md_algorithm, pkcs7_signature_mechanism=mechanism,
        revoked=revoked, usage_ok=usage_ok, trusted=trusted,
        **(status_kwargs or {})
    )


@dataclass(frozen=True)
class PDFSignatureStatus(SignatureStatus):
    complete_document: bool
    signed_dt: Optional[datetime] = None
    timestamp_validity: Optional[TimestampSignatureStatus] = None

    def summary_fields(self):
        yield from super().summary_fields()
        yield 'UNTOUCHED' if self.complete_document else 'EXTENDED'


MECHANISMS = (
    'rsassa_pkcs1v15', 'sha1_rsa', 'sha256_rsa', 'sha384_rsa', 'sha512_rsa'
)


def validate_pdf_signature(reader: PdfFileReader, sig_object,
                           signer_validation_context=None,
                           ts_validation_context=None) -> PDFSignatureStatus:
    if sig_object is None:
        raise ValueError('Signature is empty')
    if ts_validation_context is None:
        ts_validation_context = signer_validation_context

    if isinstance(sig_object, generic.IndirectObject):
        sig_object = sig_object.get_object()
    assert isinstance(sig_object, generic.DictionaryObject)
    try:
        pkcs7_content = sig_object.raw_get('/Contents', decrypt=False)
        byte_range = sig_object['/ByteRange']
    except KeyError:
        raise ValueError('Signature PDF object is not correctly formatted')

    # we need the pkcs7_content raw, so we need to deencapsulate a couple
    # pieces of data here.
    if isinstance(pkcs7_content, generic.DecryptedObjectProxy):
        # it was a direct reference, so just grab the raw one
        pkcs7_content = pkcs7_content.raw_object
    elif isinstance(pkcs7_content, generic.IndirectObject):
        pkcs7_content = reader.get_object(
            pkcs7_content, transparent_decrypt=False
        )

    message = cms.ContentInfo.load(pkcs7_content)
    signed_data = message['content']
    sd_digest = signed_data['digest_algorithms'][0]
    md_algorithm = sd_digest['algorithm'].native.lower()
    md = getattr(hashlib, md_algorithm)()
    stream = reader.stream

    # compute the digest
    old_seek = stream.tell()
    total_len = 0
    for lo, chunk_len in misc.pair_iter(byte_range):
        stream.seek(lo)
        md.update(stream.read(chunk_len))
        total_len += chunk_len
    # compute file size
    stream.seek(0, os.SEEK_END)
    # the * 2 is because of the ASCII hex encoding, and the + 2
    # is the wrapping <>
    embedded_sig_content = len(pkcs7_content) * 2 + 2
    complete_document = stream.tell() == total_len + embedded_sig_content
    stream.seek(old_seek)

    # TODO implement logic to detect whether
    #  the modifications made are permissible

    # TODO validate /SV constraints if present!

    raw_digest = md.digest()

    status_kwargs = {'complete_document': complete_document}
    try:
        signer_info, = signed_data['signer_infos']
    except ValueError:
        raise ValueError('signer_infos should contain exactly one entry')

    # try to find an embedded timestamp
    try:
        sa = signer_info['signed_attrs']
        st = find_cms_attribute(sa, 'signed_time')[0]
        status_kwargs['signed_dt'] = st.native
    except KeyError:
        pass
    # if there's a signed timestamp, find that one too
    try:
        ua = signer_info['unsigned_attrs']
        tst = find_cms_attribute(ua, 'signature_time_stamp_token')[0]
    except KeyError:
        tst = None

    # if we managed to find a signed timestamp, we now proceed to validate it
    if tst is not None:
        tst_signed_data = tst['content']
        tst_info = tst_signed_data['encap_content_info']['content'].parsed
        assert isinstance(tst_info, tsp.TSTInfo)
        timestamp = tst_info['gen_time'].native
        status_kwargs['timestamp_validity'] = validate_cms_signature(
            tst_signed_data, status_cls=TimestampSignatureStatus,
            validation_context=ts_validation_context,
            status_kwargs={'timestamp': timestamp}
        )

    return validate_cms_signature(
        signed_data, status_cls=PDFSignatureStatus,
        raw_digest=raw_digest, validation_context=signer_validation_context,
        status_kwargs=status_kwargs
    )