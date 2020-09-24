import binascii
import hashlib
import os
import logging
from dataclasses import dataclass, field as data_field
from datetime import datetime
from io import BytesIO
from typing import TypeVar, Type, Optional

from asn1crypto import cms, tsp, ocsp as asn1_ocsp
from asn1crypto.x509 import Certificate
from certvalidator import ValidationContext, CertificateValidator
from certvalidator.path import ValidationPath
from oscrypto import asymmetric
from oscrypto.errors import SignatureError

from pdf_utils import generic, misc
from pdf_utils.generic import pdf_name
from pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pdf_utils.reader import PdfFileReader
from pdf_utils.rw_common import PdfHandler
from . import DocMDPPerm
from .general import SignatureStatus, find_cms_attribute
from .timestamps import TimestampSignatureStatus

__all__ = [
    'PDFSignatureStatus', 'validate_pdf_signature', 'validate_cms_signature',
    'read_certification_data'
]

logger = logging.getLogger(__name__)


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


def read_certification_data(reader: PdfFileReader):
    try:
        docmdp = reader.root['/Perms'].raw_get('/DocMDP')
    except KeyError:
        return

    if not isinstance(docmdp, generic.IndirectObject):  # pragma: nocover
        raise ValueError('/DocMDP entry in /Perms should be an indirect ref')

    sig_dict = docmdp.get_object()
    # look up the relevant signature reference dictionary
    try:
        sig_refs = sig_dict['/Reference']
        sig_ref = None
        # not compliant, but meh
        if isinstance(sig_refs, generic.DictionaryObject):  # pragma: nocover
            logger.warning(
                '/Reference entry should be an array of dictionaries'
            )
            if sig_refs['/TransformMethod'] == pdf_name('/DocMDP'):
                sig_ref = sig_refs
        elif isinstance(sig_refs, generic.ArrayObject):
            for ref in sig_refs:
                ref = ref.get_object()
                if ref['/TransformMethod'] == pdf_name('/DocMDP'):
                    sig_ref = ref
                    break
        else:  # pragma: nocover
            logger.warning('Illegal type in /Reference, bailing.')
        if sig_ref is None:  # pragma: nocover
            raise ValueError('Could not parse signature reference dictionary.')
    except KeyError:  # pragma: nocover
        raise ValueError('Could not find signature reference dictionary.')

    try:
        permission_bits = sig_ref['/TransformParams']['/P']
    except KeyError:
        permission_bits = DocMDPPerm.FILL_FORMS

    return sig_dict, permission_bits


def unroll_path(path: ValidationPath):
    # TODO this isn't particularly efficient, but unless ValidationPath
    #  starts supporting some kind of read-only slicing mechanism, this is
    #  by far the simplest

    if len(path) == 1:
        return

    end_cert = path[len(path) - 1]

    # path.pop() does not record the last cert, as one might expect, but the
    #  path object itself
    new_path = path.copy().pop()
    yield end_cert, new_path.find_issuer(end_cert)
    yield from unroll_path(new_path)


# TODO validate DocMDP compliance and PAdES compliance
#  There are some compatibility subtleties here: e.g. valid (!) cryptographic
#  data covered by DSS and/or DocumentTimeStamps should never trigger the DocMDP
#  policy.


@dataclass
class VRI:
    certs: list = data_field(default_factory=list)
    ocsps: list = data_field(default_factory=list)
    crls: list = data_field(default_factory=list)

    def __iadd__(self, other):
        self.certs.extend(other.certs)
        self.crls.extend(other.crls)
        self.ocsps.extend(other.ocsps)
        return self

    def as_pdf_object(self):
        vri = generic.DictionaryObject({pdf_name('/Type'): pdf_name('/VRI')})
        if self.ocsps:
            vri[pdf_name('/OCSPs')] = generic.ArrayObject(self.ocsps)
        if self.crls:
            vri[pdf_name('/CRLs')] = generic.ArrayObject(self.crls)
        vri[pdf_name('/Certs')] = generic.ArrayObject(self.certs)
        return vri


def build_trust_path(validation_context, cert) -> ValidationPath:
    """
    Thin wrapper around build_paths to select one valid path.
    """

    paths = validation_context.certificate_registry.build_paths(cert)
    if not paths:
        raise ValueError(
            'Could not build path from signing cert to trust roots'
        )

    return paths[0]


def cms_objects_to_streams(writer, objs):
    return [
        writer.add_object(
            generic.StreamObject(stream_data=obj.dump())
        ) for obj in objs
    ]


def enumerate_ocsp_certs(ocsp_response):
    """
    Essentially nabbed from _extract_ocsp_certs in ValidationContext
    """

    status = ocsp_response['response_status'].native
    if status == 'successful':
        response_bytes = ocsp_response['response_bytes']
        if response_bytes['response_type'].native == 'basic_ocsp_response':
            response = response_bytes['response'].parsed
            yield from response['certs']


class DocumentSecurityStore:

    def __init__(self, writer, validation_context: ValidationContext,
                 certs=None, ocsps=None,
                 unindexed_ocsps=None, vri_entries=None,
                 backing_pdf_object=None):
        self.vri_entries = vri_entries if vri_entries is not None else {}
        self.ocsps = ocsps if ocsps is not None else {}
        self.certs = certs if certs is not None else {}
        self.unindexed_ocsps = \
            unindexed_ocsps if unindexed_ocsps is not None else []

        self.validation_context = validation_context
        self.writer = writer
        self.backing_pdf_object = (
            backing_pdf_object if backing_pdf_object is not None
            else generic.DictionaryObject()
        )

        # embed any hardcoded ocsp responses, if applicable
        if writer is not None:
            self.unindexed_ocsps.extend(
                cms_objects_to_streams(writer, validation_context.ocsps)
            )
            self._embed_certs_from_ocsp(validation_context.ocsps)

    def _embed_certs_from_ocsp(self, ocsps):
        def extra_certs():
            for resp in ocsps:
                yield from enumerate_ocsp_certs(resp)

        return [self._embed_cert(cert_) for cert_ in extra_certs()]

    def _embed_ocsp_responses(self, cert, issuer):
        if self.writer is None:
            raise TypeError('This DSS does not support updates.')

        try:
            return self.ocsps[cert.issuer_serial]
        except KeyError:
            pass

        # FIXME there seems to be an issue with the OCSP checking here.
        #  Either the BEID OCSP responder is noncompliant, or there is a dt
        #  rounding bug in the certvalidator library.
        # anyway, for now, we just retrieve the OCSP responses without checking
        # them, which is NOT allowed by PAdES.
        if cert.ocsp_urls:
            ocsps = self.validation_context.retrieve_ocsps(cert, issuer)
            ocsp_refs = cms_objects_to_streams(self.writer, ocsps)
            self.ocsps[cert.issuer_serial] = ocsp_refs
            cert_refs = self._embed_certs_from_ocsp(ocsps)
            return ocsp_refs, cert_refs
        return (), ()

    def _embed_cert(self, cert):
        if self.writer is None:
            raise TypeError('This DSS does not support updates.')

        try:
            return self.certs[cert.issuer_serial]
        except KeyError:
            pass

        ref = self.writer.add_object(
            generic.StreamObject(stream_data=cert.dump())
        )
        self.certs[cert.issuer_serial] = ref
        return ref

    @staticmethod
    def sig_content_identifier(contents_hex_data):
        ident_bytes = binascii.hexlify(hashlib.sha1(contents_hex_data).digest())
        return pdf_name('/' + ident_bytes.decode('ascii').upper())

    def collect_vri(self, signer_cert) -> VRI:
        path = build_trust_path(self.validation_context, signer_cert)
        # unindexed ocsps should be available for use in every VRI, unless
        # otherwise specified
        ocsp_refs = list(self.unindexed_ocsps)
        # we also add the root & leaf, even though it shouldn't be required, but
        # it can't hurt
        cert_refs = [self._embed_cert(signer_cert)]
        for cert, issuer in unroll_path(path):
            cert_refs.append(self._embed_cert(issuer))
            # noinspection PyProtectedMember
            if self.validation_context._allow_fetching:
                ocsp_refs, extra_certs = self._embed_ocsp_responses(
                    cert, issuer
                )
                ocsp_refs.extend(ocsp_refs)
                cert_refs.extend(extra_certs)

        return VRI(ocsps=ocsp_refs, certs=cert_refs)

    def register_vri(self, identifier, signer_certs):
        """
        Register validation information for a set of signing certificates
        associated with a particular signature.
        Typically, signer_certs has only one entry (i.e. the main signer),
        but if timestamps are embedded into the signature, more entries may be
        included to account for timestamping authorities etc.

        :param identifier:
            Identifier of the signature object (see `sig_content_identifier`)
        :param signer_certs:
            All certificates of entities that provided some signature embedded
            into the signature object being referenced.
        """

        vri = VRI()
        for cert in signer_certs:
            vri += self.collect_vri(cert)

        self.vri_entries[identifier] = self.writer.add_object(
            vri.as_pdf_object()
        )

    def as_pdf_object(self):
        pdf_dict = self.backing_pdf_object
        pdf_dict.update({
            pdf_name('/VRI'): generic.DictionaryObject(self.vri_entries),
            pdf_name('/Certs'): generic.ArrayObject(list(self.certs.values())),
        })

        def flat_ocsps():
            for fetched in self.ocsps.values():
                yield from fetched
            yield from self.unindexed_ocsps

        if self.ocsps or self.unindexed_ocsps:
            pdf_dict[pdf_name('/OCSPs')] = generic.ArrayObject(flat_ocsps())

        return pdf_dict

    @classmethod
    def read_dss(cls, handler: PdfHandler,
                 validation_context_kwargs: dict = None,
                 validation_context: ValidationContext = None):
        """
        Read a DSS record from a file and add the data to a validation context.
        :param handler:
        :param validation_context_kwargs:
            Constructor kwargs for the ValidationContext used.
        :param validation_context:
            Use existing validation context.
            NOTE: OCSP responses will not be added, only certificates.
        :return:
            A DocumentSecurityStore object describing the current state of the
            DSS, or None if none was found.
        """
        # TODO remember where we're reading from for modification detection
        #  purposes
        try:
            dss_ref = handler.root.raw_get(pdf_name('/DSS'))
        except KeyError:
            return None

        dss_dict = dss_ref.get_object()

        if validation_context is None and validation_context_kwargs is None:
            validation_context_kwargs = {}

        cert_refs = {}
        certs = []
        for cert_ref in dss_dict.get('/Certs', ()):
            cert_stream: generic.StreamObject = cert_ref.get_object()
            cert: Certificate = Certificate.load(cert_stream.data)
            cert_refs[cert.issuer_serial] = cert_ref

            if validation_context is not None:
                validation_context.certificate_registry.add_other_cert(cert)
            else:
                certs.append(cert)

        ocsp_refs = list(dss_dict.get('/OCSPs', ()))
        ocsps = []
        for ocsp_ref in ocsp_refs:
            ocsp_stream: generic.StreamObject = ocsp_ref.get_object()
            resp = asn1_ocsp.OCSPResponse.load(ocsp_stream.data)
            ocsps.append(resp)

        if validation_context is None:
            certs += validation_context_kwargs.get('other_certs', [])
            validation_context = ValidationContext(
                ocsps=ocsps, other_certs=certs, **validation_context_kwargs
            )

        # shallow-copy the VRI dictionary
        try:
            vri_entries = dict(dss_dict['/VRI'])
        except KeyError:
            vri_entries = None

        # if the handler is a writer, the DSS will support updates
        if isinstance(handler, IncrementalPdfFileWriter):
            writer = handler
            writer.mark_update(dss_ref)
        else:
            writer = None

        # the DSS returned will be backed by the original DSS object, so CRLs
        # are automagically preserved if they happened to be included in
        # the original file
        return cls(
            writer=writer, validation_context=validation_context,
            certs=cert_refs, unindexed_ocsps=ocsp_refs, vri_entries=vri_entries,
            backing_pdf_object=dss_dict
        )

    @classmethod
    def add_dss(cls, output_stream, contents_hex_data, certs,
                validation_context):
        output_stream.seek(0)
        # TODO is it actually necessary to create a separate stream here?
        #  and if so, can we somehow do this in a way that doesn't require the
        #  data to be copied around, provided the output_stream is BytesIO
        #  already?
        writer = IncrementalPdfFileWriter(BytesIO(output_stream.read()))

        dss = cls.read_dss(writer, validation_context=validation_context)
        created = False
        if dss is None:
            created = True
            dss = cls(writer=writer, validation_context=validation_context)

        identifier = DocumentSecurityStore.sig_content_identifier(
            contents_hex_data
        )

        dss.register_vri(identifier=identifier, signer_certs=certs)
        dss_dict = dss.as_pdf_object()
        # if we're updating the DSS, this is all we need to do.
        # if we're adding a fresh DSS, we need to register it.

        if created:
            dss_ref = writer.add_object(dss_dict)
            writer.root[pdf_name('/DSS')] = dss_ref
            writer.update_root()
        output_stream.seek(0, os.SEEK_END)
        writer.write(output_stream)
