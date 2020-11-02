import hashlib
import os
import logging
from dataclasses import dataclass, field as data_field
from datetime import datetime
from enum import Enum, auto
from io import BytesIO
from typing import TypeVar, Type, Optional

from asn1crypto import (
    cms, tsp, ocsp as asn1_ocsp, pdf as asn1_pdf, crl as asn1_crl
)
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
    # signed_attrs comes with some context-specific tagging
    # because it's an implicit field. This breaks validation
    signed_attrs = signer_info['signed_attrs'].untag()

    # TODO What to do if signed_attrs is absent?
    # I guess I'll wait until someone complains that a valid signature
    # isn't being validated correctly
    if raw_digest is None:
        # this means that there should be encapsulated data
        # TODO Carefully read § 5.2.1 in RFC 5652, and compare with
        #  the implementation in asn1crypto.
        raw = signed_data['encap_content_info']['content'].parsed.dump()
        raw_digest = getattr(hashlib, md_algorithm)(raw).digest()

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


class EmbeddedPdfSignature:

    def __init__(self, reader: PdfFileReader, sig_object):
        self.reader = reader

        if isinstance(sig_object, generic.IndirectObject):
            sig_object = sig_object.get_object()
        self.sig_object = sig_object
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
            pkcs7_content.get_container_ref()

        message = cms.ContentInfo.load(pkcs7_content)
        signed_data = message['content']
        self.signed_data: cms.SignedData = signed_data
        sd_digest = signed_data['digest_algorithms'][0]
        md_algorithm = sd_digest['algorithm'].native.lower()
        md = getattr(hashlib, md_algorithm)()
        stream = reader.stream

        # compute the digest
        old_seek = stream.tell()
        total_len = 0
        covered_regions = []
        for lo, chunk_len in misc.pair_iter(byte_range):
            covered_regions.append((lo, chunk_len))
            stream.seek(lo)
            md.update(stream.read(chunk_len))
            total_len += chunk_len

        self.covered_regions = covered_regions

        # compute file size
        stream.seek(0, os.SEEK_END)
        # the * 2 is because of the ASCII hex encoding, and the + 2
        # is the wrapping <>
        embedded_sig_content = len(pkcs7_content) * 2 + 2
        # TODO this ignores PAdES-LTA rules about document timestamps
        self.complete_document = (
            stream.tell() == total_len + embedded_sig_content
        )
        stream.seek(old_seek)

        self.raw_digest = md.digest()

        try:
            self.signer_info, = signed_data['signer_infos']
        except ValueError:
            raise ValueError('signer_infos should contain exactly one entry')

    @property
    def self_reported_signed_timestamp(self) -> datetime:
        try:
            sa = self.signer_info['signed_attrs']
            st = find_cms_attribute(sa, 'signed_time')[0]
            return st.native
        except KeyError:
            pass

    @property
    def external_timestamp_data(self) -> cms.SignedData:
        try:
            ua = self.signer_info['unsigned_attrs']
            tst = find_cms_attribute(ua, 'signature_time_stamp_token')[0]
            tst_signed_data = tst['content']
            return tst_signed_data
        except KeyError:
            pass


def validate_pdf_signature(reader: PdfFileReader, sig_object,
                           signer_validation_context: ValidationContext = None,
                           ts_validation_context: ValidationContext = None) \
                           -> PDFSignatureStatus:
    if sig_object is None:
        raise ValueError('Signature is empty')
    if ts_validation_context is None:
        ts_validation_context = signer_validation_context

    embedded_sig = EmbeddedPdfSignature(reader, sig_object)

    # TODO implement logic to detect whether
    #  the modifications made are permissible

    # TODO validate /SV constraints if present!

    status_kwargs = {'complete_document': embedded_sig.complete_document}

    # try to find an embedded timestamp
    signed_dt = embedded_sig.self_reported_signed_timestamp
    if signed_dt is not None:
        status_kwargs['signed_dt'] = signed_dt

    # if we managed to find an (externally) signed timestamp,
    # we now proceed to validate it
    tst_signed_data = embedded_sig.external_timestamp_data
    # TODO compare value of embedded timestamp token with the timestamp
    #  attribute if both are present
    if tst_signed_data is not None:
        tst_info = tst_signed_data['encap_content_info']['content'].parsed
        assert isinstance(tst_info, tsp.TSTInfo)
        timestamp = tst_info['gen_time'].native
        status_kwargs['timestamp_validity'] = validate_cms_signature(
            tst_signed_data, status_cls=TimestampSignatureStatus,
            validation_context=ts_validation_context,
            status_kwargs={'timestamp': timestamp}
        )

    return validate_cms_signature(
        embedded_sig.signed_data, status_cls=PDFSignatureStatus,
        raw_digest=embedded_sig.raw_digest,
        validation_context=signer_validation_context,
        status_kwargs=status_kwargs
    )


class RevocationInfoValidationType(Enum):
    ADOBE_STYLE = auto()
    PADES_LT = auto()
    # TODO add support for PAdES-LTA verification
    #  (i.e. timestamp chain verification)
    # PADES_LTA = auto()


# TODO verify formal PAdES requirements for timestamps
# TODO verify other formal PAdES requirements (coverage, etc.)
def validate_pdf_ltv_signature(reader: PdfFileReader, sig_object,
                               validation_type: RevocationInfoValidationType,
                               validation_context_kwargs=None):
    validation_context_kwargs = validation_context_kwargs or {}
    validation_context_kwargs['allow_fetching'] = False
    # certs with OCSP/CRL endpoints should have the relevant revocation data
    # embedded.
    validation_context_kwargs['revocation_mode'] = "hard-fail"

    if sig_object is None:
        raise ValueError('Signature is empty')

    embedded_sig = EmbeddedPdfSignature(reader, sig_object)
    tst_signed_data = embedded_sig.external_timestamp_data
    if tst_signed_data is None:
        raise ValueError('LTV signatures require a trusted timestamp.')
    tst_info = tst_signed_data['encap_content_info']['content'].parsed
    assert isinstance(tst_info, tsp.TSTInfo)
    timestamp = tst_info['gen_time'].native
    validation_context_kwargs['moment'] = timestamp

    if validation_type == RevocationInfoValidationType.ADOBE_STYLE:
        vc = read_adobe_revocation_info(
            embedded_sig.signer_info,
            validation_context_kwargs=validation_context_kwargs
        )
    else:
        dss, vc = DocumentSecurityStore.read_dss(
            reader, validation_context_kwargs=validation_context_kwargs
        )

    status_kwargs = {
        'complete_document': embedded_sig.complete_document,
        'signed_dt': timestamp,
        'timestamp_validity': validate_cms_signature(
            tst_signed_data, status_cls=TimestampSignatureStatus,
            validation_context=vc, status_kwargs={'timestamp': timestamp}
        )
    }

    return validate_cms_signature(
        embedded_sig.signed_data, status_cls=PDFSignatureStatus,
        raw_digest=embedded_sig.raw_digest,
        validation_context=vc, status_kwargs=status_kwargs
    )


def read_adobe_revocation_info(signer_info: cms.SignerInfo,
                               validation_context_kwargs=None) \
                               -> ValidationContext:
    validation_context_kwargs = validation_context_kwargs or {}
    try:
        revinfo: asn1_pdf.RevocationInfoArchival = find_cms_attribute(
            signer_info['signed_attrs'], "adobe_revocation_info_archival"
        )[0]
    except KeyError:
        raise ValueError("No revocation info found")
    ocsps = list(revinfo['ocsp'] or ())
    crls = list(revinfo['crl'] or ())
    return ValidationContext(
        ocsps=ocsps, crls=crls, **validation_context_kwargs
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
        permission_bits = DocMDPPerm(sig_ref['/TransformParams']['/P'])
    except KeyError:
        permission_bits = DocMDPPerm.FILL_FORMS

    return sig_dict, permission_bits


# TODO validate DocMDP compliance and PAdES compliance
#  There are some compatibility subtleties here: e.g. valid (!) cryptographic
#  data covered by DSS and/or DocumentTimeStamps should never trigger the DocMDP
#  policy.


@dataclass
class VRI:
    certs: set = data_field(default_factory=set)
    ocsps: set = data_field(default_factory=set)
    crls: set = data_field(default_factory=set)

    def __iadd__(self, other):
        self.certs.update(other.certs)
        self.crls.update(other.crls)
        self.ocsps.update(other.ocsps)
        return self

    def as_pdf_object(self):
        vri = generic.DictionaryObject({pdf_name('/Type'): pdf_name('/VRI')})
        if self.ocsps:
            vri[pdf_name('/OCSP')] = generic.ArrayObject(self.ocsps)
        if self.crls:
            vri[pdf_name('/CRL')] = generic.ArrayObject(self.crls)
        vri[pdf_name('/Cert')] = generic.ArrayObject(self.certs)
        return vri


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

    def __init__(self, writer, certs=None, ocsps=None, crls=None,
                 vri_entries=None, backing_pdf_object=None):
        self.vri_entries = vri_entries if vri_entries is not None else {}
        self.certs = certs if certs is not None else {}
        self.ocsps = ocsps if ocsps is not None else []
        self.crls = crls if crls is not None else []

        self.writer = writer
        self.backing_pdf_object = (
            backing_pdf_object if backing_pdf_object is not None
            else generic.DictionaryObject()
        )

        ocsps_seen = {}
        for ocsp_ref in self.ocsps:
            ocsp_bytes = ocsp_ref.get_object().data
            ocsps_seen[ocsp_bytes] = ocsp_ref
        self._ocsps_seen = ocsps_seen

        crls_seen = {}
        for crl_ref in self.crls:
            crl_bytes = crl_ref.get_object().data
            crls_seen[crl_bytes] = crl_ref
        self._crls_seen = crls_seen

    def _cms_objects_to_streams(self, objs, seen, dest):
        for obj in objs:
            obj_bytes = obj.dump()
            try:
                yield seen[obj_bytes]
            except KeyError:
                ref = self.writer.add_object(
                    generic.StreamObject(stream_data=obj_bytes)
                )
                seen[obj_bytes] = ref
                dest.append(ref)
                yield ref

    def _embed_certs_from_ocsp(self, ocsps):
        def extra_certs():
            for resp in ocsps:
                yield from enumerate_ocsp_certs(resp)

        return [self._embed_cert(cert_) for cert_ in extra_certs()]

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
    def sig_content_identifier(contents):
        ident = hashlib.sha1(contents).digest().hex().upper()
        return pdf_name('/' + ident)

    def register_vri(self, identifier, paths, validation_context):
        """
        Register validation information for a set of signing certificates
        associated with a particular signature.
        Typically, signer_certs has only one entry (i.e. the main signer),
        but if timestamps are embedded into the signature, more entries may be
        included to account for timestamping authorities etc.

        :param identifier:
            Identifier of the signature object (see `sig_content_identifier`)
        :param paths:
            Validation paths to add.
        :param validation_context:
            Validation context to source CRLs and OCSP responses from.
        """

        if self.writer is None:
            raise TypeError('This DSS does not support updates.')

        # embed any hardcoded ocsp responses and CRLs, if applicable
        ocsps = set(
            self._cms_objects_to_streams(
                validation_context.ocsps, self._ocsps_seen, self.ocsps
            )
        )
        crls = set(
            self._cms_objects_to_streams(
                validation_context.crls, self._crls_seen, self.crls
            )
        )
        path: ValidationPath
        # TODO while somewhat less common, CRL signing can also be delegated
        #  we should take that into account
        cert_refs = set(self._embed_certs_from_ocsp(validation_context.ocsps))
        for path in paths:
            for cert in path:
                cert_refs.add(self._embed_cert(cert))

        vri = VRI(certs=cert_refs, ocsps=ocsps, crls=crls)
        self.vri_entries[identifier] = self.writer.add_object(
            vri.as_pdf_object()
        )

    def as_pdf_object(self):
        pdf_dict = self.backing_pdf_object
        pdf_dict.update({
            pdf_name('/VRI'): generic.DictionaryObject(self.vri_entries),
            pdf_name('/Certs'): generic.ArrayObject(list(self.certs.values())),
        })

        if self.ocsps:
            pdf_dict[pdf_name('/OCSPs')] = generic.ArrayObject(self.ocsps)

        if self.crls:
            pdf_dict[pdf_name('/CRLs')] = generic.ArrayObject(self.crls)

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
            DSS, and a validation context.
        """
        # TODO remember where we're reading from for modification detection
        #  purposes
        try:
            dss_ref = handler.root.raw_get(pdf_name('/DSS'))
        except KeyError:
            raise ValueError("No DSS found")

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

        crl_refs = list(dss_dict.get('/CRLs', ()))
        crls = []
        for crl_ref in crl_refs:
            crl_stream: generic.StreamObject = crl_ref.get_object()
            crl = asn1_crl.CertificateList.load(crl_stream.data)
            crls.append(crl)

        if validation_context is None:
            certs += validation_context_kwargs.get('other_certs', [])
            validation_context = ValidationContext(
                crls=crls,
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
        dss = cls(
            writer=writer, certs=cert_refs, ocsps=ocsp_refs,
            vri_entries=vri_entries, crls=crl_refs, backing_pdf_object=dss_dict
        )
        return dss, validation_context

    @classmethod
    def add_dss(cls, output_stream, sig_contents, paths,
                validation_context):
        output_stream.seek(0)
        # TODO is it actually necessary to create a separate stream here?
        #  and if so, can we somehow do this in a way that doesn't require the
        #  data to be copied around, provided the output_stream is BytesIO
        #  already?
        writer = IncrementalPdfFileWriter(BytesIO(output_stream.read()))

        try:
            # we're not interested in this validation context
            dss, vc = cls.read_dss(writer)
            created = False
        except ValueError:
            # FIXME ValueError is way too general
            created = True
            dss = cls(writer=writer)

        identifier = DocumentSecurityStore.sig_content_identifier(sig_contents)

        dss.register_vri(identifier, paths, validation_context)
        dss_dict = dss.as_pdf_object()
        # if we're updating the DSS, this is all we need to do.
        # if we're adding a fresh DSS, we need to register it.

        if created:
            dss_ref = writer.add_object(dss_dict)
            writer.root[pdf_name('/DSS')] = dss_ref
            writer.update_root()
        output_stream.seek(0, os.SEEK_END)
        writer.write(output_stream)
