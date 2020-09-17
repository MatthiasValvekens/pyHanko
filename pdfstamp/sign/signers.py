import binascii
import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime
from enum import IntFlag
from io import BytesIO

import tzlocal
from asn1crypto import x509, cms, core, algos, pem, keys, pdf as asn1_pdf
from certvalidator import ValidationContext
from certvalidator.path import ValidationPath
from oscrypto import asymmetric, keys as oskeys

from pdf_utils import generic
from pdf_utils.generic import pdf_name, pdf_date, pdf_string
from pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pdfstamp.sign import general
from pdfstamp.sign.fields import enumerate_sig_fields, _prepare_sig_field
from pdfstamp.sign.timestamps import TimeStamper
from pdfstamp.sign.general import (
    simple_cms_attribute, CertificateStore,
    SimpleCertificateStore,
)
from pdfstamp.stamp import TextStampStyle, TextStamp

__all__ = ['Signer', 'SimpleSigner', 'sign_pdf', 'DocMDPPerm',
           'SignatureObject']


class SigByteRangeObject(generic.PdfObject):

    def __init__(self):
        self._filled = False
        self._range_object_offset = None
        self.first_region_len = 0
        self.second_region_offset = 0
        self.second_region_len = 0

    def fill_offsets(self, stream, sig_start, sig_end, eof):
        if self._filled:
            raise ValueError('Offsets already filled')
        if self._range_object_offset is None:
            raise ValueError(
                'Could not determine where to write /ByteRange value'
            )

        old_seek = stream.tell()
        self.first_region_len = sig_start
        self.second_region_offset = sig_end
        self.second_region_len = eof - sig_end
        # our ArrayObject is rigged to have fixed width
        # so we can just write over it

        stream.seek(self._range_object_offset)
        self.write_to_stream(stream, None)

        stream.seek(old_seek)

    def write_to_stream(self, stream, encryption_key):
        if self._range_object_offset is None:
            self._range_object_offset = stream.tell()
        string_repr = "[ %08d %08d %08d %08d ]" % (
            0, self.first_region_len,
            self.second_region_offset, self.second_region_len,
        )
        stream.write(string_repr.encode('ascii'))


class PKCS7Placeholder(generic.PdfObject):

    def __init__(self, bytes_reserved=None):
        self._placeholder = True
        self.value = b'0' * (bytes_reserved or 8192)
        self._offsets = None

    @property
    def offsets(self):
        if self._offsets is None:
            raise ValueError('No offsets available')
        return self._offsets

    @property
    def original_bytes(self):
        return self.value

    # always ignore encryption key, since this is a placeholder
    def write_to_stream(self, stream, encryption_key):
        start = stream.tell()
        stream.write(b'<')
        stream.write(self.value)
        stream.write(b'>')
        end = stream.tell()
        if self._offsets is None:
            self._offsets = start, end


class SignatureObject(generic.DictionaryObject):

    def __init__(self, timestamp: datetime, name=None, location=None,
                 reason=None, bytes_reserved=None, use_pades=False):
        # initialise signature object
        subfilter = (
            '/ETSI.CAdES.detached' if use_pades else '/adbe.pkcs7.detached'
        )
        super().__init__(
            {
                pdf_name('/Type'): pdf_name('/Sig'),
                pdf_name('/Filter'): pdf_name('/Adobe.PPKLite'),
                pdf_name('/SubFilter'): pdf_name(subfilter),
                pdf_name('/M'): pdf_date(timestamp)
            }
        )

        if name:
            self[pdf_name('/Name')] = pdf_string(name),
        if location:
            self[pdf_name('/Location')] = pdf_string(location),
        if reason:
            self[pdf_name('/Reason')] = pdf_string(reason),

        # initialise placeholders for /Contents and /ByteRange
        pkcs7 = PKCS7Placeholder(bytes_reserved=bytes_reserved)
        self[pdf_name('/Contents')] = self.signature_contents = pkcs7
        byte_range = SigByteRangeObject()
        self[pdf_name('/ByteRange')] = self.byte_range = byte_range


class Signer:
    signing_cert: x509.Certificate
    cert_registry: CertificateStore
    pkcs7_signature_mechanism: str
    timestamper: TimeStamper = None

    def sign_raw(self, data: bytes, digest_algorithm: str, dry_run=False):
        raise NotImplementedError

    @property
    def subject_name(self):
        name: x509.Name = self.signing_cert.subject
        result = name.native['common_name']
        try:
            email = name.native['email_address']
            result = '%s <%s>' % (result, email)
        except KeyError:
            pass
        return result

    @staticmethod
    def format_revinfo(ocsp_responses: list = None, crls: list = None):

        revinfo_dict = {}
        if ocsp_responses:
            revinfo_dict['ocsp'] = ocsp_responses

        if crls:
            revinfo_dict['crl'] = crls

        if revinfo_dict:
            revinfo = asn1_pdf.RevocationInfoArchival(revinfo_dict)
            return simple_cms_attribute(
                'adobe_revocation_info_archival', revinfo
            )

        return None

    def signed_attrs(self, data_digest: bytes, timestamp: datetime = None,
                     revocation_info=None, use_pades=False):
        attrs = [
            simple_cms_attribute('content_type', 'data'),
            simple_cms_attribute('message_digest', data_digest),
            # required by PAdES
            simple_cms_attribute(
                'signing_certificate',
                general.as_signing_certificate(self.signing_cert)
            )
        ]

        # the following attributes are only meaningful in non-PAdES signatures
        #  (i.e. old school PKCS7 with Adobe-style revocation info)
        if not use_pades:
            if timestamp is not None:
                # NOTE: PAdES actually forbids this!
                st = simple_cms_attribute(
                    'signing_time',
                    cms.Time({'utc_time': core.UTCTime(timestamp)})
                )
                attrs.append(st)

            # this is not allowed under PAdES, should use DSS instead
            if revocation_info:
                attrs.append(revocation_info)

        return cms.CMSAttributes(attrs)

    def signer_info(self, digest_algorithm: str, signed_attrs, signature):
        digest_algorithm_obj = algos.DigestAlgorithm(
            {'algorithm': digest_algorithm}
        )

        signing_cert = self.signing_cert
        # build the signer info object that goes into the PKCS7 signature
        # (see RFC 2315 § 9.2)
        sig_info = cms.SignerInfo({
            'version': 'v1',
            'sid': cms.SignerIdentifier({
                'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                    'issuer': signing_cert.issuer,
                    'serial_number': signing_cert.serial_number,
                })
            }),
            'digest_algorithm': digest_algorithm_obj,
            # TODO implement PSS support
            'signature_algorithm': algos.SignedDigestAlgorithm(
                {'algorithm': self.pkcs7_signature_mechanism}
            ),
            'signed_attrs': signed_attrs,
            'signature': signature
        })
        return sig_info

    def sign(self, data_digest: bytes, digest_algorithm: str,
             timestamp: datetime = None, dry_run=False,
             revocation_info=None, use_pades=False) -> bytes:

        # Implementation loosely based on similar functionality in
        # https://github.com/m32/endesive/.

        # the piece of data we'll actually sign is a DER-encoded version of the
        # signed attributes of our message
        signed_attrs = self.signed_attrs(
            data_digest, timestamp, revocation_info=revocation_info,
            use_pades=use_pades
        )
        signature = self.sign_raw(
            signed_attrs.dump(), digest_algorithm.lower(), dry_run
        )

        sig_info = self.signer_info(digest_algorithm, signed_attrs, signature)

        if self.timestamper is not None:
            # the timestamp server needs to cross-sign our signature
            md = getattr(hashlib, digest_algorithm)()
            md.update(signature)
            ts_token = self.timestamper.timestamp(md.digest(), digest_algorithm)
            sig_info['unsigned_attrs'] = cms.CMSAttributes([ts_token])
            ts_certs = ts_token['values'][0]['content']['certificates']
            # TODO add these to DSS
            for c in ts_certs:
                self.cert_registry.register(c.chosen)

        digest_algorithm_obj = algos.DigestAlgorithm(
            {'algorithm': digest_algorithm}
        )
        certs = set(self.cert_registry)
        certs.add(self.signing_cert)
        # this is the SignedData object for our message (see RFC 2315 § 9.1)
        signed_data = {
            'version': 'v1',
            'digest_algorithms': cms.DigestAlgorithms((digest_algorithm_obj,)),
            'encap_content_info': {'content_type': 'data'},
            'certificates': certs,
            'signer_infos': [sig_info]
        }

        # time to pack up
        message = cms.ContentInfo({
            'content_type': cms.ContentType('signed_data'),
            'content': cms.SignedData(signed_data)
        })

        return message.dump()


class DocMDPPerm(IntFlag):
    """
    Cf. Table 254  in ISO 32000
    """

    NO_CHANGES = 0
    FILL_FORMS = 2
    ANNOTATE = 3


@dataclass(frozen=True)
class PdfSignatureMetadata:
    field_name: str = None
    md_algorithm: str = 'sha512'
    location: str = None
    reason: str = None
    name: str = None
    certify: bool = False

    use_pades: bool = False
    embed_revocation_info: bool = False
    validation_context: ValidationContext = None
    # PAdES compliance disallows this in favour of more robust timestamping
    # strategies
    include_signedtime_attr: bool = True
    # only relevant for certification
    docmdp_permissions: DocMDPPerm = DocMDPPerm.FILL_FORMS


logger = logging.getLogger(__name__)


# FIXME this function should really be called "load_certs_from_pemder" or sth.

def load_ca_chain(ca_chain_files):
    for ca_chain_file in ca_chain_files:
        with open(ca_chain_file, 'rb') as f:
            ca_chain_bytes = f.read()
        # use the pattern from the asn1crypto docs
        # to distinguish PEM/DER and read multiple certs
        # from one PEM file (if necessary)
        if pem.detect(ca_chain_bytes):
            pems = pem.unarmor(ca_chain_bytes, multiple=True)
            for type_name, _, der in pems:
                if type_name is None or type_name.lower() == 'certificate':
                    yield x509.Certificate.load(der)
                else:  # pragma: nocover
                    logger.debug(
                        f'Skipping PEM block of type {type_name} in '
                        f'{ca_chain_file}.'
                    )
        else:
            # no need to unarmor, just try to load it immediately
            yield x509.Certificate.load(ca_chain_bytes)


@dataclass
class SimpleSigner(Signer):
    signing_cert: x509.Certificate
    signing_key: keys.PrivateKeyInfo
    cert_registry: CertificateStore
    pkcs7_signature_mechanism: str = 'rsassa_pkcs1v15'
    timestamper: TimeStamper = None

    def sign_raw(self, data: bytes, digest_algorithm: str, dry_run=False):
        return asymmetric.rsa_pkcs1v15_sign(
            asymmetric.load_private_key(self.signing_key),
            data, digest_algorithm.lower()
        )

    @classmethod
    def _load_ca_chain(cls, ca_chain_files=None):
        try:
            return set(load_ca_chain(ca_chain_files))
        except (IOError, ValueError) as e:  # pragma: nocover
            logger.error('Could not load CA chain', e)
            return None

    @classmethod
    def load_pkcs12(cls, pfx_file, ca_chain_files=None, passphrase=None):
        # TODO support MAC integrity checking?

        try:
            with open(pfx_file, 'rb') as f:
                pfx_bytes = f.read()
        except IOError as e:  # pragma: nocover
            logger.error(f'Could not open PKCS#12 file {pfx_file}.', e)
            return None

        ca_chain = cls._load_ca_chain(ca_chain_files) if ca_chain_files else []
        if ca_chain is None:  # pragma: nocover
            return None

        (kinfo, cert, other_certs) = oskeys.parse_pkcs12(pfx_bytes, passphrase)
        return SimpleSigner(
            signing_key=kinfo, signing_cert=cert,
            cert_registry=SimpleCertificateStore(certs=ca_chain + other_certs)
        )

    @classmethod
    def load(cls, key_file, cert_file, ca_chain_files=None,
             key_passphrase=None, other_certs=None):
        try:
            # load cryptographic data (both PEM and DER are supported)
            with open(key_file, 'rb') as f:
                signing_key: keys.PrivateKeyInfo = oskeys.parse_private(
                    f.read(), password=key_passphrase
                )
            with open(cert_file, 'rb') as f:
                signing_cert: x509.Certificate = oskeys.parse_certificate(
                    f.read()
                )
        except (IOError, ValueError) as e:  # pragma: nocover
            logger.error('Could not load cryptographic material', e)
            return None

        ca_chain = cls._load_ca_chain(ca_chain_files) if ca_chain_files else []
        if ca_chain is None:  # pragma: nocover
            return None

        other_certs = ca_chain if other_certs is None \
            else ca_chain + other_certs

        cert_reg = SimpleCertificateStore(certs=other_certs)
        return SimpleSigner(
            signing_cert=signing_cert, signing_key=signing_key,
            cert_registry=cert_reg
        )


def _certification_setup(writer: IncrementalPdfFileWriter,
                         sig_obj_ref, md_algorithm, permission_level):
    """
    Cf. Tables 252, 253 and 254 in ISO 32000
    """
    transform_params = generic.DictionaryObject({
        pdf_name('/Type'): pdf_name('/TransformParams'),
        pdf_name('/V'): pdf_name('/1.2'),
        pdf_name('/P'): generic.NumberObject(permission_level)
    })
    tp_ref = writer.add_object(transform_params)

    # not to be confused with our indirect reference *to* the signature object--
    # this is part of the /Reference entry of the signature object.
    sigref_object = generic.DictionaryObject({
        pdf_name('/Type'): pdf_name('/SigRef'),
        pdf_name('/TransformMethod'): pdf_name('/DocMDP'),
        pdf_name('/DigestMethod'): pdf_name('/' + md_algorithm.upper()),
        pdf_name('/TransformParams'): tp_ref
    })

    # after preparing the sigref object, insert it into the actual signature
    # object under /Reference (for some reason this is supposed to be an array)
    sigref_list = generic.ArrayObject([writer.add_object(sigref_object)])
    sig_obj_ref.get_object()[pdf_name('/Reference')] = sigref_list

    # finally, register a /DocMDP permission entry in the document catalog
    root = writer.root
    # the usual song and dance to grab a reference to /Perms, or create it
    # TODO I've done this enough times to factor it out, I suppose
    try:
        perms_ref = root.raw_get('/Perms')
        if isinstance(perms_ref, generic.IndirectObject):
            perms = perms_ref.get_object()
            writer.mark_update(perms_ref)
        else:
            perms = perms_ref
            writer.update_root()
    except KeyError:
        root[pdf_name('/Perms')] = perms = generic.DictionaryObject()
        writer.update_root()
    perms[pdf_name('/DocMDP')] = sig_obj_ref


SIG_DETAILS_DEFAULT_TEMPLATE = (
    'Digitally signed by %(signer)s.\n'
    'Timestamp: %(ts)s.'
)


def sign_pdf(pdf_out: IncrementalPdfFileWriter,
             signature_meta: PdfSignatureMetadata, signer: Signer,
             existing_fields_only=False, bytes_reserved=None):

    # TODO generate an error when DocMDP doesn't allow extra signatures.

    # TODO how hard is it to get CAdES/PAdES compliance?
    #  I think I just need DSS support with OCSPs etc. to get PAdES B-LT
    #   (i.e. level 3) compliance.

    # TODO explicitly disallow multiple certification signatures

    # TODO force md_algorithm to agree with the certification signature
    #  if present

    # TODO deal with SV dictionaries properly

    # TODO this function is becoming rather bloated, should refactor
    #  into a class for more fine-grained control

    root = pdf_out.root

    timestamp = datetime.now(tz=tzlocal.get_localzone())
    cert = signer.signing_cert
    # FIXME there seems to be an issue with the OCSP checking here. Either the
    #  BEID OCSP responder is noncompliant, or there is a dt rounding bug in
    #  the certvalidator library.

    validation_context = signature_meta.validation_context
    if signature_meta.embed_revocation_info and validation_context is None:
        raise ValueError(
            'A validation context must be provided if validation/revocation '
            'info is to be embedded into the signature.'
        )
    if validation_context is not None:
        # add the certs from the signer's certificate store to the registry
        # in the validation context
        for cert in signer.cert_registry:
            validation_context.certificate_registry.add_other_cert(cert)

        paths = validation_context.certificate_registry.build_paths(cert)
        if not paths:
            raise ValueError(
                'Could not build path from signing cert to trust roots'
            )
        path: ValidationPath = paths[0]
        if cert.ocsp_urls and signature_meta.embed_revocation_info:
            validation_context.retrieve_ocsps(cert, path.find_issuer(cert))

    # do we need adobe-style revocation info?
    if signature_meta.embed_revocation_info and not signature_meta.use_pades:
        # we don't do CRLs for now, embedding those is usually a bad idea anyhow
        revinfo = Signer.format_revinfo(
            ocsp_responses=validation_context.ocsps, crls=[]
        )
    else:
        revinfo = None

    if bytes_reserved is None:
        test_md = getattr(hashlib, signature_meta.md_algorithm)().digest()
        # PAdES prescribes another mechanism for embedding revocation info
        test_signature = signer.sign(
            test_md, signature_meta.md_algorithm,
            timestamp=timestamp, use_pades=signature_meta.use_pades,
            dry_run=True, revocation_info=revinfo
        ).hex().encode('ascii')
        # External actors such as timestamping servers can't be relied on to
        # always return exactly the same response, so we build in a 50% error
        # margin (+ ensure that bytes_reserved is even)
        test_len = len(test_signature)
        bytes_reserved = test_len + 2 * (test_len // 4)

    name = signature_meta.name
    if name is None:
        name = signer.subject_name
    # we need to add a signature object and a corresponding form field
    # to the PDF file
    # Here, we pass in the name as specified in the signature metadata.
    # When it's None, the reader will/should derive it from the contents
    # of the certificate.
    sig_obj = SignatureObject(
        timestamp, name=signature_meta.name, location=signature_meta.location,
        reason=signature_meta.reason, bytes_reserved=bytes_reserved,
        use_pades=signature_meta.use_pades
    )
    sig_obj_ref = pdf_out.add_object(sig_obj)

    if signature_meta.field_name is None:
        if not existing_fields_only:
            raise ValueError('Not specifying a signature field name is only '
                             'allowed when existing_fields_only=True')

        # most of the logic in _prepare_sig_field has to do with preparing
        # for the potential addition of a new field. That is completely
        # irrelevant in this special case, so we might as well short circuit
        # things.
        field_created = False
        empty_fields = enumerate_sig_fields(pdf_out.prev, filled_status=False)
        try:
            field_name, _, sig_field_ref = next(empty_fields)
        except StopIteration:
            raise ValueError('There are no empty signature fields.')

        others = ', '.join(fn for fn, _, _ in empty_fields if fn is not None)
        if others:
            raise ValueError(
                'There are several empty signature fields. Please specify '
                'a field name. The options are %s, %s.' % (
                    field_name, others
                )
            )
    else:
        # grab or create a sig field
        field_created, sig_field_ref = _prepare_sig_field(
            signature_meta.field_name, root, update_writer=pdf_out,
            existing_fields_only=existing_fields_only, lock_sig_flags=True
        )
    sig_field = sig_field_ref.get_object()
    # fill in a reference to the (empty) signature object
    sig_field[pdf_name('/V')] = sig_obj_ref

    if not field_created:
        # still need to mark it for updating
        pdf_out.mark_update(sig_field_ref)

    x1, y1, x2, y2 = sig_field[pdf_name('/Rect')]
    w = abs(x1 - x2)
    h = abs(y1 - y2)
    if w and h:
        # the field is probably a visible one, so we change its appearance
        # stream to show some data about the signature
        # TODO allow customisation
        tss = TextStampStyle(
            stamp_text=SIG_DETAILS_DEFAULT_TEMPLATE,
            fixed_aspect_ratio=float(w/h)
        )
        text_params = {
            'signer': name, 'ts': timestamp.strftime(tss.timestamp_format)
        }
        stamp = TextStamp(pdf_out, tss, text_params=text_params)
        sig_field[pdf_name('/AP')] = stamp.as_appearances().as_pdf_object()
        try:
            # if there was an entry like this, it's meaningless now
            del sig_field[pdf_name('/AS')]
        except KeyError:
            pass

    if signature_meta.certify:
        _certification_setup(
            pdf_out, sig_obj_ref, signature_meta.md_algorithm,
            signature_meta.docmdp_permissions
        )

    # Render the PDF to a byte buffer with placeholder values
    # for the signature data
    output = BytesIO()
    pdf_out.write(output)

    # retcon time: write the proper values of the /ByteRange entry
    #  in the signature object
    eof = output.tell()
    sig_start, sig_end = sig_obj.signature_contents.offsets
    sig_obj.byte_range.fill_offsets(output, sig_start, sig_end, eof)

    # compute the digests
    output_buffer = output.getbuffer()
    md = getattr(hashlib, signature_meta.md_algorithm)()
    # these are memoryviews, so slices should not copy stuff around
    md.update(output_buffer[:sig_start])
    md.update(output_buffer[sig_end:])
    output_buffer.release()

    signature_bytes = signer.sign(
        md.digest(), signature_meta.md_algorithm,
        timestamp=timestamp, use_pades=signature_meta.use_pades,
        revocation_info=revinfo
    )
    signature = binascii.hexlify(signature_bytes)
    # NOTE: the PDF spec is not completely clear on this, but
    # signature contents are NOT supposed to be encrypted.
    # Perhaps this falls under the "strings in encrypted containers"
    # denominator in § 7.6.1?
    assert len(signature) <= bytes_reserved, (len(signature), bytes_reserved)

    # +1 to skip the '<'
    output.seek(sig_start + 1)
    output.write(signature)

    output.seek(0)
    return output
