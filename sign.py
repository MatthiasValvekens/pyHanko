import codecs
import hashlib
import logging
from datetime import datetime
from dataclasses import dataclass
from io import BytesIO
from typing import List

import pytz
from PyPDF2 import generic
from asn1crypto import cms, x509, algos, core, keys
from oscrypto import asymmetric, keys as oskeys

from pdf_utils.incremental_writer import IncrementalPdfFileWriter

pdf_name = generic.NameObject
pdf_string = generic.createStringObject

logger = logging.getLogger(__name__)


def pdf_utf16be_string(s):
    return pdf_string(codecs.BOM_UTF16_BE + s.encode('utf-16be'))


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
        self.writeToStream(stream, None)

        stream.seek(old_seek)

    # noinspection PyPep8Naming, PyUnusedLocal
    def writeToStream(self, stream, encryption_key):
        if self._range_object_offset is None:
            self._range_object_offset = stream.tell()
        string_repr = "[ %08d %08d %08d %08d ]" % (
            0, self.first_region_len,
            self.second_region_offset, self.second_region_len,
        )
        stream.write(string_repr.encode('ascii'))


class PKCS7Placeholder(generic.PdfObject):

    # FIXME I have no idea what a reasonable size would be
    #  Write a "fake" signature first?
    def __init__(self, bytes_reserved=8192):
        self._placeholder = True
        self.value = b'0' * bytes_reserved
        self._offsets = None

    def fill_signature(self):
        self._placeholder = False
        # TODO implement

    @property
    def offsets(self):
        if self._offsets is None:
            raise ValueError('No offsets available')
        return self._offsets

    @property
    def original_bytes(self):
        return self.value

    # always ignore encryption key
    # (I think this is correct, but testing is required)
    # noinspection PyPep8Naming, PyUnusedLocal
    def writeToStream(self, stream, encryption_key):
        start = stream.tell()
        stream.write(b'<')
        stream.write(self.value)
        stream.write(b'>')
        end = stream.tell()
        if self._offsets is None:
            self._offsets = start, end


# simple PDF signature with two digested regions
# (pre- and post content)
class SignatureObject(generic.DictionaryObject):
    # TODO handle date encoding here as well
    def __init__(self, name, location, reason, date_string):
        # initialise signature object
        super().__init__(
            {
                pdf_name('/Type'): pdf_name('/Sig'),
                pdf_name('/Filter'): pdf_name('/Adobe.PPKLite'),
                pdf_name('/SubFilter'): pdf_name('/adbe.pkcs7.detached'),
                pdf_name('/Name'): pdf_string(name),
                pdf_name('/Location'): pdf_string(location),
                pdf_name('/Reason'): pdf_string(reason),
                pdf_name('/M'): pdf_string(date_string),
            }
        )
        # initialise placeholders for /Contents and /ByteRange
        pkcs7 = PKCS7Placeholder()
        self[pdf_name('/Contents')] = self.signature_contents = pkcs7
        byte_range = SigByteRangeObject()
        self[pdf_name('/ByteRange')] = self.byte_range = byte_range


class SignatureFormField(generic.DictionaryObject):
    def __init__(self, field_name, sig_object_ref, include_on_page):
        super().__init__({
            # Signature field properties
            pdf_name('/FT'): pdf_name('/Sig'),
            pdf_name('/T'): pdf_utf16be_string(field_name),
            pdf_name('/V'): sig_object_ref,
            # Annotation properties: bare minimum
            pdf_name('/Type'): pdf_name('/Annot'),
            pdf_name('/Subtype'): pdf_name('/Widget'),
            # this sets the "Locked" and "Print" bits
            pdf_name('/F'): generic.NumberObject(0b10000100),
            pdf_name('/P'): include_on_page,
            pdf_name('/Rect'): generic.ArrayObject(
                [generic.FloatObject(0.0)] * 4
            )
        })


def simple_cms_attribute(attr_type, value):
    return cms.CMSAttribute({
        'type': cms.CMSAttributeType(attr_type),
        'values': (value,)
    })


@dataclass(frozen=True)
class Signer:
    signing_cert: x509.Certificate
    ca_chain: List[x509.Certificate]
    signing_key: keys.PrivateKeyInfo
    validity_window: (datetime, datetime)

    def sign(self, data_digest: bytes, digest_algorithm: str) -> bytes:

        # Implementation loosely based on similar functionality in
        # https://github.com/m32/endesive/.

        digest_algorithm_obj = algos.DigestAlgorithm(
            {'algorithm': digest_algorithm}
        )

        timestamp = datetime.utcnow().replace(tzinfo=pytz.utc)
        signed_attrs = cms.CMSAttributes([
            simple_cms_attribute('content_type', 'data'),
            simple_cms_attribute('message_digest', data_digest),
            # TODO support using timestamping servers
            # TODO enforce consistency with the value set in the signature field
            # TODO doesn't the PDF mandate that signing_time should be
            #  an unauthenticated attribute if present? This is how JSignPDF
            #  does it, though
            simple_cms_attribute(
                'signing_time', cms.Time({'utc_time': core.UTCTime(timestamp)})
            )
            # TODO support adding Adobe-style revocation information
        ])

        # the piece of data we'll actually sign is a DER-encoded version of the
        # signed attributes of our message
        signature = asymmetric.rsa_pkcs1v15_sign(
            asymmetric.load_private_key(self.signing_key),
            signed_attrs.dump(),
            digest_algorithm.lower()
        )

        # build the signer info object that goes into the PKCS7 signature
        # (see RFC 2315 § 9.2)
        signer_info = cms.SignerInfo({
            'version': 'v1',
            'sid': cms.SignerIdentifier({
                'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                    'issuer': self.signing_cert.issuer,
                    'serial_number': self.signing_cert.serial_number,
                })
            }),
            'digest_algorithm': digest_algorithm_obj,
            # TODO implement PSS & HSM support (PKCS11 devices)
            'signature_algorithm': algos.SignedDigestAlgorithm(
                {'algorithm': 'rsassa_pkcs1v15'}
            ),
            'signed_attrs': signed_attrs,
            'signature': signature
        })

        # this is the SignedData object for our message (see RFC 2315 § 9.1)
        signed_data = {
            'version': 'v1',
            'digest_algorithms': cms.DigestAlgorithms((digest_algorithm_obj,)),
            'encap_content_info': {'content_type': 'data'},
            'certificates': [self.signing_cert] + self.ca_chain,
            'signer_infos': [signer_info]
        }

        # time to pack up
        message = cms.ContentInfo({
            'content_type': cms.ContentType('signed_data'),
            'content': cms.SignedData(signed_data)
        })

        return message.dump()

    @classmethod
    def load(cls, key_file, cert_file, key_passphrase=None):
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
        except (IOError, ValueError) as e:
            logger.error('Could not load cryptographic material', e)
            return None
        valid_from = signing_cert.not_valid_before
        valid_until = signing_cert.not_valid_after

        return Signer(
            signing_cert=signing_cert, signing_key=signing_key,
            validity_window=(valid_from, valid_until),
            ca_chain=[]  # TODO implement this
        )


@dataclass(frozen=True)
class PdfSignatureMetadata:
    name: str
    location: str
    reason: str
    date_string: str
    field_name: str
    sig_flags: int = 3


def sign_pdf(input_handle, signature_meta: PdfSignatureMetadata, signer: Signer,
             md_algorithm='sha1'):
    pdf_out = IncrementalPdfFileWriter(input_handle)
    root = pdf_out._root_object

    # we need to add a signature object and a corresponding form field
    # to the PDF file
    sig_obj = SignatureObject(
        signature_meta.name, signature_meta.location,
        signature_meta.reason, signature_meta.date_string
    )
    sig_obj_ref = pdf_out.add_object(sig_obj)
    form_field = SignatureFormField(
        signature_meta.field_name, sig_obj_ref,
        include_on_page=root['/Pages']['/Kids'][0]
    )
    form_field_ref = pdf_out.add_object(form_field)

    # TODO support certification signatures (more metadata)
    # TODO extend /AcroForm if already present
    #  (this is necessary for multiple signatures anyway)
    form = generic.DictionaryObject(
        {
            pdf_name('/Fields'): generic.ArrayObject([form_field_ref]),
            pdf_name('/SigFlags'): generic.NumberObject(
                signature_meta.sig_flags
            )
        }
    )
    root[pdf_name('/AcroForm')] = pdf_out.add_object(form)
    pdf_out.update_root()

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
    # TODO support for non-default md algorithms
    md = getattr(hashlib, md_algorithm)()
    # these are memoryviews, so slices should not copy stuff around
    md.update(output_buffer[:sig_start])
    md.update(output_buffer[sig_end:])
    output_buffer.release()

    signature = signer.sign(md.digest(), md_algorithm).hex().encode('ascii')

    # +1 to skip the '<'
    output.seek(sig_start + 1)
    output.write(signature)

    output.seek(0)
    return output


def sign_pdf_file(infile_name, outfile_name, signature_meta: PdfSignatureMetadata,
                  key_file, cert_file, key_passphrase):
    signer = Signer.load(
        cert_file=cert_file, key_file=key_file, key_passphrase=key_passphrase
    )
    with open(infile_name, 'rb') as infile:
        result = sign_pdf(infile, signature_meta, signer)
    with open(outfile_name, 'wb') as outfile:
        buf = result.getbuffer()
        outfile.write(buf)
        buf.release()
