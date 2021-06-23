import binascii
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from io import BytesIO
from typing import Optional, Set, Union, IO

import tzlocal
from asn1crypto import x509, cms, core, algos, keys, pdf as asn1_pdf
from asn1crypto.algos import SignedDigestAlgorithm
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.ec import \
    EllipticCurvePrivateKey, ECDSA
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import pkcs12

from pyhanko.pdf_utils.misc import DEFAULT_CHUNK_SIZE
from pyhanko_certvalidator.errors import PathValidationError, PathBuildingError

from pyhanko_certvalidator import ValidationContext, CertificateValidator
from pyhanko.sign.ades.api import CAdESSignedAttrSpec

from pyhanko.pdf_utils import generic, misc, embed
from pyhanko.pdf_utils.generic import pdf_name, pdf_date, pdf_string
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.layout import BoxConstraints
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import BasePdfFileWriter
from pyhanko.sign import general
from pyhanko.sign.fields import (
    enumerate_sig_fields, _prepare_sig_field,
    SigSeedValueSpec, SigSeedValFlags, SigSeedSubFilter, MDPPerm, FieldMDPSpec,
    SigFieldSpec, SeedLockDocument, _ensure_sig_flags
)
from pyhanko.sign.timestamps import TimeStamper
from pyhanko.sign.general import (
    simple_cms_attribute, CertificateStore,
    SimpleCertificateStore, SigningError, optimal_pss_params,
    load_certs_from_pemder, load_cert_from_pemder,
    _process_pss_params, load_private_key_from_pemder,
    _translate_pyca_cryptography_key_to_asn1,
    _translate_pyca_cryptography_cert_to_asn1, get_pyca_cryptography_hash,
)
from pyhanko.stamp import (
    TextStampStyle, STAMP_ART_CONTENT, BaseStampStyle,
)

__all__ = [
    'PdfSignatureMetadata',
    'Signer', 'SimpleSigner', 'PdfTimeStamper', 'PdfSigner',
    'PdfCMSEmbedder', 'SigObjSetup', 'SigAppearanceSetup', 'SigMDPSetup',
    'PdfByteRangeDigest', 'PdfSignedData',
    'SignatureObject', 'DocumentTimestamp',
    'SigIOSetup', 'sign_pdf', 'load_certs_from_pemder',
    'DEFAULT_MD', 'DEFAULT_SIGNING_STAMP_STYLE', 'DEFAULT_SIG_SUBFILTER'
]


logger = logging.getLogger(__name__)


class SigByteRangeObject(generic.PdfObject):

    def __init__(self):
        self._filled = False
        self._range_object_offset = None
        self.first_region_len = 0
        self.second_region_offset = 0
        self.second_region_len = 0

    def fill_offsets(self, stream, sig_start, sig_end, eof):
        if self._filled:
            raise ValueError('Offsets already filled')  # pragma: nocover
        if self._range_object_offset is None:
            raise ValueError(
                'Could not determine where to write /ByteRange value'
            )  # pragma: nocover

        old_seek = stream.tell()
        self.first_region_len = sig_start
        self.second_region_offset = sig_end
        self.second_region_len = eof - sig_end
        # our ArrayObject is rigged to have fixed width
        # so we can just write over it

        stream.seek(self._range_object_offset)
        self.write_to_stream(stream, None)

        stream.seek(old_seek)
        self._filled = True

    def write_to_stream(self, stream, handler=None, container_ref=None):
        if self._range_object_offset is None:
            self._range_object_offset = stream.tell()
        string_repr = "[ %08d %08d %08d %08d ]" % (
            0, self.first_region_len,
            self.second_region_offset, self.second_region_len,
        )
        stream.write(string_repr.encode('ascii'))


class DERPlaceholder(generic.PdfObject):

    def __init__(self, bytes_reserved=None):
        self._placeholder = True
        self.value = b'0' * (bytes_reserved or 16 * 1024)
        self._offsets = None

    @property
    def offsets(self):
        if self._offsets is None:
            raise ValueError('No offsets available')  # pragma: nocover
        return self._offsets

    # always ignore encryption key, since this is a placeholder
    def write_to_stream(self, stream, handler=None, container_ref=None):
        start = stream.tell()
        stream.write(b'<')
        stream.write(self.value)
        stream.write(b'>')
        end = stream.tell()
        if self._offsets is None:
            self._offsets = start, end


DEFAULT_SIG_SUBFILTER = SigSeedSubFilter.ADOBE_PKCS7_DETACHED


class PdfByteRangeDigest(generic.DictionaryObject):

    def __init__(self, data_key=pdf_name('/Contents'), *, bytes_reserved=None):
        super().__init__()
        if bytes_reserved is not None and bytes_reserved % 2 == 1:
            raise ValueError('bytes_reserved must be even')

        self.data_key = data_key
        contents = DERPlaceholder(bytes_reserved=bytes_reserved)
        self[data_key] = self.contents = contents
        byte_range = SigByteRangeObject()
        self[pdf_name('/ByteRange')] = self.byte_range = byte_range

    def fill(self, writer: BasePdfFileWriter, md_algorithm,
             in_place=False, output=None, chunk_size=DEFAULT_CHUNK_SIZE):
        """
        Generator coroutine that handles the document hash computation and
        the actual filling of the placeholder data.

        This is internal API; you should use use :class:`.PdfSigner`
        wherever possible. If you *really* need fine-grained control,
        use :class:`.PdfCMSEmbedder` instead.
        """

        if in_place:
            if not isinstance(writer, IncrementalPdfFileWriter):
                raise TypeError(
                    "in_place is only meaningful for incremental writers."
                )  # pragma: nocover
            output = writer.prev.stream
            writer.write_in_place()
        else:
            output = misc.prepare_rw_output_stream(output)

            writer.write(output)

        # retcon time: write the proper values of the /ByteRange entry
        #  in the signature object
        eof = output.tell()
        sig_start, sig_end = self.contents.offsets
        self.byte_range.fill_offsets(output, sig_start, sig_end, eof)

        # compute the digests
        md_spec = get_pyca_cryptography_hash(md_algorithm)
        md = hashes.Hash(md_spec)

        # attempt to get a memoryview for automatic buffering
        output_buffer = None
        if isinstance(output, BytesIO):
            output_buffer = output.getbuffer()
        else:
            try:
                output_buffer = memoryview(output)
            except (TypeError, IOError):
                pass

        if output_buffer is not None:
            # these are memoryviews, so slices should not copy stuff around
            #   (also, the interface files for pyca/cryptography don't specify
            #    that memoryviews are allowed, but they are)
            # noinspection PyTypeChecker
            md.update(output_buffer[:sig_start])
            # noinspection PyTypeChecker
            md.update(output_buffer[sig_end:eof])
            output_buffer.release()
        else:
            temp_buffer = bytearray(chunk_size)
            output.seek(0)
            misc.chunked_digest(temp_buffer, output, md, max_read=sig_start)
            output.seek(sig_end)
            misc.chunked_digest(temp_buffer, output, md, max_read=eof-sig_end)

        digest_value = md.finalize()
        cms_data = yield digest_value

        if isinstance(cms_data, bytes):
            der_bytes = cms_data
        else:
            der_bytes = cms_data.dump()
        cms_hex = binascii.hexlify(der_bytes).upper()

        # might as well compute this
        bytes_reserved = sig_end - sig_start - 2
        length = len(cms_hex)
        if length > bytes_reserved:
            raise SigningError(
                f"Final CMS buffer larger than expected: "
                f"allocated {bytes_reserved} bytes, but CMS required "
                f"{length} bytes."
            )  # pragma: nocover

        # +1 to skip the '<'
        output.seek(sig_start + 1)
        # NOTE: the PDF spec is not completely clear on this, but
        # signature contents are NOT supposed to be encrypted.
        # Perhaps this falls under the "strings in encrypted containers"
        # denominator in § 7.6.1?
        # Addition: the PDF 2.0 spec *does* spell out that this content
        # is not to be encrypted.
        output.write(cms_hex)

        output.seek(0)
        padding = bytes(bytes_reserved // 2 - len(der_bytes))
        yield output, der_bytes + padding


class PdfSignedData(PdfByteRangeDigest):
    """
    Generic class to model signature dictionaries in a PDF file.
    See also :class:`.SignatureObject` and :class:`.DocumentTimestamp`.

    :param obj_type:
        The type of signature object.
    :param subfilter:
        See :class:`.SigSeedSubFilter`.
    :param timestamp:
        The timestamp to embed into the ``/M`` entry.
    :param bytes_reserved:
        The number of bytes to reserve for the signature.
        Defaults to 16 KiB.

        .. warning::
            Since the CMS object is written to the output file as a hexadecimal
            string, you should request **twice** the (estimated) number of bytes
            in the DER-encoded version of the CMS object.
    """

    def __init__(self, obj_type,
                 subfilter: SigSeedSubFilter = DEFAULT_SIG_SUBFILTER,
                 timestamp: datetime = None, bytes_reserved=None):
        super().__init__(bytes_reserved=bytes_reserved)
        self.update({
            pdf_name('/Type'): obj_type,
            pdf_name('/Filter'): pdf_name('/Adobe.PPKLite'),
            pdf_name('/SubFilter'): subfilter.value,
        })

        if timestamp is not None:
            self[pdf_name('/M')] = pdf_date(timestamp)


class SignatureObject(PdfSignedData):
    """
    Class modelling a (placeholder for) a regular PDF signature.

    :param timestamp:
        The (optional) timestamp to embed into the ``/M`` entry.
    :param subfilter:
        See :class:`.SigSeedSubFilter`.
    :param bytes_reserved:
        The number of bytes to reserve for the signature.
        Defaults to 16 KiB.

        .. warning::
            Since the CMS object is written to the output file as a hexadecimal
            string, you should request **twice** the (estimated) number of bytes
            in the DER-encoded version of the CMS object.
    :param name:
        Signer name. You probably want to leave this blank, viewers should
        default to the signer's subject name.
    :param location:
        Optional signing location.
    :param reason:
        Optional signing reason. May be restricted by seed values.
    """

    def __init__(self, timestamp: Optional[datetime] = None,
                 subfilter: SigSeedSubFilter = DEFAULT_SIG_SUBFILTER,
                 name=None, location=None, reason=None, bytes_reserved=None):
        super().__init__(
            obj_type=pdf_name('/Sig'), subfilter=subfilter,
            timestamp=timestamp, bytes_reserved=bytes_reserved
        )

        if name:
            self[pdf_name('/Name')] = pdf_string(name)
        if location:
            self[pdf_name('/Location')] = pdf_string(location)
        if reason:
            self[pdf_name('/Reason')] = pdf_string(reason)


class DocumentTimestamp(PdfSignedData):
    """
    Class modelling a (placeholder for) a regular PDF signature.

    :param bytes_reserved:
        The number of bytes to reserve for the signature.
        Defaults to 16 KiB.

        .. warning::
            Since the CMS object is written to the output file as a hexadecimal
            string, you should request **twice** the (estimated) number of bytes
            in the DER-encoded version of the CMS object.
    """

    def __init__(self, bytes_reserved=None):
        super().__init__(
            obj_type=pdf_name('/DocTimeStamp'),
            subfilter=SigSeedSubFilter.ETSI_RFC3161,
            bytes_reserved=bytes_reserved
        )

        # use of Name/Location/Reason is discouraged in document timestamps by
        # PAdES, so we don't set those


class Signer:
    """
    Abstract signer object that is agnostic as to where the cryptographic
    operations actually happen.

    As of now, pyHanko provides two implementations:

    * :class:`.SimpleSigner` implements the easy case where all the key material
      can be loaded into memory.
    * :class:`~.pkcs11.PKCS11Signer` implements a signer that is capable of
      interfacing with a PKCS11 device (see also :class:`~.beid.BEIDSigner`).
    """

    signing_cert: x509.Certificate
    """
    The certificate that will be used to create the signature.
    """

    cert_registry: CertificateStore
    """
    Collection of certificates associated with this signer.
    Note that this is simply a bookkeeping tool; in particular it doesn't care
    about trust.
    """

    signature_mechanism: SignedDigestAlgorithm = None
    """
    The (cryptographic) signature mechanism to use.
    """

    def __init__(self, prefer_pss=False):
        self.prefer_pss = prefer_pss

    # TODO I guess that in theory, passing digest_algorithm should never
    #  be necessary. Should review the ASN.1 syntax for certificates once more.

    def get_signature_mechanism(self, digest_algorithm):
        """
        Get the signature mechanism for this signer to use.
        If :attr:`signature_mechanism` is set, it will be used.
        Otherwise, this method will attempt to put together a default
        based on mechanism used in the signer's certificate.

        :param digest_algorithm:
            Digest algorithm to use as part of the signature mechanism.
            Only used if a signature mechanism object has to be put together
            on-the-fly, and the digest algorithm could not be inferred from
            the signer's certificate.
        :return:
            A :class:`.SignedDigestAlgorithm` object.
        """

        if self.signature_mechanism is not None:
            return self.signature_mechanism
        if self.signing_cert is None:
            raise SigningError(
                "Could not set up a default signature mechanism."
            )  # pragma: nocover
        # Grab the certificate's algorithm (but forget about the digest)
        #  and use that to set up the default.
        # We'll specify the digest somewhere else.
        algo = self.signing_cert.public_key.algorithm
        params = None
        if algo == 'ec':
            mech = 'ecdsa'
        elif algo == 'rsa':
            if self.prefer_pss:
                mech = 'rsassa_pss'
                if digest_algorithm is None:
                    raise ValueError("Digest algorithm required")
                params = optimal_pss_params(
                    self.signing_cert, digest_algorithm
                )
            else:
                mech = 'rsassa_pkcs1v15'
        else:  # pragma: nocover
            raise SigningError(
                f"Signature mechanism {algo} is unsupported."
            )

        sda_kwargs = {'algorithm': mech}
        if params is not None:
            sda_kwargs['parameters'] = params
        return SignedDigestAlgorithm(sda_kwargs)

    def sign_raw(self, data: bytes, digest_algorithm: str, dry_run=False) \
            -> bytes:
        """
        Compute the raw cryptographic signature of the data provided, hashed
        using the digest algorithm provided.

        :param data:
            Data to sign.
        :param digest_algorithm:
            Digest algorithm to use.

            .. warning::
                If :attr:`signature_mechanism` also specifies a digest, they
                should match.
        :param dry_run:
            Do not actually create a signature, but merely output placeholder
            bytes that would suffice to contain an actual signature.
        :return:
            Signature bytes.
        """
        raise NotImplementedError

    @property
    def subject_name(self):
        """
        :return:
            The subject's common name as a string, extracted from
            :attr:`signing_cert`.
        """
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
        """
        Format Adobe-style revocation information for inclusion into a CMS
        object.

        :param ocsp_responses:
            A list of OCSP responses to include.
        :param crls:
            A list of CRLs to include.
        :return:
            A CMS attribute containing the relevant data.
        """

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

    def signed_attrs(self, data_digest: bytes, digest_algorithm: str,
                     timestamp: datetime = None, content_type='data',
                     revocation_info=None, use_pades=False,
                     cades_meta: CAdESSignedAttrSpec=None,
                     timestamper=None, dry_run=False):
        """
        .. versionchanged:: 0.4.0
            Added positional ``digest_algorithm`` parameter _(breaking change)_.
        .. versionchanged:: 0.5.0
            Added ``dry_run``, ``timestamper`` and ``cades_meta`` parameters.

        Format the signed attributes for a CMS signature.

        :param data_digest:
            Raw digest of the data to be signed.
        :param digest_algorithm:
            .. versionadded:: 0.4.0

            Name of the digest algorithm used to compute the digest.
        :param timestamp:
            Current timestamp (ignored when ``use_pades`` is ``True``).
        :param revocation_info:
            Revocation information to embed; this should be the output
            of a call to :meth:`.Signer.format_revinfo` or ``None``
            (ignored when ``use_pades`` is ``True``).
        :param use_pades:
            Respect PAdES requirements.
        :param dry_run:
            .. versionadded:: 0.5.0

            Flag indicating "dry run" mode. If ``True``, only the approximate
            size of the output matters, so cryptographic
            operations can be replaced by placeholders.
        :param timestamper:
            .. versionadded:: 0.5.0

            Timestamper to use when creating timestamp tokens.
        :param cades_meta:
            .. versionadded:: 0.5.0

            Specification for CAdES-specific attributes.
        :param content_type:
            CMS content type of the encapsulated data. Default is `data`.

            .. danger::
                This parameter is internal API, and non-default values must not
                be used to produce PDF signatures.
        :return:
            An :class:`.asn1crypto.cms.CMSAttributes` object.
        """

        attrs = [
            simple_cms_attribute('content_type', content_type),
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

            # TODO not sure if PAdES allows this, need to check.
            #  It *should*, but perhaps the version of CMS it is based on is too
            #  old, or it might not allow undefined signed attributes.
            # In the meantime, we only add this attribute to non-PAdES sigs
            algid_protection = cms.CMSAlgorithmProtection({
                'digest_algorithm': algos.DigestAlgorithm(
                    {'algorithm': digest_algorithm}
                ),
                'signature_algorithm':
                    self.get_signature_mechanism(digest_algorithm)
            })
            attrs.append(
                simple_cms_attribute(
                    'cms_algorithm_protection', algid_protection
                )
            )

        # apply CAdES-specific attributes regardless of use_pades
        if cades_meta is not None:
            cades_attrs = cades_meta.extra_signed_attributes(
                data_digest, digest_algorithm, timestamper=timestamper,
                dry_run=dry_run
            )
            attrs.extend(cades_attrs)

        return cms.CMSAttributes(attrs)

    def unsigned_attrs(self, digest_algorithm, signature: bytes,
                       timestamper=None, dry_run=False) \
            -> Optional[cms.CMSAttributes]:
        """
        Compute the unsigned attributes to embed into the CMS object.
        This function is called after signing the hash of the signed attributes
        (see :meth:`signed_attrs`).

        By default, this method only handles timestamp requests, but other
        functionality may be added by subclasses

        If this method returns ``None``, no unsigned attributes will be
        embedded.

        :param digest_algorithm:
            Digest algorithm used to hash the signed attributes.
        :param signature:
            Signature of the signed attribute hash.
        :param timestamper:
            Timestamp supplier to use.
        :param dry_run:
            Flag indicating "dry run" mode. If ``True``, only the approximate
            size of the output matters, so cryptographic
            operations can be replaced by placeholders.
        :return:
            The unsigned attributes to add, or ``None``.
        """

        if timestamper is not None:
            # the timestamp server needs to cross-sign our signature

            md_spec = get_pyca_cryptography_hash(digest_algorithm)
            md = hashes.Hash(md_spec)
            md.update(signature)
            if dry_run:
                ts_token = timestamper.dummy_response(digest_algorithm)
            else:
                ts_token = timestamper.timestamp(
                    md.finalize(), digest_algorithm
                )
            return cms.CMSAttributes(
                [simple_cms_attribute('signature_time_stamp_token', ts_token)]
            )

    def signer_info(self, digest_algorithm: str, signed_attrs, signature):
        """
        Format the ``SignerInfo`` entry for a CMS signature.

        :param digest_algorithm:
            Digest algorithm to use.
        :param signed_attrs:
            Signed attributes (see :meth:`signed_attrs`).
        :param signature:
            The raw signature to embed (see :meth:`sign_raw`).
        :return:
            An :class:`.asn1crypto.cms.SignerInfo` object.
        """
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
            'signature_algorithm': self.get_signature_mechanism(
                digest_algorithm
            ),
            'signed_attrs': signed_attrs,
            'signature': signature
        })
        return sig_info

    def sign(self, data_digest: bytes, digest_algorithm: str,
             timestamp: datetime = None, dry_run=False,
             revocation_info=None, use_pades=False, timestamper=None,
             cades_signed_attr_meta: CAdESSignedAttrSpec = None,
             encap_content_info=None) -> cms.ContentInfo:

        """
        Produce a detached CMS signature from a raw data digest.

        :param data_digest:
            Digest of the actual content being signed.
        :param digest_algorithm:
            Digest algorithm to use. This should be the same digest method
            as the one used to hash the (external) content.
        :param timestamp:
            Signing time to embed into the signed attributes
            (will be ignored if ``use_pades`` is ``True``).

            .. note::
                This timestamp value is to be interpreted as an unfounded
                assertion by the signer, which may or may not be good enough
                for your purposes.
        :param dry_run:
            If ``True``, the actual signing step will be replaced with
            a placeholder.

            In a PDF signing context, this is necessary to estimate the size
            of the signature container before computing the actual digest of
            the document.
        :param revocation_info:
            Revocation information to embed; this should be the output
            of a call to :meth:`.Signer.format_revinfo`
            (ignored when ``use_pades`` is ``True``).
        :param use_pades:
            Respect PAdES requirements.
        :param timestamper:
            :class:`~.timestamps.TimeStamper` used to obtain a trusted timestamp
            token that can be embedded into the signature container.

            .. note::
                If ``dry_run`` is true, the timestamper's
                :meth:`~.timestamps.TimeStamper.dummy_response` method will be
                called to obtain a placeholder token.
                Note that with a standard :class:`~.timestamps.HTTPTimeStamper`,
                this might still hit the timestamping server (in order to
                produce a realistic size estimate), but the dummy response will
                be cached.
        :param cades_signed_attr_meta:
            .. versionadded:: 0.5.0

            Specification for CAdES-specific signed attributes.
        :param encap_content_info:
            Data to encapsulate in the CMS object.

            .. danger::
                This parameter is internal API, and must not be used to produce
                PDF signatures.
        :return:
            An :class:`~.asn1crypto.cms.ContentInfo` object.
        """

        encap_content_info = encap_content_info or {'content_type': 'data'}
        if isinstance(encap_content_info, core.Sequence):
            # could be cms.ContentInfo or cms.EncapsulatedContentInfo depending
            # on circumstances, so let's just stick to Sequence
            content_type = encap_content_info['content_type'].native
        else:
            content_type = encap_content_info.get('content_type', 'data')

        digest_algorithm = digest_algorithm.lower()
        # the piece of data we'll actually sign is a DER-encoded version of the
        # signed attributes of our message
        signed_attrs = self.signed_attrs(
            data_digest, digest_algorithm, timestamp,
            revocation_info=revocation_info, use_pades=use_pades,
            timestamper=timestamper, cades_meta=cades_signed_attr_meta,
            dry_run=dry_run, content_type=content_type
        )

        digest_algorithm_obj = algos.DigestAlgorithm(
            {'algorithm': digest_algorithm}
        )
        implied_hash_algo = None
        try:
            if self.signature_mechanism is not None:
                implied_hash_algo = self.signature_mechanism.hash_algo
        except ValueError:
            # this is OK, just use the specified message digest
            pass
        if implied_hash_algo is not None \
                and implied_hash_algo != digest_algorithm:
            raise SigningError(
                f"Selected signature mechanism specifies message digest "
                f"{implied_hash_algo}, but {digest_algorithm} "
                f"was requested."
            )

        signature = self.sign_raw(
            signed_attrs.dump(), digest_algorithm.lower(), dry_run
        )

        sig_info = self.signer_info(digest_algorithm, signed_attrs, signature)

        unsigned_attrs = self.unsigned_attrs(
            digest_algorithm, signature, timestamper=timestamper,
            dry_run=dry_run
        )
        if unsigned_attrs is not None:
            sig_info['unsigned_attrs'] = unsigned_attrs

        # do not add the TS certs at this point
        certs = set(self.cert_registry)
        certs.add(self.signing_cert)
        # this is the SignedData object for our message (see RFC 2315 § 9.1)
        signed_data = {
            'version': 'v1' if content_type == 'data' else 'v3',
            'digest_algorithms': cms.DigestAlgorithms((digest_algorithm_obj,)),
            'encap_content_info': encap_content_info,
            'certificates': certs,
            'signer_infos': [sig_info]
        }

        # time to pack up
        return cms.ContentInfo({
            'content_type': cms.ContentType('signed_data'),
            'content': cms.SignedData(signed_data)
        })

    def sign_general_data(self, input_data: Union[IO, bytes,
                                                  cms.ContentInfo,
                                                  cms.EncapsulatedContentInfo],
                          digest_algorithm: str, detached=True,
                          timestamp: datetime = None,
                          use_cades=False, timestamper=None,
                          cades_signed_attr_meta: CAdESSignedAttrSpec = None,
                          chunk_size=DEFAULT_CHUNK_SIZE,
                          max_read=None) -> cms.ContentInfo:
        """
        Produce a CMS signature for an arbitrary data stream
        (not necessarily PDF data).

        :param input_data:
            The input data to sign. This can be either a :class:`bytes` object
            a file-type object, a :class:`cms.ContentInfo` object or
            a :class:`cms.EncapsulatedContentInfo` object.

            .. warning::
                ``asn1crypto`` mandates :class:`cms.ContentInfo` for CMS v1
                signatures. In practical terms, this means that you need to
                use :class:`cms.ContentInfo` if the content type is ``data``,
                and :class:`cms.EncapsulatedContentInfo` otherwise.

            .. warning::
                We currently only support CMS v1 and v3 signatures.
                This is only a concern if you need attribute certificate
                support, in which case you can override the CMS version number
                yourself (this will not invalidate any signatures).
        :param digest_algorithm:
            The name of the digest algorithm to use.
        :param detached:
            If ``True``, create a CMS detached signature (i.e. an object where
            the encapsulated content is not embedded in the signature object
            itself). This is the default. If ``False``, the content to be
            signed will be embedded as encapsulated content.

            .. note::
                If ``input_data`` is of type :class:`cms.ContentInfo` or
                :class:`cms.EncapsulatedContentInfo`, the implied value of this
                parameter is ``False``.

        :param timestamp:
            Signing time to embed into the signed attributes
            (will be ignored if ``use_cades`` is ``True``).

            .. note::
                This timestamp value is to be interpreted as an unfounded
                assertion by the signer, which may or may not be good enough
                for your purposes.
        :param use_cades:
            Construct a CAdES-style CMS object.
        :param timestamper:
            :class:`.PdfTimeStamper` to use to create a signature timestamp

            .. note::
                If you want to create a *content* timestamp (as opposed to
                a *signature* timestamp), see :class:`.CAdESSignedAttrSpec`.
        :param cades_signed_attr_meta:
            Specification for CAdES-specific signed attributes.
        :param chunk_size:
            Chunk size to use when consuming input data.
        :param max_read:
            Maximal number of bytes to read from the input stream.
        :return:
            A CMS ContentInfo object of type signedData.
        """
        h = hashes.Hash(get_pyca_cryptography_hash(digest_algorithm))
        encap_content_info = None
        if isinstance(input_data, core.Sequence):
            encap_content_info = input_data
            h.update(bytes(encap_content_info['content']))
        elif isinstance(input_data, bytes):
            h.update(input_data)
            if not detached:
                # use dicts instead of Asn1Value objects, to leave asn1crypto
                # to decide whether to use cms.ContentInfo or
                # cms.EncapsulatedContentInfo (for backwards compat with PCKS#7)
                encap_content_info = {
                    'content_type': 'data', 'content': input_data
                }
        elif not detached:
            # input stream is a buffer, and we're in 'enveloping' mode
            # read the entire thing into memory, since we need to embed
            # it anyway
            input_bytes = input_data.read(max_read)
            h.update(input_bytes)
            # see above
            encap_content_info = {
                'content_type': 'data',
                'content': input_bytes
            }
        else:
            temp_buf = bytearray(chunk_size)
            misc.chunked_digest(temp_buf, input_data, h, max_read=max_read)
        digest_bytes = h.finalize()

        return self.sign(
            data_digest=digest_bytes, digest_algorithm=digest_algorithm,
            timestamp=timestamp, use_pades=use_cades,
            timestamper=timestamper, encap_content_info=encap_content_info,
            cades_signed_attr_meta=cades_signed_attr_meta
        )


# TODO I've encountered TSAs that will spew invalid timestamps when presented
#  with a sha512 req (Adobe Reader agrees).
#  Should get to the bottom of that. In the meantime, default to sha256
DEFAULT_MD = 'sha256'
"""
Default message digest algorithm used when computing digests for use in
signatures.
"""

DEFAULT_SIGNER_KEY_USAGE = {"non_repudiation"}
"""
Default key usage bits required for the signer's certificate.
"""


@dataclass(frozen=True)
class PdfSignatureMetadata:
    """
    Specification for a PDF signature.
    """

    field_name: str = None
    """
    The name of the form field to contain the signature.
    If there is only one available signature field, the name may be inferred.
    """

    md_algorithm: str = None
    """
    The name of the digest algorithm to use.
    It should be supported by `pyca/cryptography`.

    If ``None``, this will ordinarily default to the value of
    :const:`.DEFAULT_MD`, unless a seed value dictionary and/or a prior
    certification signature happen to be available.
    """

    location: str = None
    """
    Location of signing.
    """

    reason: str = None
    """
    Reason for signing (textual).
    """

    name: str = None
    """
    Name of the signer. This value is usually not necessary to set, since
    it should appear on the signer's certificate, but there are cases
    where it might be useful to specify it here (e.g. in situations where 
    signing is delegated to a trusted third party).
    """

    certify: bool = False
    """
    Sign with an author (certification) signature, as opposed to an approval
    signature. A document can contain at most one such signature, and it must
    be the first one.
    """
    # TODO Does this restriction also apply to prior document timestamps?

    subfilter: SigSeedSubFilter = None
    """
    Signature subfilter to use.
    
    This should be one of 
    :attr:`~.fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED` or
    :attr:`~.fields.SigSeedSubFilter.PADES`.
    If not specified, the value may be inferred from the signature field's
    seed value dictionary. Failing that,
    :attr:`~.fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED` is used as the
    default value.
    """

    embed_validation_info: bool = False
    """
    Flag indicating whether validation info (OCSP responses and/or CRLs)
    should be embedded or not. This is necessary to be able to validate
    signatures long after they have been made.
    This flag requires :attr:`validation_context` to be set.
    
    The precise manner in which the validation info is embedded depends on
    the (effective) value of :attr:`subfilter`:
    
    * With :attr:`~.fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED`, the
      validation information will be embedded inside the CMS object containing
      the signature.
    * With :attr:`~.fields.SigSeedSubFilter.PADES`, the validation information
      will be embedded into the document security store (DSS).
    """

    use_pades_lta: bool = False
    """
    If ``True``, the signer will append an additional document timestamp after
    writing the signature's validation information to the document security
    store (DSS).
    This flag is only meaningful if :attr:`subfilter` is 
    :attr:`~.fields.SigSeedSubFilter.PADES`.
    
    The PAdES B-LTA profile solves the long-term validation problem by
    adding a timestamp chain to the document after the regular signatures, which
    is updated with new timestamps at regular intervals.
    This provides an audit trail that ensures the long-term integrity of the 
    validation information in the DSS, since OCSP responses and CRLs also have 
    a finite lifetime.
    
    See also :meth:`.PdfTimeStamper.update_archival_timestamp_chain`.
    """

    timestamp_field_name: str = None
    """
    Name of the timestamp field created when :attr:`use_pades_lta` is ``True``.
    If not specified, a unique name will be generated using :mod:`uuid`.
    """

    validation_context: ValidationContext = None
    """
    The validation context to use when validating signatures.
    If provided, the signer's certificate and any timestamp certificates
    will be validated before signing.
    
    This parameter is mandatory when :attr:`embed_validation_info` is ``True``.
    """

    docmdp_permissions: MDPPerm = MDPPerm.FILL_FORMS
    """
    Indicates the document modification policy that will be in force after    
    this signature is created. Only relevant for certification signatures
    or signatures that apply locking.
    
    .. warning::
        For non-certification signatures, this is only explicitly allowed since 
        PDF 2.0 (ISO 32000-2), so older software may not respect this setting
        on approval signatures.
    """

    signer_key_usage: Set[str] = field(
        default_factory=lambda: DEFAULT_SIGNER_KEY_USAGE
    )
    """
    Key usage extensions required for the signer's certificate.
    Defaults to ``non_repudiation`` only, but sometimes ``digital_signature``
    or a combination of both may be more appropriate.
    See :class:`x509.KeyUsage` for a complete list.
    
    Only relevant if a validation context is also provided.
    """

    cades_signed_attr_spec: Optional[CAdESSignedAttrSpec] = None
    """
    .. versionadded:: 0.5.0

    Specification for CAdES-specific attributes.
    """


class SimpleSigner(Signer):
    """
    Simple signer implementation where the key material is available in local
    memory.
    """

    signing_key: keys.PrivateKeyInfo
    """
    Private key associated with the certificate in :attr:`signing_cert`.
    """

    def __init__(self, signing_cert: x509.Certificate,
                 signing_key: keys.PrivateKeyInfo,
                 cert_registry: CertificateStore,
                 signature_mechanism: SignedDigestAlgorithm = None,
                 prefer_pss=False):
        self.signing_cert = signing_cert
        self.signing_key = signing_key
        self.cert_registry = cert_registry
        self.signature_mechanism = signature_mechanism
        super().__init__(prefer_pss=prefer_pss)

    def sign_raw(self, data: bytes, digest_algorithm: str, dry_run=False) \
            -> bytes:

        signature_mechanism = self.get_signature_mechanism(digest_algorithm)
        mechanism = signature_mechanism.signature_algo
        priv_key = serialization.load_der_private_key(
            self.signing_key.dump(), password=None
        )

        if mechanism == 'rsassa_pkcs1v15':
            padding = PKCS1v15()
            hash_algo = get_pyca_cryptography_hash(digest_algorithm)
            assert isinstance(priv_key, RSAPrivateKey)
            return priv_key.sign(data, padding, hash_algo)
        elif mechanism == 'rsassa_pss':
            params = signature_mechanism['parameters']
            padding, hash_algo = _process_pss_params(
                params, digest_algorithm
            )
            assert isinstance(priv_key, RSAPrivateKey)
            return priv_key.sign(data, padding, hash_algo)
        elif mechanism == 'ecdsa':
            hash_algo = get_pyca_cryptography_hash(digest_algorithm)
            assert isinstance(priv_key, EllipticCurvePrivateKey)
            return priv_key.sign(data, signature_algorithm=ECDSA(hash_algo))
        else:  # pragma: nocover
            raise SigningError(
                f"The signature mechanism {mechanism} "
                "is unsupported by this signer."
            )

    @classmethod
    def _load_ca_chain(cls, ca_chain_files=None):
        try:
            return set(load_certs_from_pemder(ca_chain_files))
        except (IOError, ValueError) as e:  # pragma: nocover
            logger.error('Could not load CA chain', exc_info=e)
            return None

    @classmethod
    def load_pkcs12(cls, pfx_file, ca_chain_files=None, passphrase=None,
                    signature_mechanism=None, prefer_pss=False):
        """
        Load certificates and key material from a PCKS#12 archive
        (usually ``.pfx`` or ``.p12`` files).

        :param pfx_file:
            Path to the PKCS#12 archive.
        :param ca_chain_files:
            Path to (PEM/DER) files containing other relevant certificates
            not included in the PKCS#12 file.
        :param passphrase:
            Passphrase to decrypt the PKCS#12 archive, if required.
        :param signature_mechanism:
            Override the signature mechanism to use.
        :param prefer_pss:
            Prefer PSS signature mechanism over RSA PKCS#1 v1.5 if
            there's a choice.
        :return:
            A :class:`.SimpleSigner` object initialised with key material loaded
            from the PKCS#12 file provided.
        """
        # TODO support MAC integrity checking?

        try:
            with open(pfx_file, 'rb') as f:
                pfx_bytes = f.read()
        except IOError as e:  # pragma: nocover
            logger.error(f'Could not open PKCS#12 file {pfx_file}.', exc_info=e)
            return None

        ca_chain = cls._load_ca_chain(ca_chain_files) \
            if ca_chain_files else set()
        if ca_chain is None:  # pragma: nocover
            return None

        (private_key, cert, other_certs) = pkcs12.load_key_and_certificates(
            pfx_bytes, passphrase
        )
        kinfo = _translate_pyca_cryptography_key_to_asn1(private_key)
        cert = _translate_pyca_cryptography_cert_to_asn1(cert)
        other_certs = set(
            map(_translate_pyca_cryptography_cert_to_asn1, other_certs)
        )

        cs = SimpleCertificateStore()
        cs.register_multiple(ca_chain | set(other_certs))
        return SimpleSigner(
            signing_key=kinfo, signing_cert=cert,
            cert_registry=cs, signature_mechanism=signature_mechanism,
            prefer_pss=prefer_pss
        )

    @classmethod
    def load(cls, key_file, cert_file, ca_chain_files=None,
             key_passphrase=None, other_certs=None,
             signature_mechanism=None, prefer_pss=False):
        """
        Load certificates and key material from PEM/DER files.

        :param key_file:
            File containing the signer's private key.
        :param cert_file:
            File containing the signer's certificate.
        :param ca_chain_files:
            File containing other relevant certificates.
        :param key_passphrase:
            Passphrase to decrypt the private key (if required).
        :param other_certs:
            Other relevant certificates, specified as a list of
            :class:`.asn1crypto.x509.Certificate` objects.
        :param signature_mechanism:
            Override the signature mechanism to use.
        :param prefer_pss:
            Prefer PSS signature mechanism over RSA PKCS#1 v1.5 if
            there's a choice.
        :return:
            A :class:`.SimpleSigner` object initialised with key material loaded
            from the files provided.
        """
        try:
            # load cryptographic data (both PEM and DER are supported)
            signing_key = load_private_key_from_pemder(
                key_file, passphrase=key_passphrase
            )
            signing_cert = load_cert_from_pemder(cert_file)
        except (IOError, ValueError, TypeError) as e:  # pragma: nocover
            logger.error('Could not load cryptographic material', exc_info=e)
            return None

        ca_chain = cls._load_ca_chain(ca_chain_files) if ca_chain_files else []
        if ca_chain is None:  # pragma: nocover
            return None

        other_certs = ca_chain if other_certs is None \
            else ca_chain + other_certs

        cert_reg = SimpleCertificateStore()
        cert_reg.register_multiple(other_certs)
        return SimpleSigner(
            signing_cert=signing_cert, signing_key=signing_key,
            cert_registry=cert_reg, signature_mechanism=signature_mechanism,
            prefer_pss=prefer_pss
        )


def docmdp_reference_dictionary(md_algorithm, permission_level: MDPPerm):
    # this is part of the /Reference entry of the signature object.
    return generic.DictionaryObject({
        pdf_name('/Type'): pdf_name('/SigRef'),
        pdf_name('/TransformMethod'): pdf_name('/DocMDP'),
        pdf_name('/DigestMethod'): pdf_name('/' + md_algorithm.upper()),
        pdf_name('/TransformParams'): generic.DictionaryObject({
            pdf_name('/Type'): pdf_name('/TransformParams'),
            pdf_name('/V'): pdf_name('/1.2'),
            pdf_name('/P'): generic.NumberObject(permission_level.value)
        })
    })


def fieldmdp_reference_dictionary(field_mdp_spec: FieldMDPSpec,
                                  md_algorithm: str,
                                  data_ref: generic.Reference):
    data_ref = generic.IndirectObject(
        data_ref.idnum, data_ref.generation, data_ref.pdf
    )
    # this is part of the /Reference entry of the signature object.
    return generic.DictionaryObject({
        pdf_name('/Type'): pdf_name('/SigRef'),
        pdf_name('/TransformMethod'): pdf_name('/FieldMDP'),
        pdf_name('/Data'): data_ref,
        pdf_name('/DigestMethod'): pdf_name('/' + md_algorithm.upper()),
        pdf_name('/TransformParams'): field_mdp_spec.as_transform_params()
    })


SIG_DETAILS_DEFAULT_TEMPLATE = (
    'Digitally signed by %(signer)s.\n'
    'Timestamp: %(ts)s.'
)


def sign_pdf(pdf_out: BasePdfFileWriter,
             signature_meta: PdfSignatureMetadata, signer: Signer,
             timestamper: TimeStamper = None,
             new_field_spec: Optional[SigFieldSpec] = None,
             existing_fields_only=False, bytes_reserved=None, in_place=False,
             output=None):
    """
    Thin convenience wrapper around :meth:`.PdfSigner.sign_pdf`.

    :param pdf_out:
        An :class:`.IncrementalPdfFileWriter`.
    :param bytes_reserved:
        Bytes to reserve for the CMS object in the PDF file.
        If not specified, make an estimate based on a dummy signature.
    :param signature_meta:
        The specification of the signature to add.
    :param signer:
        :class:`.Signer` object to use to produce the signature object.
    :param timestamper:
        :class:`.TimeStamper` object to use to produce any time stamp tokens
        that might be required.
    :param in_place:
        Sign the input in-place. If ``False``, write output to a
        :class:`.BytesIO` object.
    :param existing_fields_only:
        If ``True``, never create a new empty signature field to contain
        the signature.
        If ``False``, a new field may be created if no field matching
        :attr:`~.PdfSignatureMetadata.field_name` exists.
    :param new_field_spec:
        If a new field is to be created, this parameter allows the caller
        to specify the field's properties in the form of a
        :class:`.SigFieldSpec`. This parameter is only meaningful if
        ``existing_fields_only`` is ``False``.
    :param output:
        Write the output to the specified output stream.
        If ``None``, write to a new :class:`.BytesIO` object.
        Default is ``None``.
    :return:
        The output stream containing the signed output.
    """

    if new_field_spec is not None and existing_fields_only:
        raise SigningError(
            "Specifying a signature field spec is not meaningful when "
            "existing_fields_only=True."
        )

    signer = PdfSigner(
        signature_meta, signer, timestamper=timestamper,
        new_field_spec=new_field_spec
    )
    return signer.sign_pdf(
        pdf_out, existing_fields_only=existing_fields_only,
        bytes_reserved=bytes_reserved, in_place=in_place, output=output
    )


# Wrapper around _prepare_sig_fields with some error reporting

def _get_or_create_sigfield(field_name, pdf_out: BasePdfFileWriter,
                            existing_fields_only,
                            new_field_spec: Optional[SigFieldSpec] = None):
    root = pdf_out.root
    if field_name is None:
        if not existing_fields_only:
            raise SigningError(
                'Not specifying a field name is only allowed '
                'when existing_fields_only=True'
            )

        # most of the logic in _prepare_sig_field has to do with preparing
        # for the potential addition of a new field. That is completely
        # irrelevant in this special case, so we might as well short circuit
        # things.
        field_created = False
        empty_fields = enumerate_sig_fields(pdf_out, filled_status=False)
        try:
            found_field_name, _, sig_field_ref = next(empty_fields)
        except StopIteration:
            raise SigningError('There are no empty signature fields.')

        others = ', '.join(
            fn for fn, _, _ in empty_fields if fn is not None
        )
        if others:
            raise SigningError(
                'There are several empty signature fields. Please specify '
                'a field name. The options are %s, %s.' % (
                    found_field_name, others
                )
            )
    else:
        # grab or create a sig field
        if new_field_spec is not None:
            sig_field_kwargs = {
                'box': new_field_spec.box,
                'include_on_page': pdf_out.find_page_for_modification(
                    new_field_spec.on_page
                )[0],
                'combine_annotation': new_field_spec.combine_annotation
            }
        else:
            sig_field_kwargs = {}

        field_created, sig_field_ref = _prepare_sig_field(
            field_name, root, update_writer=pdf_out,
            existing_fields_only=existing_fields_only,
            **sig_field_kwargs
        )

    _ensure_sig_flags(writer=pdf_out, lock_sig_flags=True)

    return field_created, sig_field_ref


@dataclass(frozen=True)
class SigMDPSetup:

    md_algorithm: str
    """
    Message digest algorithm to write into the signature reference dictionary,
    if one is written at all.
    
    .. warning::
        It is the caller's responsibility to make sure that this value agrees
        with the value embedded into the CMS object, and with the algorithm
        used to hash the document.
        The low-level :class:`.PdfCMSEmbedder` API *will* simply take it at
        face value.
    """

    certify: bool = False
    """
    Sign with an author (certification) signature, as opposed to an approval
    signature. A document can contain at most one such signature, and it must
    be the first one.
    """

    field_lock: Optional[FieldMDPSpec] = None
    """
    Field lock information to write to the signature reference dictionary.
    """

    docmdp_perms: Optional[MDPPerm] = None
    """
    DocMDP permissions to write to the signature reference dictionary.
    """

    def _apply(self, sig_obj_ref, writer):

        certify = self.certify
        docmdp_perms = self.docmdp_perms

        lock = self.field_lock
        md_algorithm = self.md_algorithm

        reference_array = generic.ArrayObject()

        if certify:
            assert docmdp_perms is not None
            # To make a certification signature, we need to leave a record
            #  in the document catalog.
            root = writer.root
            try:
                perms = root['/Perms']
            except KeyError:
                root['/Perms'] = perms = generic.DictionaryObject()
            perms[pdf_name('/DocMDP')] = sig_obj_ref
            writer.update_container(perms)
            reference_array.append(
                docmdp_reference_dictionary(md_algorithm, docmdp_perms)
            )

        if lock is not None:
            fieldmdp_ref = fieldmdp_reference_dictionary(
                lock, md_algorithm, data_ref=writer.root_ref
            )
            reference_array.append(fieldmdp_ref)

            if docmdp_perms is not None:
                # NOTE: this is NOT spec-compatible, but emulates Acrobat
                # behaviour
                fieldmdp_ref['/TransformParams']['/P'] = \
                    generic.NumberObject(docmdp_perms.value)

        if reference_array:
            sig_obj_ref.get_object()['/Reference'] = reference_array


@dataclass(frozen=True)
class SigAppearanceSetup:
    """
    Signature appearance configuration.

    Part of the low-level :class:`.PdfCMSEmbedder` API, see
    :class:`SigObjSetup`.
    """

    style: BaseStampStyle
    """
    Stamp style to use to generate the appearance.
    """

    timestamp: datetime
    """
    Timestamp to show in the signature appearance.
    """

    name: str
    """
    Signer name to show in the signature appearance.
    """

    text_params: dict = None
    """
    Additional text interpolation parameters to pass to the underlying
    stamp style.
    """

    def _apply(self, sig_annot, writer):
        try:
            x1, y1, x2, y2 = sig_annot['/Rect']
        except KeyError:
            return
        w = abs(x1 - x2)
        h = abs(y1 - y2)
        if w and h:
            # the field is probably a visible one, so we change its appearance
            # stream to show some data about the signature
            stamp = self._appearance_stamp(
                writer, BoxConstraints(width=w, height=h)
            )
            sig_annot['/AP'] = stamp.as_appearances().as_pdf_object()
            try:
                # if there was an entry like this, it's meaningless now
                del sig_annot[pdf_name('/AS')]
            except KeyError:
                pass

    def _appearance_stamp(self, writer, box):
        style = self.style

        name = self.name
        timestamp = self.timestamp
        extra_text_params = self.text_params or {}
        text_params = {
            'signer': name,
            **extra_text_params
        }
        if isinstance(style, TextStampStyle):
            text_params['ts'] = timestamp.strftime(style.timestamp_format)

        return style.create_stamp(writer, box, text_params)


@dataclass(frozen=True)
class SigObjSetup:
    """
    Describes the signature dictionary to be embedded as the form field's value.
    """

    sig_placeholder: PdfSignedData
    """
    Bare-bones placeholder object, usually of type :class:`.SignatureObject`
    or :class:`.DocumentTimestamp`.
    
    In particular, this determines the number of bytes to allocate for the
    CMS object.
    """

    mdp_setup: Optional[SigMDPSetup] = None
    """
    Optional DocMDP settings, see :class:`.SigMDPSetup`.
    """

    appearance_setup: Optional[SigAppearanceSetup] = None
    """
    Optional appearance settings, see :class:`.SigAppearanceSetup`.
    """


@dataclass(frozen=True)
class SigIOSetup:
    """
    I/O settings for writing signed PDF documents.

    Objects of this type are used in the penultimate phase of
    the :class:`.PdfCMSEmbedder` protocol.
    """

    md_algorithm: str
    """
    Message digest algorithm to use to compute the document hash.
    It should be supported by `pyca/cryptography`.
    
    .. warning::
        This is also the message digest algorithm that should appear in the
        corresponding ``signerInfo`` entry in the CMS object that ends up
        being embedded in the signature field.
    """

    in_place: bool = False
    """
    Sign the input in-place. If ``False``, write output to a :class:`.BytesIO`
    object, or :attr:`output` if the latter is not ``None``.
    """

    chunk_size: int = DEFAULT_CHUNK_SIZE
    """
    Size of the internal buffer (in bytes) used to feed data to the message 
    digest function if the input stream does not support ``memoryview``.
    """

    output: Optional[IO] = None
    """
    Write the output to the specified output stream. If ``None``, write to a 
    new :class:`.BytesIO` object. Default is ``None``.
    """


class PdfCMSEmbedder:
    """
    Low-level class that handles embedding CMS objects into PDF signature
    fields.

    It also takes care of appearance generation and DocMDP configuration,
    but does not otherwise offer any of the conveniences of
    :class:`.PdfSigner`.

    :param new_field_spec:
        :class:`.SigFieldSpec` to use when creating new fields on-the-fly.
    """

    def __init__(self, new_field_spec: Optional[SigFieldSpec] = None):
        self.new_field_spec = new_field_spec

    def write_cms(self, field_name: str, writer: BasePdfFileWriter,
                  existing_fields_only=False):
        """
        This method returns a generator coroutine that controls the process
        of embedding CMS data into a PDF signature field.
        Can be used for both timestamps and regular signatures.

        .. danger::
            This is a very low-level interface that performs virtually no
            error checking, and is intended to be used in situations
            where the construction of the CMS object to be embedded
            is not under the caller's control (e.g. a remote signer
            that produces full-fledged CMS objects).

            In almost every other case, you're better of using
            :class:`.PdfSigner` instead, with a custom :class:`.Signer`
            implementation to handle the cryptographic operations if necessary.

        The coroutine follows the following specific protocol.

        1. First, it retrieves or creates the signature field to embed the
           CMS object in, and yields a reference to said field.
        2. The caller should then send in a :class:`.SigObjSetup` object, which
           is subsequently processed by the coroutine. For convenience, the
           coroutine will then yield a reference to the signature dictionary
           (as embedded in the PDF writer).
        3. Next, the caller should send a :class:`.SigIOSetup` object,
           describing how the resulting document should be hashed and written
           to the output. The coroutine will write the entire document with a
           placeholder region reserved for the signature, compute the document's
           hash and yield it to the caller.

           From this point onwards, **no objects may be changed or added** to
           the :class:`.IncrementalPdfFileWriter` currently in use.
        4. Finally, the caller should pass in a CMS object to place inside
           the signature dictionary. The CMS object can be supplied as a raw
           :class:`bytes` object, or an :mod:`asn1crypto`-style object.
           The coroutine's final yield is a tuple ``output, sig_contents``,
           where ``output`` is the output stream used, and ``sig_contents`` is
           the value of the signature dictionary's ``/Contents`` entry, given as
           a hexadecimal string.

        .. caution::
            It is the caller's own responsibility to ensure that enough room
            is available in the placeholder signature object to contain
            the final CMS object.

        :param field_name:
            The name of the field to fill in. This should be a field of type
            ``/Sig``.
        :param writer:
            An :class:`.IncrementalPdfFileWriter` containing the
            document to sign.
        :param existing_fields_only:
            If ``True``, never create a new empty signature field to contain
            the signature.
            If ``False``, a new field may be created if no field matching
            :attr:`~.PdfSignatureMetadata.field_name` exists.
        :return:
            A generator coroutine implementing the protocol described above.
        """

        new_field_spec = self.new_field_spec \
            if not existing_fields_only else None
        # start by creating or fetching the appropriate signature field
        field_created, sig_field_ref = _get_or_create_sigfield(
            field_name, writer,
            existing_fields_only,
            new_field_spec=new_field_spec
        )

        # yield control to caller to further process the field dictionary
        # if necessary, request setup specs for sig object
        sig_obj_setup = yield sig_field_ref
        assert isinstance(sig_obj_setup, SigObjSetup)

        sig_field = sig_field_ref.get_object()

        # take care of the field's visual appearance (if applicable)
        appearance_setup = sig_obj_setup.appearance_setup
        if appearance_setup is not None:
            try:
                sig_annot, = sig_field['/Kids']
                sig_annot = sig_annot.get_object()
            except (ValueError, TypeError):
                raise SigningError(
                    "Failed to access signature field's annotation. "
                    "Signature field must have exactly one child annotation, "
                    "or it must be combined with its annotation."
                )
            except KeyError:
                sig_annot = sig_field

            appearance_setup._apply(sig_annot, writer)

        sig_obj = sig_obj_setup.sig_placeholder
        sig_obj_ref = writer.add_object(sig_obj)

        # fill in a reference to the (empty) signature object
        sig_field[pdf_name('/V')] = sig_obj_ref

        if not field_created:
            # still need to mark it for updating
            writer.mark_update(sig_field_ref)

        mdp_setup = sig_obj_setup.mdp_setup
        if mdp_setup is not None:
            mdp_setup._apply(sig_obj_ref, writer)

        # again, pass control to the caller
        # and request I/O parameters for putting the cryptographic signature
        # into the output.
        # We pass a reference to the embedded signature object as a convenience.

        sig_io = yield sig_obj_ref
        assert isinstance(sig_io, SigIOSetup)

        # pass control to the sig object's write_signature coroutine
        yield from sig_obj.fill(
            writer, sig_io.md_algorithm, in_place=sig_io.in_place,
            output=sig_io.output, chunk_size=sig_io.chunk_size
        )


def _finalise_output(orig_output, returned_output):

    # The internal API transparently replaces non-readable/seekable
    # buffers with BytesIO for signing operations, but we don't want to
    # expose that to the public API user.

    if orig_output is not None and orig_output is not returned_output:
        # original output is a write-only buffer
        assert isinstance(returned_output, BytesIO)
        raw_buf = returned_output.getbuffer()
        orig_output.write(raw_buf)
        raw_buf.release()
        return orig_output
    return returned_output


class PdfTimeStamper:
    """
    Class to encapsulate the process of appending document timestamps to
    PDF files.
    """

    def __init__(self, timestamper: TimeStamper):
        self.default_timestamper = timestamper

    def generate_timestamp_field_name(self) -> str:
        """
        Generate a unique name for a document timestamp field using :mod:`uuid`.

        :return:
            The field name, as a (Python) string.
        """
        return 'Timestamp-' + str(uuid.uuid4())

    # TODO maybe make validation_context optional? In a PAdES context
    #  that doesn't make sense, but document timestamps are in principle more
    #  generally applicable.

    # TODO I'm not entirely sure that allowing validation_paths to be cached
    #  is wise. In principle, the TSA could issue their next timestamp with a
    #  different certificate (e.g. due to load balancing), which would require
    #  validation regardless.

    def timestamp_pdf(self, pdf_out: IncrementalPdfFileWriter,
                      md_algorithm, validation_context=None,
                      bytes_reserved=None, validation_paths=None,
                      timestamper: Optional[TimeStamper] = None, *,
                      in_place=False, output=None,
                      chunk_size=DEFAULT_CHUNK_SIZE):
        """Timestamp the contents of ``pdf_out``.
        Note that ``pdf_out`` should not be written to after this operation.

        :param pdf_out:
            An :class:`.IncrementalPdfFileWriter`.
        :param md_algorithm:
            The hash algorithm to use when computing message digests.
        :param validation_context:
            The :class:`.pyhanko_certvalidator.ValidationContext`
            against which the TSA response should be validated.
            This validation context will also be used to update the DSS.
        :param bytes_reserved:
            Bytes to reserve for the CMS object in the PDF file.
            If not specified, make an estimate based on a dummy signature.
        :param validation_paths:
            If the validation path(s) for the TSA's certificate are already
            known, you can pass them using this parameter to avoid having to
            run the validation logic again.
        :param timestamper:
            Override the default :class:`.TimeStamper` associated with this
            :class:`.PdfTimeStamper`.
        :param output:
            Write the output to the specified output stream.
            If ``None``, write to a new :class:`.BytesIO` object.
            Default is ``None``.
        :param in_place:
            Sign the original input stream in-place.
            This parameter overrides ``output``.
        :param chunk_size:
            Size of the internal buffer (in bytes) used to feed data to the
            message digest function if the input stream does not support
            ``memoryview``.
        :return:
            The output stream containing the signed output.
        """

        timestamper = timestamper or self.default_timestamper
        field_name = self.generate_timestamp_field_name()
        if bytes_reserved is None:
            test_signature_cms = timestamper.dummy_response(md_algorithm)
            test_len = len(test_signature_cms.dump()) * 2
            # see sign_pdf comments
            bytes_reserved = test_len + 2 * (test_len // 4)

        timestamp_obj = DocumentTimestamp(bytes_reserved=bytes_reserved)

        cms_writer = PdfCMSEmbedder().write_cms(
            field_name=field_name, writer=pdf_out,
            # for LTA, requiring existing_fields_only doesn't make sense
            # since we should in principle be able to add document timestamps
            # ad infinitum.
            existing_fields_only=False
        )

        next(cms_writer)
        cms_writer.send(SigObjSetup(sig_placeholder=timestamp_obj))

        sig_io = SigIOSetup(
            md_algorithm=md_algorithm,
            in_place=in_place, output=output, chunk_size=chunk_size
        )
        true_digest = cms_writer.send(sig_io)
        timestamp_cms = timestamper.timestamp(true_digest, md_algorithm)
        res_output, sig_contents = cms_writer.send(timestamp_cms)

        # update the DSS
        if validation_context is not None:
            from pyhanko.sign import validation
            if validation_paths is None:
                validation_paths = list(
                    timestamper.validation_paths(validation_context)
                )

            validation.DocumentSecurityStore.add_dss(
                output_stream=res_output, sig_contents=sig_contents,
                paths=validation_paths, validation_context=validation_context
            )

        output = _finalise_output(output, res_output)

        return output

    def update_archival_timestamp_chain(self, reader: PdfFileReader,
                                        validation_context, in_place=True,
                                        output=None,
                                        chunk_size=DEFAULT_CHUNK_SIZE,
                                        default_md_algorithm=DEFAULT_MD):
        """
        Validate the last timestamp in the timestamp chain on a PDF file, and
        write an updated version to an output stream.

        :param reader:
            A :class:`PdfReader` encapsulating the input file.
        :param validation_context:
            :class:`.pyhanko_certvalidator.ValidationContext` object to validate
            the last timestamp.
        :param output:
            Write the output to the specified output stream.
            If ``None``, write to a new :class:`.BytesIO` object.
            Default is ``None``.
        :param in_place:
            Sign the original input stream in-place.
            This parameter overrides ``output``.
        :param chunk_size:
            Size of the internal buffer (in bytes) used to feed data to the
            message digest function if the input stream does not support
            ``memoryview``.
        :param default_md_algorithm:
            Message digest to use if there are no preceding timestamps in the
            file.
        :return:
            The output stream containing the signed output.
        """
        # In principle, we only have to validate that the last timestamp token
        # in the current chain is valid.
        # TODO: add an option to validate the entire timestamp chain
        #  plus all signatures
        from .validation import (
            _establish_timestamp_trust, DocumentSecurityStore,
            get_timestamp_chain
        )

        timestamps = get_timestamp_chain(reader)
        try:
            last_timestamp = next(timestamps)
        except StopIteration:
            logger.warning(
                "Document does not have any document timestamps yet. "
                "This may cause unexpected results."
            )
            last_timestamp = None

        # Validate the previous timestamp if present
        tst_status = None
        if last_timestamp is None:
            md_algorithm = default_md_algorithm
        else:
            last_timestamp.compute_digest()
            last_timestamp.compute_tst_digest()

            tst_token = last_timestamp.signed_data
            expected_imprint = last_timestamp.external_digest

            # run validation logic
            tst_status = _establish_timestamp_trust(
                tst_token, validation_context, expected_imprint
            )

            md_algorithm = tst_status.md_algorithm

        # Prepare output
        if in_place:
            output = reader.stream
        else:
            output = misc.prepare_rw_output_stream(output)
            reader.stream.seek(0)
            misc.chunked_write(
                bytearray(chunk_size), reader.stream, output
            )

        if last_timestamp is not None:
            # update the DSS
            DocumentSecurityStore.add_dss(
                output, last_timestamp.pkcs7_content,
                paths=(tst_status.validation_path,),
                validation_context=validation_context
            )

        # append a new timestamp
        return self.timestamp_pdf(
            IncrementalPdfFileWriter(output), md_algorithm,
            validation_context, in_place=True
        )


DEFAULT_SIGNING_STAMP_STYLE = TextStampStyle(
    stamp_text=SIG_DETAILS_DEFAULT_TEMPLATE, background=STAMP_ART_CONTENT
)
"""
Default stamp style used for visible signatures.
"""


class PdfSigner(PdfTimeStamper):
    """
    Class to handle PDF signatures in general.

    :param signature_meta:
        The specification of the signature to add.
    :param signer:
        :class:`.Signer` object to use to produce the signature object.
    :param timestamper:
        :class:`.TimeStamper` object to use to produce any time stamp tokens
        that might be required.
    :param stamp_style:
        Stamp style specification to determine the visible style of the
        signature, typically an object of type :class:`.TextStampStyle` or
        :class:`.QRStampStyle`. Defaults to
        :const:`.DEFAULT_SIGNING_STAMP_STYLE`.
    :param new_field_spec:
        If a new field is to be created, this parameter allows the caller
        to specify the field's properties in the form of a
        :class:`.SigFieldSpec`. This parameter is only meaningful if
        ``existing_fields_only`` is ``False``.
    """
    _ignore_sv = False

    def __init__(self, signature_meta: PdfSignatureMetadata, signer: Signer,
                 *, timestamper: TimeStamper = None,
                 stamp_style: Optional[BaseStampStyle] = None,
                 new_field_spec: Optional[SigFieldSpec] = None):
        self.signature_meta = signature_meta
        if new_field_spec is not None and \
                new_field_spec.sig_field_name != signature_meta.field_name:
            raise SigningError(
                "Field names specified in SigFieldSpec and "
                "PdfSignatureMetadata do not agree."
            )

        self.signer = signer
        stamp_style = stamp_style or DEFAULT_SIGNING_STAMP_STYLE
        self.stamp_style: BaseStampStyle = stamp_style
        try:
            self.signer_hash_algo = \
                self.signer.get_signature_mechanism(None).hash_algo
        except ValueError:
            self.signer_hash_algo = None

        self.new_field_spec = new_field_spec
        super().__init__(timestamper)

    @property
    def default_md_for_signer(self) -> Optional[str]:
        return self.signature_meta.md_algorithm or self.signer_hash_algo

    def generate_timestamp_field_name(self) -> str:
        """
        Look up the timestamp field name in the :class:`.PdfSignatureMetadata`
        object associated with this :class:`.PdfSigner`.
        If not specified, generate a unique field name using :mod:`uuid`.

        :return:
            The field name, as a (Python) string.
        """
        return self.signature_meta.timestamp_field_name or (
            super().generate_timestamp_field_name()
        )

    def _apply_locking_rules(self, sig_field, md_algorithm,
                             sv_spec: SigSeedValueSpec = None) -> SigMDPSetup:
        # TODO allow equivalent functionality to the /Lock dictionary
        #  to be specified in PdfSignatureMetadata

        # this helper method handles /Lock dictionary and certification
        #  semantics.
        # The fallback rules are messy and ad-hoc; behaviour is mostly
        # documented by tests.

        # read recommendations and/or requirements from the SV dictionary
        if sv_spec is not None and not self._ignore_sv:
            sv_lock_values = {
                SeedLockDocument.LOCK:
                    (MDPPerm.NO_CHANGES,),
                SeedLockDocument.DO_NOT_LOCK:
                    (MDPPerm.FILL_FORMS, MDPPerm.ANNOTATE),
            }.get(sv_spec.lock_document, None)
            sv_lock_value_req = sv_lock_values is not None and (
                sv_spec.flags & SigSeedValFlags.LOCK_DOCUMENT
            )
        else:
            sv_lock_values = None
            sv_lock_value_req = False

        lock = lock_dict = None
        # init the DocMDP value with what the /LockDocument setting in the SV
        # dict recommends. If the constraint is mandatory, it might conflict
        # with the /Lock dictionary, but we'll deal with that later.
        docmdp_perms = sv_lock_values[0] if sv_lock_values is not None else None
        try:
            lock_dict = sig_field['/Lock']
            lock = FieldMDPSpec.from_pdf_object(lock_dict)
            docmdp_value = lock_dict['/P']
            docmdp_perms = MDPPerm(docmdp_value)
            if sv_lock_value_req and docmdp_perms not in sv_lock_values:
                raise SigningError(
                    "Inconsistency in form field data. "
                    "The field lock dictionary imposes the DocMDP policy "
                    f"'{docmdp_perms}', but the seed value "
                    "dictionary's /LockDocument does not allow that."
                )
        except KeyError:
            pass
        except ValueError as e:
            raise SigningError("Failed to read /Lock dictionary", e)

        meta_perms = self.signature_meta.docmdp_permissions
        meta_certify = self.signature_meta.certify

        # only pull meta_perms into the validation if we're trying to make a
        # cert sig, or there already is some other docmdp_perms value available.
        # (in other words, if there's no SV dict or /Lock, and we're not
        # certifying, this will be skipped)
        if meta_perms is not None \
                and (meta_certify or docmdp_perms is not None):
            if sv_lock_value_req and meta_perms not in sv_lock_values:
                # in this case, we have to override
                docmdp_perms = sv_lock_values[0]
            else:
                # choose the stricter option if both are available
                docmdp_perms = meta_perms if docmdp_perms is None else (
                    min(docmdp_perms, meta_perms)
                )
            if docmdp_perms != meta_perms:
                logger.warning(
                    f"DocMDP policy '{meta_perms}', was requested, "
                    f"but the signature field settings do "
                    f"not allow that. Setting '{docmdp_perms}' instead."
                )

        # if not certifying and docmdp_perms is not None, ensure the
        # appropriate permission in the Lock dictionary is set
        if not meta_certify and docmdp_perms is not None:
            if lock_dict is None:
                # set a field lock that doesn't do anything
                sig_field['/Lock'] = lock_dict = generic.DictionaryObject({
                    pdf_name('/Action'): pdf_name('/Include'),
                    pdf_name('/Fields'): generic.ArrayObject()
                })
            lock_dict['/P'] = generic.NumberObject(docmdp_perms.value)

        return SigMDPSetup(
            certify=meta_certify, field_lock=lock, docmdp_perms=docmdp_perms,
            md_algorithm=md_algorithm
        )

    def _enforce_certification_constraints(self, reader: PdfFileReader):
        # TODO we really should take into account the /DocMDP constraints
        #  of _all_ previous signatures

        from .validation import read_certification_data
        cd = read_certification_data(reader)
        # if there is no author signature, we don't have to do anything
        if cd is None:
            return
        if self.signature_meta.certify:
            raise SigningError(
                "Document already contains a certification signature"
            )
        if cd.permission == MDPPerm.NO_CHANGES:
            raise SigningError("Author signature forbids all changes")
        return cd.digest_method

    def _enforce_seed_value_constraints(self, sig_field, validation_path) \
            -> Optional[SigSeedValueSpec]:
        # for testing & debugging
        if self._ignore_sv:
            return None

        sv_dict = sig_field.get('/SV')
        if sv_dict is None:
            return None
        sv_spec: SigSeedValueSpec = SigSeedValueSpec.from_pdf_object(sv_dict)
        flags: SigSeedValFlags = sv_spec.flags

        if sv_spec.cert is not None:
            sv_spec.cert.satisfied_by(self.signer.signing_cert, validation_path)

        if sv_spec.seed_signature_type is not None:
            sv_certify = sv_spec.seed_signature_type.certification_signature()
            if sv_certify != self.signature_meta.certify:
                def _type(certify):
                    return 'a certification' if certify else 'an approval'
                raise SigningError(
                    "The seed value dictionary's /MDP entry specifies that "
                    f"this field should contain {_type(sv_certify)} "
                    f"signature, but {_type(self.signature_meta.certify)} "
                    "was requested."
                )
            sv_mdp_perm = sv_spec.seed_signature_type.mdp_perm
            if sv_certify \
                    and sv_mdp_perm != self.signature_meta.docmdp_permissions:
                raise SigningError(
                    "The seed value dictionary specified that this "
                    "certification signature should use the MDP policy "
                    f"'{sv_mdp_perm}', "
                    f"but '{self.signature_meta.docmdp_permissions}' was "
                    "requested."
                )

        if not flags:
            return sv_spec

        selected_sf = self.signature_meta.subfilter
        if (flags & SigSeedValFlags.SUBFILTER) \
                and sv_spec.subfilters is not None:
            # empty array = no supported subfilters
            if not sv_spec.subfilters:
                raise NotImplementedError(
                    "The signature encodings mandated by the seed value "
                    "dictionary are not supported."
                )
            # standard mandates that we take the first available subfilter
            mandated_sf: SigSeedSubFilter = sv_spec.subfilters[0]
            if selected_sf is not None and mandated_sf != selected_sf:
                raise SigningError(
                    "The seed value dictionary mandates subfilter '%s', "
                    "but '%s' was requested." % (
                        mandated_sf.value, selected_sf.value
                    )
                )

        # SV dict serves as a source of defaults as well
        if selected_sf is None and sv_spec.subfilters is not None:
            selected_sf = sv_spec.subfilters[0]

        if (flags & SigSeedValFlags.APPEARANCE_FILTER) \
                and sv_spec.appearance is not None:
            raise SigningError(
                "pyHanko does not define any named appearances, but "
                "the seed value dictionary requires that the named appearance "
                f"'{sv_spec.appearance}' be used."
            )

        if (flags & SigSeedValFlags.ADD_REV_INFO) \
                and sv_spec.add_rev_info is not None:
            if sv_spec.add_rev_info != \
                    self.signature_meta.embed_validation_info:
                raise SigningError(
                    "The seed value dict mandates that revocation info %sbe "
                    "added; adjust PdfSignatureMetadata settings accordingly."
                    % ("" if sv_spec.add_rev_info else "not ")
                )
            if sv_spec.add_rev_info and \
                    selected_sf != SigSeedSubFilter.ADOBE_PKCS7_DETACHED:
                raise SigningError(
                    "The seed value dict mandates that Adobe-style revocation "
                    "info be added; this requires subfilter '%s'" % (
                        SigSeedSubFilter.ADOBE_PKCS7_DETACHED.value
                    )
                )
        if (flags & SigSeedValFlags.DIGEST_METHOD) \
                and sv_spec.digest_methods is not None:
            selected_md = self.default_md_for_signer
            if selected_md is not None:
                selected_md = selected_md.lower()
                if selected_md not in sv_spec.digest_methods:
                    raise SigningError(
                        "The selected message digest %s is not allowed by the "
                        "seed value dictionary. Please select one of %s."
                        % (selected_md, ", ".join(sv_spec.digest_methods))
                    )

        if flags & SigSeedValFlags.REASONS:
            # standard says that omission of the /Reasons key amounts to
            #  a prohibition in this case
            must_omit = not sv_spec.reasons or sv_spec.reasons == ["."]
            reason_given = self.signature_meta.reason
            if must_omit and reason_given is not None:
                raise SigningError(
                    "The seed value dictionary prohibits giving a reason "
                    "for signing."
                )
            if not must_omit and reason_given not in sv_spec.reasons:
                raise SigningError(
                    "Reason \"%s\" is not a valid reason for signing, "
                    "please choose one of the following: %s." % (
                        reason_given,
                        ", ".join("\"%s\"" % s for s in sv_spec.reasons)
                    )
                )

        # LOCK_DOCUMENT is only enforced later
        return sv_spec

    def sign_pdf(self, pdf_out: BasePdfFileWriter,
                 existing_fields_only=False, bytes_reserved=None, *,
                 appearance_text_params=None, in_place=False,
                 output=None, chunk_size=DEFAULT_CHUNK_SIZE):
        """
        Sign a PDF file using the provided output writer.

        :param pdf_out:
            A PDF file writer (usually an :class:`.IncrementalPdfFileWriter`)
            containing the data to sign.
        :param existing_fields_only:
            If ``True``, never create a new empty signature field to contain
            the signature.
            If ``False``, a new field may be created if no field matching
            :attr:`~.PdfSignatureMetadata.field_name` exists.
        :param bytes_reserved:
            Bytes to reserve for the CMS object in the PDF file.
            If not specified, make an estimate based on a dummy signature.
        :param appearance_text_params:
            Dictionary with text parameters that will be passed to the
            signature appearance constructor (if applicable).
        :param output:
            Write the output to the specified output stream.
            If ``None``, write to a new :class:`.BytesIO` object.
            Default is ``None``.
        :param in_place:
            Sign the original input stream in-place.
            This parameter overrides ``output``.
        :param chunk_size:
            Size of the internal buffer (in bytes) used to feed data to the
            message digest function if the input stream does not support
            ``memoryview``.
        :return:
            The output stream containing the signed data.
        """

        timestamper = self.default_timestamper

        # TODO if PAdES is requested, set the ESIC extension to the proper value

        timestamp = datetime.now(tz=tzlocal.get_localzone())
        signature_meta: PdfSignatureMetadata = self.signature_meta
        signer: Signer = self.signer
        validation_context = signature_meta.validation_context
        if signature_meta.embed_validation_info:
            if validation_context is None:
                raise SigningError(
                    'A validation context must be provided if '
                    'validation/revocation info is to be embedded into the '
                    'signature.'
                )
            elif not validation_context._allow_fetching:
                logger.warning(
                    "Validation/revocation info will be embedded, but "
                    "fetching is not allowed. This may give rise to unexpected "
                    "results."
                )
        validation_paths = []
        signer_cert_validation_path = None
        weak_hash_algos = ()
        if validation_context is not None:
            weak_hash_algos = validation_context.weak_hash_algos
            # validate cert
            # (this also keeps track of any validation data automagically)
            validator = CertificateValidator(
                signer.signing_cert, intermediate_certs=signer.cert_registry,
                validation_context=validation_context
            )
            try:
                signer_cert_validation_path = validator.validate_usage(
                    signature_meta.signer_key_usage
                )
            except (PathBuildingError, PathValidationError) as e:
                raise SigningError(
                    "The signer's certificate could not be validated", e
                )
            validation_paths.append(signer_cert_validation_path)

            # If LTA:
            # if the original document already included a document timestamp,
            # we need to collect revocation information for it, to preserve
            # the integrity of the timestamp chain
            from .validation import get_timestamp_chain
            if signature_meta.use_pades_lta \
                    and isinstance(pdf_out, IncrementalPdfFileWriter):

                # try to grab the most recent document timestamp
                last_ts = None
                try:
                    last_ts = next(get_timestamp_chain(pdf_out.prev))
                except StopIteration:
                    pass

                if last_ts is not None:
                    ts_validator = CertificateValidator(
                        last_ts.signer_cert,
                        intermediate_certs=signer.cert_registry,
                        validation_context=validation_context
                    )
                    try:
                        last_ts_validation_path = ts_validator.validate_usage(
                            set(), extended_key_usage={"time_stamping"}
                        )
                    except (PathBuildingError, PathValidationError) as e:
                        raise SigningError(
                            "Requested a PAdES-LTA signature on an existing "
                            "document, but the most recent timestamp "
                            "could not be validated.", e
                        )
                    validation_paths.append(last_ts_validation_path)

        cms_writer = PdfCMSEmbedder(
            new_field_spec=self.new_field_spec
        ).write_cms(
            field_name=signature_meta.field_name, writer=pdf_out,
            existing_fields_only=existing_fields_only
        )

        # let the CMS writer put in a field for us
        sig_field_ref = next(cms_writer)

        sig_field = sig_field_ref.get_object()

        # process the signature's seed value dictionary
        sv_spec = self._enforce_seed_value_constraints(
            sig_field, signer_cert_validation_path
        )

        author_sig_md_algorithm = None
        if isinstance(pdf_out, IncrementalPdfFileWriter):
            author_sig_md_algorithm = self._enforce_certification_constraints(
                pdf_out.prev
            )
        # priority order for the message digest algorithm
        #  (1) If signature_meta specifies a message digest algorithm, use it
        #      (it has been cleared by the SV dictionary checker already)
        #  (2) Use the first algorithm specified in the seed value dictionary,
        #      if a suggestion is present
        #  (3) If there is a certification signature, use the digest method
        #      specified there.
        #  (4) fall back to DEFAULT_MD
        if sv_spec is not None and sv_spec.digest_methods:
            sv_md_algorithm = sv_spec.digest_methods[0]
        else:
            sv_md_algorithm = None

        if self.default_md_for_signer is not None:
            md_algorithm = self.default_md_for_signer
        elif sv_md_algorithm is not None:
            md_algorithm = sv_md_algorithm
        elif author_sig_md_algorithm is not None:
            md_algorithm = author_sig_md_algorithm
        else:
            md_algorithm = DEFAULT_MD

        if md_algorithm in weak_hash_algos:
            raise SigningError(
                f"The hash algorithm {md_algorithm} is considered weak in the "
                f"specified validation context. Please choose another."
            )

        # same for the subfilter: try signature_meta and SV dict, fall back
        #  to /adbe.pkcs7.detached by default
        subfilter = signature_meta.subfilter
        if subfilter is None:
            if sv_spec is not None and sv_spec.subfilters:
                subfilter = sv_spec.subfilters[0]
            else:
                subfilter = SigSeedSubFilter.ADOBE_PKCS7_DETACHED
        use_pades = subfilter == SigSeedSubFilter.PADES

        ts_validation_paths = None
        ts_required = sv_spec is not None and sv_spec.timestamp_required
        if ts_required and timestamper is None:
            timestamper = sv_spec.build_timestamper()

        if timestamper is not None:
            # this might hit the TS server, but the response is cached
            # and it collects the certificates we need to verify the TS response
            timestamper.dummy_response(md_algorithm)
            if validation_context is not None:
                ts_validation_paths = list(
                    timestamper.validation_paths(validation_context)
                )
                validation_paths += ts_validation_paths

        # do we need adobe-style revocation info?
        if signature_meta.embed_validation_info and not use_pades:
            assert validation_context is not None  # checked earlier
            revinfo = Signer.format_revinfo(
                ocsp_responses=validation_context.ocsps,
                crls=validation_context.crls
            )
        else:
            # PAdES prescribes another mechanism for embedding revocation info
            revinfo = None

        if bytes_reserved is None:
            md_spec = get_pyca_cryptography_hash(md_algorithm)
            test_md = hashes.Hash(md_spec).finalize()
            test_signature_cms = signer.sign(
                test_md, md_algorithm,
                timestamp=timestamp, use_pades=use_pades,
                dry_run=True, revocation_info=revinfo,
                timestamper=timestamper,
                cades_signed_attr_meta=signature_meta.cades_signed_attr_spec
            )
            test_len = len(test_signature_cms.dump()) * 2
            # External actors such as timestamping servers can't be relied on to
            # always return exactly the same response, so we build in a 50%
            # error margin (+ ensure that bytes_reserved is even)
            bytes_reserved = test_len + 2 * (test_len // 4)

        sig_mdp_setup = self._apply_locking_rules(
            sig_field, md_algorithm=md_algorithm, sv_spec=sv_spec
        )

        # Pass instructions to the CMS writer to set up the
        # (PDF) signature object and its appearance
        name_specified = signature_meta.name
        sig_appearance = SigAppearanceSetup(
            style=self.stamp_style,
            name=name_specified or self.signer.subject_name,
            timestamp=timestamp, text_params=appearance_text_params
        )
        sig_obj = SignatureObject(
            bytes_reserved=bytes_reserved, subfilter=subfilter,
            timestamp=timestamp,
            name=name_specified if name_specified else None,
            location=signature_meta.location, reason=signature_meta.reason,
        )
        cms_writer.send(SigObjSetup(
            sig_placeholder=sig_obj,
            mdp_setup=sig_mdp_setup,
            appearance_setup=sig_appearance
        ))

        # pass in I/O parameters, get back a hash
        true_digest = cms_writer.send(SigIOSetup(
            md_algorithm=md_algorithm, in_place=in_place, chunk_size=chunk_size,
            output=output
        ))

        # Tell the signer to construct a CMS object
        signature_cms = signer.sign(
            true_digest, md_algorithm,
            timestamp=timestamp, use_pades=use_pades,
            revocation_info=revinfo, timestamper=timestamper,
            cades_signed_attr_meta=signature_meta.cades_signed_attr_spec
        )
        # ... and feed it to the CMS writer
        res_output, sig_contents = cms_writer.send(signature_cms)

        if use_pades and signature_meta.embed_validation_info:
            from pyhanko.sign import validation
            validation.DocumentSecurityStore.add_dss(
                output_stream=res_output, sig_contents=sig_contents,
                paths=validation_paths, validation_context=validation_context
            )

            if timestamper is not None and signature_meta.use_pades_lta:
                # append an LTV document timestamp
                w = IncrementalPdfFileWriter(res_output)
                self.timestamp_pdf(
                    w, md_algorithm, validation_context,
                    validation_paths=ts_validation_paths, in_place=True,
                    timestamper=timestamper, chunk_size=chunk_size
                )

        # we put the finalisation step after the DSS manipulations, since
        # otherwise we'd also run into issues with non-seekable output buffers
        output = _finalise_output(output, res_output)
        return output


def embed_payload_with_cms(pdf_writer: BasePdfFileWriter,
                           file_spec_string: str,
                           payload: embed.EmbeddedFileObject,
                           cms_obj: cms.ContentInfo, extension='.sig',
                           file_name: Optional[str] = None,
                           file_spec_kwargs=None, cms_file_spec_kwargs=None):
    """
    Embed some data as an embedded file stream into a PDF, and associate it
    with a CMS object.

    The resulting CMS object will also be turned into an embedded file, and
    associated with the original payload through a related file relationship.

    This can be used to bundle (non-PDF) detached signatures with PDF
    attachments, for example.

    :param pdf_writer:
        The PDF writer to use.
    :param file_spec_string:
        See :attr:`embed.FileSpec.file_spec_string`.
    :param payload:
        Payload object.
    :param cms_obj:
        CMS object pertaining to the payload.
    :param extension:
        File extension to use for the CMS attachment.
    :param file_name:
        See :attr:`embed.FileSpec.file_name`.
    :param file_spec_kwargs:
        Extra arguments to pass to the :class:`embed.FileSpec` constructor
        for the main attachment specification.
    :param cms_file_spec_kwargs:
        Extra arguments to pass to the :class:`embed.FileSpec` constructor
        for the CMS attachment specification.
    """

    # prepare an embedded file object for the signature
    now = datetime.now(tz=tzlocal.get_localzone())
    cms_ef_obj = embed.EmbeddedFileObject.from_file_data(
        pdf_writer=pdf_writer,
        data=cms_obj.dump(), compress=False,
        mime_type='application/pkcs7-mime',
        params=embed.EmbeddedFileParams(
            creation_date=now, modification_date=now
        )
    )

    # replace extension
    cms_data_f = file_spec_string.rsplit('.', 1)[0] + extension

    # deal with new-style Unicode file names
    cms_data_uf = uf_related_files = None
    if file_name is not None:
        cms_data_uf = file_name.rsplit('.', 1)[0] + extension
        uf_related_files = [
            embed.RelatedFileSpec(cms_data_uf, embedded_data=cms_ef_obj)
        ]

    spec = embed.FileSpec(
        file_spec_string=file_spec_string, file_name=file_name,
        embedded_data=payload,
        f_related_files=[
            embed.RelatedFileSpec(cms_data_f, embedded_data=cms_ef_obj)
        ],
        uf_related_files=uf_related_files,
        **(file_spec_kwargs or {}),
    )

    embed.embed_file(pdf_writer, spec)

    # also embed the CMS data as a standalone attachment
    cms_spec = embed.FileSpec(
        file_spec_string=cms_data_f, file_name=cms_data_uf,
        embedded_data=cms_ef_obj, **(cms_file_spec_kwargs or {})
    )
    embed.embed_file(pdf_writer, cms_spec)
