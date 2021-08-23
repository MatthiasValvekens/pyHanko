"""
This module defines utility classes to format CMS objects for use in PDF
signatures.
"""

import logging
from dataclasses import dataclass
from typing import Optional, Union, IO
from datetime import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.ec import \
    EllipticCurvePrivateKey, ECDSA
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import pkcs12
from asn1crypto import x509, cms, core, keys, algos, pdf as asn1_pdf
from asn1crypto.algos import SignedDigestAlgorithm
from pyhanko.sign.general import (
    CertificateStore, SimpleCertificateStore,
    SigningError, optimal_pss_params, simple_cms_attribute,
    get_pyca_cryptography_hash, as_signing_certificate_v2,
    load_private_key_from_pemder, load_cert_from_pemder,
    load_certs_from_pemder, _process_pss_params,
    _translate_pyca_cryptography_cert_to_asn1,
    _translate_pyca_cryptography_key_to_asn1
)
from pyhanko.pdf_utils import misc
from pyhanko.sign.ades.api import CAdESSignedAttrSpec

__all__ = [
    'Signer', 'SimpleSigner', 'ExternalSigner',
    'PdfCMSSignedAttributes'
]

logger = logging.getLogger(__name__)


class Signer:
    """
    Abstract signer object that is agnostic as to where the cryptographic
    operations actually happen.

    As of now, pyHanko provides two implementations:

    * :class:`.SimpleSigner` implements the easy case where all the key material
      can be loaded into memory.
    * :class:`~pyhanko.sign.pkcs11.PKCS11Signer` implements a signer that is
      capable of interfacing with a PKCS11 device
      (see also :class:`~pyhanko.sign.beid.BEIDSigner`).

    :param prefer_pss:
        When signing using an RSA key, prefer PSS padding to legacy PKCS#1 v1.5
        padding. Default is ``False``. This option has no effect on non-RSA
        signatures.
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

    def get_signature_mechanism(self, digest_algorithm):
        """
        Get the signature mechanism for this signer to use.
        If :attr:`signature_mechanism` is set, it will be used.
        Otherwise, this method will attempt to put together a default
        based on mechanism used in the signer's certificate.

        :param digest_algorithm:
            Digest algorithm to use as part of the signature mechanism.
            Only used if a signature mechanism object has to be put together
            on-the-fly.
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
            # with ECDSA, RFC 5753 requires us to encode the digest
            # algorithm together with the signing algorithm.
            # The correspondence with the digestAlgorithm field in CMS is
            # verified separately.
            if digest_algorithm is None:
                raise ValueError(
                    "Digest algorithm required for ECDSA"
                )
            mech = digest_algorithm + '_ecdsa'
        elif algo == 'rsa':
            if self.prefer_pss:
                mech = 'rsassa_pss'
                if digest_algorithm is None:
                    raise ValueError(
                        "Digest algorithm required for RSASSA-PSS"
                    )
                params = optimal_pss_params(self.signing_cert, digest_algorithm)
            elif digest_algorithm is not None:
                mech = digest_algorithm + '_rsa'
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
                     cades_meta: CAdESSignedAttrSpec = None,
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
                'signing_certificate_v2',
                as_signing_certificate_v2(self.signing_cert)
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

        # the piece of data we'll actually sign is a DER-encoded version of the
        # signed attributes of our message
        signed_attrs = self.signed_attrs(
            data_digest, digest_algorithm, timestamp,
            revocation_info=revocation_info, use_pades=use_pades,
            timestamper=timestamper, cades_meta=cades_signed_attr_meta,
            dry_run=dry_run, content_type=content_type
        )
        if isinstance(content_type, core.ObjectIdentifier):
            content_type = content_type.native

        cms_version = 'v1' if content_type == 'data' else 'v3'
        return self.sign_prescribed_attributes(
            digest_algorithm, signed_attrs,
            cms_version=cms_version, dry_run=dry_run, timestamper=timestamper,
            encap_content_info=encap_content_info
        )

    def sign_prescribed_attributes(self, digest_algorithm: str,
                                   signed_attrs: cms.CMSAttributes,
                                   cms_version='v1',
                                   dry_run=False, timestamper=None,
                                   encap_content_info=None) -> cms.ContentInfo:
        """
        .. versionadded: 0.7.0

        Start the CMS signing process with the prescribed set of signed
        attributes.

        :param digest_algorithm:
            Digest algorithm to use. This should be the same digest method
            as the one used to hash the (external) content.
        :param signed_attrs:
            CMS attributes to sign.
        :param dry_run:
            If ``True``, the actual signing step will be replaced with
            a placeholder.

            In a PDF signing context, this is necessary to estimate the size
            of the signature container before computing the actual digest of
            the document.
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
        :param cms_version:
            CMS version to use.
        :param encap_content_info:
            Data to encapsulate in the CMS object.

            .. danger::
                This parameter is internal API, and must not be used to produce
                PDF signatures.
        :return:
            An :class:`~.asn1crypto.cms.ContentInfo` object.
        """

        encap_content_info = encap_content_info or {'content_type': 'data'}
        digest_algorithm = digest_algorithm.lower()
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
            'version': cms_version,
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
                          chunk_size=misc.DEFAULT_CHUNK_SIZE,
                          max_read=None) -> cms.ContentInfo:
        """
        Produce a CMS signature for an arbitrary data stream
        (not necessarily PDF data).

        .. versionadded:: 0.7.0

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
        if isinstance(input_data,
                      (cms.ContentInfo, cms.EncapsulatedContentInfo)):
            h.update(bytes(input_data['content']))
            if detached:
                encap_content_info = {
                    'content_type': input_data['content_type']
                }
            else:
                encap_content_info = input_data
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
    def load_pkcs12(cls, pfx_file, ca_chain_files=None,
                    other_certs=None, passphrase=None,
                    signature_mechanism=None, prefer_pss=False):
        """
        Load certificates and key material from a PCKS#12 archive
        (usually ``.pfx`` or ``.p12`` files).

        :param pfx_file:
            Path to the PKCS#12 archive.
        :param ca_chain_files:
            Path to (PEM/DER) files containing other relevant certificates
            not included in the PKCS#12 file.
        :param other_certs:
            Other relevant certificates, specified as a list of
            :class:`.asn1crypto.x509.Certificate` objects.
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
        try:
            (private_key, cert, other_certs_pkcs12) \
                = pkcs12.load_key_and_certificates(pfx_bytes, passphrase)
        except (IOError, ValueError, TypeError) as e:
            logger.error(
                'Could not load key material from PKCS#12 file', exc_info=e
            )
            return None
        kinfo = _translate_pyca_cryptography_key_to_asn1(private_key)
        cert = _translate_pyca_cryptography_cert_to_asn1(cert)
        other_certs_pkcs12 = set(map(
            _translate_pyca_cryptography_cert_to_asn1,
            other_certs_pkcs12
        ))

        cs = SimpleCertificateStore()
        certs_to_register = ca_chain | other_certs_pkcs12
        if other_certs is not None:
            certs_to_register |= set(other_certs)
        cs.register_multiple(certs_to_register)
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
        except (IOError, ValueError, TypeError) as e:
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


class ExternalSigner(Signer):
    """
    Class to help formatting CMS objects for use with remote signing.
    It embeds a fixed signature value into the CMS, set at initialisation.

    Intended for use with :ref:`interrupted-signing`.
    """

    def __init__(self, signing_cert: x509.Certificate,
                 cert_registry: CertificateStore,
                 signature_value: bytes,
                 signature_mechanism: SignedDigestAlgorithm = None,
                 prefer_pss=False):
        self.signing_cert = signing_cert
        self.cert_registry = cert_registry
        self.signature_mechanism = signature_mechanism
        self._signature_value = signature_value
        super().__init__(prefer_pss=prefer_pss)

    def sign_raw(self, data: bytes, digest_algorithm: str, dry_run=False) \
            -> bytes:
        """
        Return a fixed signature value.
        """
        return self._signature_value


# TODO consider deprecating the current signed_attrs kwargs in favour of this
#  dataclass

@dataclass(frozen=True)
class PdfCMSSignedAttributes:
    """
    .. versionadded:: 0.7.0

    Serialisable container class describing input for various signed attributes
    in a CMS object for a PDF signature.
    """

    signing_time: Optional[datetime] = None
    """
    Timestamp for the ``signingTime`` attribute. Will be ignored in a PAdES
    context.
    """

    adobe_revinfo_attr: Optional[cms.CMSAttribute] = None
    """
    Adobe-style signed revocation info attribute.
    """

    cades_signed_attrs: Optional[CAdESSignedAttrSpec] = None
    """
    Optional settings for CAdES-style signed attributes.
    """
