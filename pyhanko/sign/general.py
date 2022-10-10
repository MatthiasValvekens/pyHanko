"""
General tools related to Cryptographic Message Syntax (CMS) signatures,
not necessarily to the extent implemented in the PDF specification.

CMS is defined in :rfc:`5652`. To parse CMS messages, pyHanko relies heavily on
`asn1crypto <https://github.com/wbond/asn1crypto>`_.
"""

import hashlib
import logging
from dataclasses import dataclass
from typing import IO, Iterable, List, Optional, Tuple, Union

from asn1crypto import algos, cms, keys, pem, tsp, x509
from asn1crypto.algos import SignedDigestAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from pyhanko_certvalidator.registry import (
    CertificateStore,
    SimpleCertificateStore,
)

from pyhanko.pdf_utils import misc

__all__ = [
    'simple_cms_attribute',
    'find_cms_attribute', 'find_unique_cms_attribute',
    'NonexistentAttributeError', 'MultivaluedAttributeError',
    'CertificateStore', 'SimpleCertificateStore',
    'SigningError', 'UnacceptableSignerError',
    'SignedDataCerts', 'extract_signer_info', 'extract_certificate_info',
    'load_certs_from_pemder', 'load_cert_from_pemder',
    'load_private_key_from_pemder',
    'load_certs_from_pemder_data', 'load_private_key_from_pemder_data',
    'get_cms_hash_algo_for_mechanism', 'get_pyca_cryptography_hash',
    'optimal_pss_params', 'process_pss_params', 'as_signing_certificate',
    'as_signing_certificate_v2', 'match_issuer_serial',
    'check_ess_certid', 'CMSExtractionError', 'byte_range_digest',
    'ValueErrorWithMessage', 'CMSStructuralError'
]

logger = logging.getLogger(__name__)


class ValueErrorWithMessage(ValueError):
    """
    Value error with a failure message attribute that can be conveniently
    extracted, instead of having to rely on extracting exception args
    generically.
    """
    def __init__(self, failure_message):
        self.failure_message = str(failure_message)


class CMSStructuralError(ValueErrorWithMessage):
    """Structural error in a CMS object."""


class CMSExtractionError(ValueErrorWithMessage):
    pass


def simple_cms_attribute(attr_type, value):
    """
    Convenience method to quickly construct a CMS attribute object with
    one value.

    :param attr_type:
        The attribute type, as a string or OID.
    :param value:
        The value.
    :return:
        A :class:`.cms.CMSAttribute` object.
    """
    return cms.CMSAttribute({
        'type': cms.CMSAttributeType(attr_type),
        'values': (value,)
    })


class NonexistentAttributeError(KeyError):
    pass


class MultivaluedAttributeError(ValueError):
    pass


def find_cms_attribute(attrs, name):
    """
    Find and return CMS attribute values of a given type.

    .. note::
        This function will also check for duplicates, but not in the sense
        of multivalued attributes. In other words: multivalued attributes
        are allowed; listing the same attribute OID more than once is not.

    :param attrs:
        The :class:`.cms.CMSAttributes` object.
    :param name:
        The attribute type as a string (as defined in ``asn1crypto``).
    :return:
        The values associated with the requested type, if present.
    :raise NonexistentAttributeError:
        Raised when no such type entry could be found in the
        :class:`.cms.CMSAttributes` object.
    :raise CMSStructuralError:
        Raised if the given OID occurs more than once.
    """

    found_values = None
    if attrs:
        for attr in attrs:
            if attr['type'].native == name:
                if found_values is not None:
                    raise CMSStructuralError(
                        f"Attribute {name!r} was duplicated"
                    )
                found_values = attr['values']

    if found_values is not None:
        return found_values
    else:
        raise NonexistentAttributeError(f'Unable to locate attribute {name}.')


def find_unique_cms_attribute(attrs, name):
    """
    Find and return a unique CMS attribute value of a given type.

    :param attrs:
        The :class:`.cms.CMSAttributes` object.
    :param name:
        The attribute type as a string (as defined in ``asn1crypto``).
    :return:
        The value associated with the requested type, if present.
    :raise NonexistentAttributeError:
        Raised when no such type entry could be found in the
        :class:`.cms.CMSAttributes` object.
    :raise MultivaluedAttributeError:
        Raised when the attribute's cardinality is not 1.
    """
    values = find_cms_attribute(attrs, name)
    if len(values) != 1:
        raise MultivaluedAttributeError(
            f"Expected single-valued {name} attribute, but found "
            f"{len(values)} values"
        )
    return values[0]


def as_signing_certificate(cert: x509.Certificate) -> tsp.SigningCertificate:
    """
    Format an ASN.1 ``SigningCertificate`` object, where the certificate
    is identified by its SHA-1 digest.

    :param cert:
        An X.509 certificate.
    :return:
        A :class:`tsp.SigningCertificate` object referring to the original
        certificate.
    """
    # see RFC 2634, § 5.4.1
    return tsp.SigningCertificate({
        'certs': [
            tsp.ESSCertID({
                'cert_hash': hashlib.sha1(cert.dump()).digest(),
                'issuer_serial': {
                    'issuer': [
                        x509.GeneralName({'directory_name': cert.issuer})
                    ],
                    'serial_number': cert['tbs_certificate']['serial_number']
                }
            })
        ]
    })


def as_signing_certificate_v2(cert: x509.Certificate, hash_algo='sha256') \
        -> tsp.SigningCertificateV2:
    """
    Format an ASN.1 ``SigningCertificateV2`` value, where the certificate
    is identified by the hash algorithm specified.

    :param cert:
        An X.509 certificate.
    :param hash_algo:
        Hash algorithm to use to digest the certificate.
        Default is SHA-256.
    :return:
        A :class:`tsp.SigningCertificateV2` object referring to the original
        certificate.
    """

    # see RFC 5035
    hash_spec = get_pyca_cryptography_hash(hash_algo)
    md = hashes.Hash(hash_spec)
    md.update(cert.dump())
    digest_value = md.finalize()
    return tsp.SigningCertificateV2({
        'certs': [
            tsp.ESSCertIDv2({
                'hash_algorithm': {'algorithm': hash_algo},
                'cert_hash': digest_value,
                'issuer_serial': {
                    'issuer': [
                        x509.GeneralName({'directory_name': cert.issuer})
                    ],
                    'serial_number': cert['tbs_certificate']['serial_number']
                }
            })
        ]
    })


def check_ess_certid(cert: x509.Certificate,
                     certid: Union[tsp.ESSCertID, tsp.ESSCertIDv2]):
    """
    Match an ``ESSCertID`` value against a certificate.

    :param cert:
        The certificate to match against.
    :param certid:
        The ``ESSCertID`` value.
    :return:
        ``True`` if the ``ESSCertID`` matches the certificate,
        ``False`` otherwise.
    """
    if isinstance(certid, tsp.ESSCertID):
        hash_algo = 'sha1'
    else:
        hash_algo = certid['hash_algorithm']['algorithm'].native

    hash_spec = get_pyca_cryptography_hash(hash_algo)
    md = hashes.Hash(hash_spec)
    md.update(cert.dump())
    digest_value = md.finalize()
    expected_digest_value = certid['cert_hash'].native
    if digest_value != expected_digest_value:
        return False
    expected_issuer_serial: tsp.IssuerSerial = certid['issuer_serial']
    return (
        not expected_issuer_serial or
        match_issuer_serial(expected_issuer_serial, cert)
    )


def match_issuer_serial(expected_issuer_serial:
                        Union[cms.IssuerAndSerialNumber, tsp.IssuerSerial],
                        cert: x509.Certificate) -> bool:
    """
    Match the issuer and serial number of an X.509 certificate against some
    expected identifier.
    
    :param expected_issuer_serial: 
        A certificate identifier, either :class:`cms.IssuerAndSerialNumber`
        or :class:`tsp.IssuerSerial`.
    :param cert: 
        An :class:`x509.Certificate`.
    :return:
        ``True`` if there's a match, ``False`` otherwise.
    """
    # don't decode
    # (well, the decoded version is probably cached somewhere anyhow, but
    # decoding serial numbers as integers isn't terribly good practice)
    serial_asn1 = cert['tbs_certificate']['serial_number']
    expected_issuer = expected_issuer_serial['issuer']

    # This case is for IssuerSerial in an ESSCertId.
    # Since this function applies to regular certs (i.e. not attribute certs)
    # we need to check that the expected issuer value only contains one
    # name of type directoryName.
    if isinstance(expected_issuer, x509.GeneralNames):
        if len(expected_issuer) != 1 or \
                expected_issuer[0].name != 'directory_name':
            return False
        expected_issuer = expected_issuer[0].chosen

    # Some certificates contain name elements that can't be compared, e.g.
    # because they violate the stringprep profile for directory strings.
    # Instead of failing those outright, we attempt a byte-for-byte comparison
    # first. If the encoding happens to match exactly, we're good. If not,
    # we invoke (asn1crypto's implementation of) the directory name matching
    # routine.
    try:
        issuer_match = (
            expected_issuer.dump() == cert.issuer.dump()
            or expected_issuer == cert.issuer
        )
    except ValueError:
        issuer_match = False
    return (
        issuer_match and expected_issuer_serial['serial_number'] == serial_asn1
    )


class SigningError(ValueError):
    """
    Error encountered while signing a file.
    """
    def __init__(self, msg: str, *args):
        self.msg = msg
        super().__init__(msg, *args)


class UnacceptableSignerError(SigningError):
    """
    Error raised when a signer was judged unacceptable.
    """
    pass


def get_pyca_cryptography_hash(algorithm, prehashed=False) \
        -> Union[hashes.HashAlgorithm, Prehashed]:
    if algorithm.lower() == 'shake256':
        # force the output length to 64 bytes = 512 bits
        hash_algo = hashes.SHAKE256(digest_size=64)
    else:
        hash_algo = getattr(hashes, algorithm.upper())()
    return Prehashed(hash_algo) if prehashed else hash_algo


def get_cms_hash_algo_for_mechanism(mech: SignedDigestAlgorithm) -> str:
    """
    Internal function that takes a :class:`.SignedDigestAlgorithm` instance
    and returns the name of the digest algorithm that has to be used to compute
    the ``messageDigest`` attribute.

    :param mech:
        A signature mechanism.
    :return:
        A digest algorithm name.
    """
    # anticipate resolution of this discussion:
    # https://github.com/wbond/asn1crypto/pull/230

    sig_algo = mech.signature_algo
    if sig_algo == 'ed25519':
        return 'sha512'
    elif sig_algo == 'ed448':
        return 'shake256'
    else:
        return mech.hash_algo


def process_pss_params(params: algos.RSASSAPSSParams, digest_algorithm,
                       prehashed=False):
    """
    Extract PSS padding settings and message digest from an
    ``RSASSAPSSParams`` value.

    Internal API.
    """

    hash_algo: algos.DigestAlgorithm = params['hash_algorithm']
    md_name = hash_algo['algorithm'].native
    if md_name.casefold() != digest_algorithm.casefold():
        raise ValueError(
            f"PSS MD '{md_name}' must agree with signature "
            f"MD '{digest_algorithm}'."
        )  # pragma: nocover
    mga: algos.MaskGenAlgorithm = params['mask_gen_algorithm']
    if not mga['algorithm'].native == 'mgf1':
        raise NotImplementedError("Only MFG1 is supported")

    mgf_md_name = mga['parameters']['algorithm'].native

    if mgf_md_name != md_name:
        logger.warning(
            f"Message digest for MGF1 is {mgf_md_name}, and the one used for "
            f"signing is {md_name}. If these do not agree, some software may "
            f"refuse to validate the signature."
        )
    salt_len: int = params['salt_length'].native

    mgf_md = get_pyca_cryptography_hash(mgf_md_name, prehashed=False)
    md = get_pyca_cryptography_hash(md_name, prehashed=prehashed)
    pss_padding = padding.PSS(
        mgf=padding.MGF1(algorithm=mgf_md),
        salt_length=salt_len
    )
    return pss_padding, md


def optimal_pss_params(cert: x509.Certificate, digest_algorithm: str) \
        -> algos.RSASSAPSSParams:
    """
    Figure out the optimal RSASSA-PSS parameters for a given certificate.
    The subject's public key must be an RSA key.

    :param cert:
        An RSA X.509 certificate.
    :param digest_algorithm:
        The digest algorithm to use.
    :return:
        RSASSA-PSS parameters.
    """

    digest_algorithm = digest_algorithm.lower()

    key: RSAPublicKey = serialization.load_der_public_key(
        cert.public_key.dump()
    )
    md = get_pyca_cryptography_hash(digest_algorithm)
    # the PSS salt calculation function is not in the .pyi file, apparently.
    # noinspection PyUnresolvedReferences
    optimal_salt_len = padding.calculate_max_pss_salt_length(key, md)
    return algos.RSASSAPSSParams({
        'hash_algorithm': algos.DigestAlgorithm({
            'algorithm': digest_algorithm
        }),
        'mask_gen_algorithm': algos.MaskGenAlgorithm({
            'algorithm': 'mgf1',
            'parameters': algos.DigestAlgorithm({
                'algorithm': digest_algorithm
            }),
        }),
        'salt_length': optimal_salt_len
    })


def load_certs_from_pemder(cert_files):
    """
    A convenience function to load PEM/DER-encoded certificates from files.

    :param cert_files:
        An iterable of file names.
    :return:
        A generator producing :class:`.asn1crypto.x509.Certificate` objects.
    """
    for cert_file in cert_files:
        with open(cert_file, 'rb') as f:
            cert_data_bytes = f.read()
        yield from load_certs_from_pemder_data(cert_data_bytes)


def load_certs_from_pemder_data(cert_data_bytes: bytes):
    """
    A convenience function to load PEM/DER-encoded certificates from
    binary data.

    :param cert_data_bytes:
        ``bytes`` object from which to extract certificates.
    :return:
        A generator producing :class:`.asn1crypto.x509.Certificate` objects.
    """
    # use the pattern from the asn1crypto docs
    # to distinguish PEM/DER and read multiple certs
    # from one PEM file (if necessary)
    if pem.detect(cert_data_bytes):
        pems = pem.unarmor(cert_data_bytes, multiple=True)
        for type_name, _, der in pems:
            if type_name is None or type_name.lower() == 'certificate':
                yield x509.Certificate.load(der)
            else:  # pragma: nocover
                logger.debug(
                    f'Skipping PEM block of type {type_name} in '
                    f'CA chain file.'
                )
    else:
        # no need to unarmor, just try to load it immediately
        yield x509.Certificate.load(cert_data_bytes)


def load_cert_from_pemder(cert_file):
    """
    A convenience function to load a single PEM/DER-encoded certificate
    from a file.

    :param cert_file:
        A file name.
    :return:
        An :class:`.asn1crypto.x509.Certificate` object.
    """
    certs = list(load_certs_from_pemder([cert_file]))
    if len(certs) != 1:
        raise ValueError(
            f"Number of certs in {cert_file} should be exactly 1"
        )
    return certs[0]


def load_private_key_from_pemder(key_file, passphrase: Optional[bytes]) \
        -> keys.PrivateKeyInfo:
    """
    A convenience function to load PEM/DER-encoded keys from files.

    :param key_file:
        File to read the key from.
    :param passphrase:
        Key passphrase.
    :return:
        A private key encoded as an unencrypted PKCS#8 PrivateKeyInfo object.
    """
    with open(key_file, 'rb') as f:
        key_bytes = f.read()
    return load_private_key_from_pemder_data(key_bytes, passphrase=passphrase)


def load_private_key_from_pemder_data(
        key_bytes: bytes,
        passphrase: Optional[bytes]) -> keys.PrivateKeyInfo:
    """
    A convenience function to load PEM/DER-encoded keys from binary data.

    :param key_bytes:
        ``bytes`` object to read the key from.
    :param passphrase:
        Key passphrase.
    :return:
        A private key encoded as an unencrypted PKCS#8 PrivateKeyInfo object.
    """
    load_fun = (
        serialization.load_pem_private_key if pem.detect(key_bytes)
        else serialization.load_der_private_key
    )
    return _translate_pyca_cryptography_key_to_asn1(
        load_fun(key_bytes, password=passphrase)
    )


def _translate_pyca_cryptography_key_to_asn1(private_key) \
        -> keys.PrivateKeyInfo:
    # Store the cert and key as generic ASN.1 structures for more
    # "standardised" introspection. This comes at the cost of some encoding/
    # decoding operations, but those should be fairly insignificant in the
    # grand scheme of things.
    #
    # Note: we're not losing any memory protections here:
    #  (https://cryptography.io/en/latest/limitations.html)
    # Arguably, memory safety is nigh impossible to obtain in a Python
    # context anyhow, and people with that kind of Serious (TM) security
    # requirements should be using HSMs to manage keys.
    return keys.PrivateKeyInfo.load(
        private_key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
    )


def _translate_pyca_cryptography_cert_to_asn1(cert) -> x509.Certificate:
    return x509.Certificate.load(
        cert.public_bytes(serialization.Encoding.DER)
    )


@dataclass(frozen=True)
class SignedDataCerts:
    """
    Value type to describe certificates included in a CMS signed data payload.
    """

    signer_cert: x509.Certificate
    """
    The certificate identified as the signer's certificate.
    """

    other_certs: List[x509.Certificate]
    """
    Other (public-key) certificates included in the signed data object.
    """

    attribute_certs: List[cms.AttributeCertificateV2]
    """
    Attribute certificates included in the signed data object.
    """


def _get_signer_predicate(sid: cms.SignerIdentifier):
    if sid.name == 'issuer_and_serial_number':
        return lambda c: match_issuer_serial(sid.chosen, c)
    elif sid.name == 'subject_key_identifier':
        # subject key identifier (not all certs have this, but that shouldn't
        # be an issue in this case)
        ski = sid.chosen.native
        logger.warning(
            "The signature in this SignedData value seems to be identified by "
            "a subject key identifier --- this is legal in CMS, but many PDF "
            "viewers and SDKs do not support this feature."
        )
        return lambda c: c.key_identifier == ski
    raise NotImplementedError


def _partition_certs(certs, signer_info):
    # The 'certificates' entry is defined as a set in PCKS#7.
    # In particular, we cannot make any assumptions about the order.
    # This means that we have to manually dig through the list to find
    # the actual signer
    predicate = _get_signer_predicate(signer_info['sid'])
    cert = None
    other_certs = []
    for c in certs:
        if predicate(c):
            cert = c
        else:
            other_certs.append(c)
    if cert is None:
        raise CMSExtractionError('signer certificate not included in signature')
    return cert, other_certs


def extract_signer_info(signed_data: cms.SignedData) -> cms.SignerInfo:
    """
    Extract the unique ``SignerInfo`` entry of a CMS signed data value, or
    throw a ``ValueError``.

    :param signed_data:
        A CMS ``SignedData`` value.
    :return:
        A CMS ``SignerInfo`` value.
    :raises ValueError:
        If the number of ``SignerInfo`` values is not exactly one.
    """
    try:
        signer_info, = signed_data['signer_infos']
        return signer_info
    except ValueError:
        raise CMSExtractionError(
            'signer_infos should contain exactly one entry'
        )


def extract_certificate_info(signed_data: cms.SignedData) -> SignedDataCerts:
    """
    Extract and classify embedded certificates found in the ``certificates``
    field of the signed data value.

    :param signed_data:
        A CMS ``SignedData`` value.
    :return:
        A :class:`SignedDataCerts` object containing the embedded certificates.
    """
    certs = []
    attr_certs = []
    for c in signed_data['certificates']:
        cert = c.chosen.untag()
        if c.name == 'certificate':
            certs.append(cert)
        elif c.name == 'v2_attr_cert':
            attr_certs.append(cert)
    signer_info = extract_signer_info(signed_data)
    signer_cert, other_certs = _partition_certs(certs, signer_info)

    cert_info = SignedDataCerts(
        signer_cert=signer_cert, other_certs=other_certs,
        attribute_certs=attr_certs
    )
    return cert_info


def byte_range_digest(stream: IO, byte_range: Iterable[int],
                      md_algorithm: str,
                      chunk_size=misc.DEFAULT_CHUNK_SIZE) -> Tuple[int, bytes]:
    """
    Internal API to compute byte range digests. Potentially dangerous if used
    without due caution.

    :param stream:
        Stream over which to compute the digest. Must support seeking and
        reading.
    :param byte_range:
        The byte range, as a list of (offset, length) pairs, flattened.
    :param md_algorithm:
        The message digest algorithm to use.
    :param chunk_size:
        The I/O chunk size to use.
    :return:
        A tuple of the total digested length, and the actual digest.
    """
    md_spec = get_pyca_cryptography_hash(md_algorithm)
    md = hashes.Hash(md_spec)

    # compute the digest
    # here, we allow arbitrary byte ranges
    # for the coverage check, we'll impose more constraints
    total_len = 0
    chunk_buf = bytearray(chunk_size)
    for lo, chunk_len in misc.pair_iter(byte_range):
        stream.seek(lo)
        misc.chunked_digest(chunk_buf, stream, md, max_read=chunk_len)
        total_len += chunk_len

    return total_len, md.finalize()
