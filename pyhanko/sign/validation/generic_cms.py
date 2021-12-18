import logging
from datetime import datetime
from typing import IO, Optional, Tuple, Type, TypeVar, Union

from asn1crypto import cms, tsp, x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from pyhanko_certvalidator import CertificateValidator, ValidationContext

from pyhanko.sign.general import (
    MultivaluedAttributeError,
    NonexistentAttributeError,
    check_ess_certid,
    extract_certificate_info,
    extract_signer_info,
    find_unique_cms_attribute,
    get_pyca_cryptography_hash,
)

from ...pdf_utils import misc
from .errors import SignatureValidationError, WeakHashAlgorithmError
from .settings import KeyUsageConstraints
from .status import (
    SignatureStatus,
    StandardCMSSignatureStatus,
    TimestampSignatureStatus,
)
from .utils import (
    DEFAULT_WEAK_HASH_ALGORITHMS,
    extract_message_digest,
    validate_raw,
)

__all__ = [
    'validate_sig_integrity', 'async_validate_cms_signature',
    'collect_timing_info', 'validate_tst_signed_data',
    'async_validate_detached_cms', 'cms_basic_validation',
    'compute_signature_tst_digest', 'extract_tst_data',
    'extract_self_reported_ts'
]

logger = logging.getLogger(__name__)

StatusType = TypeVar('StatusType', bound=SignatureStatus)


def _check_signing_certificate(cert: x509.Certificate,
                               signed_attrs: cms.CMSAttributes):
    # TODO check certificate policies, enforce restrictions on chain of trust
    # TODO document and/or mark as internal API explicitly
    def _grab(attr_name):
        try:
            return find_unique_cms_attribute(signed_attrs, attr_name)
        except NonexistentAttributeError:
            return None
        except MultivaluedAttributeError as e:
            raise SignatureValidationError(
                "Wrong cardinality for signing certificate attribute"
            ) from e

    attr = _grab('signing_certificate_v2')
    if attr is None:
        attr = _grab('signing_certificate')

    if attr is None:
        # if neither attr is present -> no constraints
        return True

    # we only care about the first value, the others limit the set of applicable
    # CA certs
    certid = attr['certs'][0]
    return check_ess_certid(cert, certid)


def validate_sig_integrity(signer_info: cms.SignerInfo,
                           cert: x509.Certificate,
                           expected_content_type: str,
                           actual_digest: bytes,
                           weak_hash_algorithms=DEFAULT_WEAK_HASH_ALGORITHMS) \
        -> Tuple[bool, bool]:
    """
    Validate the integrity of a signature for a particular signerInfo object
    inside a CMS signed data container.

    .. warning::
        This function does not do any trust checks, and is considered
        "dangerous" API because it is easy to misuse.

    :param signer_info:
        A :class:`cms.SignerInfo` object.
    :param cert:
        The signer's certificate.

        .. note::
            This function will not attempt to extract certificates from
            the signed data.
    :param expected_content_type:
        The expected value for the content type attribute (as a Python string,
        see :class:`cms.ContentType`).
    :param actual_digest:
        The actual digest to be matched to the message digest attribute.
    :param weak_hash_algorithms:
        List, tuple or set of weak hashing algorithms.
    :return:
        A tuple of two booleans. The first indicates whether the provided
        digest matches the value in the signed attributes.
        The second indicates whether the signature of the digest is valid.
    """

    signature_algorithm: cms.SignedDigestAlgorithm = \
        signer_info['signature_algorithm']
    digest_algorithm_obj = signer_info['digest_algorithm']
    md_algorithm = digest_algorithm_obj['algorithm'].native
    if md_algorithm in weak_hash_algorithms:
        raise WeakHashAlgorithmError(md_algorithm)
    signature = signer_info['signature'].native

    # signed_attrs comes with some context-specific tagging.
    # We need to re-tag it with a universal SET OF tag.
    signed_attrs = signer_info['signed_attrs'].untag()

    if not signed_attrs:
        embedded_digest = None
        prehashed = True
        signed_data = actual_digest
    else:
        prehashed = False
        # check the CMSAlgorithmProtection attr, if present
        try:
            cms_algid_protection = find_unique_cms_attribute(
                signed_attrs, 'cms_algorithm_protection'
            )
        except NonexistentAttributeError:
            cms_algid_protection = None
        except MultivaluedAttributeError:
            raise SignatureValidationError(
                'Multiple CMS protection attributes present'
            )
        if cms_algid_protection is not None:
            signed_digest_algorithm = \
                cms_algid_protection['digest_algorithm'].native
            if signed_digest_algorithm != digest_algorithm_obj.native:
                raise SignatureValidationError(
                    "Digest algorithm does not match CMS algorithm protection "
                    "attribute."
                )
            signed_sig_algorithm = \
                cms_algid_protection['signature_algorithm'].native
            if signed_sig_algorithm is None:
                raise SignatureValidationError(
                    "CMS algorithm protection attribute not valid for signed "
                    "data"
                )
            elif signed_sig_algorithm != signature_algorithm.native:
                raise SignatureValidationError(
                    "Signature mechanism does not match CMS algorithm "
                    "protection attribute."
                )

        # check the signing-certificate or signing-certificate-v2 attr
        if not _check_signing_certificate(cert, signed_attrs):
            raise SignatureValidationError(
                f"Signing certificate attribute does not match selected "
                f"signer's certificate for subject"
                f"\"{cert.subject.human_friendly}\"."
            )

        try:
            content_type = find_unique_cms_attribute(
                signed_attrs, 'content_type'
            )
        except (NonexistentAttributeError, MultivaluedAttributeError):
            raise SignatureValidationError(
                'Content type not found in signature, or multiple content-type '
                'attributes present.'
            )
        content_type = content_type.native
        if content_type != expected_content_type:
            raise SignatureValidationError(
                f'Content type {content_type} did not match expected value '
                f'{expected_content_type}'
            )

        embedded_digest = extract_message_digest(signer_info)

        signed_data = signed_attrs.dump()
    try:
        validate_raw(
            signature, signed_data, cert, signature_algorithm, md_algorithm,
            prehashed=prehashed, weak_hash_algorithms=weak_hash_algorithms
        )
        valid = True
    except InvalidSignature:
        valid = False

    intact = (
        actual_digest == embedded_digest
        if embedded_digest is not None else valid
    )

    return intact, valid


async def cms_basic_validation(
        signed_data: cms.SignedData,
        status_cls: Type[StatusType] = SignatureStatus,
        raw_digest: bytes = None,
        validation_context: ValidationContext = None,
        status_kwargs: dict = None,
        key_usage_settings: KeyUsageConstraints = None,
        encap_data_invalid=False):

    """
    Perform basic validation of CMS and PKCS#7 signatures in isolation
    (i.e. integrity and trust checks).

    Internal API.
    """
    signer_info = extract_signer_info(signed_data)
    cert_info = extract_certificate_info(signed_data)
    cert = cert_info.signer_cert
    other_certs = cert_info.other_certs

    weak_hash_algos = None
    if validation_context is not None:
        weak_hash_algos = validation_context.weak_hash_algos
    if weak_hash_algos is None:
        weak_hash_algos = DEFAULT_WEAK_HASH_ALGORITHMS

    signature_algorithm: cms.SignedDigestAlgorithm = \
        signer_info['signature_algorithm']
    mechanism = signature_algorithm['algorithm'].native
    md_algorithm = signer_info['digest_algorithm']['algorithm'].native
    eci = signed_data['encap_content_info']
    expected_content_type = eci['content_type'].native
    if raw_digest is None:
        # this means that there should be encapsulated data
        raw = bytes(eci['content'])
        md_spec = get_pyca_cryptography_hash(md_algorithm)
        md = hashes.Hash(md_spec)
        md.update(raw)
        raw_digest = md.finalize()

    # first, do the cryptographic identity checks
    intact, valid = validate_sig_integrity(
        signer_info, cert, expected_content_type=expected_content_type,
        actual_digest=raw_digest, weak_hash_algorithms=weak_hash_algos
    )

    # if the data being encapsulated by the signature is itself invalid,
    #  this flag is set
    intact &= not encap_data_invalid
    valid &= intact

    # next, validate trust
    trusted = revoked = False
    path = None
    if valid:
        validator = CertificateValidator(
            cert, intermediate_certs=other_certs,
            validation_context=validation_context
        )
        trusted, revoked, path = await status_cls.validate_cert_usage(
            validator, key_usage_settings=key_usage_settings
        )

    status_kwargs = status_kwargs or {}
    status_kwargs.update(
        intact=intact, valid=valid, signing_cert=cert,
        md_algorithm=md_algorithm, pkcs7_signature_mechanism=mechanism,
        revoked=revoked, trusted=trusted,
        validation_path=path
    )
    return status_kwargs


async def async_validate_cms_signature(
                           signed_data: cms.SignedData,
                           status_cls: Type[StatusType] = SignatureStatus,
                           raw_digest: bytes = None,
                           validation_context: ValidationContext = None,
                           status_kwargs: dict = None,
                           key_usage_settings: KeyUsageConstraints = None,
                           encap_data_invalid=False):
    """
    Validate a CMS signature (i.e. a ``SignedData`` object).

    :param signed_data:
        The :class:`.asn1crypto.cms.SignedData` object to validate.
    :param status_cls:
        Status class to use for the validation result.
    :param raw_digest:
        Raw digest, computed from context.
    :param validation_context:
        Validation context to validate the signer's certificate.
    :param status_kwargs:
        Other keyword arguments to pass to the ``status_class`` when reporting
        validation results.
    :param key_usage_settings:
        A :class:`.KeyUsageConstraints` object specifying which key usages
        must or must not be present in the signer's certificate.
    :param encap_data_invalid:
        If ``True``, the encapsulated data inside the CMS is invalid,
        but the remaining validation logic still has to be run (e.g. a
        timestamp token, which requires validation of the embedded message
        imprint).

        This option is considered internal API, the semantics of which may
        change without notice in the future.
    :return:
        A :class:`.SignatureStatus` object (or an instance of a proper subclass)
    """
    status_kwargs = await cms_basic_validation(
        signed_data, status_cls, raw_digest, validation_context,
        status_kwargs, key_usage_settings, encap_data_invalid
    )
    return status_cls(**status_kwargs)


def extract_self_reported_ts(signer_info: cms.SignerInfo) -> Optional[datetime]:
    """
    Extract self-reported timestamp (from the ``signingTime`` attribute)

    Internal API.

    :param signer_info:
        A ``SignerInfo`` value.
    :return:
        The value of the ``signingTime`` attribute as a ``datetime``, or
        ``None``.
    """
    try:
        sa = signer_info['signed_attrs']
        st = find_unique_cms_attribute(sa, 'signing_time')
        return st.native
    except (NonexistentAttributeError, MultivaluedAttributeError):
        pass


def extract_tst_data(signer_info, signed=False) -> Optional[cms.SignedData]:
    """
    Extract signed data associated with a timestamp token.

    Internal API.

    :param signer_info:
        A ``SignerInfo`` value.
    :param signed:
        If ``True``, look for a content timestamp (among the signed
        attributes), else look for a signature timestamp (among the unsigned
        attributes).
    :return:
        The ``SignedData`` value found, or ``None``.
    """
    try:
        if signed:
            sa = signer_info['signed_attrs']
            tst = find_unique_cms_attribute(sa, 'content_time_stamp')
        else:
            ua = signer_info['unsigned_attrs']
            tst = find_unique_cms_attribute(ua, 'signature_time_stamp_token')
        tst_signed_data = tst['content']
        return tst_signed_data
    except (NonexistentAttributeError, MultivaluedAttributeError):
        pass


def compute_signature_tst_digest(signer_info: cms.SignerInfo) \
        -> Optional[bytes]:
    """
    Compute the digest of the signature according to the message imprint
    algorithm information in a signature timestamp token.

    Internal API.

    :param signer_info:
        A ``SignerInfo`` value.
    :return:
        The computed digest, or ``None`` if there is no signature timestamp.
    """

    tst_data = extract_tst_data(signer_info)
    if tst_data is None:
        return None

    eci = tst_data['encap_content_info']
    mi = eci['content'].parsed['message_imprint']
    tst_md_algorithm = mi['hash_algorithm']['algorithm'].native

    signature_bytes = signer_info['signature'].native
    tst_md_spec = get_pyca_cryptography_hash(tst_md_algorithm)
    md = hashes.Hash(tst_md_spec)
    md.update(signature_bytes)
    return md.finalize()

# TODO support signerInfo with multivalued timestamp attributes


async def collect_timing_info(signer_info: cms.SignerInfo,
                              ts_validation_context: ValidationContext,
                              raw_digest: bytes):
    """
    Collect and validate timing information in a ``SignerInfo`` value.
    This includes the ``signingTime`` attribute, content timestamp information
    and signature timestamp information.

    :param signer_info:
        A ``SignerInfo`` value.
    :param ts_validation_context:
        The timestamp validation context to validate against.
    :param raw_digest:
        The raw external message digest bytes (only relevant for the
        validation of the content timestamp token, if there is one)
    """

    status_kwargs = {}

    # timestamp-related validation
    signer_reported_dt = extract_self_reported_ts(signer_info)
    if signer_reported_dt is not None:
        status_kwargs['signer_reported_dt'] = signer_reported_dt

    tst_signed_data = extract_tst_data(signer_info, signed=False)
    if tst_signed_data is not None:
        tst_validity_kwargs = await validate_tst_signed_data(
            tst_signed_data, ts_validation_context,
            compute_signature_tst_digest(signer_info),
        )
        tst_validity = TimestampSignatureStatus(**tst_validity_kwargs)
        status_kwargs['timestamp_validity'] = tst_validity

    content_tst_signed_data = extract_tst_data(signer_info, signed=True)
    if content_tst_signed_data is not None:
        content_tst_validity_kwargs = await validate_tst_signed_data(
            content_tst_signed_data, ts_validation_context,
            expected_tst_imprint=raw_digest
        )
        content_tst_validity = TimestampSignatureStatus(
            **content_tst_validity_kwargs
        )
        status_kwargs['content_timestamp_validity'] = content_tst_validity

    return status_kwargs


async def validate_tst_signed_data(
        tst_signed_data: cms.SignedData,
        validation_context: ValidationContext,
        expected_tst_imprint: bytes):
    """
    Validate the ``SignedData`` of a time stamp token.

    :param tst_signed_data:
        The ``SignedData`` value to validate; must encapsulate a ``TSTInfo``
        value.
    :param validation_context:
        The validation context to validate against.
    :param expected_tst_imprint:
        The expected message imprint value that should be contained in
        the encapsulated ``TSTInfo``.
    :return:
        Keyword arguments for a :class:`.TimeStampSignatureStatus`.
    """

    tst_info = tst_signed_data['encap_content_info']['content'].parsed
    if not isinstance(tst_info, tsp.TSTInfo):
        raise SignatureValidationError(
            "SignedData does not encapsulate TSTInfo"
        )
    # compare the expected TST digest against the message imprint
    # inside the signed data
    tst_imprint = tst_info['message_imprint']['hashed_message'].native
    if expected_tst_imprint != tst_imprint:
        logger.warning(
            f"Timestamp token imprint is {tst_imprint.hex()}, but expected "
            f"{expected_tst_imprint.hex()}."
        )
        encap_data_invalid = True
    else:
        encap_data_invalid = False
    timestamp = tst_info['gen_time'].native
    return await cms_basic_validation(
        tst_signed_data, status_cls=TimestampSignatureStatus,
        validation_context=validation_context,
        status_kwargs={'timestamp': timestamp},
        encap_data_invalid=encap_data_invalid
    )


async def async_validate_detached_cms(
        input_data: Union[bytes, IO,
                          cms.ContentInfo, cms.EncapsulatedContentInfo],
        signed_data: cms.SignedData,
        signer_validation_context: ValidationContext = None,
        ts_validation_context: ValidationContext = None,
        key_usage_settings: KeyUsageConstraints = None,
        chunk_size=misc.DEFAULT_CHUNK_SIZE,
        max_read=None) -> StandardCMSSignatureStatus:
    """
    .. versionadded: 0.9.0

    Validate a detached CMS signature.

    :param input_data:
        The input data to sign. This can be either a :class:`bytes` object,
        a file-like object or a :class:`cms.ContentInfo` /
        :class:`cms.EncapsulatedContentInfo` object.

        If a CMS content info object is passed in, the `content` field
        will be extracted.
    :param signed_data:
        The :class:`cms.SignedData` object containing the signature to verify.
    :param signer_validation_context:
        Validation context to use to verify the signer certificate's trust.
    :param ts_validation_context:
        Validation context to use to verify the TSA certificate's trust, if
        a timestamp token is present.
        By default, the same validation context as that of the signer is used.
    :param key_usage_settings:
        Key usage parameters for the signer.
    :param chunk_size:
        Chunk size to use when consuming input data.
    :param max_read:
        Maximal number of bytes to read from the input stream.
    :return:
        A description of the signature's status.
    """

    if ts_validation_context is None:
        ts_validation_context = signer_validation_context
    signer_info = extract_signer_info(signed_data)
    digest_algorithm = signer_info['digest_algorithm']['algorithm'].native
    h = hashes.Hash(get_pyca_cryptography_hash(digest_algorithm))
    if isinstance(input_data, bytes):
        h.update(input_data)
    elif isinstance(input_data, (cms.ContentInfo, cms.EncapsulatedContentInfo)):
        h.update(bytes(input_data['content']))
    else:
        temp_buf = bytearray(chunk_size)
        misc.chunked_digest(temp_buf, input_data, h, max_read=max_read)
    digest_bytes = h.finalize()

    status_kwargs = await collect_timing_info(
        signer_info, ts_validation_context=ts_validation_context,
        raw_digest=digest_bytes
    )
    return await async_validate_cms_signature(
        signed_data, status_cls=StandardCMSSignatureStatus,
        raw_digest=digest_bytes,
        validation_context=signer_validation_context,
        status_kwargs=status_kwargs,
        key_usage_settings=key_usage_settings
    )
