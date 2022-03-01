import asyncio
import logging
from datetime import datetime
from typing import IO, Iterable, List, Optional, Tuple, Type, TypeVar, Union

from asn1crypto import cms, core, tsp, x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from pyhanko_certvalidator import CertificateValidator, ValidationContext
from pyhanko_certvalidator.errors import PathBuildingError, PathValidationError
from pyhanko_certvalidator.validate import ACValidationResult, async_validate_ac

from pyhanko.sign.general import (
    CMSExtractionError,
    MultivaluedAttributeError,
    NonexistentAttributeError,
    SignedDataCerts,
    check_ess_certid,
    extract_certificate_info,
    extract_signer_info,
    find_unique_cms_attribute,
    get_pyca_cryptography_hash,
)

from ...pdf_utils import misc
from ..ades.report import AdESFailure, AdESIndeterminate
from .errors import SignatureValidationError, WeakHashAlgorithmError
from .settings import KeyUsageConstraints
from .status import (
    CAdESSignerAttributeAssertions,
    CertifiedAttributes,
    ClaimedAttributes,
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
    'extract_self_reported_ts', 'extract_certs_for_validation',
    'collect_signer_attr_status',
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
        return

    # we only care about the first value, the others limit the set of applicable
    # CA certs
    certid = attr['certs'][0]

    if not check_ess_certid(cert, certid):
        raise SignatureValidationError(
            f"Signing certificate attribute does not match selected "
            f"signer's certificate for subject"
            f"\"{cert.subject.human_friendly}\".",
            ades_subindication=AdESIndeterminate.NO_SIGNING_CERTIFICATE_FOUND
        )


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
                'Multiple CMS protection attributes present',
                ades_subindication=AdESFailure.FORMAT_FAILURE
            )
        if cms_algid_protection is not None:
            signed_digest_algorithm = \
                cms_algid_protection['digest_algorithm'].native
            if signed_digest_algorithm != digest_algorithm_obj.native:
                raise SignatureValidationError(
                    "Digest algorithm does not match CMS algorithm protection "
                    "attribute.",
                    # these are conceptually failures, but AdES doesn't have
                    # them in its validation model, so 'GENERIC' it is.
                    #  (same applies to other such cases)
                    ades_subindication=AdESIndeterminate.GENERIC
                )
            signed_sig_algorithm = \
                cms_algid_protection['signature_algorithm'].native
            if signed_sig_algorithm is None:
                raise SignatureValidationError(
                    "CMS algorithm protection attribute not valid for signed "
                    "data",
                    ades_subindication=AdESIndeterminate.GENERIC
                )
            elif signed_sig_algorithm != signature_algorithm.native:
                raise SignatureValidationError(
                    "Signature mechanism does not match CMS algorithm "
                    "protection attribute.",
                    ades_subindication=AdESIndeterminate.GENERIC
                )

        # check the signing-certificate or signing-certificate-v2 attr
        # Note: Through the usual "full validation" call path, this check is
        #   performed twice. AdES requires the check to be performed when
        #   selecting the signer's certificate (which happens elsewhere), but
        #   we keep this check for compatibility for those cases where
        #   validate_sig_integrity is used standalone.
        _check_signing_certificate(cert, signed_attrs)

        try:
            content_type = find_unique_cms_attribute(
                signed_attrs, 'content_type'
            )
        except (NonexistentAttributeError, MultivaluedAttributeError):
            raise SignatureValidationError(
                'Content type not found in signature, or multiple content-type '
                'attributes present.',
                ades_subindication=AdESFailure.FORMAT_FAILURE
            )
        content_type = content_type.native
        if content_type != expected_content_type:
            raise SignatureValidationError(
                f'Content type {content_type} did not match expected value '
                f'{expected_content_type}',
                ades_subindication=AdESFailure.FORMAT_FAILURE
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


def extract_certs_for_validation(signed_data: cms.SignedData) \
        -> SignedDataCerts:
    """
    Extract certificates from a CMS signed data object for validation purposes,
    identifying the signer's certificate in accordance with ETSI EN 319 102-1,
    5.2.3.4.

    :param signed_data:
        The CMS payload.
    :return:
        The extracted certificates.
    """

    # TODO allow signer certificate to be obtained from elsewhere?

    try:
        cert_info = extract_certificate_info(signed_data)
        cert = cert_info.signer_cert
    except CMSExtractionError:
        raise SignatureValidationError(
            'signer certificate not included in signature',
            ades_subindication=AdESIndeterminate.NO_SIGNING_CERTIFICATE_FOUND
        )
    signer_info = extract_signer_info(signed_data)
    signed_attrs = signer_info['signed_attrs']
    # check the signing-certificate or signing-certificate-v2 attr
    _check_signing_certificate(cert, signed_attrs)
    return cert_info


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
    cert_info = extract_certs_for_validation(signed_data)
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
    ades_status = path = None
    if valid:
        try:
            validator = CertificateValidator(
                cert, intermediate_certs=other_certs,
                validation_context=validation_context
            )
            ades_status, path = await status_cls.validate_cert_usage(
                validator, key_usage_settings=key_usage_settings
            )
        except ValueError as e:
            logger.error("Processing error in validation process", exc_info=e)
            ades_status = AdESIndeterminate.CERTIFICATE_CHAIN_GENERAL_FAILURE

    status_kwargs = status_kwargs or {}
    status_kwargs.update(
        intact=intact, valid=valid, signing_cert=cert,
        md_algorithm=md_algorithm, pkcs7_signature_mechanism=mechanism,
        trust_problem_indic=ades_status, validation_path=path
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

    tst_info = None
    tst_info_bytes = tst_signed_data['encap_content_info']['content']
    if isinstance(tst_info_bytes, core.ParsableOctetString):
        tst_info = tst_info_bytes.parsed
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


async def process_certified_attrs(
        acs: Iterable[cms.AttributeCertificateV2],
        signer_cert: x509.Certificate,
        validation_context: ValidationContext) \
        -> Tuple[List[ACValidationResult], List[Exception]]:
    jobs = [
        async_validate_ac(ac, validation_context, holder_cert=signer_cert)
        for ac in acs
    ]
    results = []
    errors = []
    for job in asyncio.as_completed(jobs):
        try:
            results.append(await job)
        except (PathBuildingError, PathValidationError) as e:
            errors.append(e)
    return results, errors


async def collect_signer_attr_status(
        sd_attr_certificates: Iterable[cms.AttributeCertificateV2],
        signer_cert: x509.Certificate,
        validation_context: Optional[ValidationContext],
        sd_signed_attrs: cms.CMSAttributes):
    # check if we need to process signer-attrs-v2 first
    try:
        signer_attrs = \
            find_unique_cms_attribute(sd_signed_attrs, 'signer_attributes_v2')
    except NonexistentAttributeError:
        signer_attrs = None
    except MultivaluedAttributeError as e:
        raise SignatureValidationError(str(e)) from e

    result = {}
    cades_ac_results = None
    cades_ac_errors = None
    if signer_attrs is not None:
        claimed_asn1 = signer_attrs['claimed_attributes']
        # process claimed attributes (no verification possible/required,
        # so this is independent of whether we have a validation context
        # available)
        # TODO offer a strict mode where all attributes must be recognised
        #  and/or at least parseable?
        claimed = ClaimedAttributes.from_iterable(
            claimed_asn1 if not isinstance(claimed_asn1, core.Void) else ()
        )
        # extract all X.509 attribute certs
        certified_asn1 = signer_attrs['certified_attributes_v2']
        unknown_cert_attrs = False
        if not isinstance(certified_asn1, core.Void):
            # if there are certified attributes but validation_context is None,
            # then cades_ac_results remains None
            cades_acs = [
                attr.chosen for attr in certified_asn1
                if attr.name == 'attr_cert'
            ]
            # record if there were other types of certified attributes
            unknown_cert_attrs = len(cades_acs) != len(certified_asn1)
            if validation_context is not None:
                # validate retrieved AC's
                val_job = process_certified_attrs(
                    cades_acs, signer_cert, validation_context,
                )
                cades_ac_results, cades_ac_errors = await val_job

        # If we were able to validate AC's from the signers-attrs-v2 attribute,
        # compile the validation results
        if cades_ac_results is not None:
            # TODO offer a strict mode where all attributes must be recognised
            #  and/or at least parseable?
            certified = CertifiedAttributes.from_results(cades_ac_results)
        else:
            certified = None

        # If there's a validation context (i.e. the caller cares about attribute
        #  validation semantics), then log a warning message in case there were
        # signed assertions or certified attributes that we didn't understand.
        unknown_attrs = (
            unknown_cert_attrs or
            not isinstance(signer_attrs['signed_assertions'], core.Void)
        )
        if validation_context is not None and unknown_attrs:
            logger.warning(
                "CAdES signer attributes with externally certified assertions "
                "for which no validation method is available. This may affect "
                "signature semantics in unexpected ways."
            )

        # store the result of the signer-attrs-v2 processing step
        result['cades_signer_attrs'] = CAdESSignerAttributeAssertions(
            claimed_attrs=claimed, certified_attrs=certified,
            ac_validation_errs=cades_ac_errors,
            unknown_attrs_present=unknown_attrs
        )

    if validation_context is not None:
        # validate the ac's in the SD's 'certificates' entry, we have to do that
        # anyway
        ac_results, ac_errors = await process_certified_attrs(
            sd_attr_certificates, signer_cert, validation_context
        )
        # if there were validation results from the signer-attrs-v2 validation,
        # add them to the report here.
        if cades_ac_results:
            ac_results.extend(cades_ac_results)
        if cades_ac_errors:
            ac_errors.extend(cades_ac_errors)
        result['ac_attrs'] = CertifiedAttributes.from_results(ac_results)
        result['ac_validation_errs'] = ac_errors
    return result


async def async_validate_detached_cms(
        input_data: Union[bytes, IO,
                          cms.ContentInfo, cms.EncapsulatedContentInfo],
        signed_data: cms.SignedData,
        signer_validation_context: ValidationContext = None,
        ts_validation_context: ValidationContext = None,
        ac_validation_context: ValidationContext = None,
        key_usage_settings: KeyUsageConstraints = None,
        chunk_size=misc.DEFAULT_CHUNK_SIZE,
        max_read=None) -> StandardCMSSignatureStatus:
    """
    .. versionadded: 0.9.0

    .. versionchanged: 0.11.0
        Added ``ac_validation_context`` param.

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
    :param ac_validation_context:
        Validation context to use to validate attribute certificates.
        If not supplied, no AC validation will be performed.

        .. note::
            :rfc:`5755` requires attribute authority trust roots to be specified
            explicitly; hence why there's no default.
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
    status_kwargs = await cms_basic_validation(
        signed_data, status_cls=StandardCMSSignatureStatus,
        raw_digest=digest_bytes,
        validation_context=signer_validation_context,
        status_kwargs=status_kwargs,
        key_usage_settings=key_usage_settings
    )
    cert_info = extract_certificate_info(signed_data)
    if ac_validation_context is not None:
        ac_validation_context.certificate_registry.register_multiple(
            cert_info.other_certs
        )
    status_kwargs.update(
        await collect_signer_attr_status(
            sd_attr_certificates=cert_info.attribute_certs,
            signer_cert=cert_info.signer_cert,
            validation_context=ac_validation_context,
            sd_signed_attrs=signer_info['signed_attrs']
        )
    )
    return StandardCMSSignatureStatus(**status_kwargs)
