import itertools
import logging
import sys
from dataclasses import dataclass
from datetime import datetime
from importlib import resources
from typing import (
    Any,
    FrozenSet,
    Generator,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
    TypeVar,
    Union,
)

from asn1crypto import x509
from cryptography.x509 import load_der_x509_certificate
from lxml import etree
from lxml.etree import QName
from pyhanko.generated.etsi import (
    MimeType,
    OtherTSLPointer,
    SchemeTerritory,
    SchemeTypeCommunityRules,
    ServiceStatus,
    ServiceTypeIdentifier,
    TrustServiceStatusList,
    ts_119612,
    ts_119612_extra,
    ts_119612_sie,
    xades,
)
from pyhanko.keys import load_certs_from_pemder_data
from pyhanko.sign.ades.report import AdESFailure, AdESIndeterminate
from pyhanko.sign.validation.errors import SignatureValidationError
from pyhanko.sign.validation.qualified.tsp import (
    _SVCINFOEXT_URI_BASE,
    _TRUSTEDLIST_URI_BASE,
    CA_QC_URI,
    QTST_URI,
    AdditionalServiceInformation,
    BaseServiceInformation,
    CAServiceInformation,
    CertSubjectDNCriterion,
    CriteriaCombination,
    CriteriaList,
    Criterion,
    KeyUsageCriterion,
    PolicySetCriterion,
    QcCertType,
    QTSTServiceInformation,
    Qualification,
    QualifiedServiceInformation,
    Qualifier,
    TSPRegistry,
    TSPServiceParsingError,
)
from pyhanko.sign.validation.settings import KeyUsageConstraints
from signxml.exceptions import SignXMLException as InvalidXmlSignature
from signxml.xades import XAdESSignatureConfiguration, XAdESVerifier
from xsdata.exceptions import XmlContextError
from xsdata.formats.dataclass.models.builders import XmlMetaBuilder
from xsdata.formats.dataclass.parsers import XmlParser
from xsdata.formats.dataclass.parsers.config import ParserConfig
from xsdata.formats.dataclass.parsers.handlers import LxmlEventHandler
from xsdata.formats.dataclass.parsers.handlers.lxml import EVENTS

__all__ = [
    'latest_known_lotl_tlso_certs',
    'ojeu_bootstrap_lotl_tlso_certs',
    'parse_lotl_unsafe',
    'read_qualified_service_definitions',
    'trust_list_to_registry',
    'trust_list_to_registry_unsafe',
    'validate_and_parse_lotl',
]

logger = logging.getLogger(__name__)
STATUS_GRANTED = f'{_TRUSTEDLIST_URI_BASE}/Svcstatus/granted'
_SCHEME_RULES_URI_BASE = f'{_TRUSTEDLIST_URI_BASE}/schemerules'
LOTL_RULE = f'{_SCHEME_RULES_URI_BASE}/EUlistofthelists'
ETSI_TSL_MIME_TYPE = 'application/vnd.etsi.tsl+xml'
_CERTIFICATE_TYPE_BY_URI = {
    f'{_SVCINFOEXT_URI_BASE}/ForeSignatures': QcCertType.QC_ESIGN,
    f'{_SVCINFOEXT_URI_BASE}/ForeSeals': QcCertType.QC_ESEAL,
    f'{_SVCINFOEXT_URI_BASE}/ForWebSiteAuthentication': QcCertType.QC_WEB,
}
_QUALIFIER_BY_URI = {q.uri: q for q in Qualifier}
PREFERRED_LANGUAGE: str = 'en'

if sys.version_info >= (3, 14):
    # monkeypatch until there is an xsdata release with this fix:
    # https://github.com/tefra/xsdata/pull/1173

    def _find_declared_class(
        _cls: type, clazz: type, name: str
    ) -> Any:  # pragma: nocover
        import inspect

        for base in clazz.__mro__:
            ann = inspect.get_annotations(base)
            if ann and name in ann:
                return base

        raise XmlContextError(
            f"Failed to detect the declared class for field {name}"
        )

    XmlMetaBuilder.find_declared_class = _find_declared_class  # type: ignore


def _service_name_from_intl_string(
    intl_string: Optional[ts_119612.InternationalNamesType],
) -> str:
    return (
        _extract_from_intl_string(intl_string.name)
        if intl_string
        else "unknown"
    )


def _extract_from_intl_string(
    intl_string: Tuple[
        Union[ts_119612.MultiLangStringType, ts_119612.MultiLangNormStringType],
        ...,
    ],
):
    first_value = intl_string[0].value
    for part in intl_string:
        if part.lang == PREFERRED_LANGUAGE:
            return part.value
    return first_value


T = TypeVar('T')


def _required(thing: Optional[T], descr: str) -> T:
    if thing is None:
        raise TSPServiceParsingError(f"{descr} must be provided")
    return thing


def _as_certs(sdi: ts_119612.ServiceDigitalIdentity):
    for digital_id in sdi.digital_id:
        cert_bytes = digital_id.x509_certificate
        if cert_bytes:
            yield x509.Certificate.load(cert_bytes)


def _process_criteria_list(
    criteria: Optional[ts_119612_sie.CriteriaListType],
) -> CriteriaList:
    entries = frozenset(_process_criteria_list_entries(criteria))
    if entries:
        assert criteria is not None
        assertion_type = _required(
            criteria.assert_value, "Criteria assertion type"
        ).value
        combine_as = CriteriaCombination(str(assertion_type))
        return CriteriaList(combine_as=combine_as, criteria=entries)
    else:
        raise TSPServiceParsingError("No criteria")


def _parse_xades_oid(oid: xades.ObjectIdentifierType) -> str:
    return _required(oid.identifier, "Identifier tag in OID").value


def _process_criteria_list_entries(
    criteria_list: Optional[ts_119612_sie.CriteriaListType],
) -> Generator[Criterion, None, None]:
    if not criteria_list:
        return
    if criteria_list.policy_set:
        # TODO also take policy qualifiers into account
        for policy_set_criterion in criteria_list.policy_set:
            yield PolicySetCriterion(
                required_policy_oids=frozenset(
                    _parse_xades_oid(policy)
                    for policy in policy_set_criterion.policy_identifier
                )
            )
    if criteria_list.key_usage:
        for ku_criterion in criteria_list.key_usage:
            key_usage_must_have = frozenset(
                _required(bit.name, "Key usage bit type name").name.lower()
                for bit in ku_criterion.key_usage_bit
                if bit.value is True
            )
            key_usage_forbidden = frozenset(
                _required(bit.name, "Key usage bit type name").name.lower()
                for bit in ku_criterion.key_usage_bit
                if bit.value is False
            )
            yield KeyUsageCriterion(
                settings=KeyUsageConstraints(
                    key_usage=key_usage_must_have,
                    key_usage_forbidden=key_usage_forbidden,
                )
            )
    sublists: Iterable[ts_119612_sie.CriteriaListType] = (
        criteria_list.criteria_list
    )
    if sublists:
        for sublist in sublists:
            yield _process_criteria_list(sublist)
    if criteria_list.other_criteria_list:
        for el in criteria_list.other_criteria_list.content:
            if isinstance(el, ts_119612_extra.CertSubjectDNAttribute):
                yield CertSubjectDNCriterion(
                    frozenset(
                        _parse_xades_oid(oid_xml)
                        for oid_xml in el.attribute_oid
                    )
                )
            elif isinstance(el, ts_119612_extra.ExtendedKeyUsage):
                kpids = frozenset(
                    _parse_xades_oid(kpid_xml) for kpid_xml in el.key_purpose_id
                )
                yield KeyUsageCriterion(
                    settings=KeyUsageConstraints(extd_key_usage=kpids)
                )
            else:
                raise TSPServiceParsingError(
                    f"Unknown criterion {el} in qualifier definition"
                )


def _process_qualifiers(qualifiers: Iterable[ts_119612_sie.QualifierType]):
    for qual in qualifiers:
        try:
            yield _QUALIFIER_BY_URI[qual.uri]
        except KeyError:
            logger.info(f"Qualifier {qual.uri} in SDI ignored...")


def _get_qualifications(qualifications: ts_119612_sie.Qualifications):
    for qual in qualifications.qualification_element:
        quals_xml = qual.qualifiers
        if not quals_xml:
            continue
        # note: all the qualifiers we currently support only make sense
        # for qualified CAs, not other types of services
        # (qualified or otherwise).
        qualifiers = frozenset(_process_qualifiers(quals_xml.qualifier))
        criteria = _process_criteria_list(qual.criteria_list)
        if qualifiers and criteria:
            yield Qualification(qualifiers=qualifiers, criteria_list=criteria)
        else:
            logger.warning(f"Could not process qualifiers in {quals_xml}")


def _process_additional_info(
    info: ts_119612.AdditionalServiceInformation, critical: bool
):
    return AdditionalServiceInformation(
        uri=_required(info.uri, "Additional service info URI").value,
        textual_info=info.information_value,
        critical=critical,
    )


def _interpret_service_info_for_ca(
    service: ts_119612.TSPService,
):
    return _interpret_service_info_for_tsp(
        service, _interpret_historical_service_info_for_ca
    )


def _interpret_service_info_for_tsp(
    service: ts_119612.TSPService,
    historical_interpreter,
):
    service_info = service.service_information
    assert service_info is not None
    return historical_interpreter(
        service_info=ts_119612.ServiceHistoryInstance(
            service_type_identifier=service_info.service_type_identifier,
            service_name=service_info.service_name,
            service_digital_identity=service_info.service_digital_identity,
            service_status=service_info.service_status,
            status_starting_time=service_info.status_starting_time,
            service_information_extensions=service_info.service_information_extensions,
        ),
        next_update_at=None,
    )


def _interpret_historical_service_info_for_ca(
    service_info: ts_119612.ServiceHistoryInstance,
    next_update_at: Optional[datetime],
):
    certs = list(
        _as_certs(
            _required(
                service_info.service_digital_identity,
                "Service digital identity",
            )
        )
    )
    service_name = _service_name_from_intl_string(service_info.service_name)
    qualifications: FrozenSet[Qualification] = frozenset()
    expired_revinfo_date = None
    additional_info = []
    extensions_xml = (
        service_info.service_information_extensions.extension
        if service_info.service_information_extensions
        else ()
    )
    asi_qc_type: Set[QcCertType] = set()
    for ext in extensions_xml:
        for ext_content in ext.content:
            if isinstance(ext_content, ts_119612_sie.Qualifications):
                qualifications = frozenset(_get_qualifications(ext_content))
            elif isinstance(ext_content, ts_119612.ExpiredCertsRevocationInfo):
                expired_revinfo_date = _required(
                    ext_content.value,
                    "Date in expired certs revocation info cutoff",
                ).to_datetime()
            elif isinstance(
                ext_content, ts_119612.AdditionalServiceInformation
            ):
                additional_info_entry = _process_additional_info(
                    ext_content, ext.critical or False
                )
                try:
                    asi_qc_type.add(
                        _CERTIFICATE_TYPE_BY_URI[additional_info_entry.uri]
                    )
                except KeyError:
                    additional_info.append(additional_info_entry)
            elif ext.critical:
                raise TSPServiceParsingError(
                    f"Cannot process a critical extension "
                    f"in service named '{service_name}'.\n"
                    f"Content: {ext_content}"
                )
    valid_from_date = service_info.status_starting_time
    if valid_from_date is None:
        raise TSPServiceParsingError(
            f"The validity start of the status of "
            f"the the service named {service_name} is not known. "
            f"This is an error."
        )
    base_service_info = BaseServiceInformation(
        service_type=_required(
            service_info.service_type_identifier, "Service type identifier"
        ).value,
        valid_from=valid_from_date.to_datetime(),
        valid_until=next_update_at,
        service_name=service_name,
        provider_certs=tuple(certs),
        additional_info_certificate_type=frozenset(asi_qc_type),
        other_additional_info=frozenset(additional_info),
    )

    return CAServiceInformation(
        base_info=base_service_info,
        qualifications=qualifications,
        expired_certs_revocation_info=expired_revinfo_date,
    )


def _interpret_historical_service_info_for_qtst(
    service_info: ts_119612.ServiceHistoryInstance,
    next_update_at: Optional[datetime],
):
    # todo dedupe
    certs = list(
        _as_certs(
            _required(
                service_info.service_digital_identity,
                "Service digital identity",
            )
        )
    )
    service_name = _service_name_from_intl_string(service_info.service_name)
    qualifications: FrozenSet[Qualification] = frozenset()
    additional_info: List[AdditionalServiceInformation] = []
    extensions_xml = (
        service_info.service_information_extensions.extension
        if service_info.service_information_extensions
        else ()
    )
    for ext in extensions_xml:
        for ext_content in ext.content:
            if isinstance(ext_content, ts_119612_sie.Qualifications):
                qualifications = frozenset(_get_qualifications(ext_content))
            elif ext.critical:
                raise TSPServiceParsingError(
                    f"Cannot process a critical extension "
                    f"in service named '{service_name}'.\n"
                    f"Content: {ext_content}"
                )
    valid_from_date = service_info.status_starting_time
    if valid_from_date is None:
        raise TSPServiceParsingError(
            f"The validity start of the status of "
            f"the the service named {service_name} is not known. "
            f"This is an error."
        )
    base_service_info = BaseServiceInformation(
        service_type=_required(
            service_info.service_type_identifier, "Service type identifier"
        ).value,
        valid_from=valid_from_date.to_datetime(),
        valid_until=next_update_at,
        service_name=service_name,
        provider_certs=tuple(certs),
        additional_info_certificate_type=frozenset(),
        other_additional_info=frozenset(additional_info),
    )

    return QTSTServiceInformation(
        base_info=base_service_info,
        qualifications=qualifications,
    )


def _read_service_history(
    history_items, validity_start, service_name, interpreter
):
    errors_encountered = []
    item_index_sorted_by_date = sorted(
        (
            (orig_ix, item.status_starting_time.to_datetime())
            for orig_ix, item in enumerate(history_items)
            if item.status_starting_time
        ),
        key=lambda t: t[1],
        reverse=True,
    )
    end_of_validity_by_orig_ix = {
        orig_ix: next_start
        for (orig_ix, cur_start), next_start in zip(
            item_index_sorted_by_date,
            itertools.chain(
                (validity_start.to_datetime(),),
                (st for _, st in item_index_sorted_by_date[:-1]),
            ),
        )
    }

    for orig_ix, validity_end in end_of_validity_by_orig_ix.items():
        history_item = history_items[orig_ix]
        if history_item.service_status != ServiceStatus(STATUS_GRANTED):
            continue
        try:
            validity_end = end_of_validity_by_orig_ix[orig_ix]
            yield interpreter(
                history_item,
                next_update_at=validity_end,
            )
        except TSPServiceParsingError as e:
            logger.debug(
                f"Failed to parse item {orig_ix + 1} in history "
                f"of service {service_name}. This history "
                f"entry will not be processed further.",
                exc_info=e,
            )
            errors_encountered.append(e)
    return errors_encountered


def _interpret_service_info_for_tsps(
    services: Iterable[ts_119612.TSPService],
    service_type: ServiceTypeIdentifier,
    interpreter,
):
    errors_encountered = []
    for service in services:
        service_info = service.service_information
        if (
            not service_info
            or service_info.service_type_identifier != service_type
        ):
            continue

        service_name = _service_name_from_intl_string(service_info.service_name)
        # TODO allow the user to specify if they also want to include
        #  other statuses (e.g. national level)
        # TODO evaluate historical definitions too in case of point-in-time
        #  work, store that info on the object
        if service_info.service_status == ServiceStatus(STATUS_GRANTED):
            try:
                yield _interpret_service_info_for_tsp(service, interpreter)
            except TSPServiceParsingError as e:
                logger.warning(
                    f"Failed to process current status "
                    f"of service {service_name}. This history "
                    f"entry will not be processed further.",
                    exc_info=e,
                )
                errors_encountered.append(e)
                continue

        validity_start = service_info.status_starting_time
        if validity_start and service.service_history:
            history_items = service.service_history.service_history_instance
            history_errors = yield from _read_service_history(
                history_items, validity_start, service_name, interpreter
            )
            errors_encountered.extend(history_errors)

    return errors_encountered


class _RestrictedLxmlEventHandler(LxmlEventHandler):
    # Disable xinclude support and entity resolution

    def parse(self, source: Any, ns_map: dict[Optional[str], str]) -> Any:
        if isinstance(source, (etree._ElementTree, etree._Element)):
            ctx = etree.iterwalk(source, EVENTS)
        else:
            ctx = etree.iterparse(
                source,
                EVENTS,
                recover=True,
                remove_comments=True,
                load_dtd=self.parser.config.load_dtd,
                resolve_entities=False,
                no_network=True,
            )

        return self.process_context(ctx, ns_map)


def _raw_tl_parse(tl_xml: str) -> ts_119612.TrustServiceStatusList:
    parser = XmlParser(
        config=ParserConfig(
            load_dtd=False,
            process_xinclude=False,
            fail_on_unknown_properties=False,
            fail_on_unknown_attributes=False,
        ),
        handler=_RestrictedLxmlEventHandler,
    )
    return parser.from_string(tl_xml, clazz=ts_119612.TrustServiceStatusList)


def read_qualified_service_definitions(
    tl_xml: str,
) -> Generator[QualifiedServiceInformation, None, List[TSPServiceParsingError]]:
    """
    Internal function to read qualified service definitions from a trusted list
    payload (does not include signature validation).
    """

    parse_result = _raw_tl_parse(tl_xml)
    tspl = parse_result.trust_service_provider_list
    errors_encountered = []
    for tsp in _required(tspl, "TSP list").trust_service_provider:
        tsp_errors = yield from _interpret_service_info_for_tsps(
            _required(tsp.tspservices, "TSP services (CA)").tspservice,
            service_type=ServiceTypeIdentifier(CA_QC_URI),
            interpreter=_interpret_historical_service_info_for_ca,
        )
        errors_encountered.extend(tsp_errors)

        tsp_errors = yield from _interpret_service_info_for_tsps(
            _required(tsp.tspservices, "TSP services (QTST)").tspservice,
            service_type=ServiceTypeIdentifier(QTST_URI),
            interpreter=_interpret_historical_service_info_for_qtst,
        )
        errors_encountered.extend(tsp_errors)
    return errors_encountered


def trust_list_to_registry_unsafe(
    tl_xml: str, registry: Optional[TSPRegistry] = None
) -> Tuple[TSPRegistry, List[TSPServiceParsingError]]:
    """
    Parse a trusted list (ETSI TS 119 612) into a :class:`TSPRegistry`.

    .. warning::
        The XML signature on the trusted list is _not_ validated as part
        of this method. Currently, ensuring the integrity of the trusted list
        is the caller's responsibility.

    :param tl_xml:
        XML payload describing the trusted list in the ETSI TS 119 612 format
    :param registry:
        Registry to which the entries should be added. If not supplied, a new
        one will be created.
    :return:
    """
    registry = registry or TSPRegistry()
    g = read_qualified_service_definitions(tl_xml)
    while True:
        try:
            sd = next(g)
            if isinstance(sd, CAServiceInformation):
                registry.register_ca(sd)
            elif isinstance(sd, QTSTServiceInformation):
                registry.register_tst(sd)
        except StopIteration as e:
            return registry, e.value


def _verify_xml(tl_xml: str, tlso_cert: x509.Certificate):
    tl_xml_bytes = tl_xml.encode('utf8')
    verifier = XAdESVerifier()
    cert_obj = load_der_x509_certificate(tlso_cert.dump())
    config = XAdESSignatureConfiguration(
        require_x509=True,
        expect_references=True,
    )
    try:
        verify_results = verifier.verify(
            tl_xml_bytes,
            x509_cert=cert_obj,
            expect_config=config,
        )
    except InvalidXmlSignature as e:
        raise SignatureValidationError(
            f"Invalid XML signature on trusted list: {e}",
            ades_subindication=AdESIndeterminate.GENERIC,
        ) from e
    return verify_results


def _validate_and_extract_tl_data(
    tl_xml: str, tlso_cert: x509.Certificate
) -> str:
    verify_results = _verify_xml(tl_xml, tlso_cert)
    tl_signed_xml = None
    for result in verify_results:
        if result.signed_xml is None:
            continue
        if result.signed_xml.tag == QName(
            TrustServiceStatusList.Meta.namespace, 'TrustServiceStatusList'
        ):
            tl_signed_xml = result.signed_data.decode("utf-8")
            break
    if not tl_signed_xml:
        raise SignatureValidationError(
            "Failed to identify trusted list in signed data",
            ades_subindication=AdESFailure.FORMAT_FAILURE,
        )

    logger.debug(
        "Validated TL data with TLSO certificate %s\n(SHA-256 fingerprint %s)",
        tlso_cert.subject.human_friendly,
        tlso_cert.sha256_fingerprint,
    )
    return tl_signed_xml


def _validate_and_extract_tl_data_multiple_certs(
    tl_xml: str, tlso_cert_candidates: List[x509.Certificate]
) -> str:
    # sort the issuer certs by newest first
    sorted_candidates = sorted(
        tlso_cert_candidates, key=lambda c: c.not_valid_before, reverse=True
    )
    errors = []
    result = None
    for candidate in sorted_candidates:
        try:
            result = _validate_and_extract_tl_data(tl_xml, candidate)
            break
        except SignatureValidationError as e:
            errors.append(e)
    if not result:
        msg = (
            f"None of the candidate TLSO certs could be used to validate "
            f"the TL signature: {','.join(e.failure_message for e in errors)}"
        )
        raise SignatureValidationError(
            msg,
            ades_subindication=AdESIndeterminate.GENERIC,
        )
    return result


def trust_list_to_registry(
    tl_xml: str,
    tlso_certs: List[x509.Certificate],
    registry: Optional[TSPRegistry] = None,
) -> Tuple[TSPRegistry, List[TSPServiceParsingError]]:
    """
    Validate and parse a trusted list (ETSI TS 119 612) into a :class:`TSPRegistry`.

    .. note::
        The TSLO certs are used in the validation of the trusted list,
        but are not validated by this function.

    :param tl_xml:
        XML payload describing the trusted list in the ETSI TS 119 612 format
    :param tlso_certs:
        The certificates containing the public keys with which
        the TL could be validated.
    :param registry:
        Registry to which the entries should be added. If not supplied, a new
        one will be created.
    :raises SignatureValidationError:
        If the trusted list's signature cannot be validated.
    :return:
    """
    tl_signed_xml = _validate_and_extract_tl_data_multiple_certs(
        tl_xml, tlso_certs
    )
    return trust_list_to_registry_unsafe(tl_signed_xml, registry)


def _parse_tsl_info(pointer: OtherTSLPointer):
    rules = set()
    territory = list_type = None
    additional_info = _required(
        pointer.additional_information, "TSL pointer additional information"
    )
    for other_info in additional_info.other_information:
        for item in other_info.content:
            if isinstance(item, SchemeTypeCommunityRules):
                for uri in item.uri:
                    rules.add(uri.value)
            elif isinstance(item, SchemeTerritory):
                territory = item.value
            elif isinstance(item, MimeType):
                list_type = item.value
    return pointer.tsllocation, list_type, territory, rules


@dataclass(frozen=True)
class TLReference:
    """
    Reference to a trusted list.
    """

    location_uri: str
    """
    URI where the trusted list can be found.
    """

    territory: str
    """
    Territory with which the references trusted list is assocated.
    """

    tlso_certs: List[x509.Certificate]
    """
    Certificates that can be used to validate the signature
    on the referenced trusted list.
    """

    scheme_rules: FrozenSet[str]
    """
    URIs for scheme rules that apply to the referenced trusted list.
    """


@dataclass(frozen=True)
class LOTLParseResult:
    references: List[TLReference]
    errors: List[TSPServiceParsingError]
    pivot_urls: List[str]


def parse_lotl_unsafe(
    lotl_xml: str,
) -> LOTLParseResult:
    """
    Parse a list-of-the-lists (LOTL).

    .. warning::
        This function does not include validating
        the signature on the LOTL.

    :param lotl_xml:
        XML LOTL payload
    :return:
        A parse result.
    """
    parse_result = _raw_tl_parse(lotl_xml)

    scheme_info = _required(
        parse_result.scheme_information, "LOTL scheme information"
    )
    pointers = _required(
        scheme_info.pointers_to_other_tsl, "pointers to other TSLs"
    )
    info_uris = _required(
        scheme_info.scheme_information_uri, "scheme information URIs"
    )

    references = []
    errors = []
    for pointer in pointers.other_tslpointer:
        location, list_type, territory, rules = _parse_tsl_info(pointer)
        if (
            list_type != ETSI_TSL_MIME_TYPE
            or location is None
            or territory is None
            or pointer.service_digital_identities is None
        ):
            continue
        tl_issuer_certs = []
        for (
            digital_identity
        ) in pointer.service_digital_identities.service_digital_identity:
            for sdi in digital_identity.digital_id:
                cert_bytes = sdi.x509_certificate
                if cert_bytes is not None:
                    try:
                        tl_issuer_certs.append(
                            x509.Certificate.load(cert_bytes)
                        )
                    except Exception as e:
                        errors.append(
                            TSPServiceParsingError(
                                f"Failed to load certificate for {territory} ({location}): {e}"
                            )
                        )
        ref = TLReference(
            location, territory, tl_issuer_certs, frozenset(rules)
        )
        references.append(ref)
    pivots = [
        info_uri.value
        for info_uri in info_uris.uri
        if info_uri.value.endswith(".xml")
    ]
    return LOTLParseResult(
        references=references, errors=errors, pivot_urls=pivots
    )


def _lotl_certs_file(fname: str) -> List[x509.Certificate]:
    pkg_files = resources.files("pyhanko.sign.validation.qualified")
    data = pkg_files.joinpath("lotl-certs", fname).read_bytes()
    return list(load_certs_from_pemder_data(data))


def latest_known_lotl_tlso_certs() -> List[x509.Certificate]:
    """
    Retrieve the lastest known (at the time of the most recent pyHanko release)
    list of LOTL signer certs.
    """
    return _lotl_certs_file("latest.cert.pem")


def ojeu_bootstrap_lotl_tlso_certs() -> List[x509.Certificate]:
    """
    Retrieve the list of certificates published
    in `OJ C 276, 16.8.2019 <https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2019.276.01.0001.01.ENG>`_,
    which is bundled with this library.
    """
    return _lotl_certs_file("bootstrap.cert.pem")


# TODO check validity time windows


def validate_and_parse_lotl(
    lotl_xml: str, lotl_tlso_certs: Optional[List[x509.Certificate]] = None
) -> LOTLParseResult:
    """
    Validate and parse a list-of-the-lists (LOTL).

    :param lotl_xml:
        XML LOTL payload
    :param lotl_tlso_certs:
        List of certificates that can be used to validate the list-of-the-lists.
        If not specified, the list-of-the-lists will be validated against the
        last known set of list-of-the-lists signer certs bundled with this
        library.

        See :func:`validate_and_parse_lotl`.
    :return:
        A parse result.
    """

    if not lotl_tlso_certs:
        lotl_tlso_certs = latest_known_lotl_tlso_certs()
    lotl_xml_validated = _validate_and_extract_tl_data_multiple_certs(
        lotl_xml, lotl_tlso_certs
    )
    return parse_lotl_unsafe(lotl_xml_validated)
