import itertools
import logging
from datetime import datetime
from typing import (
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
from xsdata.formats.dataclass.parsers import XmlParser
from xsdata.formats.dataclass.parsers.config import ParserConfig

from pyhanko.generated.etsi import (
    ts_119612,
    ts_119612_extra,
    ts_119612_sie,
    xades,
)
from pyhanko.sign.validation import KeyUsageConstraints
from pyhanko.sign.validation.qualified.tsp import (
    _SVCINFOEXT_URI_BASE,
    _TRSTSVC_URI_BASE,
    _TRUSTEDLIST_URI_BASE,
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
    Qualification,
    Qualifier,
    TSPServiceParsingError,
)

__all__ = ['read_qualified_certificate_authorities']

logger = logging.getLogger(__name__)
CA_QC_URI = f'{_TRSTSVC_URI_BASE}/Svctype/CA/QC'
QTST_URI = f'{_TRSTSVC_URI_BASE}/Svctype/TSA/QTST'
STATUS_GRANTED = f'{_TRUSTEDLIST_URI_BASE}/Svcstatus/granted'
_CERTIFICATE_TYPE_BY_URI = {
    f'{_SVCINFOEXT_URI_BASE}/ForeSignatures': QcCertType.QC_ESIGN,
    f'{_SVCINFOEXT_URI_BASE}/ForeSeals': QcCertType.QC_ESEAL,
    f'{_SVCINFOEXT_URI_BASE}/ForWebSiteAuthentication': QcCertType.QC_WEB,
}
_QUALIFIER_BY_URI = {q.uri: q for q in Qualifier}
PREFERRED_LANGUAGE: str = 'en'


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
    ]
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
                if bit.value == True
            )
            key_usage_forbidden = frozenset(
                _required(bit.name, "Key usage bit type name").name.lower()
                for bit in ku_criterion.key_usage_bit
                if bit.value == False
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
    service_info = service.service_information
    assert service_info is not None
    return _interpret_historical_service_info_for_ca(
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
        ),
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


def _read_service_history(history_items, validity_start, service_name):
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
        if history_item.service_status != STATUS_GRANTED:
            continue
        try:
            validity_end = end_of_validity_by_orig_ix[orig_ix]
            yield _interpret_historical_service_info_for_ca(
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


def _interpret_service_info_for_cas(
    services: Iterable[ts_119612.TSPService],
):
    errors_encountered = []
    for service in services:
        service_info = service.service_information
        if (
            not service_info
            or service_info.service_type_identifier != CA_QC_URI
        ):
            continue

        service_name = _service_name_from_intl_string(service_info.service_name)
        # TODO allow the user to specify if they also want to include
        #  other statuses (e.g. national level)
        # TODO evaluate historical definitions too in case of point-in-time
        #  work, store that info on the object
        if service_info.service_status == STATUS_GRANTED:
            try:
                yield _interpret_service_info_for_ca(service)
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
                history_items, validity_start, service_name
            )
            errors_encountered.extend(history_errors)

    return errors_encountered


def _raw_tl_parse(tl_xml: str) -> ts_119612.TrustServiceStatusList:
    parser = XmlParser(
        config=ParserConfig(
            load_dtd=False,
            process_xinclude=False,
            fail_on_unknown_properties=False,
            fail_on_unknown_attributes=False,
        ),
    )
    return parser.from_string(tl_xml, clazz=ts_119612.TrustServiceStatusList)


# TODO introduce a similar method for other types of service (TSAs etc)
def read_qualified_certificate_authorities(
    tl_xml: str,
) -> Generator[CAServiceInformation, None, List[TSPServiceParsingError]]:
    parse_result = _raw_tl_parse(tl_xml)
    tspl = parse_result.trust_service_provider_list
    errors_encountered = []
    for tsp in _required(tspl, "TSP list").trust_service_provider:
        tsp_errors = yield from _interpret_service_info_for_cas(
            _required(tsp.tspservices, "TSP services").tspservice
        )
        errors_encountered.extend(tsp_errors)
    return errors_encountered
