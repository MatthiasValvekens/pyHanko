from dataclasses import dataclass, field

from xsdata.models.datatype import XmlDateTime

from ..w3c.xmldsig_core import KeyValue, Signature
from ..xml import Langvalue

__NAMESPACE__ = "http://uri.etsi.org/02231/v2#"


@dataclass(frozen=True)
class AnyType:
    content: tuple[object, ...] = field(
        default_factory=tuple,
        metadata={
            "type": "Wildcard",
            "namespace": "##any",
            "mixed": True,
        },
    )


@dataclass(frozen=True)
class AttributedNonEmptyURIType:
    value: str = field(
        default="",
        metadata={
            "required": True,
            "min_length": 1,
        },
    )
    type_value: str | None = field(
        default=None,
        metadata={
            "name": "type",
            "type": "Attribute",
        },
    )


@dataclass(frozen=True)
class ExpiredCertsRevocationInfo:
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"

    value: XmlDateTime | None = field(
        default=None,
        metadata={
            "required": True,
        },
    )


@dataclass(frozen=True)
class NextUpdateType:
    date_time: XmlDateTime | None = field(
        default=None,
        metadata={
            "name": "dateTime",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
        },
    )


@dataclass(frozen=True)
class NonEmptyURIListType:
    uri: tuple[str, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "URI",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "min_occurs": 1,
            "min_length": 1,
        },
    )


@dataclass(frozen=True)
class SchemeTerritory:
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"

    value: str = field(
        default="",
        metadata={
            "required": True,
        },
    )


@dataclass(frozen=True)
class ServiceStatus:
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"

    value: str = field(
        default="",
        metadata={
            "required": True,
            "min_length": 1,
        },
    )


@dataclass(frozen=True)
class ServiceTypeIdentifier:
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"

    value: str = field(
        default="",
        metadata={
            "required": True,
            "min_length": 1,
        },
    )


@dataclass(frozen=True)
class TSLType:
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"

    value: str = field(
        default="",
        metadata={
            "required": True,
            "min_length": 1,
        },
    )


@dataclass(frozen=True)
class DigitalIdentityType:
    x509_certificate: bytes | None = field(
        default=None,
        metadata={
            "name": "X509Certificate",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "format": "base64",
        },
    )
    x509_subject_name: str | None = field(
        default=None,
        metadata={
            "name": "X509SubjectName",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
        },
    )
    key_value: KeyValue | None = field(
        default=None,
        metadata={
            "name": "KeyValue",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
        },
    )
    x509_ski: bytes | None = field(
        default=None,
        metadata={
            "name": "X509SKI",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "format": "base64",
        },
    )
    other: AnyType | None = field(
        default=None,
        metadata={
            "name": "Other",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
        },
    )


@dataclass(frozen=True)
class DistributionPoints(NonEmptyURIListType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"


@dataclass(frozen=True)
class ExtensionType(AnyType):
    critical: bool | None = field(
        default=None,
        metadata={
            "name": "Critical",
            "type": "Attribute",
            "required": True,
        },
    )


@dataclass(frozen=True)
class MultiLangNormStringType:
    value: str = field(
        default="",
        metadata={
            "required": True,
            "min_length": 1,
        },
    )
    lang: str | Langvalue | None = field(
        default=None,
        metadata={
            "type": "Attribute",
            "namespace": "http://www.w3.org/XML/1998/namespace",
            "required": True,
        },
    )


@dataclass(frozen=True)
class MultiLangStringType:
    value: str = field(
        default="",
        metadata={
            "required": True,
            "min_length": 1,
        },
    )
    lang: str | Langvalue | None = field(
        default=None,
        metadata={
            "type": "Attribute",
            "namespace": "http://www.w3.org/XML/1998/namespace",
            "required": True,
        },
    )


@dataclass(frozen=True)
class NextUpdate(NextUpdateType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"


@dataclass(frozen=True)
class NonEmptyMultiLangURIType:
    value: str = field(
        default="",
        metadata={
            "required": True,
            "min_length": 1,
        },
    )
    lang: str | Langvalue | None = field(
        default=None,
        metadata={
            "type": "Attribute",
            "namespace": "http://www.w3.org/XML/1998/namespace",
            "required": True,
        },
    )


@dataclass(frozen=True)
class PostalAddressType:
    street_address: str | None = field(
        default=None,
        metadata={
            "name": "StreetAddress",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
            "min_length": 1,
        },
    )
    locality: str | None = field(
        default=None,
        metadata={
            "name": "Locality",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
            "min_length": 1,
        },
    )
    state_or_province: str | None = field(
        default=None,
        metadata={
            "name": "StateOrProvince",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "min_length": 1,
        },
    )
    postal_code: str | None = field(
        default=None,
        metadata={
            "name": "PostalCode",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "min_length": 1,
        },
    )
    country_name: str | None = field(
        default=None,
        metadata={
            "name": "CountryName",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
            "min_length": 1,
        },
    )
    lang: str | Langvalue | None = field(
        default=None,
        metadata={
            "type": "Attribute",
            "namespace": "http://www.w3.org/XML/1998/namespace",
            "required": True,
        },
    )


@dataclass(frozen=True)
class ServiceSupplyPointsType:
    service_supply_point: tuple[AttributedNonEmptyURIType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "ServiceSupplyPoint",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "min_occurs": 1,
        },
    )


@dataclass(frozen=True)
class AdditionalInformationType:
    textual_information: tuple[MultiLangStringType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "TextualInformation",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
        },
    )
    other_information: tuple[AnyType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "OtherInformation",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
        },
    )


@dataclass(frozen=True)
class AdditionalServiceInformationType:
    uri: NonEmptyMultiLangURIType | None = field(
        default=None,
        metadata={
            "name": "URI",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    information_value: str | None = field(
        default=None,
        metadata={
            "name": "InformationValue",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
        },
    )
    other_information: AnyType | None = field(
        default=None,
        metadata={
            "name": "OtherInformation",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
        },
    )


@dataclass(frozen=True)
class DigitalIdentityListType:
    digital_id: tuple[DigitalIdentityType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "DigitalId",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
        },
    )


@dataclass(frozen=True)
class ElectronicAddressType:
    uri: tuple[NonEmptyMultiLangURIType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "URI",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "min_occurs": 1,
        },
    )


@dataclass(frozen=True)
class Extension(ExtensionType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"


@dataclass(frozen=True)
class InternationalNamesType:
    name: tuple[MultiLangNormStringType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "Name",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "min_occurs": 1,
        },
    )


@dataclass(frozen=True)
class NonEmptyMultiLangURIListType:
    uri: tuple[NonEmptyMultiLangURIType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "URI",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "min_occurs": 1,
        },
    )


@dataclass(frozen=True)
class PolicyOrLegalnoticeType:
    tslpolicy: tuple[NonEmptyMultiLangURIType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "TSLPolicy",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
        },
    )
    tsllegal_notice: tuple[MultiLangStringType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "TSLLegalNotice",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
        },
    )


@dataclass(frozen=True)
class PostalAddress(PostalAddressType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"


@dataclass(frozen=True)
class ServiceSupplyPoints(ServiceSupplyPointsType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"


@dataclass(frozen=True)
class AdditionalInformation(AdditionalInformationType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"


@dataclass(frozen=True)
class AdditionalServiceInformation(AdditionalServiceInformationType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"


@dataclass(frozen=True)
class ElectronicAddress(ElectronicAddressType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"


@dataclass(frozen=True)
class ExtensionsListType:
    extension: tuple[Extension, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "Extension",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "min_occurs": 1,
        },
    )


@dataclass(frozen=True)
class PolicyOrLegalNotice(PolicyOrLegalnoticeType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"


@dataclass(frozen=True)
class PostalAddressListType:
    postal_address: tuple[PostalAddress, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "PostalAddress",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "min_occurs": 1,
        },
    )


@dataclass(frozen=True)
class SchemeInformationURI(NonEmptyMultiLangURIListType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"


@dataclass(frozen=True)
class SchemeName(InternationalNamesType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"


@dataclass(frozen=True)
class SchemeOperatorName(InternationalNamesType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"


@dataclass(frozen=True)
class SchemeTypeCommunityRules(NonEmptyMultiLangURIListType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"


@dataclass(frozen=True)
class ServiceDigitalIdentity(DigitalIdentityListType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"


@dataclass(frozen=True)
class PostalAddresses(PostalAddressListType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"


@dataclass(frozen=True)
class ServiceDigitalIdentityListType:
    service_digital_identity: tuple[ServiceDigitalIdentity, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "ServiceDigitalIdentity",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "min_occurs": 1,
        },
    )


@dataclass(frozen=True)
class ServiceHistoryInstanceType:
    service_type_identifier: ServiceTypeIdentifier | None = field(
        default=None,
        metadata={
            "name": "ServiceTypeIdentifier",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    service_name: InternationalNamesType | None = field(
        default=None,
        metadata={
            "name": "ServiceName",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    service_digital_identity: ServiceDigitalIdentity | None = field(
        default=None,
        metadata={
            "name": "ServiceDigitalIdentity",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    service_status: ServiceStatus | None = field(
        default=None,
        metadata={
            "name": "ServiceStatus",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    status_starting_time: XmlDateTime | None = field(
        default=None,
        metadata={
            "name": "StatusStartingTime",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    service_information_extensions: ExtensionsListType | None = field(
        default=None,
        metadata={
            "name": "ServiceInformationExtensions",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
        },
    )


@dataclass(frozen=True)
class TSPServiceInformationType:
    service_type_identifier: ServiceTypeIdentifier | None = field(
        default=None,
        metadata={
            "name": "ServiceTypeIdentifier",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    service_name: InternationalNamesType | None = field(
        default=None,
        metadata={
            "name": "ServiceName",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    service_digital_identity: ServiceDigitalIdentity | None = field(
        default=None,
        metadata={
            "name": "ServiceDigitalIdentity",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    service_status: ServiceStatus | None = field(
        default=None,
        metadata={
            "name": "ServiceStatus",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    status_starting_time: XmlDateTime | None = field(
        default=None,
        metadata={
            "name": "StatusStartingTime",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    scheme_service_definition_uri: NonEmptyMultiLangURIListType | None = field(
        default=None,
        metadata={
            "name": "SchemeServiceDefinitionURI",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
        },
    )
    service_supply_points: ServiceSupplyPoints | None = field(
        default=None,
        metadata={
            "name": "ServiceSupplyPoints",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
        },
    )
    tspservice_definition_uri: NonEmptyMultiLangURIListType | None = field(
        default=None,
        metadata={
            "name": "TSPServiceDefinitionURI",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
        },
    )
    service_information_extensions: ExtensionsListType | None = field(
        default=None,
        metadata={
            "name": "ServiceInformationExtensions",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
        },
    )


@dataclass(frozen=True)
class AddressType:
    postal_addresses: PostalAddresses | None = field(
        default=None,
        metadata={
            "name": "PostalAddresses",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    electronic_address: ElectronicAddress | None = field(
        default=None,
        metadata={
            "name": "ElectronicAddress",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )


@dataclass(frozen=True)
class ServiceDigitalIdentities(ServiceDigitalIdentityListType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"


@dataclass(frozen=True)
class ServiceHistoryInstance(ServiceHistoryInstanceType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"


@dataclass(frozen=True)
class ServiceInformation(TSPServiceInformationType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"


@dataclass(frozen=True)
class OtherTSLPointerType:
    service_digital_identities: ServiceDigitalIdentities | None = field(
        default=None,
        metadata={
            "name": "ServiceDigitalIdentities",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
        },
    )
    tsllocation: str | None = field(
        default=None,
        metadata={
            "name": "TSLLocation",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
            "min_length": 1,
        },
    )
    additional_information: AdditionalInformation | None = field(
        default=None,
        metadata={
            "name": "AdditionalInformation",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
        },
    )


@dataclass(frozen=True)
class ServiceHistoryType:
    service_history_instance: tuple[ServiceHistoryInstance, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "ServiceHistoryInstance",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
        },
    )


@dataclass(frozen=True)
class TSPInformationType:
    tspname: InternationalNamesType | None = field(
        default=None,
        metadata={
            "name": "TSPName",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    tsptrade_name: InternationalNamesType | None = field(
        default=None,
        metadata={
            "name": "TSPTradeName",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
        },
    )
    tspaddress: AddressType | None = field(
        default=None,
        metadata={
            "name": "TSPAddress",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    tspinformation_uri: NonEmptyMultiLangURIListType | None = field(
        default=None,
        metadata={
            "name": "TSPInformationURI",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    tspinformation_extensions: ExtensionsListType | None = field(
        default=None,
        metadata={
            "name": "TSPInformationExtensions",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
        },
    )


@dataclass(frozen=True)
class OtherTSLPointer(OtherTSLPointerType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"


@dataclass(frozen=True)
class ServiceHistory(ServiceHistoryType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"


@dataclass(frozen=True)
class TSPInformation(TSPInformationType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"


@dataclass(frozen=True)
class OtherTSLPointersType:
    other_tslpointer: tuple[OtherTSLPointer, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "OtherTSLPointer",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "min_occurs": 1,
        },
    )


@dataclass(frozen=True)
class TSPServiceType:
    service_information: ServiceInformation | None = field(
        default=None,
        metadata={
            "name": "ServiceInformation",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    service_history: ServiceHistory | None = field(
        default=None,
        metadata={
            "name": "ServiceHistory",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
        },
    )


@dataclass(frozen=True)
class PointersToOtherTSL(OtherTSLPointersType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"


@dataclass(frozen=True)
class TSPService(TSPServiceType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"


@dataclass(frozen=True)
class TSLSchemeInformationType:
    tslversion_identifier: int | None = field(
        default=None,
        metadata={
            "name": "TSLVersionIdentifier",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    tslsequence_number: int | None = field(
        default=None,
        metadata={
            "name": "TSLSequenceNumber",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    tsltype: TSLType | None = field(
        default=None,
        metadata={
            "name": "TSLType",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    scheme_operator_name: SchemeOperatorName | None = field(
        default=None,
        metadata={
            "name": "SchemeOperatorName",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    scheme_operator_address: AddressType | None = field(
        default=None,
        metadata={
            "name": "SchemeOperatorAddress",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    scheme_name: SchemeName | None = field(
        default=None,
        metadata={
            "name": "SchemeName",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    scheme_information_uri: SchemeInformationURI | None = field(
        default=None,
        metadata={
            "name": "SchemeInformationURI",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    status_determination_approach: str | None = field(
        default=None,
        metadata={
            "name": "StatusDeterminationApproach",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
            "min_length": 1,
        },
    )
    scheme_type_community_rules: SchemeTypeCommunityRules | None = field(
        default=None,
        metadata={
            "name": "SchemeTypeCommunityRules",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
        },
    )
    scheme_territory: SchemeTerritory | None = field(
        default=None,
        metadata={
            "name": "SchemeTerritory",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
        },
    )
    policy_or_legal_notice: PolicyOrLegalNotice | None = field(
        default=None,
        metadata={
            "name": "PolicyOrLegalNotice",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
        },
    )
    historical_information_period: int | None = field(
        default=None,
        metadata={
            "name": "HistoricalInformationPeriod",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    pointers_to_other_tsl: PointersToOtherTSL | None = field(
        default=None,
        metadata={
            "name": "PointersToOtherTSL",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
        },
    )
    list_issue_date_time: XmlDateTime | None = field(
        default=None,
        metadata={
            "name": "ListIssueDateTime",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    next_update: NextUpdate | None = field(
        default=None,
        metadata={
            "name": "NextUpdate",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    distribution_points: DistributionPoints | None = field(
        default=None,
        metadata={
            "name": "DistributionPoints",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
        },
    )
    scheme_extensions: ExtensionsListType | None = field(
        default=None,
        metadata={
            "name": "SchemeExtensions",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
        },
    )


@dataclass(frozen=True)
class TSPServicesListType:
    tspservice: tuple[TSPService, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "TSPService",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "min_occurs": 1,
        },
    )


@dataclass(frozen=True)
class SchemeInformation(TSLSchemeInformationType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"


@dataclass(frozen=True)
class TSPServices(TSPServicesListType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"


@dataclass(frozen=True)
class TSPType:
    tspinformation: TSPInformation | None = field(
        default=None,
        metadata={
            "name": "TSPInformation",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    tspservices: TSPServices | None = field(
        default=None,
        metadata={
            "name": "TSPServices",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )


@dataclass(frozen=True)
class TrustServiceProvider(TSPType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"


@dataclass(frozen=True)
class TrustServiceProviderListType:
    trust_service_provider: tuple[TrustServiceProvider, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "TrustServiceProvider",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "min_occurs": 1,
        },
    )


@dataclass(frozen=True)
class TrustServiceProviderList(TrustServiceProviderListType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"


@dataclass(frozen=True)
class TrustStatusListType:
    scheme_information: SchemeInformation | None = field(
        default=None,
        metadata={
            "name": "SchemeInformation",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    trust_service_provider_list: TrustServiceProviderList | None = field(
        default=None,
        metadata={
            "name": "TrustServiceProviderList",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
        },
    )
    signature: Signature | None = field(
        default=None,
        metadata={
            "name": "Signature",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
        },
    )
    tsltag: str | None = field(
        default=None,
        metadata={
            "name": "TSLTag",
            "type": "Attribute",
            "required": True,
        },
    )
    id: str | None = field(
        default=None,
        metadata={
            "name": "Id",
            "type": "Attribute",
        },
    )


@dataclass(frozen=True)
class TrustServiceStatusList(TrustStatusListType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2#"
