from dataclasses import dataclass, field
from enum import Enum

from .xades import AnyType, ObjectIdentifierType

__NAMESPACE__ = (
    "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#"
)


class CriteriaListTypeassert(Enum):
    ALL = "all"
    AT_LEAST_ONE = "atLeastOne"
    NONE = "none"


class KeyUsageBitTypename(Enum):
    DIGITAL_SIGNATURE = "digitalSignature"
    NON_REPUDIATION = "nonRepudiation"
    KEY_ENCIPHERMENT = "keyEncipherment"
    DATA_ENCIPHERMENT = "dataEncipherment"
    KEY_AGREEMENT = "keyAgreement"
    KEY_CERT_SIGN = "keyCertSign"
    CRL_SIGN = "crlSign"
    ENCIPHER_ONLY = "encipherOnly"
    DECIPHER_ONLY = "decipherOnly"


@dataclass(frozen=True)
class QualifierType:
    uri: str | None = field(
        default=None,
        metadata={
            "type": "Attribute",
        },
    )


@dataclass(frozen=True)
class KeyUsageBitType:
    value: bool | None = field(
        default=None,
        metadata={
            "required": True,
        },
    )
    name: KeyUsageBitTypename | None = field(
        default=None,
        metadata={
            "type": "Attribute",
        },
    )


@dataclass(frozen=True)
class PoliciesListType:
    policy_identifier: tuple[ObjectIdentifierType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "PolicyIdentifier",
            "type": "Element",
            "namespace": "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#",
            "min_occurs": 1,
        },
    )


@dataclass(frozen=True)
class QualifiersType:
    qualifier: tuple[QualifierType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "Qualifier",
            "type": "Element",
            "namespace": "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#",
            "min_occurs": 1,
        },
    )


@dataclass(frozen=True)
class KeyUsageType:
    key_usage_bit: tuple[KeyUsageBitType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "KeyUsageBit",
            "type": "Element",
            "namespace": "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#",
            "min_occurs": 1,
            "max_occurs": 9,
        },
    )


@dataclass(frozen=True)
class CriteriaListType:
    key_usage: tuple[KeyUsageType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "KeyUsage",
            "type": "Element",
            "namespace": "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#",
        },
    )
    policy_set: tuple[PoliciesListType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "PolicySet",
            "type": "Element",
            "namespace": "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#",
        },
    )
    criteria_list: tuple["CriteriaListType", ...] = field(
        default_factory=tuple,
        metadata={
            "name": "CriteriaList",
            "type": "Element",
            "namespace": "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#",
        },
    )
    description: str | None = field(
        default=None,
        metadata={
            "name": "Description",
            "type": "Element",
            "namespace": "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#",
        },
    )
    other_criteria_list: AnyType | None = field(
        default=None,
        metadata={
            "name": "otherCriteriaList",
            "type": "Element",
            "namespace": "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#",
        },
    )
    assert_value: CriteriaListTypeassert | None = field(
        default=None,
        metadata={
            "name": "assert",
            "type": "Attribute",
        },
    )


@dataclass(frozen=True)
class QualificationElementType:
    qualifiers: QualifiersType | None = field(
        default=None,
        metadata={
            "name": "Qualifiers",
            "type": "Element",
            "namespace": "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#",
            "required": True,
        },
    )
    criteria_list: CriteriaListType | None = field(
        default=None,
        metadata={
            "name": "CriteriaList",
            "type": "Element",
            "namespace": "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#",
            "required": True,
        },
    )


@dataclass(frozen=True)
class QualificationsType:
    qualification_element: tuple[QualificationElementType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "QualificationElement",
            "type": "Element",
            "namespace": "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#",
            "min_occurs": 1,
        },
    )


@dataclass(frozen=True)
class Qualifications(QualificationsType):
    class Meta:
        namespace = "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#"
