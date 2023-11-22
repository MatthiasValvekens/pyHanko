from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Tuple

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
    uri: Optional[str] = field(
        default=None,
        metadata={
            "type": "Attribute",
        },
    )


@dataclass(frozen=True)
class KeyUsageBitType:
    value: Optional[bool] = field(
        default=None,
        metadata={
            "required": True,
        },
    )
    name: Optional[KeyUsageBitTypename] = field(
        default=None,
        metadata={
            "type": "Attribute",
        },
    )


@dataclass(frozen=True)
class PoliciesListType:
    policy_identifier: Tuple[ObjectIdentifierType, ...] = field(
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
    qualifier: Tuple[QualifierType, ...] = field(
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
    key_usage_bit: Tuple[KeyUsageBitType, ...] = field(
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
    key_usage: Tuple[KeyUsageType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "KeyUsage",
            "type": "Element",
            "namespace": "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#",
        },
    )
    policy_set: Tuple[PoliciesListType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "PolicySet",
            "type": "Element",
            "namespace": "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#",
        },
    )
    criteria_list: Tuple["CriteriaListType", ...] = field(
        default_factory=tuple,
        metadata={
            "name": "CriteriaList",
            "type": "Element",
            "namespace": "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#",
        },
    )
    description: Optional[str] = field(
        default=None,
        metadata={
            "name": "Description",
            "type": "Element",
            "namespace": "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#",
        },
    )
    other_criteria_list: Optional[AnyType] = field(
        default=None,
        metadata={
            "name": "otherCriteriaList",
            "type": "Element",
            "namespace": "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#",
        },
    )
    assert_value: Optional[CriteriaListTypeassert] = field(
        default=None,
        metadata={
            "name": "assert",
            "type": "Attribute",
        },
    )


@dataclass(frozen=True)
class QualificationElementType:
    qualifiers: Optional[QualifiersType] = field(
        default=None,
        metadata={
            "name": "Qualifiers",
            "type": "Element",
            "namespace": "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#",
            "required": True,
        },
    )
    criteria_list: Optional[CriteriaListType] = field(
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
    qualification_element: Tuple[QualificationElementType, ...] = field(
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
