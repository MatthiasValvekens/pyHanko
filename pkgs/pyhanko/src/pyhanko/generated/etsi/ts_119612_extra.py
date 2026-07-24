from dataclasses import dataclass, field

from .ts_119612 import (
    AnyType,
    InternationalNamesType,
    NonEmptyMultiLangURIType,
    SchemeOperatorName,
)
from .xades import ObjectIdentifierType

__NAMESPACE__ = "http://uri.etsi.org/02231/v2/additionaltypes#"


@dataclass(frozen=True)
class MimeType:
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2/additionaltypes#"

    value: str = field(
        default="",
        metadata={
            "required": True,
        },
    )


@dataclass(frozen=True)
class PublicKeyLocation:
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2/additionaltypes#"

    value: str = field(
        default="",
        metadata={
            "required": True,
            "min_length": 1,
        },
    )


@dataclass(frozen=True)
class X509CertificateLocation:
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2/additionaltypes#"

    value: str = field(
        default="",
        metadata={
            "required": True,
            "min_length": 1,
        },
    )


@dataclass(frozen=True)
class CertSubjectDNAttributeType:
    attribute_oid: tuple[ObjectIdentifierType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "AttributeOID",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2/additionaltypes#",
            "min_occurs": 1,
        },
    )


@dataclass(frozen=True)
class ExtendedKeyUsageType:
    key_purpose_id: tuple[ObjectIdentifierType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "KeyPurposeId",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2/additionaltypes#",
            "min_occurs": 1,
        },
    )


@dataclass(frozen=True)
class TakenOverByType:
    uri: NonEmptyMultiLangURIType | None = field(
        default=None,
        metadata={
            "name": "URI",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2/additionaltypes#",
            "required": True,
        },
    )
    tspname: InternationalNamesType | None = field(
        default=None,
        metadata={
            "name": "TSPName",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2/additionaltypes#",
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
    scheme_territory: str | None = field(
        default=None,
        metadata={
            "name": "SchemeTerritory",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2#",
            "required": True,
        },
    )
    other_qualifier: tuple[AnyType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "OtherQualifier",
            "type": "Element",
            "namespace": "http://uri.etsi.org/02231/v2/additionaltypes#",
        },
    )


@dataclass(frozen=True)
class CertSubjectDNAttribute(CertSubjectDNAttributeType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2/additionaltypes#"


@dataclass(frozen=True)
class ExtendedKeyUsage(ExtendedKeyUsageType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2/additionaltypes#"


@dataclass(frozen=True)
class TakenOverBy(TakenOverByType):
    class Meta:
        namespace = "http://uri.etsi.org/02231/v2/additionaltypes#"
