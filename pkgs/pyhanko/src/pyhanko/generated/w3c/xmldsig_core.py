from dataclasses import dataclass, field

__NAMESPACE__ = "http://www.w3.org/2000/09/xmldsig#"


@dataclass(frozen=True)
class CanonicalizationMethodType:
    algorithm: str | None = field(
        default=None,
        metadata={
            "name": "Algorithm",
            "type": "Attribute",
            "required": True,
        },
    )
    content: tuple[object, ...] = field(
        default_factory=tuple,
        metadata={
            "type": "Wildcard",
            "namespace": "##any",
            "mixed": True,
        },
    )


@dataclass(frozen=True)
class DSAKeyValueType:
    p: bytes | None = field(
        default=None,
        metadata={
            "name": "P",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
            "format": "base64",
        },
    )
    q: bytes | None = field(
        default=None,
        metadata={
            "name": "Q",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
            "format": "base64",
        },
    )
    g: bytes | None = field(
        default=None,
        metadata={
            "name": "G",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
            "format": "base64",
        },
    )
    y: bytes | None = field(
        default=None,
        metadata={
            "name": "Y",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
            "required": True,
            "format": "base64",
        },
    )
    j: bytes | None = field(
        default=None,
        metadata={
            "name": "J",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
            "format": "base64",
        },
    )
    seed: bytes | None = field(
        default=None,
        metadata={
            "name": "Seed",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
            "format": "base64",
        },
    )
    pgen_counter: bytes | None = field(
        default=None,
        metadata={
            "name": "PgenCounter",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
            "format": "base64",
        },
    )


@dataclass(frozen=True)
class DigestMethodType:
    algorithm: str | None = field(
        default=None,
        metadata={
            "name": "Algorithm",
            "type": "Attribute",
            "required": True,
        },
    )
    content: tuple[object, ...] = field(
        default_factory=tuple,
        metadata={
            "type": "Wildcard",
            "namespace": "##any",
            "mixed": True,
        },
    )


@dataclass(frozen=True)
class DigestValue:
    class Meta:
        namespace = "http://www.w3.org/2000/09/xmldsig#"

    value: bytes | None = field(
        default=None,
        metadata={
            "required": True,
            "format": "base64",
        },
    )


@dataclass(frozen=True)
class KeyName:
    class Meta:
        namespace = "http://www.w3.org/2000/09/xmldsig#"

    value: str = field(
        default="",
        metadata={
            "required": True,
        },
    )


@dataclass(frozen=True)
class MgmtData:
    class Meta:
        namespace = "http://www.w3.org/2000/09/xmldsig#"

    value: str = field(
        default="",
        metadata={
            "required": True,
        },
    )


@dataclass(frozen=True)
class ObjectType:
    id: str | None = field(
        default=None,
        metadata={
            "name": "Id",
            "type": "Attribute",
        },
    )
    mime_type: str | None = field(
        default=None,
        metadata={
            "name": "MimeType",
            "type": "Attribute",
        },
    )
    encoding: str | None = field(
        default=None,
        metadata={
            "name": "Encoding",
            "type": "Attribute",
        },
    )
    content: tuple[object, ...] = field(
        default_factory=tuple,
        metadata={
            "type": "Wildcard",
            "namespace": "##any",
            "mixed": True,
        },
    )


@dataclass(frozen=True)
class PGPDataType:
    pgpkey_id: bytes | None = field(
        default=None,
        metadata={
            "name": "PGPKeyID",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
            "required": True,
            "format": "base64",
        },
    )
    pgpkey_packet: tuple[bytes, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "PGPKeyPacket",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
            "max_occurs": 2,
            "format": "base64",
        },
    )
    other_element: tuple[object, ...] = field(
        default_factory=tuple,
        metadata={
            "type": "Wildcard",
            "namespace": "##other",
        },
    )


@dataclass(frozen=True)
class RSAKeyValueType:
    modulus: bytes | None = field(
        default=None,
        metadata={
            "name": "Modulus",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
            "required": True,
            "format": "base64",
        },
    )
    exponent: bytes | None = field(
        default=None,
        metadata={
            "name": "Exponent",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
            "required": True,
            "format": "base64",
        },
    )


@dataclass(frozen=True)
class SPKIDataType:
    spkisexp: tuple[bytes, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "SPKISexp",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
            "min_occurs": 1,
            "sequence": 1,
            "format": "base64",
        },
    )
    other_element: tuple[object, ...] = field(
        default_factory=tuple,
        metadata={
            "type": "Wildcard",
            "namespace": "##other",
            "sequence": 1,
        },
    )


@dataclass(frozen=True)
class SignatureMethodType:
    algorithm: str | None = field(
        default=None,
        metadata={
            "name": "Algorithm",
            "type": "Attribute",
            "required": True,
        },
    )
    content: tuple[object, ...] = field(
        default_factory=tuple,
        metadata={
            "type": "Wildcard",
            "namespace": "##any",
            "mixed": True,
            "choices": (
                {
                    "name": "HMACOutputLength",
                    "type": int,
                    "namespace": "http://www.w3.org/2000/09/xmldsig#",
                },
            ),
        },
    )


@dataclass(frozen=True)
class SignaturePropertyType:
    target: str | None = field(
        default=None,
        metadata={
            "name": "Target",
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
    content: tuple[object, ...] = field(
        default_factory=tuple,
        metadata={
            "type": "Wildcard",
            "namespace": "##any",
            "mixed": True,
        },
    )


@dataclass(frozen=True)
class SignatureValueType:
    value: bytes | None = field(
        default=None,
        metadata={
            "required": True,
            "format": "base64",
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
class TransformType:
    algorithm: str | None = field(
        default=None,
        metadata={
            "name": "Algorithm",
            "type": "Attribute",
            "required": True,
        },
    )
    content: tuple[object, ...] = field(
        default_factory=tuple,
        metadata={
            "type": "Wildcard",
            "namespace": "##any",
            "mixed": True,
            "choices": (
                {
                    "name": "XPath",
                    "type": str,
                    "namespace": "http://www.w3.org/2000/09/xmldsig#",
                },
            ),
        },
    )


@dataclass(frozen=True)
class X509IssuerSerialType:
    x509_issuer_name: str | None = field(
        default=None,
        metadata={
            "name": "X509IssuerName",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
            "required": True,
        },
    )
    x509_serial_number: int | None = field(
        default=None,
        metadata={
            "name": "X509SerialNumber",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
            "required": True,
        },
    )


@dataclass(frozen=True)
class CanonicalizationMethod(CanonicalizationMethodType):
    class Meta:
        namespace = "http://www.w3.org/2000/09/xmldsig#"


@dataclass(frozen=True)
class DSAKeyValue(DSAKeyValueType):
    class Meta:
        namespace = "http://www.w3.org/2000/09/xmldsig#"


@dataclass(frozen=True)
class DigestMethod(DigestMethodType):
    class Meta:
        namespace = "http://www.w3.org/2000/09/xmldsig#"


@dataclass(frozen=True)
class Object(ObjectType):
    class Meta:
        namespace = "http://www.w3.org/2000/09/xmldsig#"


@dataclass(frozen=True)
class PGPData(PGPDataType):
    class Meta:
        namespace = "http://www.w3.org/2000/09/xmldsig#"


@dataclass(frozen=True)
class RSAKeyValue(RSAKeyValueType):
    class Meta:
        namespace = "http://www.w3.org/2000/09/xmldsig#"


@dataclass(frozen=True)
class SPKIData(SPKIDataType):
    class Meta:
        namespace = "http://www.w3.org/2000/09/xmldsig#"


@dataclass(frozen=True)
class SignatureMethod(SignatureMethodType):
    class Meta:
        namespace = "http://www.w3.org/2000/09/xmldsig#"


@dataclass(frozen=True)
class SignatureProperty(SignaturePropertyType):
    class Meta:
        namespace = "http://www.w3.org/2000/09/xmldsig#"


@dataclass(frozen=True)
class SignatureValue(SignatureValueType):
    class Meta:
        namespace = "http://www.w3.org/2000/09/xmldsig#"


@dataclass(frozen=True)
class Transform(TransformType):
    class Meta:
        namespace = "http://www.w3.org/2000/09/xmldsig#"


@dataclass(frozen=True)
class X509DataType:
    x509_issuer_serial: tuple[X509IssuerSerialType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "X509IssuerSerial",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
            "sequence": 1,
        },
    )
    x509_ski: tuple[bytes, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "X509SKI",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
            "sequence": 1,
            "format": "base64",
        },
    )
    x509_subject_name: tuple[str, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "X509SubjectName",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
            "sequence": 1,
        },
    )
    x509_certificate: tuple[bytes, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "X509Certificate",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
            "sequence": 1,
            "format": "base64",
        },
    )
    x509_crl: tuple[bytes, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "X509CRL",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
            "sequence": 1,
            "format": "base64",
        },
    )
    other_element: tuple[object, ...] = field(
        default_factory=tuple,
        metadata={
            "type": "Wildcard",
            "namespace": "##other",
            "sequence": 1,
        },
    )


@dataclass(frozen=True)
class KeyValueType:
    content: tuple[object, ...] = field(
        default_factory=tuple,
        metadata={
            "type": "Wildcard",
            "namespace": "##any",
            "mixed": True,
            "choices": (
                {
                    "name": "DSAKeyValue",
                    "type": DSAKeyValue,
                    "namespace": "http://www.w3.org/2000/09/xmldsig#",
                },
                {
                    "name": "RSAKeyValue",
                    "type": RSAKeyValue,
                    "namespace": "http://www.w3.org/2000/09/xmldsig#",
                },
            ),
        },
    )


@dataclass(frozen=True)
class SignaturePropertiesType:
    signature_property: tuple[SignatureProperty, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "SignatureProperty",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
            "min_occurs": 1,
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
class TransformsType:
    transform: tuple[Transform, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "Transform",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
            "min_occurs": 1,
        },
    )


@dataclass(frozen=True)
class X509Data(X509DataType):
    class Meta:
        namespace = "http://www.w3.org/2000/09/xmldsig#"


@dataclass(frozen=True)
class KeyValue(KeyValueType):
    class Meta:
        namespace = "http://www.w3.org/2000/09/xmldsig#"


@dataclass(frozen=True)
class SignatureProperties(SignaturePropertiesType):
    class Meta:
        namespace = "http://www.w3.org/2000/09/xmldsig#"


@dataclass(frozen=True)
class Transforms(TransformsType):
    class Meta:
        namespace = "http://www.w3.org/2000/09/xmldsig#"


@dataclass(frozen=True)
class ReferenceType:
    transforms: Transforms | None = field(
        default=None,
        metadata={
            "name": "Transforms",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
        },
    )
    digest_method: DigestMethod | None = field(
        default=None,
        metadata={
            "name": "DigestMethod",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
            "required": True,
        },
    )
    digest_value: DigestValue | None = field(
        default=None,
        metadata={
            "name": "DigestValue",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
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
    uri: str | None = field(
        default=None,
        metadata={
            "name": "URI",
            "type": "Attribute",
        },
    )
    type_value: str | None = field(
        default=None,
        metadata={
            "name": "Type",
            "type": "Attribute",
        },
    )


@dataclass(frozen=True)
class RetrievalMethodType:
    transforms: Transforms | None = field(
        default=None,
        metadata={
            "name": "Transforms",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
        },
    )
    uri: str | None = field(
        default=None,
        metadata={
            "name": "URI",
            "type": "Attribute",
        },
    )
    type_value: str | None = field(
        default=None,
        metadata={
            "name": "Type",
            "type": "Attribute",
        },
    )


@dataclass(frozen=True)
class Reference(ReferenceType):
    class Meta:
        namespace = "http://www.w3.org/2000/09/xmldsig#"


@dataclass(frozen=True)
class RetrievalMethod(RetrievalMethodType):
    class Meta:
        namespace = "http://www.w3.org/2000/09/xmldsig#"


@dataclass(frozen=True)
class KeyInfoType:
    id: str | None = field(
        default=None,
        metadata={
            "name": "Id",
            "type": "Attribute",
        },
    )
    content: tuple[object, ...] = field(
        default_factory=tuple,
        metadata={
            "type": "Wildcard",
            "namespace": "##any",
            "mixed": True,
            "choices": (
                {
                    "name": "KeyName",
                    "type": KeyName,
                    "namespace": "http://www.w3.org/2000/09/xmldsig#",
                },
                {
                    "name": "KeyValue",
                    "type": KeyValue,
                    "namespace": "http://www.w3.org/2000/09/xmldsig#",
                },
                {
                    "name": "RetrievalMethod",
                    "type": RetrievalMethod,
                    "namespace": "http://www.w3.org/2000/09/xmldsig#",
                },
                {
                    "name": "X509Data",
                    "type": X509Data,
                    "namespace": "http://www.w3.org/2000/09/xmldsig#",
                },
                {
                    "name": "PGPData",
                    "type": PGPData,
                    "namespace": "http://www.w3.org/2000/09/xmldsig#",
                },
                {
                    "name": "SPKIData",
                    "type": SPKIData,
                    "namespace": "http://www.w3.org/2000/09/xmldsig#",
                },
                {
                    "name": "MgmtData",
                    "type": MgmtData,
                    "namespace": "http://www.w3.org/2000/09/xmldsig#",
                },
            ),
        },
    )


@dataclass(frozen=True)
class ManifestType:
    reference: tuple[Reference, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "Reference",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
            "min_occurs": 1,
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
class SignedInfoType:
    canonicalization_method: CanonicalizationMethod | None = field(
        default=None,
        metadata={
            "name": "CanonicalizationMethod",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
            "required": True,
        },
    )
    signature_method: SignatureMethod | None = field(
        default=None,
        metadata={
            "name": "SignatureMethod",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
            "required": True,
        },
    )
    reference: tuple[Reference, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "Reference",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
            "min_occurs": 1,
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
class KeyInfo(KeyInfoType):
    class Meta:
        namespace = "http://www.w3.org/2000/09/xmldsig#"


@dataclass(frozen=True)
class Manifest(ManifestType):
    class Meta:
        namespace = "http://www.w3.org/2000/09/xmldsig#"


@dataclass(frozen=True)
class SignedInfo(SignedInfoType):
    class Meta:
        namespace = "http://www.w3.org/2000/09/xmldsig#"


@dataclass(frozen=True)
class SignatureType:
    signed_info: SignedInfo | None = field(
        default=None,
        metadata={
            "name": "SignedInfo",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
            "required": True,
        },
    )
    signature_value: SignatureValue | None = field(
        default=None,
        metadata={
            "name": "SignatureValue",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
            "required": True,
        },
    )
    key_info: KeyInfo | None = field(
        default=None,
        metadata={
            "name": "KeyInfo",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
        },
    )
    object_value: tuple[Object, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "Object",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
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
class Signature(SignatureType):
    class Meta:
        namespace = "http://www.w3.org/2000/09/xmldsig#"
