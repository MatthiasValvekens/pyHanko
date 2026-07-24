from dataclasses import dataclass, field
from enum import Enum

from xsdata.models.datatype import XmlDateTime

from ..w3c.xmldsig_core import (
    DigestMethod,
    DigestValue,
    Signature,
    SignatureValue,
)
from .ts_119612 import DigitalIdentityType, TSPInformationType
from .xades import DigestAlgAndValueType, SignaturePolicyIdentifierType

__NAMESPACE__ = "http://uri.etsi.org/19102/v1.2.1#"


@dataclass(frozen=True)
class ConstraintStatusType:
    status: str | None = field(
        default=None,
        metadata={
            "name": "Status",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )
    overridden_by: str | None = field(
        default=None,
        metadata={
            "name": "OverriddenBy",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )


@dataclass(frozen=True)
class NsPrefixMappingType:
    namespace_uri: str | None = field(
        default=None,
        metadata={
            "name": "NamespaceURI",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )
    namespace_prefix: str | None = field(
        default=None,
        metadata={
            "name": "NamespacePrefix",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )


@dataclass(frozen=True)
class SAFilterType:
    filter: str | None = field(
        default=None,
        metadata={
            "name": "Filter",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )


@dataclass(frozen=True)
class SAOCSPIDType:
    produced_at: XmlDateTime | None = field(
        default=None,
        metadata={
            "name": "ProducedAt",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )
    responder_idby_name: str | None = field(
        default=None,
        metadata={
            "name": "ResponderIDByName",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    responder_idby_key: bytes | None = field(
        default=None,
        metadata={
            "name": "ResponderIDByKey",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "format": "base64",
        },
    )


class SAOneSignerRoleTypeEndorsementType(Enum):
    CERTIFIED = "certified"
    CLAIMED = "claimed"
    SIGNED = "signed"


@dataclass(frozen=True)
class SignatureQualityType:
    signature_quality_information: tuple[str, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "SignatureQualityInformation",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "min_occurs": 1,
        },
    )


@dataclass(frozen=True)
class SignatureValidationProcessType:
    signature_validation_process_id: str | None = field(
        default=None,
        metadata={
            "name": "SignatureValidationProcessID",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    signature_validation_service_policy: str | None = field(
        default=None,
        metadata={
            "name": "SignatureValidationServicePolicy",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    signature_validation_practice_statement: str | None = field(
        default=None,
        metadata={
            "name": "SignatureValidationPracticeStatement",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    other_element: object | None = field(
        default=None,
        metadata={
            "type": "Wildcard",
            "namespace": "##other",
        },
    )


@dataclass(frozen=True)
class TypedDataType:
    type_value: str | None = field(
        default=None,
        metadata={
            "name": "Type",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )
    value: object | None = field(
        default=None,
        metadata={
            "name": "Value",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )


@dataclass(frozen=True)
class VOReferenceType:
    any_element: object | None = field(
        default=None,
        metadata={
            "type": "Wildcard",
            "namespace": "##any",
        },
    )
    voreference: tuple[str, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "VOReference",
            "type": "Attribute",
            "tokens": True,
        },
    )


@dataclass(frozen=True)
class AdditionalValidationReportDataType:
    report_data: tuple[TypedDataType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "ReportData",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "min_occurs": 1,
        },
    )


@dataclass(frozen=True)
class AttributeBaseType:
    attribute_object: tuple[VOReferenceType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "AttributeObject",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    signed: bool | None = field(
        default=None,
        metadata={
            "name": "Signed",
            "type": "Attribute",
        },
    )


@dataclass(frozen=True)
class CertificateChainType:
    signing_certificate: VOReferenceType | None = field(
        default=None,
        metadata={
            "name": "SigningCertificate",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )
    intermediate_certificate: tuple[VOReferenceType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "IntermediateCertificate",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    trust_anchor: VOReferenceType | None = field(
        default=None,
        metadata={
            "name": "TrustAnchor",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    other_element: object | None = field(
        default=None,
        metadata={
            "type": "Wildcard",
            "namespace": "##other",
        },
    )


@dataclass(frozen=True)
class CryptoInformationType:
    validation_object_id: VOReferenceType | None = field(
        default=None,
        metadata={
            "name": "ValidationObjectId",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )
    algorithm: str | None = field(
        default=None,
        metadata={
            "name": "Algorithm",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )
    algorithm_parameters: TypedDataType | None = field(
        default=None,
        metadata={
            "name": "AlgorithmParameters",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    secure_algorithm: bool | None = field(
        default=None,
        metadata={
            "name": "SecureAlgorithm",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )
    not_after: XmlDateTime | None = field(
        default=None,
        metadata={
            "name": "NotAfter",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    other_element: object | None = field(
        default=None,
        metadata={
            "type": "Wildcard",
            "namespace": "##other",
        },
    )


@dataclass(frozen=True)
class POEType:
    poetime: XmlDateTime | None = field(
        default=None,
        metadata={
            "name": "POETime",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )
    type_of_proof: str | None = field(
        default=None,
        metadata={
            "name": "TypeOfProof",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )
    poeobject: VOReferenceType | None = field(
        default=None,
        metadata={
            "name": "POEObject",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )


@dataclass(frozen=True)
class RevocationStatusInformationType:
    validation_object_id: VOReferenceType | None = field(
        default=None,
        metadata={
            "name": "ValidationObjectId",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )
    revocation_time: XmlDateTime | None = field(
        default=None,
        metadata={
            "name": "RevocationTime",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )
    revocation_reason: str | None = field(
        default=None,
        metadata={
            "name": "RevocationReason",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    revocation_object: VOReferenceType | None = field(
        default=None,
        metadata={
            "name": "RevocationObject",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    other_element: object | None = field(
        default=None,
        metadata={
            "type": "Wildcard",
            "namespace": "##other",
        },
    )


@dataclass(frozen=True)
class SACRLIDType:
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


@dataclass(frozen=True)
class SACertIDType:
    x509_issuer_serial: bytes | None = field(
        default=None,
        metadata={
            "name": "X509IssuerSerial",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "format": "base64",
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


@dataclass(frozen=True)
class SAOneSignerRoleType:
    role: str | None = field(
        default=None,
        metadata={
            "name": "Role",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )
    endorsement_type: SAOneSignerRoleTypeEndorsementType | None = field(
        default=None,
        metadata={
            "name": "EndorsementType",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )


@dataclass(frozen=True)
class SignatureIdentifierType:
    digest_alg_and_value: DigestAlgAndValueType | None = field(
        default=None,
        metadata={
            "name": "DigestAlgAndValue",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    signature_value: SignatureValue | None = field(
        default=None,
        metadata={
            "name": "SignatureValue",
            "type": "Element",
            "namespace": "http://www.w3.org/2000/09/xmldsig#",
        },
    )
    hash_only: bool | None = field(
        default=None,
        metadata={
            "name": "HashOnly",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )
    doc_hash_only: bool | None = field(
        default=None,
        metadata={
            "name": "DocHashOnly",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )
    daidentifier: str | None = field(
        default=None,
        metadata={
            "name": "DAIdentifier",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    other_element: tuple[object, ...] = field(
        default_factory=tuple,
        metadata={
            "type": "Wildcard",
            "namespace": "##other",
        },
    )
    id: str | None = field(
        default=None,
        metadata={
            "type": "Attribute",
        },
    )


@dataclass(frozen=True)
class SignatureValidationPolicyType:
    signature_policy_identifier: SignaturePolicyIdentifierType | None = field(
        default=None,
        metadata={
            "name": "SignaturePolicyIdentifier",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )
    policy_name: str | None = field(
        default=None,
        metadata={
            "name": "PolicyName",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    formal_policy_uri: str | None = field(
        default=None,
        metadata={
            "name": "FormalPolicyURI",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    readable_policy_uri: str | None = field(
        default=None,
        metadata={
            "name": "ReadablePolicyURI",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    formal_policy_object: VOReferenceType | None = field(
        default=None,
        metadata={
            "name": "FormalPolicyObject",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )


@dataclass(frozen=True)
class SignatureValidatorType:
    digital_id: tuple[DigitalIdentityType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "DigitalId",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "min_occurs": 1,
        },
    )
    tspinformation: TSPInformationType | None = field(
        default=None,
        metadata={
            "name": "TSPInformation",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
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
class SignerInformationType:
    signer_certificate: VOReferenceType | None = field(
        default=None,
        metadata={
            "name": "SignerCertificate",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )
    signer: str | None = field(
        default=None,
        metadata={
            "name": "Signer",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    other_element: object | None = field(
        default=None,
        metadata={
            "type": "Wildcard",
            "namespace": "##other",
        },
    )
    pseudonym: bool | None = field(
        default=None,
        metadata={
            "name": "Pseudonym",
            "type": "Attribute",
        },
    )


@dataclass(frozen=True)
class SignersDocumentType:
    digest_alg_and_value: DigestAlgAndValueType | None = field(
        default=None,
        metadata={
            "name": "DigestAlgAndValue",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )
    signers_document_representation: tuple[VOReferenceType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "SignersDocumentRepresentation",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "min_occurs": 1,
            "max_occurs": 2,
            "sequence": 1,
        },
    )
    signers_document_ref: VOReferenceType | None = field(
        default=None,
        metadata={
            "name": "SignersDocumentRef",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )


@dataclass(frozen=True)
class ValidationObjectRepresentationType:
    direct: object | None = field(
        default=None,
        metadata={
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    base64: bytes | None = field(
        default=None,
        metadata={
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "format": "base64",
        },
    )
    digest_alg_and_value: DigestAlgAndValueType | None = field(
        default=None,
        metadata={
            "name": "DigestAlgAndValue",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    uri: str | None = field(
        default=None,
        metadata={
            "name": "URI",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )


@dataclass(frozen=True)
class XAdESSignaturePtrType:
    ns_prefix_mapping: tuple[NsPrefixMappingType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "NsPrefixMapping",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    which_document: str | None = field(
        default=None,
        metadata={
            "name": "WhichDocument",
            "type": "Attribute",
        },
    )
    xpath: str | None = field(
        default=None,
        metadata={
            "name": "XPath",
            "type": "Attribute",
        },
    )
    schema_refs: tuple[str, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "SchemaRefs",
            "type": "Attribute",
            "tokens": True,
        },
    )


@dataclass(frozen=True)
class SACertIDListType(AttributeBaseType):
    cert_id: tuple[SACertIDType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "CertID",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )


@dataclass(frozen=True)
class SACommitmentTypeIndicationType(AttributeBaseType):
    commitment_type_identifier: str | None = field(
        default=None,
        metadata={
            "name": "CommitmentTypeIdentifier",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )


@dataclass(frozen=True)
class SAContactInfoType(AttributeBaseType):
    contact_info_element: str | None = field(
        default=None,
        metadata={
            "name": "ContactInfoElement",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )


@dataclass(frozen=True)
class SADSSType(AttributeBaseType):
    certs: VOReferenceType | None = field(
        default=None,
        metadata={
            "name": "Certs",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    crls: VOReferenceType | None = field(
        default=None,
        metadata={
            "name": "CRLs",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    ocsps: VOReferenceType | None = field(
        default=None,
        metadata={
            "name": "OCSPs",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )


@dataclass(frozen=True)
class SADataObjectFormatType(AttributeBaseType):
    content_type: str | None = field(
        default=None,
        metadata={
            "name": "ContentType",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    mime_type: str | None = field(
        default=None,
        metadata={
            "name": "MimeType",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )


@dataclass(frozen=True)
class SAMessageDigestType(AttributeBaseType):
    digest: bytes | None = field(
        default=None,
        metadata={
            "name": "Digest",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
            "format": "base64",
        },
    )


@dataclass(frozen=True)
class SANameType(AttributeBaseType):
    name_element: str | None = field(
        default=None,
        metadata={
            "name": "NameElement",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )


@dataclass(frozen=True)
class SAReasonType(AttributeBaseType):
    reason_element: str | None = field(
        default=None,
        metadata={
            "name": "ReasonElement",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )


@dataclass(frozen=True)
class SARevIDListType(AttributeBaseType):
    crlid: tuple[SACRLIDType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "CRLID",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    ocspid: tuple[SAOCSPIDType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "OCSPID",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )


@dataclass(frozen=True)
class SASigPolicyIdentifierType(AttributeBaseType):
    sig_policy_id: str | None = field(
        default=None,
        metadata={
            "name": "SigPolicyId",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )


@dataclass(frozen=True)
class SASignatureProductionPlaceType(AttributeBaseType):
    address_string: tuple[str, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "AddressString",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "min_occurs": 1,
        },
    )


@dataclass(frozen=True)
class SASignerRoleType(AttributeBaseType):
    role_details: tuple[SAOneSignerRoleType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "RoleDetails",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "min_occurs": 1,
        },
    )


@dataclass(frozen=True)
class SASigningTimeType(AttributeBaseType):
    time: XmlDateTime | None = field(
        default=None,
        metadata={
            "name": "Time",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )


@dataclass(frozen=True)
class SASubFilterType(AttributeBaseType):
    sub_filter_element: str | None = field(
        default=None,
        metadata={
            "name": "SubFilterElement",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )


@dataclass(frozen=True)
class SATimestampType(AttributeBaseType):
    time_stamp_value: XmlDateTime | None = field(
        default=None,
        metadata={
            "name": "TimeStampValue",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )


@dataclass(frozen=True)
class ValidationReportDataType:
    trust_anchor: VOReferenceType | None = field(
        default=None,
        metadata={
            "name": "TrustAnchor",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    certificate_chain: CertificateChainType | None = field(
        default=None,
        metadata={
            "name": "CertificateChain",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    related_validation_object: tuple[VOReferenceType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "RelatedValidationObject",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    revocation_status_information: RevocationStatusInformationType | None = (
        field(
            default=None,
            metadata={
                "name": "RevocationStatusInformation",
                "type": "Element",
                "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            },
        )
    )
    crypto_information: CryptoInformationType | None = field(
        default=None,
        metadata={
            "name": "CryptoInformation",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    additional_validation_report_data: (
        AdditionalValidationReportDataType | None
    ) = field(
        default=None,
        metadata={
            "name": "AdditionalValidationReportData",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )


@dataclass(frozen=True)
class ValidationTimeInfoType:
    validation_time: XmlDateTime | None = field(
        default=None,
        metadata={
            "name": "ValidationTime",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )
    best_signature_time: POEType | None = field(
        default=None,
        metadata={
            "name": "BestSignatureTime",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )


@dataclass(frozen=True)
class XAdESSignaturePtr(XAdESSignaturePtrType):
    class Meta:
        namespace = "http://uri.etsi.org/19102/v1.2.1#"


@dataclass(frozen=True)
class SAVRIType(AttributeBaseType):
    certs: VOReferenceType | None = field(
        default=None,
        metadata={
            "name": "Certs",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    crls: VOReferenceType | None = field(
        default=None,
        metadata={
            "name": "CRLs",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    ocsps: VOReferenceType | None = field(
        default=None,
        metadata={
            "name": "OCSPs",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    tu: str | None = field(
        default=None,
        metadata={
            "name": "TU",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    ts: SATimestampType | None = field(
        default=None,
        metadata={
            "name": "TS",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )


@dataclass(frozen=True)
class SignatureReferenceType:
    canonicalization_method: str | None = field(
        default=None,
        metadata={
            "name": "CanonicalizationMethod",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    digest_method: str | None = field(
        default=None,
        metadata={
            "name": "DigestMethod",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    digest_value: bytes | None = field(
        default=None,
        metadata={
            "name": "DigestValue",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "format": "base64",
        },
    )
    xad_essignature_ptr: XAdESSignaturePtr | None = field(
        default=None,
        metadata={
            "name": "XAdESSignaturePtr",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    pad_esfield_name: str | None = field(
        default=None,
        metadata={
            "name": "PAdESFieldName",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
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
class ValidationStatusType:
    main_indication: str | None = field(
        default=None,
        metadata={
            "name": "MainIndication",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )
    sub_indication: tuple[str, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "SubIndication",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    associated_validation_report_data: tuple[ValidationReportDataType, ...] = (
        field(
            default_factory=tuple,
            metadata={
                "name": "AssociatedValidationReportData",
                "type": "Element",
                "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            },
        )
    )


@dataclass(frozen=True)
class IndividualValidationConstraintReportType:
    validation_constraint_identifier: str | None = field(
        default=None,
        metadata={
            "name": "ValidationConstraintIdentifier",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )
    validation_constraint_parameter: tuple[TypedDataType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "ValidationConstraintParameter",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    constraint_status: ConstraintStatusType | None = field(
        default=None,
        metadata={
            "name": "ConstraintStatus",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )
    validation_status: ValidationStatusType | None = field(
        default=None,
        metadata={
            "name": "ValidationStatus",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    indications: object | None = field(
        default=None,
        metadata={
            "name": "Indications",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )


@dataclass(frozen=True)
class POEProvisioningType:
    poetime: XmlDateTime | None = field(
        default=None,
        metadata={
            "name": "POETime",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )
    validation_object: tuple[VOReferenceType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "ValidationObject",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    signature_reference: tuple[SignatureReferenceType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "SignatureReference",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )


@dataclass(frozen=True)
class SACounterSignatureType(AttributeBaseType):
    counter_signature: SignatureReferenceType | None = field(
        default=None,
        metadata={
            "name": "CounterSignature",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )


@dataclass(frozen=True)
class SignatureReference(SignatureReferenceType):
    class Meta:
        namespace = "http://uri.etsi.org/19102/v1.2.1#"


@dataclass(frozen=True)
class SignatureAttributesType:
    signing_time: tuple[SASigningTimeType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "SigningTime",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    signing_certificate: tuple[SACertIDListType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "SigningCertificate",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    data_object_format: tuple[SADataObjectFormatType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "DataObjectFormat",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    commitment_type_indication: tuple[SACommitmentTypeIndicationType, ...] = (
        field(
            default_factory=tuple,
            metadata={
                "name": "CommitmentTypeIndication",
                "type": "Element",
                "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            },
        )
    )
    all_data_objects_time_stamp: tuple[SATimestampType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "AllDataObjectsTimeStamp",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    individual_data_objects_time_stamp: tuple[SATimestampType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "IndividualDataObjectsTimeStamp",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    sig_policy_identifier: tuple[SASigPolicyIdentifierType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "SigPolicyIdentifier",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    signature_production_place: tuple[SASignatureProductionPlaceType, ...] = (
        field(
            default_factory=tuple,
            metadata={
                "name": "SignatureProductionPlace",
                "type": "Element",
                "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            },
        )
    )
    signer_role: tuple[SASignerRoleType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "SignerRole",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    counter_signature: tuple[SACounterSignatureType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "CounterSignature",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    signature_time_stamp: tuple[SATimestampType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "SignatureTimeStamp",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    complete_certificate_refs: tuple[SACertIDListType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "CompleteCertificateRefs",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    complete_revocation_refs: tuple[SARevIDListType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "CompleteRevocationRefs",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    attribute_certificate_refs: tuple[SACertIDListType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "AttributeCertificateRefs",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    attribute_revocation_refs: tuple[SARevIDListType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "AttributeRevocationRefs",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    sig_and_refs_time_stamp: tuple[SATimestampType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "SigAndRefsTimeStamp",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    refs_only_time_stamp: tuple[SATimestampType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "RefsOnlyTimeStamp",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    certificate_values: tuple[AttributeBaseType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "CertificateValues",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    revocation_values: tuple[AttributeBaseType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "RevocationValues",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    attr_authorities_cert_values: tuple[AttributeBaseType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "AttrAuthoritiesCertValues",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    attribute_revocation_values: tuple[AttributeBaseType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "AttributeRevocationValues",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    time_stamp_validation_data: tuple[AttributeBaseType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "TimeStampValidationData",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    archive_time_stamp: tuple[SATimestampType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "ArchiveTimeStamp",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    renewed_digests: tuple[tuple[int, ...], ...] = field(
        default_factory=tuple,
        metadata={
            "name": "RenewedDigests",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "tokens": True,
        },
    )
    message_digest: tuple[SAMessageDigestType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "MessageDigest",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    dss: tuple[SADSSType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "DSS",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    vri: tuple[SAVRIType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "VRI",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    doc_time_stamp: tuple[SATimestampType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "DocTimeStamp",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    reason: tuple[SAReasonType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "Reason",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    name: tuple[SANameType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "Name",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    contact_info: tuple[SAContactInfoType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "ContactInfo",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    sub_filter: tuple[SASubFilterType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "SubFilter",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    byte_range: tuple[tuple[int, ...], ...] = field(
        default_factory=tuple,
        metadata={
            "name": "ByteRange",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "tokens": True,
        },
    )
    filter: tuple[SAFilterType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "Filter",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
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
class ValidationConstraintsEvaluationReportType:
    signature_validation_policy: SignatureValidationPolicyType | None = field(
        default=None,
        metadata={
            "name": "SignatureValidationPolicy",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    validation_constraint: tuple[
        IndividualValidationConstraintReportType, ...
    ] = field(
        default_factory=tuple,
        metadata={
            "name": "ValidationConstraint",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )


@dataclass(frozen=True)
class SignatureValidationReportType:
    signature_identifier: SignatureIdentifierType | None = field(
        default=None,
        metadata={
            "name": "SignatureIdentifier",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    validation_constraints_evaluation_report: (
        ValidationConstraintsEvaluationReportType | None
    ) = field(
        default=None,
        metadata={
            "name": "ValidationConstraintsEvaluationReport",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    validation_time_info: ValidationTimeInfoType | None = field(
        default=None,
        metadata={
            "name": "ValidationTimeInfo",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    signers_document: SignersDocumentType | None = field(
        default=None,
        metadata={
            "name": "SignersDocument",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    signature_attributes: SignatureAttributesType | None = field(
        default=None,
        metadata={
            "name": "SignatureAttributes",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    signer_information: SignerInformationType | None = field(
        default=None,
        metadata={
            "name": "SignerInformation",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    signature_quality: SignatureQualityType | None = field(
        default=None,
        metadata={
            "name": "SignatureQuality",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    signature_validation_process: SignatureValidationProcessType | None = field(
        default=None,
        metadata={
            "name": "SignatureValidationProcess",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    signature_validation_status: ValidationStatusType | None = field(
        default=None,
        metadata={
            "name": "SignatureValidationStatus",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )
    any_element: tuple[object, ...] = field(
        default_factory=tuple,
        metadata={
            "type": "Wildcard",
            "namespace": "##any",
        },
    )


@dataclass(frozen=True)
class ValidationObjectType:
    object_type: str | None = field(
        default=None,
        metadata={
            "name": "ObjectType",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )
    validation_object_representation: (
        ValidationObjectRepresentationType | None
    ) = field(
        default=None,
        metadata={
            "name": "ValidationObjectRepresentation",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "required": True,
        },
    )
    poe: POEType | None = field(
        default=None,
        metadata={
            "name": "POE",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    poeprovisioning: POEProvisioningType | None = field(
        default=None,
        metadata={
            "name": "POEProvisioning",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    validation_report: SignatureValidationReportType | None = field(
        default=None,
        metadata={
            "name": "ValidationReport",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    id: str | None = field(
        default=None,
        metadata={
            "type": "Attribute",
            "required": True,
        },
    )


@dataclass(frozen=True)
class ValidationObjectListType:
    validation_object: tuple[ValidationObjectType, ...] = field(
        default_factory=tuple,
        metadata={
            "name": "ValidationObject",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
            "min_occurs": 1,
        },
    )


@dataclass(frozen=True)
class ValidationReportType:
    signature_validation_report: tuple[SignatureValidationReportType, ...] = (
        field(
            default_factory=tuple,
            metadata={
                "name": "SignatureValidationReport",
                "type": "Element",
                "namespace": "http://uri.etsi.org/19102/v1.2.1#",
                "min_occurs": 1,
            },
        )
    )
    signature_validation_objects: ValidationObjectListType | None = field(
        default=None,
        metadata={
            "name": "SignatureValidationObjects",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
        },
    )
    signature_validator: SignatureValidatorType | None = field(
        default=None,
        metadata={
            "name": "SignatureValidator",
            "type": "Element",
            "namespace": "http://uri.etsi.org/19102/v1.2.1#",
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


@dataclass(frozen=True)
class ValidationReport(ValidationReportType):
    class Meta:
        namespace = "http://uri.etsi.org/19102/v1.2.1#"
