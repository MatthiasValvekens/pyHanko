from asn1crypto import core, cms, algos
from .asn1_util import register_cms_attribute

"""
ASN.1 type definitions from the CAdES specification.

All definitions are as used in ETSI EN 319 122-1 V1.1.0.
See also RFC 5126.

Note: not all of these are applicable in PAdES.
"""

__all__ = [
    'CommitmentTypeIdentifier', 'CommitmentTypeQualifier',
    'CommitmentTypeQualifiers', 'CommitmentTypeIndication',
    'SigPolicyQualifierId', 'NoticeNumbers', 'NoticeReference',
    'SPUserNotice', 'SPDocSpecification', 'SigPolicyQualifierInfo',
    'SigPolicyQualifierInfos', 'SignaturePolicyId', 'SignaturePolicyIdentifier',
    'SignaturePolicyDocument', 'SignaturePolicyStore',
    'DisplayText'
]


class CommitmentTypeIdentifier(core.ObjectIdentifier):
    _map = {
        # from ETSI TS 119 172-1 Annex B, RFC 5126
        '1.2.840.113549.1.9.16.6.1': 'proof_of_origin',
        '1.2.840.113549.1.9.16.6.2': 'proof_of_receipt',
        '1.2.840.113549.1.9.16.6.3': 'proof_of_delivery',
        '1.2.840.113549.1.9.16.6.4': 'proof_of_sender',
        '1.2.840.113549.1.9.16.6.5': 'proof_of_approval',
        '1.2.840.113549.1.9.16.6.6': 'proof_of_creation',
    }


class CommitmentTypeQualifier(core.Sequence):
    _fields = [
        ('commitment_type_identifier', CommitmentTypeIdentifier),
        ('qualifier', core.Any)
    ]

    _oid_pair = ('commitment_type_identifier', 'qualifier')
    # CAdES generic commitment types don't use qualifiers, so this is reserved
    # for more advanced uses
    _oid_specs = {}


class CommitmentTypeQualifiers(core.SequenceOf):
    _child_spec = CommitmentTypeQualifier


class CommitmentTypeIndication(core.Sequence):
    _fields = [
        ('commitment_type_id', CommitmentTypeIdentifier),
        ('commitment_type_qualifier',
         CommitmentTypeQualifiers, {'optional': True})
    ]


class SigPolicyQualifierId(core.ObjectIdentifier):
    _map = {
        # RFC 5126
        '1.2.840.113549.1.9.16.5.1': 'sp_uri',
        '1.2.840.113549.1.9.16.5.2': 'sp_unotice',
        # ETSI EN 319 122-1
        '0.4.0.19122.2.1': 'sp_doc_specification'
    }


class DisplayText(core.Choice):
    # TODO does asn1crypto support length limitations?
    #  These strings have a length limit of 200 characters
    _alternatives = [
        ('visible_string', core.VisibleString),
        ('bmp_string', core.BMPString),
        ('utf8_string', core.UTF8String)
    ]


class NoticeNumbers(core.SequenceOf):
    _child_spec = core.Integer


class NoticeReference(core.Sequence):
    _fields = [
        ('organization', DisplayText),
        ('notice_numbers', NoticeNumbers)
    ]


class SPUserNotice(core.Sequence):
    _fields = [
        ('notice_ref', NoticeReference, {'optional': True}),
        ('explicit_text', DisplayText, {'optional': True}),
    ]


class SPDocSpecification(core.Sequence):
    _fields = [
        ('oid', core.ObjectIdentifier),
        ('uri', core.IA5String)
    ]


class SigPolicyQualifierInfo(core.Sequence):
    _fields = [
        ('sig_policy_qualifier_id', SigPolicyQualifierId),
        ('sig_qualifier', core.Any)
    ]

    _oid_pair = ('sig_policy_qualifier_id', 'sig_qualifier')
    _oid_specs = {
        # RFC 5126
        'sp_uri': core.IA5String,
        'sp_unotice': SPUserNotice,
        # ETSI EN 319 122-1
        'sp_doc_specification': SPDocSpecification
    }


class SigPolicyQualifierInfos(core.SequenceOf):
    _child_spec = SigPolicyQualifierInfo


class SignaturePolicyId(core.Sequence):
    _fields = [
        ('sig_policy_id', core.ObjectIdentifier),
        ('sig_policy_hash', algos.DigestInfo),
        ('sig_policy_qualifiers', SigPolicyQualifierInfos, {'optional': True})
    ]


class SignaturePolicyIdentifier(core.Choice):
    _alternatives = [
        ('signature_policy_id', SignaturePolicyId),
        ('signature_policy_implied', core.Null)
    ]


class SignaturePolicyDocument(core.Sequence):
    _fields = [
        # TODO make this ParsableOctetString as soon as we have support for
        #  signature policies
        ('sig_policy_encoded', core.OctetString),
        ('sig_policy_local_uri', core.IA5String),
    ]


class SignaturePolicyStore(core.Sequence):
    _fields = [
        ('sp_doc_spec', SPDocSpecification),
        ('sp_document', SignaturePolicyDocument)
    ]


# TODO define SignerLocation (uses DirectoryString from X.520), non-PAdES
# TODO define validation data archival types
#  (non-PAdES, more or less replaced by DSS in PDF)

# TODO define SignerAttributesV2 (uses AttributeCertificate from RFC 5755)

register_cms_attribute(
    '1.2.840.113549.1.9.16.2.15', 'signature_policy_identifier',
    SignaturePolicyIdentifier
)
register_cms_attribute(
    '1.2.840.113549.1.9.16.2.16', 'commitment_type', CommitmentTypeIndication
)
register_cms_attribute(
    '1.2.840.113549.1.9.16.2.20', 'content_time_stamp', cms.ContentInfo
)
register_cms_attribute('0.4.0.1733.2.1', 'mime_type', core.UTF8String)
register_cms_attribute(
    '0.4.0.19122.1', 'signature_policy_store', SignaturePolicyStore
)
