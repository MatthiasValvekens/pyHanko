import enum
from dataclasses import dataclass
from typing import Optional

from pyhanko.sign.timestamps import TimeStamper

from ..attributes import CMSAttributeProvider, TSTProvider
from .cades_asn1 import (
    CommitmentTypeIdentifier,
    CommitmentTypeIndication,
    SignaturePolicyIdentifier,
)

__all__ = ['GenericCommitment', 'CAdESSignedAttrSpec']


# TODO add semantics explanations from the standard

@enum.unique
class GenericCommitment(enum.Enum):
    PROOF_OF_ORIGIN = enum.auto()
    PROOF_OF_RECEIPT = enum.auto()
    PROOF_OF_DELIVERY = enum.auto()
    PROOF_OF_SENDER = enum.auto()
    PROOF_OF_APPROVAL = enum.auto()
    PROOF_OF_CREATION = enum.auto()

    @property
    def asn1(self) -> CommitmentTypeIndication:
        return CommitmentTypeIndication({
            'commitment_type_id': CommitmentTypeIdentifier(self.name.lower())
        })


@dataclass(frozen=True)
class CAdESSignedAttrSpec:
    """
    Class that controls signed CAdES attributes on a PDF signature.
    """

    commitment_type: Optional[CommitmentTypeIndication] = None
    """
    Signature commitment type. Can be one of the standard values, or a custom
    one.
    """

    timestamp_content: bool = False
    """
    Indicate whether the signature should include a signed timestamp.
    
    .. note::
        This should be contrasted with *unsigned* timestamps:
        a signed timestamp proves that the signature was created *after* some
        point in time, while an *unsigned* timestamp computed over the signed
        content proves that the signature existed *before* said point in time.
    """

    signature_policy_identifier: Optional[SignaturePolicyIdentifier] = None
    """
    Signature policy identifier to embed into the signature.
    
    .. warning::
        Right now, pyHanko does not "understand" signature policies, so the
        signature policy identifier will be taken at face value and embedded
        without paying any heed to the actual rules of the signature policy.
        It is the API user's responsibility to make sure that all relevant
        provisions of the signature policy are adhered to.
    """

    def prepare_providers(self, message_digest, md_algorithm,
                          timestamper: Optional[TimeStamper] = None):

        if self.timestamp_content and timestamper is not None:
            yield TSTProvider(
                digest_algorithm=md_algorithm,
                data_to_ts=message_digest,
                timestamper=timestamper, attr_type='content_time_stamp'
            )
        if self.signature_policy_identifier is not None:
            yield SigPolicyIDProvider(self.signature_policy_identifier)
        if self.commitment_type is not None:
            yield CommitmentTypeProvider(self.commitment_type)


class CommitmentTypeProvider(CMSAttributeProvider):
    attribute_type = 'commitment_type'

    def __init__(self, commitment_type: CommitmentTypeIndication):
        self.commitment_type = commitment_type

    async def build_attr_value(self, dry_run=False) -> CommitmentTypeIndication:
        return self.commitment_type


class SigPolicyIDProvider(CMSAttributeProvider):
    attribute_type = 'signature_policy_identifier'

    def __init__(self, policy_id: SignaturePolicyIdentifier):
        self.policy_id = policy_id

    async def build_attr_value(self, dry_run=False) \
            -> SignaturePolicyIdentifier:
        return self.policy_id
