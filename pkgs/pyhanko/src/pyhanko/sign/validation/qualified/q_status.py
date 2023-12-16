import enum
from dataclasses import dataclass

from pyhanko.sign.validation.qualified.tsp import QcCertType

__all__ = ['QualifiedStatus', 'QcPrivateKeyManagementType']


class QcPrivateKeyManagementType(enum.Enum):
    UNKNOWN = 0
    QCSD = 1
    QCSD_DELEGATED = 2
    QCSD_BY_POLICY = 3

    @property
    def is_qcsd(self) -> bool:
        return self != QcPrivateKeyManagementType.UNKNOWN


@dataclass(frozen=True)
class QualifiedStatus:
    """
    Represents the qualified status of a certificate.
    """

    qualified: bool
    """
    Indicates whether the certificate is to be considered qualified.
    """

    qc_type: QcCertType
    """
    Type of qualified certificate.
    """

    qc_key_security: QcPrivateKeyManagementType
    """
    Indicates whether the CA declares that the private key
    corresponding to this certificate resides in a qualified
    signature creation device (QSCD) or secure signature creation device (SSCD).
    It also indicates whether the QCSD is managed on behalf of the signer,
    if applicable.

    .. warning::
        These terms are functionally interchangeable, the only difference is
        that "SSCD" is pre-eIDAS terminology.
    """
