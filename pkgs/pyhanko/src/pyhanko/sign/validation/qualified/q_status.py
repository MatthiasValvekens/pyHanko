import enum
from dataclasses import dataclass
from typing import Optional

from pyhanko.sign.validation.qualified.tsp import (
    QcCertType,
    QualifiedServiceInformation,
)

__all__ = [
    'QualificationResult',
    'QualifiedStatus',
    'QcPrivateKeyManagementType',
]


class QcPrivateKeyManagementType(enum.Enum):
    """
    Description of the private key management methodology.
    """

    UNKNOWN = 0
    """
    Private key management methodology unknown/unspecified.
    """

    QSCD = 1
    """
    Declaration indicating that the private key resides in a qualified
    signature creation device (QSCD).
    """

    QSCD_DELEGATED = 2
    """
    Declaration indicating that the private key resides in a QSCD managed
    on behalf of the subject by another party.
    """

    QSCD_BY_POLICY = 3
    """
    QSCD declaration by pre-eIDAS certificate policy.
    """

    @property
    def is_qscd(self) -> bool:
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


@dataclass(frozen=True)
class QualificationResult:
    """
    Represents the result of a qualification evaluation.
    """

    status: QualifiedStatus
    """
    Status indicator.
    """

    service_definition: Optional[QualifiedServiceInformation]
    """
    Service definition under which the tested object was considered
    qualified.
    """
