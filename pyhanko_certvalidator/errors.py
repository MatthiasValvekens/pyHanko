# coding: utf-8
from datetime import datetime
from typing import Optional, Type, TypeVar

from asn1crypto.crl import CRLReason
from cryptography.exceptions import InvalidSignature

from pyhanko_certvalidator._state import ValProcState


class PathError(Exception):
    pass


class PathBuildingError(PathError):
    pass


class CertificateFetchError(PathBuildingError):
    pass


class CRLValidationError(Exception):
    pass


class CRLNoMatchesError(CRLValidationError):
    pass


class CRLFetchError(CRLValidationError):
    pass


class CRLValidationIndeterminateError(CRLValidationError):
    @property
    def failures(self):
        return self.args[1]


class OCSPValidationError(Exception):
    pass


class OCSPNoMatchesError(OCSPValidationError):
    pass


class OCSPValidationIndeterminateError(OCSPValidationError):
    @property
    def failures(self):
        return self.args[1]


class OCSPFetchError(OCSPValidationError):
    pass


class ValidationError(Exception):
    def __init__(self, message: str):
        self.failure_msg = message
        super().__init__(message)


TPathErr = TypeVar('TPathErr', bound='PathValidationError')


class PathValidationError(ValidationError):
    @classmethod
    def from_state(
        cls: Type[TPathErr], msg: str, proc_state: ValProcState
    ) -> TPathErr:
        return cls(
            msg,
            is_ee_cert=proc_state.is_ee_cert,
            is_side_validation=proc_state.is_side_validation,
        )

    def __init__(self, msg: str, *, is_ee_cert: bool, is_side_validation: bool):
        self.is_ee_cert = is_ee_cert
        self.is_side_validation = is_side_validation
        super().__init__(msg)


class RevokedError(PathValidationError):
    @classmethod
    def format(
        cls,
        reason: CRLReason,
        revocation_dt: datetime,
        revinfo_type: str,
        proc_state: ValProcState,
    ):
        reason_str = reason.human_friendly
        date = revocation_dt.strftime('%Y-%m-%d')
        time = revocation_dt.strftime('%H:%M:%S')
        msg = (
            f'{revinfo_type} indicates {proc_state.describe_cert()} '
            f'was revoked at {time} on {date}, due to {reason_str}.'
        )
        return RevokedError(msg, reason, revocation_dt, proc_state)

    def __init__(
        self,
        msg,
        reason: CRLReason,
        revocation_dt: datetime,
        proc_state: ValProcState,
    ):
        self.reason = reason
        self.revocation_dt = revocation_dt
        super().__init__(
            msg,
            is_ee_cert=proc_state.is_ee_cert,
            is_side_validation=proc_state.is_side_validation,
        )


class InsufficientRevinfoError(PathValidationError):
    pass


class InsufficientPOEError(PathValidationError):
    pass


class ExpiredError(PathValidationError):
    pass


class NotYetValidError(PathValidationError):
    pass


class InvalidCertificateError(PathValidationError):
    def __init__(self, msg, is_ee_cert=True, is_side_validation=False):
        super().__init__(
            msg, is_ee_cert=is_ee_cert, is_side_validation=is_side_validation
        )


class DisallowedAlgorithmError(PathValidationError):
    def __init__(
        self, *args, banned_since: Optional[datetime] = None, **kwargs
    ):
        self.banned_since = banned_since
        super().__init__(*args, **kwargs)

    @classmethod
    def from_state(
        cls,
        msg: str,
        proc_state: ValProcState,
        banned_since: Optional[datetime] = None,
    ) -> 'DisallowedAlgorithmError':
        return cls(
            msg,
            is_ee_cert=proc_state.is_ee_cert,
            is_side_validation=proc_state.is_side_validation,
            banned_since=banned_since,
        )


class InvalidAttrCertificateError(InvalidCertificateError):
    pass


class PSSParameterMismatch(InvalidSignature):
    pass


class DSAParametersUnavailable(InvalidSignature):
    # TODO Technically, such a signature isn't _really_ invalid
    #  (we merely couldn't validate it).
    # However, this is only an issue for CRLs and OCSP responses that
    # make use of DSA parameter inheritance, which is pretty much a
    # completely irrelevant problem in this day and age, so treating those
    # signatures as invalid as a matter of course seems pretty much OK.
    pass
