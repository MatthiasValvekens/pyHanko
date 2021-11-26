# coding: utf-8


class PathError(Exception):

    pass


class PathBuildingError(PathError):

    pass


class CertificateFetchError(PathBuildingError):
    pass


class DuplicateCertificateError(PathError):

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

    pass


class PathValidationError(ValidationError):

    pass


class RevokedError(PathValidationError):

    pass


class InvalidCertificateError(PathValidationError):

    pass
