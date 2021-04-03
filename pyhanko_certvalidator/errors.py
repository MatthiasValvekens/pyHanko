# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function


class PathError(Exception):

    pass


class PathBuildingError(PathError):

    pass


class DuplicateCertificateError(PathError):

    pass


class CRLValidationError(Exception):

    pass


class CRLNoMatchesError(CRLValidationError):

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


class SoftFailError(Exception):

    pass


class ValidationError(Exception):

    pass


class PathValidationError(ValidationError):

    pass


class RevokedError(PathValidationError):

    pass


class InvalidCertificateError(PathValidationError):

    pass
