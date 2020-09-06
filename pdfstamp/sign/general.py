from dataclasses import dataclass
from typing import List, ClassVar, Set

import hashlib
from asn1crypto import x509, cms, tsp
from certvalidator import (
    CertificateValidator, InvalidCertificateError,
    PathBuildingError,
)
from certvalidator.errors import RevokedError, PathValidationError

__all__ = [
    'SignatureStatus', 'simple_cms_attribute', 'find_cms_attribute',
    'as_signing_certificate'
]


@dataclass(frozen=True)
class SignatureStatus:
    intact: bool
    valid: bool
    trusted: bool
    revoked: bool
    usage_ok: bool
    signing_cert: x509.Certificate
    ca_chain: List[x509.Certificate]
    pkcs7_signature_mechanism: str
    md_algorithm: str

    # XXX frozenset makes more sense here, but asn1crypto doesn't allow that
    #  (probably legacy behaviour)
    key_usage: ClassVar[Set[str]] = {'non_repudiation'}
    extd_key_usage: ClassVar[Set[str]] = set()

    def summary_fields(self):
        if self.trusted:
            cert_status = 'TRUSTED'
        elif self.revoked:
            cert_status = 'REVOKED'
        else:
            cert_status = 'UNTRUSTED'
        yield cert_status
        if self.usage_ok:
            yield 'USAGE_OK'

    def summary(self):
        if self.intact and self.valid:
            return 'INTACT:' + ','.join(self.summary_fields())
        else:
            return 'INVALID'

    @classmethod
    def validate_cert_usage(cls, validator: CertificateValidator):

        usage_ok = revoked = trusted = False
        try:
            validator.validate_usage(
                key_usage=cls.key_usage, extended_key_usage=cls.extd_key_usage
            )
            usage_ok = trusted = True
        except InvalidCertificateError:
            trusted = True
        except RevokedError:
            revoked = True
        except (PathValidationError, PathBuildingError):
            # catch-all
            pass
        return trusted, revoked, usage_ok


def simple_cms_attribute(attr_type, value):
    return cms.CMSAttribute({
        'type': cms.CMSAttributeType(attr_type),
        'values': (value,)
    })


def find_cms_attribute(attrs, name):
    for attr in attrs:
        if attr['type'].native == name:
            return attr['values']
    raise KeyError(f'Unable to locate attribute {name}.')


def as_signing_certificate(cert: x509.Certificate) -> tsp.SigningCertificate:
    # see RFC 2634, § 5.4.1
    return tsp.SigningCertificate({
        'certs': [
            tsp.ESSCertID({'cert_hash': hashlib.sha1(cert.dump()).digest()})
        ]
    })