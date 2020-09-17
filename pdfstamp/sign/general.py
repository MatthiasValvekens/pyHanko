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

from certvalidator.registry import CertificateRegistry


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


# TODO perhaps phasing this out in favour of ESS SigningCertificate V2
#  (which allows better hash algorithms) would be preferable.
#  See RFC 5035.

def as_signing_certificate(cert: x509.Certificate) -> tsp.SigningCertificate:
    # see RFC 2634, § 5.4.1
    return tsp.SigningCertificate({
        'certs': [
            tsp.ESSCertID({'cert_hash': hashlib.sha1(cert.dump()).digest()})
        ]
    })


class CertificateStore:
    def register(self, cert: x509.Certificate):
        raise NotImplementedError

    def __iter__(self):
        raise NotImplementedError

    def fork(self, base_cls=None) -> 'SubordinateCertificateStore':
        base_cls = base_cls or SubordinateCertificateStore
        return base_cls(self)


class SimpleCertificateStore(CertificateStore):
    """
    Unopinionated replacement for certvalidator's CertificateRegistry in cases
    where we explicitly don't care about whether the certs are trusted or not.
    """

    def __init__(self, certs=None):
        self.certs = {}
        if certs:
            for cert in certs:
                self.register(cert)

    def register(self, cert: x509.Certificate):
        self.certs[cert.issuer_serial] = cert

    def __getitem__(self, item):
        return self.certs[item]

    def __iter__(self):
        return iter(self.certs.values())


class SubordinateCertificateStore(SimpleCertificateStore):
    """
    Certificate store that writes both to itself and to a "backend" store.
    Useful in cases where we want a single store accumulating certs, while still
    keeping them grouped in some meaningful way.
    """

    def __init__(self, backend: CertificateStore):
        self.backend = backend
        super().__init__()

    def register(self, cert: x509.Certificate):
        self.backend.register(cert)
        super().register(cert)


# FIXME there has to be a better way to only enable OCSP fetching
def monkeypatch_crl_client():
    from certvalidator import crl_client

    def dummy_fetch(*_args, **_kwargs):
        return []
    crl_client.fetch = dummy_fetch


# TODO find a way to do this "locally"
monkeypatch_crl_client()
