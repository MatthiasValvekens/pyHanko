"""
General tools related to Cryptographic Message Syntax (CMS) signatures,
not necessarily to the extent implemented in the PDF specification.

CMS is defined in :rfc:`5652`. To parse CMS messages, pyHanko relies heavily on
`asn1crypto <https://github.com/wbond/asn1crypto>`_.
"""

import logging
from dataclasses import dataclass
from typing import ClassVar, Set


import hashlib

from asn1crypto import x509, cms, tsp
# noinspection PyProtectedMember
from certvalidator.path import ValidationPath

from certvalidator import (
    CertificateValidator, InvalidCertificateError,
    PathBuildingError,
)
from certvalidator.errors import RevokedError, PathValidationError

__all__ = [
    'SignatureStatus', 'simple_cms_attribute', 'find_cms_attribute',
    'CertificateStore', 'SimpleCertificateStore', 'SigningError',
    'UnacceptableSignerError'
]


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SignatureStatus:
    """
    Class describing the validity of a (general) CMS signature.
    """

    intact: bool
    """
    Reports whether the signature is *intact*, i.e. whether the hash of the 
    message content (which may or may not be embedded inside the CMS object
    itself) matches the hash value that was signed.
    """

    valid: bool
    """
    Reports whether the signature is *valid*, i.e. whether the hash's signature
    actually validates.
    """

    trusted: bool
    """
    Reports whether the signer's certificate is trusted w.r.t. the currently 
    relevant validation context and key usage requirements.
    """

    # TODO add a separate expired flag

    revoked: bool
    """
    Reports whether the signer's certificate has been revoked or not.
    If this field is ``True``, then obviously :attr:`trusted` will be ``False``.
    """

    signing_cert: x509.Certificate
    """
    Contains the certificate of the signer, as embedded in the CMS object.
    """

    pkcs7_signature_mechanism: str
    """
    PKCS7 signature mechanism used.
    """

    # TODO: also here some ambiguity analysis is in order
    md_algorithm: str
    """
    Message digest algorithm used.
    """

    validation_path: ValidationPath
    """
    Validation path providing a valid chain of trust from the signer's 
    certificate to a trusted root certificate.
    """

    # XXX frozenset makes more sense here, but asn1crypto doesn't allow that
    #  (probably legacy behaviour)
    key_usage: ClassVar[Set[str]] = {'non_repudiation'}
    """
    Class property indicating which key usage extensions are required to be
    present on the signer's certificate.
    """

    extd_key_usage: ClassVar[Set[str]] = set()
    """
    Class property indicating which extended key usage extensions are required 
    to be present on the signer's certificate.
    """

    def summary_fields(self):
        if self.trusted:
            cert_status = 'TRUSTED'
        elif self.revoked:
            cert_status = 'REVOKED'
        else:
            cert_status = 'UNTRUSTED'
        yield cert_status

    # TODO explain in more detail.
    def summary(self):
        """
        Provide a textual but machine-parsable summary of the validity.
        """
        if self.intact and self.valid:
            return 'INTACT:' + ','.join(self.summary_fields())
        else:
            return 'INVALID'

    @classmethod
    def validate_cert_usage(cls, validator: CertificateValidator):

        revoked = trusted = False
        path = None
        try:
            path = validator.validate_usage(
                key_usage=cls.key_usage, extended_key_usage=cls.extd_key_usage
            )
            trusted = True
        except InvalidCertificateError as e:
            # TODO accumulate these somewhere
            logger.warning(e)
        except RevokedError:
            revoked = True
        except (PathValidationError, PathBuildingError) as e:
            logger.warning(e)
        if not trusted:
            subj = validator._certificate.subject.human_friendly
            logger.warning(
                f"Chain of trust validation for {subj} failed."
            )
        return trusted, revoked, path


def simple_cms_attribute(attr_type, value):
    """
    Convenience method to quickly construct a CMS attribute object with
    one value.

    :param attr_type:
        The attribute type, as a string or OID.
    :param value:
        The value.
    :return:
        A :class:`.cms.CMSAttribute` object.
    """
    return cms.CMSAttribute({
        'type': cms.CMSAttributeType(attr_type),
        'values': (value,)
    })


def find_cms_attribute(attrs, name):
    """
    Find and return CMS attribute values of a given type.

    :param attrs:
        The :class:`.cms.CMSAttributes` object.
    :param name:
        The attribute type as a string (as defined in ``asn1crypto``).
    :return:
        The values associated with the requested type, if present.
    :raise KeyError:
        Raised when no such type entry could be found in the
        :class:`.cms.CMSAttributes` object.
    """
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
    """
    Bare-bones interface for modelling a collection of certificates.
    """

    def register(self, cert: x509.Certificate):
        """
        Add a certificate to the collection.

        :param cert:
            The certificate to add.
        """
        raise NotImplementedError

    def __iter__(self):
        """
        Iterate over all certificates in the collection.
        """
        raise NotImplementedError

    def __getitem__(self, item) -> x509.Certificate:
        """
        Retrieve a certificate by its ``issuer_serial`` value.

        :param item:
            The ``issuer_serial`` value of the certificate.
        :return:
            The certificate corresponding to the ``issuer_serial`` key
            passed in.
        :raises KeyError:
            Raised if no certificate was found.
        """
        raise NotImplementedError

    def register_multiple(self, certs):
        """
        Register multiple certificates.

        :param certs:
            Certificates to register.
        """

        for cert in certs:
            self.register(cert)


class SimpleCertificateStore(CertificateStore):
    """
    Unopinionated replacement for certvalidator's CertificateRegistry in cases
    where we explicitly don't care about whether the certs are trusted or not.
    """

    def __init__(self):
        self.certs = {}

    def register(self, cert: x509.Certificate):
        self.certs[cert.issuer_serial] = cert

    def __getitem__(self, item):
        return self.certs[item]

    def __iter__(self):
        return iter(self.certs.values())


class SigningError(ValueError):
    """
    Error encountered while signing a file.
    """
    pass


class UnacceptableSignerError(SigningError):
    """
    Error raised when a signer was judged unacceptable.
    """
    pass
