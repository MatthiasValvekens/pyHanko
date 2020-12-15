"""
This module provides PKCS#11 integration for pyHanko, by providing a wrapper
for `python-pkcs11 <https://github.com/danni/python-pkcs11>`_ that can be
seamlessly plugged into a :class:`~.signers.PdfSigner`.
"""
from asn1crypto.algos import SignedDigestAlgorithm
from pkcs11 import Session, ObjectClass, Attribute

from typing import Set

from asn1crypto import x509
from oscrypto import keys as oskeys

from pyhanko.sign.general import CertificateStore, SimpleCertificateStore
from pyhanko.sign.signers import Signer

__all__ = ['PKCS11Signer']


class PKCS11Signer(Signer):
    """
    Signer implementation for PKCS11 devices.

    Note: this class only supports the "RSA with PKCS#1 v1.5" scheme.
    In particular, there's no ECDSA support (yet).
    """

    def __init__(self, pkcs11_session: Session,
                 cert_label: str, ca_chain=None, key_label=None):
        """
        Initialise a PKCS11 signer.

        :param pkcs11_session:
            The PKCS11 session object to use.
        :param cert_label:
            The label of the certificate that will be used for signing.
        :param ca_chain:
            Set of other relevant certificates
            (as :class:`.asn1crypto.x509.Certificate` objects).
        :param key_label:
            The label of the key that will be used for signing.
            Defaults to the value of ``cert_label`` if left unspecified.
        """
        self.cert_label = cert_label
        self.key_label = key_label or cert_label
        self.pkcs11_session = pkcs11_session
        if ca_chain is not None:
            cs = SimpleCertificateStore()
            cs.register_multiple(ca_chain)
            self._cert_registry: CertificateStore = cs
        else:
            self._cert_registry = None
        self._signing_cert = self._key_handle = None
        self._loaded = False
        self.signature_mechanism = SignedDigestAlgorithm(
            {'algorithm': 'rsassa_pkcs1v15'}
        )
        super().__init__()

    @property
    def cert_registry(self):
        # it's conceivable that one might want to load this separately from
        # the key data, so we allow for that.
        if self._cert_registry is None:
            certs = self._load_ca_chain()
            cs = SimpleCertificateStore()
            cs.register_multiple(certs)
            self._cert_registry = cs
        return self._cert_registry

    @property
    def signing_cert(self):
        self._load_objects()
        return self._signing_cert

    def sign_raw(self, data: bytes, digest_algorithm: str, dry_run=False) \
            -> bytes:
        if dry_run:
            # allocate 4096 bits for the fake signature
            return b'0' * 512

        self._load_objects()
        from pkcs11 import Mechanism, SignMixin
        kh: SignMixin = self._key_handle
        mech = {
            'sha1': Mechanism.SHA1_RSA_PKCS,
            'sha256': Mechanism.SHA256_RSA_PKCS,
            'sha384': Mechanism.SHA384_RSA_PKCS,
            'sha512': Mechanism.SHA512_RSA_PKCS,
        }[digest_algorithm.lower()]
        return kh.sign(data, mechanism=mech)

    def _load_ca_chain(self) -> Set[x509.Certificate]:
        return set()

    def _load_objects(self):
        if self._loaded:
            return

        q = self.pkcs11_session.get_objects({
            Attribute.LABEL: self.cert_label,
            Attribute.CLASS: ObjectClass.CERTIFICATE
        })
        # need to run through the full iterator to make sure the operation
        # terminates
        cert_obj, = list(q)
        self._signing_cert = oskeys.parse_certificate(cert_obj[Attribute.VALUE])

        self._load_ca_chain()

        q = self.pkcs11_session.get_objects({
            Attribute.LABEL: self.key_label,
            Attribute.CLASS: ObjectClass.PRIVATE_KEY
        })
        self._key_handle, = list(q)

        self._loaded = True
