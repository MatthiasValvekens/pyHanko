import abc
from typing import Optional

from asn1crypto import x509, keys

# TODO document properties


class TrustAnchor(abc.ABC):
    """
    Abstract trust root.
    """

    # TODO: allow specific policy restrictions per trust root.

    @property
    def name(self) -> x509.Name:
        raise NotImplementedError

    @property
    def public_key(self):
        raise NotImplementedError

    @property
    def hashable(self):
        raise NotImplementedError

    @property
    def key_id(self) -> Optional[bytes]:
        """
        Key ID as (potentially) referenced in an authorityKeyIdentifier
        extension. Only used to eliminate non-matching trust anchors,
        never to retrieve keys or to definitively identify trust anchors.
        """
        raise NotImplementedError

    def __hash__(self):
        return hash(self.hashable)

    def __eq__(self, other):
        if not isinstance(other, TrustAnchor):
            return False

        return self.hashable == other.hashable

    def is_potential_issuer_of(self, cert: x509.Certificate):
        if cert.issuer != self.name:
            return False
        if cert.authority_key_identifier and self.key_id:
            if cert.authority_key_identifier != self.key_id:
                return False
        return True


class CertTrustAnchor(TrustAnchor):
    """
    Trust anchor provisioned as a certificate
    """

    def __init__(self, cert: x509.Certificate):
        self._cert = cert

    @property
    def name(self) -> x509.Name:
        return self._cert.subject

    @property
    def public_key(self):
        return self._cert.public_key

    @property
    def hashable(self):
        cert = self._cert
        return cert.subject.hashable, cert.public_key.dump()

    @property
    def key_id(self) -> Optional[bytes]:
        return self._cert.key_identifier

    @property
    def certificate(self) -> x509.Certificate:
        return self._cert

    def is_potential_issuer_of(self, cert: x509.Certificate):
        if not super().is_potential_issuer_of(cert):
            return False
        if cert.authority_issuer_serial:
            if cert.authority_issuer_serial != self._cert.issuer_serial:
                return False
        return True


class NamedKeyTrustAnchor(TrustAnchor):
    """
    Trust anchor provisioned as a named key.
    """

    def __init__(self, entity_name: x509.Name, public_key: keys.PublicKeyInfo):
        self._name = entity_name
        self._public_key = public_key

    @property
    def name(self) -> x509.Name:
        return self._name

    @property
    def public_key(self):
        return self._public_key

    @property
    def key_id(self) -> Optional[bytes]:
        return None

    @property
    def hashable(self):
        return self._name.hashable, self._public_key.dump()
