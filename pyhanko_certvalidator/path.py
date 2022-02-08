# coding: utf-8
import itertools
from typing import FrozenSet, Optional, Iterable
from dataclasses import dataclass

from asn1crypto import x509, cms

from .asn1_types import AAControls
from .trust_anchor import TrustAnchor, CertTrustAnchor


@dataclass(frozen=True)
class QualifiedPolicy:
    issuer_domain_policy_id: str
    """
    Policy OID in the issuer domain (i.e. as listed on the certificate).
    """

    user_domain_policy_id: str
    """
    Policy OID of the equivalent policy in the user domain.
    """

    qualifiers: frozenset
    """
    Set of x509.PolicyQualifierInfo objects.
    """


class ValidationPath:
    """
    Represents a path going towards an end-entity certificate
    """

    # A list of asn1crypto.x509.Certificate objects, starting with a trust root
    # and chaining to an end-entity certificate
    _certs = None

    _qualified_policies = None

    _path_aa_controls = None

    def __init__(self, trust_anchor: TrustAnchor,
                 certs: Optional[Iterable[x509.Certificate]] = None):

        self._certs = list(certs) if certs is not None else []
        self._root = trust_anchor

    @property
    def trust_anchor(self) -> TrustAnchor:
        return self._root

    @property
    def first(self):
        """
        Returns the current beginning of the path - for a path to be complete,
        this certificate should be a trust root

        .. warning::
            This is a compatibility property, and will return the first non-root
            certificate if the trust root is not provisioned as a certificate.
            If you want the trust root itself (even when it doesn't have a
            certificate), use :attr:`trust_anchor`.

        :return:
            The first asn1crypto.x509.Certificate object in the path
        """
        if isinstance(self._root, CertTrustAnchor):
            return self._root.certificate
        else:
            return self._certs[0]

    @property
    def last(self):
        """
        Returns the current end of the path - the end entity certificate

        :return:
            The last asn1crypto.x509.Certificate object in the path
        """
        if self._certs:
            return self._certs[len(self._certs) - 1]
        elif isinstance(self._root, CertTrustAnchor):
            return self._root.certificate
        else:
            raise LookupError("No certificates in path")

    def find_issuer(self, cert):
        """
        Return the issuer of the cert specified, as defined by this path

        :param cert:
            An asn1crypto.x509.Certificate object to get the issuer of

        :raises:
            LookupError - when the issuer of the certificate could not be found

        :return:
            An asn1crypto.x509.Certificate object of the issuer
        """

        for entry in self:
            if entry.subject == cert.issuer:
                if entry.key_identifier and cert.authority_key_identifier:
                    if entry.key_identifier == cert.authority_key_identifier:
                        return entry
                else:
                    return entry

        raise LookupError('Unable to find the issuer of the certificate specified')

    def truncate_to(self, cert: x509.Certificate):
        """
        Remove all certificates in the path after the cert specified and return
        them in a new path.

        :param cert:
            An asn1crypto.x509.Certificate object to find

        :raises:
            LookupError - when the certificate could not be found

        :return:
            The current ValidationPath object, for chaining
        """

        if isinstance(self._root, CertTrustAnchor):
            if self._root.certificate.issuer_serial == cert.issuer_serial:
                return ValidationPath(self._root, [])

        certs = self._certs
        cert_index = None
        for index, entry in enumerate(certs):
            if entry.issuer_serial == cert.issuer_serial:
                cert_index = index
                break

        if cert_index is None:
            raise LookupError('Unable to find the certificate specified')
        return ValidationPath(self._root, certs[:cert_index + 1])

    def truncate_to_issuer(self, cert):
        """
        Remove all certificates in the path after the issuer of the cert
        specified, as defined by this path

        :param cert:
            An asn1crypto.x509.Certificate object to find the issuer of

        :raises:
            LookupError - when the issuer of the certificate could not be found

        :return:
            The current ValidationPath object, for chaining
        """

        issuer_index = None

        # check the trust root separately
        if self.trust_anchor.is_potential_issuer_of(cert):
            # in case of a match, truncate everything
            return ValidationPath(self._root, [])

        # now run through the rest of the path
        certs = self._certs
        for index, entry in enumerate(certs):
            if entry.subject == cert.issuer:
                if entry.key_identifier and cert.authority_key_identifier:
                    if entry.key_identifier == cert.authority_key_identifier:
                        issuer_index = index
                        break
                else:
                    issuer_index = index
                    break

        if issuer_index is None:
            raise LookupError('Unable to find the issuer of the certificate specified')

        return ValidationPath(self._root, certs[:issuer_index + 1])

    def copy_and_append(self, cert: x509.Certificate):
        new_certs = self._certs[:]
        new_certs.append(cert)
        return ValidationPath(trust_anchor=self._root, certs=new_certs)

    def copy(self):
        """
        Creates a copy of this path

        :return:
            A ValidationPath object
        """

        return ValidationPath(trust_anchor=self._root, certs=self._certs[:])

    def pop(self):
        """
        Removes the last certificate from the path

        :return:
            The current ValidationPath object, for chaining
        """

        self._certs.pop()
        return self

    def _set_qualified_policies(self, policies):
        self._qualified_policies = policies

    def qualified_policies(self) -> FrozenSet[QualifiedPolicy]:
        return self._qualified_policies

    def aa_attr_in_scope(self, attr_id: cms.AttCertAttributeType) -> bool:
        aa_controls_extensions = [
            AAControls.read_extension_value(cert) for cert in self
        ]
        aa_controls_used = any(x is not None for x in aa_controls_extensions)
        if not aa_controls_used:
            return True
        else:
            # the path validation code ensures that all non-anchor certs
            # have an AAControls extension, but we still enforce the root's
            # AAControls if there is one (since we might as well treat it
            # as a configuration setting/failsafe at that point)
            # This is appropriate in PKIX-land (see RFC 5280, § 6.2 as
            # updated in RFC 6818, § 4)
            return all(
                ctrl.accept(attr_id) for ctrl in aa_controls_extensions
                # None check for defensiveness (already enforced by validation
                # algorithm), and to (potentially) skip the root
                if ctrl is not None
            )

    @property
    def pkix_len(self):
        return len(self._certs)

    def __len__(self):
        # backwards compat
        return 1 + len(self._certs)

    def __getitem__(self, key):
        if key > 0:
            return self._certs[key - 1]
        elif isinstance(self._root, CertTrustAnchor):
            # backwards compat
            return self._root.certificate
        else:
            # Throw an error instead of returning None, because we want this
            # to fail loudly.
            raise LookupError("Root has no certificate")

    def __iter__(self):
        # backwards compat, we iterate over all certs _including_ the root
        # if it is supplied as a cert
        if isinstance(self._root, CertTrustAnchor):
            return itertools.chain((self._root.certificate,), self._certs)
        else:
            return iter(self._certs)

    def __eq__(self, other):
        if not isinstance(other, ValidationPath):
            return False
        return (
            self.trust_anchor == other.trust_anchor
            and self._certs == other._certs
        )
