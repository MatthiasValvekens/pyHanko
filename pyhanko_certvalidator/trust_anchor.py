import abc
from dataclasses import dataclass
from typing import Optional

from asn1crypto import x509, keys

from .name_trees import process_general_subtrees
from .policy_decl import PKIXValidationParams


# TODO add support for roots that are limited in time?

@dataclass(frozen=True)
class TrustQualifiers:
    """
    Parameters that allow a trust root to be qualified.
    """

    standard_parameters: Optional['PKIXValidationParams'] = None
    """
    Standard validation parameters that will apply when initialising
    the PKIX validation process.
    """

    max_path_length: Optional[int] = None
    """
    Maximal allowed path length for this trust root, excluding self-issued
    intermediate CA certificates. If ``None``, any path length will be accepted.
    """

    max_aa_path_length: Optional[int] = None
    """
    Maximal allowed path length for this trust root for the purposes of
    AAControls. If ``None``, any path length will be accepted.
    """


class TrustAnchor(abc.ABC):
    """
    Abstract trust root.
    """

    # TODO document properties

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
    def trust_qualifiers(self) -> TrustQualifiers:
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


def derive_quals_from_cert(cert: x509.Certificate) -> TrustQualifiers:
    # TODO align with RFC 5937?
    ext_found = False
    permitted_subtrees = excluded_subtrees = None
    if cert.name_constraints_value is not None:
        ext_found = True
        nc_ext: x509.NameConstraints = cert.name_constraints_value
        permitted_val = nc_ext['permitted_subtrees']
        if isinstance(permitted_val, x509.GeneralSubtrees):
            permitted_subtrees = process_general_subtrees(permitted_val)
        excluded_val = nc_ext['excluded_subtrees']
        if isinstance(excluded_val, x509.GeneralSubtrees):
            excluded_subtrees = process_general_subtrees(excluded_val)

    acceptable_policies = None
    if cert.certificate_policies_value is not None:
        ext_found = True
        policies_val: x509.CertificatePolicies = cert.certificate_policies_value
        acceptable_policies = frozenset([
            pol_info['policy_identifier'].dotted for pol_info in policies_val
        ])

    params = None
    if ext_found:
        params = PKIXValidationParams(
            user_initial_policy_set=(
                acceptable_policies or frozenset(['any_policy'])
            ),
            # For trust roots where the user asked for this derivation,
            #  let's assume that they want the policies to be enforced.
            initial_explicit_policy=acceptable_policies is not None,
            initial_permitted_subtrees=permitted_subtrees,
            initial_excluded_subtrees=excluded_subtrees
        )

    return TrustQualifiers(
        max_path_length=cert.max_path_length, standard_parameters=params
    )


class CertTrustAnchor(TrustAnchor):
    """
    Trust anchor provisioned as a certificate.

    :param cert:
        The certificate, usually self-signed.
    :param quals:
        Explicit trust qualifiers.
    :param derive_default_quals_from_cert:
        Flag indicating to derive default trust qualifiers from the certificate
        content if explicit ones are not provided. Defaults to ``False``.
    """

    def __init__(self, cert: x509.Certificate,
                 quals: Optional[TrustQualifiers] = None,
                 derive_default_quals_from_cert: bool = False):
        self._cert = cert
        self._derive = derive_default_quals_from_cert
        self._quals = quals

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

    @property
    def trust_qualifiers(self) -> TrustQualifiers:
        if self._quals is not None:
            return self._quals
        elif self._derive:
            self._quals = quals = derive_quals_from_cert(self._cert)
            return quals
        else:
            return TrustQualifiers()

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

    def __init__(self, entity_name: x509.Name, public_key: keys.PublicKeyInfo,
                 quals: Optional[TrustQualifiers] = None):
        self._name = entity_name
        self._public_key = public_key
        self._quals = quals or TrustQualifiers()

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

    @property
    def trust_qualifiers(self) -> TrustQualifiers:
        return self._quals
