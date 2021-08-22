# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import abc
from collections import defaultdict
from typing import List

from asn1crypto import pem, x509
from oscrypto import trust_list

from ._errors import pretty_message
from ._types import byte_cls, type_name
from .errors import PathBuildingError, DuplicateCertificateError
from .path import ValidationPath


class CertificateCollection(abc.ABC):
    """
    Abstract base class for read-only access to a collection of certificates.
    """

    def retrieve_by_key_identifier(self, key_identifier: bytes):
        """
        Retrieves a cert via its key identifier

        :param key_identifier:
            A byte string of the key identifier

        :return:
            None or an asn1crypto.x509.Certificate object
        """
        candidates = self.retrieve_many_by_key_identifier(key_identifier)
        if not candidates:
            return None
        else:
            return candidates[0]

    def retrieve_many_by_key_identifier(self, key_identifier: bytes):
        """
        Retrieves possibly multiple certs via the corresponding key identifiers

        :param key_identifier:
            A byte string of the key identifier

        :return:
            A list of asn1crypto.x509.Certificate objects
        """
        raise NotImplementedError

    def retrieve_by_name(self, name: x509.Name):
        """
        Retrieves a list certs via their subject name

        :param name:
            An asn1crypto.x509.Name object

        :return:
            A list of asn1crypto.x509.Certificate objects
        """
        raise NotImplementedError

    def retrieve_by_issuer_serial(self, issuer_serial):
        """
        Retrieve a certificate by its ``issuer_serial`` value.

        :param issuer_serial:
            The ``issuer_serial`` value of the certificate.
        :return:
            The certificate corresponding to the ``issuer_serial`` key
            passed in.
        :return:
            None or an asn1crypto.x509.Certificate object
        """
        raise NotImplementedError


class CertificateStore(CertificateCollection, abc.ABC):
    def register(self, cert: x509.Certificate) -> bool:
        """
        Register a single certificate.

        :param cert:
            Certificate to add.
        :return:
            ``True`` if the certificate was added, ``False`` if it already
            existed in this store.
        """
        raise NotImplementedError

    def register_multiple(self, certs):
        """
        Register multiple certificates.

        :param certs:
            Certificates to register.
        :return:
            ``True`` if at least one certificate was added, ``False``
            if all certificates already existed in this store.
        """

        added = False
        for cert in certs:
            added |= self.register(cert)
        return added


class SimpleCertificateStore(CertificateStore):
    """
    Simple trustless certificate store.
    """

    @classmethod
    def from_certs(cls, certs):
        result = cls()
        for cert in certs:
            result.register(cert)
        return result

    def __init__(self):
        self.certs = {}
        self._subject_map = defaultdict(list)
        self._key_identifier_map = defaultdict(list)

    def register(self, cert: x509.Certificate) -> bool:
        """
        Register a single certificate.

        :param cert:
            Certificate to add.
        :return:
            ``True`` if the certificate was added, ``False`` if it already
            existed in this store.
        """
        if cert.issuer_serial in self.certs:
            return False
        self.certs[cert.issuer_serial] = cert
        self._subject_map[cert.subject.hashable].append(cert)
        if cert.key_identifier:
            self._key_identifier_map[cert.key_identifier].append(cert)
        else:
            self._key_identifier_map[cert.public_key.sha1].append(cert)
        return True

    def __getitem__(self, item):
        return self.certs[item]

    def __iter__(self):
        return iter(self.certs.values())

    def retrieve_many_by_key_identifier(self, key_identifier: bytes):
        return self._key_identifier_map[key_identifier]

    def retrieve_by_name(self, name: x509.Name):
        return self._subject_map[name.hashable]

    def retrieve_by_issuer_serial(self, issuer_serial):
        try:
            return self[issuer_serial]
        except KeyError:
            return None


class CertificateRegistry(SimpleCertificateStore):
    """
    Contains certificate lists used to build validation paths
    """

    # A dict with keys being asn1crypto.x509.Certificate.signature byte string.
    # Each value is a bool - if the certificate is a CA cert.
    _ca_lookup = None

    def __init__(self, trust_roots=None, extra_trust_roots=None, other_certs=None):
        """
        :param trust_roots:
            If the operating system's trust list should not be used, instead
            pass a list of byte strings containing DER or PEM-encoded X.509
            certificates, or asn1crypto.x509.Certificate objects. These
            certificates will be used as the trust roots for the path being
            built.

        :param extra_trust_roots:
            If the operating system's trust list should be used, but augmented
            with one or more extra certificates. This should be a list of byte
            strings containing DER or PEM-encoded X.509 certificates, or
            asn1crypto.x509.Certificate objects.

        :param other_certs:
            A list of byte strings containing DER or PEM-encoded X.509
            certificates, or a list of asn1crypto.x509.Certificate objects.
            These other certs are usually provided by the service/item being
            validated. In SSL, these would be intermediate chain certs.
        """

        if trust_roots is not None and not isinstance(trust_roots, list):
            raise TypeError(pretty_message(
                '''
                trust_roots must be a list of byte strings or
                asn1crypto.x509.Certificate objects, not %s
                ''',
                type_name(trust_roots)
            ))

        if extra_trust_roots is not None and not isinstance(extra_trust_roots, list):
            raise TypeError(pretty_message(
                '''
                extra_trust_roots must be a list of byte strings or
                asn1crypto.x509.Certificate objects, not %s
                ''',
                type_name(extra_trust_roots)
            ))

        if other_certs is not None and not isinstance(other_certs, list):
            raise TypeError(pretty_message(
                '''
                other_certs must be a list of byte strings or
                asn1crypto.x509.Certificate objects, not %s
                ''',
                type_name(other_certs)
            ))
        super().__init__()

        self._ca_lookup = set()

        if other_certs is None:
            other_certs = []
        else:
            other_certs = self._validate_unarmor(other_certs, 'other_certs')

        if trust_roots is None:
            trust_roots = [e[0] for e in trust_list.get_list()]
        else:
            trust_roots = self._validate_unarmor(trust_roots, 'trust_roots')

        if extra_trust_roots is not None:
            trust_roots.extend(self._validate_unarmor(extra_trust_roots, 'extra_trust_roots'))

        for trust_root in trust_roots:
            self.register(trust_root)
            self._ca_lookup.add(trust_root.signature)

        for other_cert in other_certs:
            self.register(other_cert)

    def _validate_unarmor(self, certs, var_name):
        """
        Takes a list of byte strings or asn1crypto.x509.Certificates objects,
        validates and loads them while unarmoring any PEM-encoded contents

        :param certs:
            A list of byte strings or asn1crypto.x509.Certificate objects

        :param var_name:
            A unicode variable name to use in any TypeError exceptions

        :return:
            A list of asn1crypto.x509.Certificate objects
        """

        output = []
        for cert in certs:
            if isinstance(cert, x509.Certificate):
                output.append(cert)
            else:
                if not isinstance(cert, byte_cls):
                    raise TypeError(pretty_message(
                        '''
                        %s must contain only byte strings or
                        asn1crypto.x509.Certificate objects, not %s
                        ''',
                        var_name,
                        type_name(cert)
                    ))
                if pem.detect(cert):
                    _, _, cert = pem.unarmor(cert)
                output.append(x509.Certificate.load(cert))
        return output

    def is_ca(self, cert):
        """
        Checks if a certificate is in the list of CA certs in this registry

        :param cert:
            An asn1crypto.x509.Certificate object

        :return:
            A boolean - if the certificate is in the CA list
        """

        return cert.signature in self._ca_lookup

    def add_other_cert(self, cert):
        """
        Allows adding an "other" cert that is obtained from doing revocation
        check via OCSP or CRL, or some other method

        :param cert:
            An asn1crypto.x509.Certificate object or a byte string of a DER or
            PEM-encoded certificate

        :return:
            A boolean indicating if the certificate was added - will return
            False if the certificate was already present
        """

        if not isinstance(cert, x509.Certificate):
            if not isinstance(cert, byte_cls):
                raise TypeError(pretty_message(
                    '''
                    cert must be a byte string or an instance of
                    asn1crypto.x509.Certificate, not %s
                    ''',
                    type_name(cert)
                ))
            if pem.detect(cert):
                _, _, cert = pem.unarmor(cert)
            cert = x509.Certificate.load(cert)

        return self.register(cert)

    def retrieve_by_name(self, name, first_certificate=None):
        """
        Retrieves a list certs via their subject name

        :param name:
            An asn1crypto.x509.Name object

        :param first_certificate:
            An asn1crypto.x509.Certificate object that if found, should be
            placed first in the result list

        :return:
            A list of asn1crypto.x509.Certificate objects
        """

        if not isinstance(name, x509.Name):
            raise TypeError(pretty_message(
                '''
                name must be an instance of asn1crypto.x509.Name, not %s
                ''',
                type_name(name)
            ))

        if first_certificate and not isinstance(first_certificate, x509.Certificate):
            raise TypeError(pretty_message(
                '''
                first_certificate must be an instance of
                asn1crypto.x509.Certificate, not %s
                ''',
                type_name(first_certificate)
            ))

        output = []
        first = None
        for cert in super().retrieve_by_name(name):
            if first_certificate and first_certificate.sha256 == cert.sha256:
                first = cert
            else:
                output.append(cert)
        if first:
            output.insert(0, first)
        return output

    def build_paths(self, end_entity_cert):
        """
        Builds a list of ValidationPath objects from a certificate in the
        operating system trust store to the end-entity certificate

        :param end_entity_cert:
            A byte string of a DER or PEM-encoded X.509 certificate, or an
            instance of asn1crypto.x509.Certificate

        :return:
            A list of pyhanko_certvalidator.path.ValidationPath objects that represent
            the possible paths from the end-entity certificate to one of the CA
            certs.
        """

        if not isinstance(end_entity_cert, byte_cls) and not isinstance(end_entity_cert, x509.Certificate):
            raise TypeError(pretty_message(
                '''
                end_entity_cert must be a byte string or an instance of
                asn1crypto.x509.Certificate, not %s
                ''',
                type_name(end_entity_cert)
            ))

        if isinstance(end_entity_cert, byte_cls):
            if pem.detect(end_entity_cert):
                _, _, end_entity_cert = pem.unarmor(end_entity_cert)
            end_entity_cert = x509.Certificate.load(end_entity_cert)

        path = ValidationPath(end_entity_cert)
        paths = []
        failed_paths = []

        self._walk_issuers(path, paths, failed_paths)

        if len(paths) == 0:
            cert_name = end_entity_cert.subject.human_friendly
            missing_issuer_name = failed_paths[0].first.issuer.human_friendly
            raise PathBuildingError(pretty_message(
                '''
                Unable to build a validation path for the certificate "%s" - no
                issuer matching "%s" was found
                ''',
                cert_name,
                missing_issuer_name
            ))

        return paths

    def _walk_issuers(self, path, paths, failed_paths):
        """
        Recursively looks through the list of known certificates for the issuer
        of the certificate specified, stopping once the certificate in question
        is one contained within the CA certs list

        :param path:
            A ValidationPath object representing the current traversal of
            possible paths

        :param paths:
            A list of completed ValidationPath objects. This is mutated as
            results are found.

        :param failed_paths:
            A list of pyhanko_certvalidator.path.ValidationPath objects that failed due
            to no matching issuer before reaching a certificate from the CA
            certs list
        """

        if path.first.signature in self._ca_lookup:
            paths.append(path)
            return

        new_branches = 0
        for issuer in self._possible_issuers(path.first):
            try:
                self._walk_issuers(path.copy().prepend(issuer), paths, failed_paths)
                new_branches += 1
            except (DuplicateCertificateError):
                pass

        if not new_branches:
            failed_paths.append(path)

    def _possible_issuers(self, cert):
        """
        Returns a generator that will list all possible issuers for the cert

        :param cert:
            An asn1crypto.x509.Certificate object to find the issuer of
        """

        issuer_hashable = cert.issuer.hashable
        for issuer in self._subject_map[issuer_hashable]:
            # Info from the authority key identifier extension can be used to
            # eliminate possible options when multiple keys with the same
            # subject exist, such as during a transition, or with cross-signing.
            if cert.authority_key_identifier and issuer.key_identifier:
                if cert.authority_key_identifier != issuer.key_identifier:
                    continue
            elif cert.authority_issuer_serial:
                if cert.authority_issuer_serial != issuer.issuer_serial:
                    continue

            yield issuer


class LayeredCertificateStore(CertificateCollection):
    """
    Trustless certificate store that looks up certificates in other stores
    in a specific order.
    """

    def __init__(self, stores: List[CertificateStore]):
        self._stores = stores

    def retrieve_many_by_key_identifier(self, key_identifier: bytes):
        def _gen():
            for store in self._stores:
                yield from store.retrieve_many_by_key_identifier(key_identifier)
        return list(_gen())

    def retrieve_by_name(self, name: x509.Name):
        def _gen():
            for store in self._stores:
                yield from store.retrieve_by_name(name)
        return list(_gen())

    def retrieve_by_issuer_serial(self, issuer_serial):
        for store in self._stores:
            result = store.retrieve_by_issuer_serial(issuer_serial)
            if result is not None:
                return result
        return None
