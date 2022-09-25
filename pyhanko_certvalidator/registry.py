# coding: utf-8

import abc
import asyncio
from collections import defaultdict
from typing import Iterable, Iterator, List, Optional, Union

from asn1crypto import x509
from oscrypto import trust_list

from .authority import CertTrustAnchor, TrustAnchor
from .errors import PathBuildingError
from .fetchers import CertificateFetcher
from .path import ValidationPath
from .util import ConsList


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

    def __iter__(self):
        raise NotImplementedError


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


TrustRootList = Iterable[Union[x509.Certificate, TrustAnchor]]


class TrustManager:
    """
    Abstract trust manager API.
    """

    def is_root(self, cert: x509.Certificate) -> bool:
        """
        Checks if a certificate is in the list of trust roots in this registry

        :param cert:
            An asn1crypto.x509.Certificate object

        :return:
            A boolean - if the certificate is in the CA list
        """
        raise NotImplementedError

    def find_potential_issuers(
        self, cert: x509.Certificate
    ) -> Iterator[TrustAnchor]:
        """
        Find potential issuers that might have (directly) issued
        a particular certificate.

        :param cert:
            Issued certificate.
        :return:
            An iterator with potentially relevant trust anchors.
        """
        raise NotImplementedError


class SimpleTrustManager(TrustManager):
    """
    Trust manager backed by a list of trust roots, possibly in addition to the
    system trust list.
    """

    def __init__(self):

        self._roots = set()
        self._root_subject_map = defaultdict(list)

    @classmethod
    def build(
        cls,
        trust_roots: Optional[TrustRootList] = None,
        extra_trust_roots: Optional[TrustRootList] = None,
    ) -> 'SimpleTrustManager':
        """
        :param trust_roots:
            If the operating system's trust list should not be used, instead
            pass a list of asn1crypto.x509.Certificate objects. These
            certificates will be used as the trust roots for the path being
            built.

        :param extra_trust_roots:
            If the operating system's trust list should be used, but augmented
            with one or more extra certificates. This should be a list of
            asn1crypto.x509.Certificate objects.
        :return:
        """
        if trust_roots is None:
            trust_roots = [e[0] for e in trust_list.get_list()]
        else:
            trust_roots = list(trust_roots)

        if extra_trust_roots is not None:
            trust_roots.extend(extra_trust_roots)

        manager = SimpleTrustManager()
        for trust_root in trust_roots:
            manager._register_root(trust_root)
        return manager

    def _register_root(self, trust_root: Union[TrustAnchor, x509.Certificate]):
        if isinstance(trust_root, TrustAnchor):
            anchor = trust_root
        else:
            anchor = CertTrustAnchor(trust_root)
        if anchor not in self._roots:
            authority = anchor.authority
            self._roots.add(anchor)
            self._root_subject_map[authority.name.hashable].append(anchor)

    def is_root(self, cert: x509.Certificate):
        """
        Checks if a certificate is in the list of trust roots in this registry

        :param cert:
            An asn1crypto.x509.Certificate object

        :return:
            A boolean - if the certificate is in the CA list
        """

        return CertTrustAnchor(cert) in self._roots

    def iter_certs(self) -> Iterator[x509.Certificate]:
        return (
            root.certificate
            for root in self._roots
            if isinstance(root, CertTrustAnchor)
        )

    def find_potential_issuers(
        self, cert: x509.Certificate
    ) -> Iterator[TrustAnchor]:
        issuer_hashable = cert.issuer.hashable
        root: TrustAnchor
        for root in self._root_subject_map[issuer_hashable]:
            if root.authority.is_potential_issuer_of(cert):
                yield root


class CertificateRegistry(SimpleCertificateStore):
    """
    Contains certificate lists used to build validation paths, and
    is also capable of fetching missing certificates if a certificate
    fetcher is supplied.
    """

    def __init__(self, *, cert_fetcher: Optional[CertificateFetcher] = None):
        super().__init__()
        self.fetcher = cert_fetcher

    @classmethod
    def build(
        cls,
        certs: Iterable[x509.Certificate] = (),
        *,
        cert_fetcher: Optional[CertificateFetcher] = None,
    ):
        """
        Convenience method to set up a certificate registry and import
        certs into it.

        :param certs:
            Initial list of certificates to import.
        :param cert_fetcher:
            Certificate fetcher to handle retrieval of missing certificates
            (in situations where that is possible).
        :return:
            A populated certificate registry.
        """

        result: CertificateRegistry = cls(cert_fetcher=cert_fetcher)
        for cert in certs:
            result.register(cert)

        result.fetcher = cert_fetcher
        return result

    def retrieve_by_name(
        self,
        name: x509.Name,
        first_certificate: Optional[x509.Certificate] = None,
    ):
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

    def find_potential_issuers(
        self, cert: x509.Certificate, trust_manager: TrustManager
    ) -> Iterator[Union[TrustAnchor, x509.Certificate]]:

        issuer_hashable = cert.issuer.hashable

        # Info from the authority key identifier extension can be used to
        # eliminate possible options when multiple keys with the same
        # subject exist, such as during a transition, or with cross-signing.

        # go through matching trust roots first
        yield from trust_manager.find_potential_issuers(cert)

        for issuer in self._subject_map[issuer_hashable]:
            if trust_manager.is_root(issuer):
                continue  # skip, we've had these in the previous step
            if cert.authority_key_identifier and issuer.key_identifier:
                if cert.authority_key_identifier != issuer.key_identifier:
                    continue
            elif cert.authority_issuer_serial:
                if cert.authority_issuer_serial != issuer.issuer_serial:
                    continue

            yield issuer

    async def fetch_missing_potential_issuers(self, cert: x509.Certificate):
        if self.fetcher is None:
            return

        async for issuer in self.fetcher.fetch_cert_issuers(cert):
            # register the cert for future reference
            self.register(issuer)
            yield issuer


class PathBuilder:
    """
    Class to handle path building.
    """

    def __init__(
        self, trust_manager: TrustManager, registry: CertificateRegistry
    ):
        self.trust_manager = trust_manager
        self.registry = registry

    def build_paths(self, end_entity_cert):
        """
        Builds a list of ValidationPath objects from a certificate in the
        operating system trust store to the end-entity certificate

        .. note::
            This is a synchronous equivalent of :meth:`async_build_paths`
            that calls the latter in a new event loop. As such, it can't be used
            from within asynchronous code.

        :param end_entity_cert:
            A byte string of a DER or PEM-encoded X.509 certificate, or an
            instance of asn1crypto.x509.Certificate

        :return:
            A list of pyhanko_certvalidator.path.ValidationPath objects that
            represent the possible paths from the end-entity certificate to one
            of the CA certs.
        """
        return asyncio.run(self.async_build_paths(end_entity_cert))

    async def async_build_paths(self, end_entity_cert: x509.Certificate):
        """
        Builds a list of ValidationPath objects from a certificate in the
        operating system trust store to the end-entity certificate

        :param end_entity_cert:
            A byte string of a DER or PEM-encoded X.509 certificate, or an
            instance of asn1crypto.x509.Certificate

        :return:
            A list of pyhanko_certvalidator.path.ValidationPath objects that
            represent the possible paths from the end-entity certificate to one
            of the CA certs.
        """

        if self.trust_manager.is_root(end_entity_cert):
            result = ValidationPath(CertTrustAnchor(end_entity_cert), [], None)
            return [result]

        path: ConsList[x509.Certificate] = ConsList.sing(end_entity_cert)
        certs_seen: ConsList[bytes] = ConsList.sing(
            end_entity_cert.issuer_serial
        )
        paths: List[ValidationPath] = []
        failed_paths: List[ConsList[x509.Certificate]] = []

        await self._walk_issuers(path, certs_seen, paths, failed_paths)

        if len(paths) == 0:
            cert_name = end_entity_cert.subject.human_friendly
            path_head = failed_paths[0].head
            assert isinstance(path_head, x509.Certificate)
            missing_issuer_name = path_head.issuer.human_friendly
            raise PathBuildingError(
                f"Unable to build a validation path for the certificate "
                f"\"{cert_name}\" - no issuer matching "
                f"\"{missing_issuer_name}\" was found"
            )

        return paths

    async def _walk_issuers(
        self,
        path: ConsList[x509.Certificate],
        certs_seen: ConsList[bytes],
        paths: List[ValidationPath],
        failed_paths,
    ):
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

        if isinstance(path.head, TrustAnchor):
            assert path.tail is not None
            certs = list(path.tail)
            paths.append(ValidationPath(path.head, certs[:-1], certs[-1]))
            return

        cert = path.head
        assert isinstance(cert, x509.Certificate)
        new_branches = 0
        potential_issuers = self.registry.find_potential_issuers(
            cert, self.trust_manager
        )
        for issuer in potential_issuers:
            if isinstance(issuer, x509.Certificate):
                cert_id = issuer.issuer_serial
                if cert_id in certs_seen:  # no duplicates
                    continue
                new_certs_seen = certs_seen.cons(cert_id)
            else:
                new_certs_seen = certs_seen
            await self._walk_issuers(
                path.cons(issuer), new_certs_seen, paths, failed_paths
            )
            new_branches += 1

        if not new_branches:
            # attempt to download certs if there's nothing in the context
            async for issuer in self.registry.fetch_missing_potential_issuers(
                cert
            ):
                cert_id = issuer.issuer_serial
                if cert_id in certs_seen:
                    continue
                new_certs_seen = certs_seen.cons(cert_id)
                await self._walk_issuers(
                    path.cons(issuer), new_certs_seen, paths, failed_paths
                )
                new_branches += 1
        if not new_branches:
            failed_paths.append(path)


class LayeredCertificateStore(CertificateCollection):
    """
    Trustless certificate store that looks up certificates in other stores
    in a specific order.
    """

    def __init__(self, stores: List[CertificateCollection]):
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
