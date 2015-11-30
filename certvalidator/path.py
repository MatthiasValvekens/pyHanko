# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from asn1crypto import pem, x509

from ._errors import pretty_message
from ._types import byte_cls, type_name
from .errors import DuplicateCertificateError


class ValidationPath():
    """
    Represents a path going towards an end-entity certificate
    """

    # A list of asn1crypto.x509.Certificate objects, starting with a trust root
    # and chaining to an end-entity certificate
    _certs = None

    # A set of asn1crypto.x509.Certificate.issuer_serial byte strings of
    # certificates that are already in ._certs
    _cert_hashes = None

    def __init__(self, end_entity_cert=None):
        """
        :param end_entity_cert:
            An asn1crypto.x509.Certificate object for the end-entity certificate
        """

        self._certs = []
        self._cert_hashes = set()
        if end_entity_cert:
            self.prepend(end_entity_cert)

    @property
    def first(self):
        """
        Returns the current beginning of the path - for a path to be complete,
        this certificate should be a trust root

        :return:
            The first asn1crypto.x509.Certificate object in the path
        """

        return self._certs[0]

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

    def truncate_to(self, cert):
        """
        Remove all certificates in the path after the cert specified

        :param cert:
            An asn1crypto.x509.Certificate object to find

        :raises:
            LookupError - when the certificate could not be found

        :return:
            The current ValidationPath object, for chaining
        """

        cert_index = None
        for index, entry in enumerate(self):
            if entry.issuer_serial == cert.issuer_serial:
                cert_index = index
                break

        if cert_index is None:
            raise LookupError('Unable to find the certificate specified')

        while len(self) > cert_index + 1:
            self.pop()

        return self

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
        for index, entry in enumerate(self):
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

        while len(self) > issuer_index + 1:
            self.pop()

        return self

    def copy(self):
        """
        Creates a copy of this path

        :return:
            A ValidationPath object
        """

        copy = self.__class__()
        copy._certs = self._certs[:]
        copy._cert_hashes = self._cert_hashes.copy()
        return copy

    def pop(self):
        """
        Removes the last certificate from the path

        :return:
            The current ValidationPath object, for chaining
        """

        last_cert = self._certs.pop()
        self._cert_hashes.remove(last_cert.issuer_serial)

        return self

    def append(self, cert):
        """
        Appends a cert to the path. This should be a cert issued by the last
        cert in the path.

        :param cert:
            An asn1crypto.x509.Certificate object

        :return:
            The current ValidationPath object, for chaining
        """

        if not isinstance(cert, x509.Certificate):
            if not isinstance(cert, byte_cls):
                raise TypeError(pretty_message(
                    '''
                    cert must be a byte string or an
                    asn1crypto.x509.Certificate object, not %s
                    ''',
                    type_name(cert)
                ))
            if pem.detect(cert):
                _, _, cert = pem.unarmor(cert)
            cert = x509.Certificate.load(cert)

        if cert.issuer_serial in self._cert_hashes:
            raise DuplicateCertificateError()

        self._cert_hashes.add(cert.issuer_serial)
        self._certs.append(cert)

        return self

    def prepend(self, cert):
        """
        Prepends a cert to the path. This should be the issuer of the previously
        prepended cert.

        :param cert:
            An asn1crypto.x509.Certificate object or a byte string

        :return:
            The current ValidationPath object, for chaining
        """

        if not isinstance(cert, x509.Certificate):
            if not isinstance(cert, byte_cls):
                raise TypeError(pretty_message(
                    '''
                    cert must be a byte string or an
                    asn1crypto.x509.Certificate object, not %s
                    ''',
                    type_name(cert)
                ))
            if pem.detect(cert):
                _, _, cert = pem.unarmor(cert)
            cert = x509.Certificate.load(cert)

        if cert.issuer_serial in self._cert_hashes:
            raise DuplicateCertificateError()

        self._cert_hashes.add(cert.issuer_serial)
        self._certs.insert(0, cert)

        return self

    def __len__(self):
        return len(self._certs)

    def __getitem__(self, key):
        return self._certs[key]

    def __iter__(self):
        return iter(self._certs)

    def __eq__(self, other):
        return self._certs == other._certs
