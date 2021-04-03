# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from asn1crypto import pem
from asn1crypto.x509 import Certificate

from .context import ValidationContext
from .errors import ValidationError, PathBuildingError, InvalidCertificateError
from .validate import validate_path, validate_tls_hostname, validate_usage
from .version import __version__, __version_info__
from ._errors import pretty_message
from ._types import type_name, str_cls, byte_cls


__all__ = [
    '__version__',
    '__version_info__',
    'CertificateValidator',
    'ValidationContext',
]


class CertificateValidator():

    # A pyhanko_certvalidator.context.ValidationContext object
    _context = None

    # An asn1crypto.x509.Certificate object
    _certificate = None

    # A pyhanko_certvalidator.path.ValidationPath object - only set once validated
    _path = None

    def __init__(self, end_entity_cert, intermediate_certs=None, validation_context=None):
        """
        :param end_entity_cert:
            An asn1crypto.x509.Certificate object or a byte string of the DER or
            PEM-encoded X.509 end-entity certificate to validate

        :param intermediate_certs:
            None or a list of asn1crypto.x509.Certificate objects or a byte
            string of a DER or PEM-encoded X.509 certificate. Used in
            constructing certificate paths for validation.

        :param validation_context:
            A pyhanko_certvalidator.context.ValidationContext() object that controls
            validation options
        """

        if not isinstance(end_entity_cert, Certificate):
            if not isinstance(end_entity_cert, byte_cls):
                raise TypeError(pretty_message(
                    '''
                    end_entity_cert must be a byte string or an instance of
                    asn1crypto.x509.Certificate, not %s
                    ''',
                    type_name(end_entity_cert)
                ))
            if pem.detect(end_entity_cert):
                _, _, end_entity_cert = pem.unarmor(end_entity_cert)
            end_entity_cert = Certificate.load(end_entity_cert)

        if validation_context is None:
            validation_context = ValidationContext()

        if not isinstance(validation_context, ValidationContext):
            raise TypeError(pretty_message(
                '''
                validation_context must be an instance of
                pyhanko_certvalidator.context.ValidationContext, not %s
                ''',
                type_name(validation_context)
            ))

        if intermediate_certs is not None:
            certificate_registry = validation_context.certificate_registry
            for intermediate_cert in intermediate_certs:
                certificate_registry.add_other_cert(intermediate_cert)

        self._context = validation_context
        self._certificate = end_entity_cert

    def _validate_path(self):
        """
        Builds possible certificate paths and validates them until a valid one
        is found, or all fail.

        :raises:
            pyhanko_certvalidator.errors.PathValidationError - when an error occurs validating the path
            pyhanko_certvalidator.errors.RevokedError - when the certificate or another certificate in its path has been revoked
        """

        if self._path is not None:
            return

        exceptions = []

        if self._certificate.hash_algo in self._context.weak_hash_algos:
            raise InvalidCertificateError(pretty_message(
                '''
                The X.509 certificate provided has a signature using the weak
                hash algorithm %s
                ''',
                self._certificate.hash_algo
            ))

        try:
            paths = self._context.certificate_registry.build_paths(self._certificate)
        except (PathBuildingError):
            if self._certificate.self_signed in set(['yes', 'maybe']):
                raise InvalidCertificateError(pretty_message(
                    '''
                    The X.509 certificate provided is self-signed - "%s"
                    ''',
                    self._certificate.subject.human_friendly
                ))
            raise

        for candidate_path in paths:
            try:
                validate_path(self._context, candidate_path)
                self._path = candidate_path
                return
            except (ValidationError) as e:
                exceptions.append(e)

        if len(exceptions) == 1:
            raise exceptions[0]

        non_signature_exception = None
        for exception in exceptions:
            if 'signature' not in str_cls(exception):
                non_signature_exception = exception

        if non_signature_exception:
            raise non_signature_exception

        raise exceptions[0]

    def validate_usage(self, key_usage, extended_key_usage=None, extended_optional=False):
        """
        Validates the certificate path and that the certificate is valid for
        the key usage and extended key usage purposes specified.

        :param key_usage:
            A set of unicode strings of the required key usage purposes. Valid
            values include:

             - "digital_signature"
             - "non_repudiation"
             - "key_encipherment"
             - "data_encipherment"
             - "key_agreement"
             - "key_cert_sign"
             - "crl_sign"
             - "encipher_only"
             - "decipher_only"

        :param extended_key_usage:
            A set of unicode strings of the required extended key usage
            purposes. These must be either dotted number OIDs, or one of the
            following extended key usage purposes:

             - "server_auth"
             - "client_auth"
             - "code_signing"
             - "email_protection"
             - "ipsec_end_system"
             - "ipsec_tunnel"
             - "ipsec_user"
             - "time_stamping"
             - "ocsp_signing"
             - "wireless_access_points"

            An example of a dotted number OID:

             - "1.3.6.1.5.5.7.3.1"

        :param extended_optional:
            A bool - if the extended_key_usage extension may be ommited and still
            considered valid

        :raises:
            pyhanko_certvalidator.errors.PathValidationError - when an error occurs validating the path
            pyhanko_certvalidator.errors.RevokedError - when the certificate or another certificate in its path has been revoked
            pyhanko_certvalidator.errors.InvalidCertificateError - when the certificate is not valid for the usages specified

        :return:
            A pyhanko_certvalidator.path.ValidationPath object of the validated
            certificate validation path
        """

        self._validate_path()
        validate_usage(
            self._context,
            self._certificate,
            key_usage,
            extended_key_usage,
            extended_optional
        )
        return self._path

    def validate_tls(self, hostname):
        """
        Validates the certificate path, that the certificate is valid for
        the hostname provided and that the certificate is valid for the purpose
        of a TLS connection.

        :param hostname:
            A unicode string of the TLS server hostname

        :raises:
            pyhanko_certvalidator.errors.PathValidationError - when an error occurs validating the path
            pyhanko_certvalidator.errors.RevokedError - when the certificate or another certificate in its path has been revoked
            pyhanko_certvalidator.errors.InvalidCertificateError - when the certificate is not valid for TLS or the hostname

        :return:
            A pyhanko_certvalidator.path.ValidationPath object of the validated
            certificate validation path
        """

        self._validate_path()
        validate_tls_hostname(self._context, self._certificate, hostname)
        return self._path
