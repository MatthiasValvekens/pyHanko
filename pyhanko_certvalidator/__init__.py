import asyncio
import warnings
from typing import Optional, Iterable

from asn1crypto import x509

from .context import ValidationContext, PKIXValidationParams
from .errors import ValidationError, PathBuildingError, InvalidCertificateError
from .validate import async_validate_path, validate_tls_hostname, validate_usage
from .version import __version__, __version_info__
from ._errors import pretty_message
from ._types import type_name


__all__ = [
    '__version__',
    '__version_info__',
    'CertificateValidator',
    'ValidationContext',
    'PKIXValidationParams'
]


class CertificateValidator:

    # A pyhanko_certvalidator.context.ValidationContext object
    _context = None

    # An asn1crypto.x509.Certificate object
    _certificate = None

    # A pyhanko_certvalidator.path.ValidationPath object - only set once validated
    _path = None

    # A pyhanko_certvalidator.context.PKIXValidationParams object
    _params = None

    def __init__(
            self,
            end_entity_cert: x509.Certificate,
            intermediate_certs: Optional[Iterable[x509.Certificate]] = None,
            validation_context: Optional[ValidationContext] = None,
            pkix_params: PKIXValidationParams = None):
        """
        :param end_entity_cert:
            An asn1crypto.x509.Certificate object X.509 end-entity
            certificate to validate

        :param intermediate_certs:
            None or a list of asn1crypto.x509.Certificate
            Used in constructing certificate paths for validation.

        :param validation_context:
            A pyhanko_certvalidator.context.ValidationContext() object that
            controls generic validation options and tracks revocation data.

            The same validation context will also be used in the validation
            of relevant certificates found in OCSP responses and/or CRLs.

        :param pkix_params:
            A pyhanko_certvalidator.context.PKIXValidationParams() object that
            controls advanced PKIX validation parameters used to validate
            the end-entity certificate. These can be used to constrain
            policy processing and names.

            Ancillary validation of CRLs and OCSP responses ignore these
            settings.
        """

        if validation_context is None:
            validation_context = ValidationContext()

        if intermediate_certs is not None:
            certificate_registry = validation_context.certificate_registry
            for intermediate_cert in intermediate_certs:
                certificate_registry.add_other_cert(intermediate_cert)

        self._context = validation_context
        self._certificate = end_entity_cert
        self._params = pkix_params

    async def _validate_path(self):
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
            paths = await self._context.certificate_registry.async_build_paths(
                self._certificate
            )
        except PathBuildingError:
            if self._certificate.self_signed in {'yes', 'maybe'}:
                raise InvalidCertificateError(pretty_message(
                    '''
                    The X.509 certificate provided is self-signed - "%s"
                    ''',
                    self._certificate.subject.human_friendly
                ))
            raise

        for candidate_path in paths:
            try:
                await async_validate_path(self._context, candidate_path, self._params)
                self._path = candidate_path
                return
            except ValidationError as e:
                exceptions.append(e)

        if len(exceptions) == 1:
            raise exceptions[0]

        non_signature_exception = None
        for exception in exceptions:
            if 'signature' not in str(exception):
                non_signature_exception = exception

        if non_signature_exception:
            raise non_signature_exception

        raise exceptions[0]

    def validate_usage(self, key_usage, extended_key_usage=None, extended_optional=False):
        """
        Validates the certificate path and that the certificate is valid for
        the key usage and extended key usage purposes specified.

        .. deprecated:: 0.17.0
            Use :meth:`async_validate_usage` instead.

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

        warnings.warn(
            "'validate_usage' is deprecated, use "
            "'async_validate_usage' instead",
            DeprecationWarning
        )

        return asyncio.run(
            self.async_validate_usage(
                key_usage, extended_key_usage, extended_optional
            )
        )

    async def async_validate_usage(self, key_usage, extended_key_usage=None,
                                   extended_optional=False):
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

        await self._validate_path()
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

        .. deprecated:: 0.17.0
            Use :meth:`async_validate_tls` instead.

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

        warnings.warn(
            "'validate_tls' is deprecated, use 'async_validate_tls' instead",
            DeprecationWarning
        )

        return asyncio.run(self.async_validate_tls(hostname))

    async def async_validate_tls(self, hostname):
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

        await self._validate_path()
        validate_tls_hostname(self._context, self._certificate, hostname)
        return self._path
