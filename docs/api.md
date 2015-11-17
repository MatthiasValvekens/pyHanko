# *certvalidator* API Documentation

### `CertificateValidator()` class

> ##### constructor
>
> > ```python
> > def __init__(self, end_entity_cert, intermediate_certs=None, validation_context=None):
> >     """
> >     :param end_entity_cert:
> >         An asn1crypto.x509.Certificate object or a byte string of the DER or
> >         PEM-encoded X.509 end-entity certificate to validate
> >     
> >     :param intermediate_certs:
> >         None or a list of asn1crypto.x509.Certificate objects or a byte
> >         string of a DER or PEM-encoded X.509 certificate. Used in
> >         constructing certificate paths for validation.
> >     
> >     :param validation_context:
> >         A certvalidator.context.ValidationContext() object that controls
> >         validation options
> >     """
> > ```
>
> ##### `.validate_tls()` method
>
> > ```python
> > def validate_tls(self, hostname):
> >     """
> >     :param hostname:
> >         A unicode string of the TLS server hostname
> >     
> >     :raises:
> >         certvalidator.errors.PathValidationError - when an error occurs validating the path
> >         certvalidator.errors.RevokedError - when the certificate or another certificate in its path has been revoked
> >         certvalidator.errors.InvalidCertificateError - when the certificate is not valid for TLS or the hostname
> >     
> >     :return:
> >         A certvalidator.path.ValidationPath object of the validated
> >         certificate validation path
> >     """
> > ```
> >
> > Validates the certificate path, that the certificate is valid for
> > the hostname provided and that the certificate is valid for the purpose
> > of a TLS connection.
>
> ##### `.validate_usage()` method
>
> > ```python
> > def validate_usage(self, key_usage, extended_key_usage=None, extended_optional=False):
> >     """
> >     :param key_usage:
> >         A set of unicode strings of the required key usage purposes
> >     
> >     :param extended_key_usage:
> >         A set of unicode strings of the required extended key usage purposes
> >     
> >     :param extended_optional:
> >         A bool - if the extended_key_usage extension may be ommited and still
> >         considered valid
> >     
> >     :raises:
> >         certvalidator.errors.PathValidationError - when an error occurs validating the path
> >         certvalidator.errors.RevokedError - when the certificate or another certificate in its path has been revoked
> >         certvalidator.errors.InvalidCertificateError - when the certificate is not valid for the usages specified
> >     
> >     :return:
> >         A certvalidator.path.ValidationPath object of the validated
> >         certificate validation path
> >     """
> > ```
> >
> > Validates the certificate path and that the certificate is valid for
> > the key usage and extended key usage purposes specified.

### `ValidationContext()` class

> ##### constructor
>
> > ```python
> > def __init__(self, ca_certs=None, other_certs=None, whitelisted_certs=None,
> >              moment=None, allow_fetching=False, crls=None, crl_fetch_params=None,
> >              ocsps=None, ocsp_fetch_params=None, skip_revocation_checks=False,
> >              require_revocation_checks=False):
> >     """
> >     :param ca_certs:
> >         If the operating system's trust list should not be used, instead
> >         pass a list of byte strings containing DER or PEM-encoded X.509
> >         certificates, or a list of asn1crypto.x509.Certificate objects.
> >         These certificates will be used as the trust roots for the path
> >         being built.
> >     
> >     :param other_certs:
> >         A list of byte strings containing DER or PEM-encoded X.509
> >         certificates, or a list of asn1crypto.x509.Certificate objects.
> >         These other certs are usually provided by the service/item being
> >         validated. In SSL, these would be intermediate chain certs.
> >     
> >     :param whitelisted_certs:
> >         None or a list of byte strings or unicode strings of the SHA-1
> >         fingerprint of one or more certificates. The fingerprint is a hex
> >         encoding of the SHA-1 byte string, optionally separated into pairs
> >         by spaces or colons. These whilelisted certificates will not be
> >         checked for validity dates. If one of the certificates is an
> >         end-entity certificate in a certificate path, any TLS hostname
> >         mismatches, key usage errors or extended key usage errors will also
> >         be ignored.
> >     
> >     :param moment:
> >         If certificate validation should be performed based on a date and
> >         time other than right now. A datetime.datetime object with a tzinfo
> >         value. If this parameter is specified, then the only way to check
> >         OCSP and CRL responses is to pass them via the crls and ocsps
> >         parameters. Can not be combined with allow_fetching=True.
> >     
> >     :param crls:
> >         None or a list/tuple of asn1crypto.crl.CertificateList objects of
> >         pre-fetched/cached CRLs to be utilized during validation of paths
> >     
> >     :param crl_fetch_params:
> >         None or a dict of keyword args to pass to
> >         certvalidator.crl_client.fetch() when fetching CRLs or associated
> >         certificates. Only applicable when allow_fetching=True.
> >     
> >     :param ocsps:
> >         None or a list/tuple of asn1crypto.ocsp.OCSPResponse objects of
> >         pre-fetched/cached OCSP responses to be utilized during validation
> >         of paths
> >     
> >     :param ocsp_fetch_params:
> >         None or a dict of keyword args to pass to
> >         certvalidator.ocsp_client.fetch() when fetching OSCP responses.
> >         Only applicable when allow_fetching=True.
> >     
> >     :param allow_fetching:
> >         A bool - if HTTP requests should be made to fetch CRLs and OCSP
> >         responses. If this is True and certificates contain the location of
> >         a CRL or OCSP responder, an HTTP request will be made to obtain
> >         information for revocation checking.
> >     
> >     :param skip_revocation_checks:
> >         If CRL/OCSP revocation checks should be skipped. Can not be combined
> >         with require_revocation_checks.
> >     
> >     :param require_revocation_checks:
> >         If a valid CRL or OCSP response should be required for each
> >         certificate in a path, even if the certificate does not contain
> >         information on how to obtain said revocation information. Can not
> >         be combined with skip_revocation_checks.
> >     """
> > ```
>
> ##### `.crls` attribute
>
> > A list of all cached asn1crypto.crl.CertificateList objects
>
> ##### `.ocsps` attribute
>
> > A list of all cached asn1crypto.ocsp.OCSPResponse objects
>
> ##### `.new_revocation_certs` attribute
>
> > A list of newly-fetched asn1crypto.x509.Certificate objects that were
> > obtained from OCSP responses and CRLs
