# *certvalidator* Usage

 - [Basic Path Validation](#basic-path-validation)
 - [TLS/SSL Server Validation](#tlsssl-server-validation)
 - [Advanced Features](#advanced-features)
   - [Whitelisting Certificates](#whitelisting-certificates)
   - [Revocation Checking](#revocation-checking)
   - [Custom Trust Roots/CA Certs](#custom-trust-roots-ca-certs)
   - [Moment-In-Time Validation](#moment-in-time-validation)

## Basic Path Validation

Basic path validation is peformed using the `CertificateValidator()` class. The
only required parameter for the class is the `end_entity_cert`, which must be
a byte string of a DER or PEM-encoded X.509 certificate, or an instance of
`asn1crypto.x509.Certificate`.

```python
from certvalidator import CertificateValidator


with open('/path/to/cert.crt', 'rb') as f:
    end_entity_cert = f.read()

validator = CertificateValidator(end_entity_cert)
```

Any intermediate certificates required for validation can be provided as a
`list` via the second parameter `intermediate_certs`. Each element in the list
should also be a byte string of a DER or PEM-encoded X.509 certificate, or an
instance of `asn1crypto.x509.Certificate`.

```python
from asn1crypto import pem
from certvalidator import CertificateValidator


end_entity_cert = None
intermediates = []
with open('/path/to/cert_chain.pem', 'rb') as f:
    for type_name, headers, der_bytes in pem.unarmor(f.read(), multiple=True):
        if end_entity_cert is None:
            end_entity_cert = der_bytes
        else:
            intermediates.append(der_bytes)

validator = CertificateValidator(end_entity_cert, intermediates)
```

Once the `CertificateValidator()` object has been constructed, the method
`.validate_usage()` is called to build a valid path and verify key usage for
the end-entity certificate. The first parameter is a `set` of required key
usage purposes required for the certificate to be valid. If an error occurs
trying to build a path or check the key usage, a
`certvalidator.errors.PathValidationError` exception will be raised.

```python
from certvalidator import CertificateValidator, errors


with open('/path/to/cert.crt', 'rb') as f:
    end_entity_cert = f.read()

try:
    validator = CertificateValidator(end_entity_cert)
    validator.validate_usage(set(['digital_signature']))
except (errors.PathValidationError):
    # The certificate could not be validated
```

The list of valid key usages can be found in the
[`CertificateValidator.validate_usage()`](api.md#validate_usage-method)
documentation.

To check extended key usage, the second parameter, `extended_key_usage` may be
passed containing a `set` of extended key usage purposes. Any pre-defined name
from the [`CertificateValidator.validate_usage()`](api.md#validate_usage-method)
documentation may be passed, or any dotted number OID string. If extended key
usage should only be checked if the extension is present, pass `True` to the
third parameter, `extended_optional`.

```python
from certvalidator import CertificateValidator, errors


with open('/path/to/cert.crt', 'rb') as f:
    end_entity_cert = f.read()

try:
    validator = CertificateValidator(end_entity_cert)
    validator.validate_usage(
        set(['digital_signature']),
        set(['server_auth']),
        True
    )
except (errors.PathValidationError):
    # The certificate could not be validated
```

## TLS/SSL Server Validation

To validate a certificate chain from a TLS server, the `.validate_tls()` method
may be used. The method takes a single parameter, `hostname`, which must be a
unicode string of the server hostname. *Appropriate key usage and extended
key usage parameters are automatically checked.*

```python
from oscrypto import tls
from certvalidator import CertificateValidator, errors

session = tls.TLSSession(manual_validation=True)
connection = tls.TLSSocket('www.google.com', 443, session=session)

try:
    validator = CertificateValidator(connection.certificate, connection.intermediates)
    validator.validate_tls(connection.hostname)
except (errors.PathValidationError):
    # The certificate did not match the hostname, or could not be otherwise validated
```

## Advanced Features

Beyond basic path validation and TLS server validation, `CertificateValidator()`
allows control of different aspects of the validation via the
`ValidationContext()` object. This object is passed via the `validation_context`
keyword parameter to the `CertificateValidator()`.

 - [Whitelisting Certificates](#whitelisting-certificates)
 - [Revocation Checking](#revocation-checking)
 - [Custom Trust Roots/CA Certs](#custom-trust-roots-ca-certs)
 - [Moment-In-Time Validation](#moment-in-time-validation)

### Whitelisting Certificates

In the event that a service provider has provisioned a certificate containing
a hostname mismatch, or a certificate that has expired, it may be necessary to
ignore such errors using a whitelist.

Whitelisting a certificate will skip all expiration date checks, whether the
certificate is an intermediate or an end-entity certificate. Additionally, for
end-entity certificates, TLS hostname, key usage and extended key usage checks
will be skipped. All other aspects of path validation will be performed.

Certificates are identifier by the SHA-1 fingerprint of the certificate. The
fingerprint must be a unicode string of the hex encoded bytes. The letters may
be upper or lower case, and may be separated by a space, colon or nothing.
Example formats:

 - `"A2 DC AB 7C 7B CF E4 67 0A 61 2D 89 E2 9F DF 61 D0 B1 8F 77"`
 - `"A2:DC:AB:7C:7B:CF:E4:67:0A:61:2D:89:E2:9F:DF:61:D0:B1:8F:77"`
 - `"a2:dc:ab:7c:7b:cf:e4:67:0a:61:2d:89:e2:9f:df:61:d0:b1:8f:77"`
 - `"A2DCAB7C7BCFE4670A612D89E29FDF61D0B18F77"`

Fingerprints may be obtained from most web browser certificate dialog boxes,
the `asn1crypto.x509.Certificate().sha1_fingerprint` attribute, or from the
OpenSSL command line:

```bash
openssl s_client -connect example.com:443 </dev/null 2>/dev/null | openssl x509 -fingerprint
```

Typically when user interaction is involved, displaying the `.sha1_fingerprint`
attribute of the `asn1crypto.x509.Certificate()` causing the error will be the
most useful method.

```python
from certvalidator import CertificateValidator, ValidationContext

with open('/path/to/cert.crt', 'rb') as f:
    end_entity_cert = f.read()

whitelist = [
     end_entity_cert.sha1_fingerprint,
]
context = ValidationContext(whitelisted_certs=whitelist)
validator = CertificateValidator(end_entity_cert, validation_context=context)
```

### Revocation Checking

By default, `CertificateValidator()` does not perform revocation checking via
CRL or OCSP. This is consistent with many modern browsers, such as Google Chrome
and Safari on OS X.

When revocation checks are desired, they are configured via the
`ValidationContext()`. It is possible to provide CRLs and OCSP responses that
have been fetched out-of-band, or allow the *certvalidator* package to fetch
them itself.

#### Allow Fetching

To allow the fetching of CRLs or OCSP responses, the `allow_fetching` parameter
of `ValidationContext()` must be `True`.

```python
from certvalidator import CertificateValidator, ValidationContext

with open('/path/to/cert.crt', 'rb') as f:
    end_entity_cert = f.read()

context = ValidationContext(allow_fetching=True)
validator = CertificateValidator(end_entity_cert, validation_context=context)
```

With this configuration, any CRLs or OCSP responders listed in the end-entity
certificate or any intermediate certificates will be fetching via HTTP. *Please
note that the default revocation mode is `soft-fail`. If there is no revocation
information, the information can not be fetched, or does not match the
certificate in question, it will not be used.*

If there is the desire to customize the timeout or user agent for the fetchers,
please use the `crl_fetch_params` and `ocsp_fetch_params` keyword parameters.

#### Out-of-Band Sources

If CRLs or OCSP responses are fetched via another mechanism, they can be
provided via the `crls` and `ocsps` keyword parameters of the constructor. The
`crls` parameter should be a list of byte strings containing the DER-encoded
CRLs, or `asn1crypto.crl.CertificateList` objects. The `ocsps` parameter should
be a list of byte strings containing the DER-encoded OCSP responses, or
`asn1crypto.ocsp.OCSPResponse` objects.

```python
from certvalidator import CertificateValidator, ValidationContext

with open('/path/to/cert.crt', 'rb') as f:
    end_entity_cert = f.read()

crls = []
with open('/path/to/root_crl.der', 'rb') as f:
    crls.append(f.read())

ocsps = []
with open('/path/to/end_entity_ocsp_response.der', 'rb') as f:
    ocsps.append(f.read())

context = ValidationContext(crls=crls, ocsps=ocsps)
validator = CertificateValidator(end_entity_cert, validation_context=context)
```

*Please note that providing revocation information does allow soft failures
unless the . If
there is no revocation information or does not match the certificate in
question, it will not be used.*

#### Setting the Revocation Mode

In the case that `soft-fail` is not the desired mode of operation, it is
possible to change the revocation mode into one of two other modes:

 - `hard-fail`
 - `require`

In `hard-fail` mode, any error in checking revocation is considered a failure.
However, if there is no known source of revocation information, it is not
considered a failure.

In `require` mode, any error in checking revocation is considered a failure. In
addition, all certificates must have revocation information, otherwise it is
considered a path validation failure.

The `revocation_mode` keyword parameter of `ValidationContext()` accepts a
unicode string of: `"soft-fail"`, `"hard-fail"` or `"require"`.

```python
from __future__ import unicode_literals
from certvalidator import CertificateValidator, ValidationContext

with open('/path/to/cert.crt', 'rb') as f:
    end_entity_cert = f.read()

context = ValidationContext(allow_fetching=True, revocation_mode="hard-fail")
validator = CertificateValidator(end_entity_cert, validation_context=context)
```

#### Certificates for Revocation Information

If extra certificates are required to validate CRLs or OCSP responses, they may
be provided via the `other_certs` keyword parameter of the `ValidationContext()`
object.

When `allow_fetching` is `True`, the fetchers will download any necessary
certificates referenced in the CRLs or OCSP responses. Thus, the `other_certs`
parameter is primarily useful when passing out-of-band revocation information
via the `crls` and `ocsps` parameters.

The certificates should be byte strings of DER or PEM-encoded X.509
certificates, or `asn1crypto.x509.Certificate` objects.

```python
from certvalidator import CertificateValidator, ValidationContext

with open('/path/to/cert.crt', 'rb') as f:
    end_entity_cert = f.read()

crls = []
with open('/path/to/root_crl.der', 'rb') as f:
    crls.append(f.read())

ocsps = []
with open('/path/to/end_entity_ocsp_response.der', 'rb') as f:
    ocsps.append(f.read())

other_certs = []
with open('/path/to/ocsp_responder_cert.crt', 'rb') as f:
    other_certs.append(f.read())

context = ValidationContext(crls=crls, ocsps=ocsps, other_certs=other_certs)
validator = CertificateValidator(end_entity_cert, validation_context=context)
```

### Custom Trust Roots/CA Certs

By default, *certvalidator* uses the trust roots provided by the operating
system to build a validation path.

To use a custom list, provide a list of byte strings containing DER or
PEM-encoded X.509 certificates or `asn1crypto.x509.Certificate` objects to the
`trust_roots` keyword parameter of `ValidationContext()`.

```python
from asn1crypto import pem
from certvalidator import CertificateValidator, ValidationContext

trust_roots = []
with open('/path/to/ca_certs.bundle', 'rb') as f:
    for _, _, der_bytes in pem.unarmor(f.read(), multiple=True):
        trust_roots.append(der_bytes)

with open('/path/to/cert.crt', 'rb') as f:
    end_entity_cert = f.read()

context = ValidationContext(trust_roots=trust_roots)
validator = CertificateValidator(end_entity_cert, validation_context=context)
```

To simply add one or more extra trust roots, pass the list to the
`extra_trust_roots` keyword parameter.

```python
from asn1crypto import pem
from certvalidator import CertificateValidator, ValidationContext

extra_trust_roots = []
with open('/path/to/extra_ca_certs.bundle', 'rb') as f:
    for _, _, der_bytes in pem.unarmor(f.read(), multiple=True):
        extra_trust_roots.append(der_bytes)

with open('/path/to/cert.crt', 'rb') as f:
    end_entity_cert = f.read()

context = ValidationContext(extra_trust_roots=extra_trust_roots)
validator = CertificateValidator(end_entity_cert, validation_context=context)
```

### Moment-In-Time Validation

Unless otherwise configured, `CertificateValidator()` uses the current UTC
date and time for certificate validation. To use a time in the past, a
`datetime.datetime` object with a `tzinfo` attribute must be passed to the
`moment` keyword parameter of `CertificateValidator()`.

The [pytz](http://pytz.sourceforge.net) package may be useful in constructing
a `datetime` object in a specific timezone. If the `datetime` will be in the
UTC timezone, `asn1crypto.util.timezone.utc` can be used.

```python
from datetime import datetime
from asn1crypto.util import timezone
from certvalidator import CertificateValidator, ValidationContext

with open('/path/to/cert.crt', 'rb') as f:
    end_entity_cert = f.read()

validation_time = datetime(2012, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
context = ValidationContext(moment=validation_time)
validator = CertificateValidator(end_entity_cert, validation_context=context)
```

If moment-in-time validation is being performed, the `allow_fetching` option
can not be used. Instead, any revocation CRLs or OCSP responses should be
provided via the `crls` or `ocsps` parameters.
