# certvalidator Documentation

*certvalidator* is a Python library for validating X.509 certificates and paths.

The documentation consists of the following topics:

 - [Implementation Details](#implementation-details)
 - [Usage](usage.md)
 - [API Documentation](api.md)

## Implementation Details

*certvalidator* implements the following algorithms:

 - [X.509/CRL] [Certificate Path Validation algorithm from RFC 5280 Section 5](https://tools.ietf.org/html/rfc5280#section-6)
   - Minus name constraints
 - [OCSP] [Signed Response Acceptance Requirements from RFC 6960](https://tools.ietf.org/html/rfc6960#section-3.2)
 - [TLS] [DNS-ID and CN-ID Matching from RFC 6125](https://tools.ietf.org/html/rfc6125#section-6)

Supported features include:

 - X.509 path building
 - X.509 basic path validation
   - Signatures
     - RSA, DSA and EC algorithms
   - Name chaining
   - Validity dates
   - Basic constraints extension
     - CA flag
     - Path length constraint
   - Key usage extension
   - Extended key usage extension
   - Certificate policies
     - Policy constraints
     - Policy mapping
     - Inhibit anyPolicy
   - Failure on unknown/unsupported critical extensions
 - TLS/SSL server validation
 - Whitelisting certificates
 - Blacklisting hash algorithms
 - Revocation checks
   - CRLs
     - Indirect CRLs
     - Delta CRLs
   - OCSP checks
     - Delegated OCSP responders
   - Disable, require or allow soft failures
   - Caching of CRLs/OCSP responses
 - CRL and OCSP HTTP clients
 - Point-in-time validation

Currently unsupported features:
 
 - Name constraints

Testing is performed using:

 - [Public Key Interoperability Test Suite from NIST](http://csrc.nist.gov/groups/ST/crypto_apps_infra/pki/pkitesting.html)
 - [OCSP tests from OpenSSL](https://github.com/openssl/openssl/blob/master/test/recipes/80-test_ocsp.t)
 - Various certificates generated for TLS certificate validation
