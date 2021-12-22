# changelog

## 0.19.2

 - Patch `asn1crypto` to work around tagging issue in AC issuer field

## 0.19.1

 - Properly enforce algo matching in AC validation

## 0.19.0

 - Attribute certificate validation support
 - Support for `AAControls` extension
 - Refactored OCSP and CRL logic to work with attribute certificate validation
 - Many nominal type checks removed in favour of type annotations
 - Many API entry points now accept both `asn1crypto.x509.Certificate` and `asn1crypto.cms.AttributeCertificateV2`
 - Minor breaking change: `bytes` is no longer acceptable as a substitute for `asn1crypto.x509.Certificate` in the public API


## 0.18.1

 - Various improvements to error handling in certificate fetchers

## 0.18.0

 - Replace `revocation_mode` with more flexible revocation policy controls,
   aligned with ETSI TS 119 172. Old `revocation_mode` params will be transparently
   translated to corresponding 'refined' policies, but the `revocation_mode` property
   on `ValidationContext` was removed.
 - Handle soft fails as part of revocation policies. Concretely, this means that the
   `SoftFailError` exception type was removed. Exceptions arising from quashed
   'soft' failures can still be retrieved via the `soft_fail_exceptions` property
   on `ValidationContext` instances; the resulting list can contain any exception type.
 - Fix various hiccups in CRL and OCSP handling.


## 0.17.4

 - Fix mistaken assumption when a certificate's MIME type is announced as `application/x-x509-ca-cert`.
 - Update aiohttp to 3.8.0

## 0.17.3

 - Fix a deadlocking bug caused by improper exception handling
   in the fetcher code.
 - Exceptions are now communicated to fetch jobs waiting for results.

## 0.17.2

 - Replace `run_until_complete()` with `asyncio.run()` for better
   event loop state management.

## 0.17.1

 - Fixes a packaging error in `0.17.0`

## 0.17.0

**!!Compatibility note!!**

**This release contains breaking changes in lower-level APIs.**
High-level API functions should continue to work as-is, although some have been deprecated.
However, the rewrite of the CRL & OCSP fetch logic breaks compatibility with the previous
version's API.

 - Refactor OCSP/certificate/CRL fetch logic to be more modular and swappable.
 - Automatically fetch missing issuer certificates if there is an AIA record indicating where to
   find them
 - Favour asynchronous I/O throughout the API. `CertificateValidator.validate_usage`,
   `CertificateValidator.validate_tls` and the `ValidationContext.retrieve_XYZ` methods were
   deprecated in favour of their asynchronous equivalents.
 - Support two backends for fetching revocation information and certificates: `requests` (legacy)
   and `aiohttp` (via the `async_http` optional dependency group).
   - It is expected that using `aiohttp` fetchers will yield better performance with the
     asynchronous APIs, but as these require some resource management on the caller's part,
     `requests` is still the default.
   - Fetcher backends can be swapped out by means of the `fetcher_backend` argument to
     `ValidationContext`.

## 0.16.0

 - Refactor CertificateRegistry
 - Change OCSP responder cert selection procedure to give priority to certificates embedded into
   the response data (if there are any).

## 0.15.3

 - Short-circuit anyPolicy when reporting policies
 - Export PKIXValidationParams
 - Limit CRL client to HTTP-based URLs

## 0.15.2

 - Properly handle missing Content-Type header in server response when fetching CA certificates
   referenced in a CRL.

## 0.15.1

 - Gracefully handle lack of thisUpdate / nextUpdate in OCSP responses.

## 0.15.0

 - Use `pyca/cryptography` for signature validation. `oscrypto` is still included to access the system trust list.
 - Support RSASSA-PSS and EdDSA certificates.
 - Support name constraints.
 - Support all input parameters to the PKIX validation algorithm (acceptable policy set, policy mapping inhibition, ...).
 - Further increase PKITS coverage.

## 0.14.1

 - No code changes, rerelease because distribution package was polluted due to improper build
   cache cleanup.

## 0.14.0

 - Raise RequestError if CRL / OCSP client returns a status code other than 200.
   Previously, this would fail with a cryptic ASN.1 deserialisation error instead.
 - Rename Python package to `pyhanko_certvalidator` to avoid the potential name conflict
   with the upstream `certvalidator` package.

## 0.13.1
 - Consider SHA-1 weak by default, and do not hard-code the list of potential weak hash algos.

## 0.13.0
 - Added an optional `retroactive_revinfo` flag to `ValidationContext` to ignore the
   `thisUpdate` field in OCSP responses and CRLs. 
   The effect of this is that CRLs and OCSP responses are also considered valid
   for point-in-time validation with respect to a time in the past.
   This is useful for some validation profiles. The default state of the flag
   remains `False` nonetheless.

## 0.12.1
 - Fixed a packaging error.

## 0.12.0
 - Forked from [certvalidator](https://github.com/wbond/certvalidator)
   to add patches for [pyHanko](https://github.com/MatthiasValvekens/pyHanko).
 - Replaced urllib calls with `requests` library for universal mocking.
 - Added a `time_tolerance` parameter to the validation context to allow for
   some time drift on CRLs and OCSP responses.
 - Deal with no-matches on OCSP and CRLs strictly in hard-fail mode.
 - Drop support for Python 2, and all Python 3 versions prior to 3.7.
   It is likely that the code still runs on older Python 3 versions, but I have
   no interest in maintaining support for those.

## 0.11.1

 - Updated [asn1crypto](https://github.com/wbond/asn1crypto) dependency to
   `0.18.1`, [oscrypto](https://github.com/wbond/oscrypto) dependency to
   `0.16.1`.

## 0.11.0

 - Updated for compatibility with oscrypto 0.16.0

## 0.10.0

 - Backwards compability break: the `require_revocation_checks` parameter was
   removed and a new keyword parameter, `revocation_mode`, was added to
   `ValidationContext()`. Validation may now be in a `soft-fail` (default),
   `hard-fail`, or `require` mode. See the documentation for information about
   the behavior of each mode.
 - Added certificate signature hash algorithm checks, with a default blacklist
   of `md2` and `md5`
 - Trust roots no longer need to be self-signed, allowing for cross-signed roots
 - Keys with no `key_usage` extension are now permitted to sign CRLs
 - An OCSP or CRL check may fail and not result in an error if the other is
   successful
 - Exceptions for expired or not-yet-valid certificates now include full date
   and time
 - Self-signed certificates now have a unique exception message instead of a
   generic message indicating the issuer could not be found in the trust roots
 - `crl_client` can now handle CRLs that are PEM-encoded
 - Fixed encoding of URLs in Python 2 when fetching CRLs and OCSP responses
 - Corrected an error when trying to check the signature of a certificate to
   determine if it is self-signed or not
 - Fixed a bug with duplicate HTTP headers during OCSP requests on Python 3
 - Fixed an exception that would be thrown if a signature not using RSA, DSA or
   ECDSA is found

## 0.9.1

 - Fixed a bug with whitelisting certificates on Python 3.2

## 0.9.0

 - Initial release
