# certvalidator

This library started as a fork of [wbond/certvalidator](https://github.com/wbond/certvalidator) with patches for [pyHanko](https://github.com/MatthiasValvekens/pyHanko), but has since diverged considerably from its parent repository.

GitHub issues are disabled on this repository. Bug reports regarding this library should be submitted to the [pyHanko issue tracker](https://github.com/MatthiasValvekens/pyHanko/issues).
Similarly, questions regarding this library's usage can be asked in the [pyHanko discussion forum](https://github.com/MatthiasValvekens/pyHanko/discussions).

`pyhanko-certvalidator` is a Python library for validating X.509 certificates paths. It supports various
options, including: validation at a specific moment in time, whitelisting and revocation checks.

 - [Features](#features)
 - [Current Release](#current-release)
 - [Installation](#installation)
 - [License](#license)
 - [Documentation](#documentation)
 - [Continuous Integration](#continuous-integration)
 - [Testing](#testing)


## Features

 - X.509 path building
 - X.509 basic path validation
   - Signatures
     - RSA (including PSS padding), DSA, ECDSA and EdDSA algorithms.
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
 - Name constraints
 - Attribute certificate support

## Current Release

![pypi](https://img.shields.io/pypi/v/pyhanko-certvalidator.svg)

## Dependencies

 - *asn1crypto*
 - *cryptography*
 - *uritools*
 - *oscrypto*
 - Python 3.10 or higher

Fetching validation data and certificates over the network is an opt-in feature
requiring additional dependencies.

 - `async-http` &mdash; *aiohttp* and *certifi*, the preferred backend
 - `requests` &mdash; *requests*, used as a fallback if *aiohttp* isn't installed

If both are available, `aiohttp` is used unless the caller specifies otherwise.

Note: `pyhanko` depends on `pyhanko-certvalidator[async-http]`, so this subtlety is only
relevant for those who use `pyhanko-certvalidator` as a standalone library without pyHanko.

 ### Note on compatibility

 Starting with `pyhanko-certvalidator` version `0.17.0`, the library has been refactored to use asynchronous I/O as much as possible. Most high-level API entrypoints can still be used synchronously, but have been deprecated in favour of their asyncio equivalents. 
 As part of this move, the OCSP and CRL clients now have two separate implementations: a `requests`-based one, and an `aiohttp`-based one. The latter is more performant and is preferred whenever it's installed; `requests` is used as a fallback.


## Installation

```bash
pip install pyhanko-certvalidator
```

To also install a backend for fetching revocation info and certificates over
the network:

```bash
pip install 'pyhanko-certvalidator[async-http]'
```

## License

*certvalidator* is licensed under the terms of the MIT license. See the
[LICENSE](LICENSE) file for the exact license text.



## Testing

### Test framework

Tests are written using `pytest` and require an asynchronous test case backend
such as `pytest-asyncio`.

### Test cases

The test cases for the library are comprised of:

 - [Public Key Interoperability Test Suite from NIST](http://csrc.nist.gov/groups/ST/crypto_apps_infra/pki/pkitesting.html)
 - [OCSP tests from OpenSSL](https://github.com/openssl/openssl/blob/master/test/recipes/80-test_ocsp.t)
 - Various certificates generated for bespoke X.509 certificate validation scenarios


Existing releases can be found at https://pypi.org/project/pyhanko-certvalidator.
