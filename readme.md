# certvalidator

A Python library for validating X.509 certificates or paths. Supports various
options, including: validation at a specific moment in time, whitelisting and
revocation checks.

 - [Features](#features)
 - [Related Crypto Libraries](#related-crypto-libraries)
 - [Current Release](#current-release)
 - [Dependencies](#dependencies)
 - [Installation](#installation)
 - [License](#license)
 - [Documentation](#documentation)
 - [Continuous Integration](#continuous-integration)
 - [Testing](#testing)
 - [Development](#development)

## Features

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

Unsupported features:
 
 - Name constraints

## Related Crypto Libraries

*certvalidator* is part of the modularcrypto family of Python packages:

 - [asn1crypto](https://github.com/wbond/asn1crypto)
 - [oscrypto](https://github.com/wbond/oscrypto)
 - [csrbuilder](https://github.com/wbond/csrbuilder)
 - [certbuilder](https://github.com/wbond/certbuilder)
 - [crlbuilder](https://github.com/wbond/crlbuilder)
 - [ocspbuilder](https://github.com/wbond/ocspbuilder)
 - [certvalidator](https://github.com/wbond/certvalidator)

## Current Release

0.11.0 - [changelog](changelog.md)

## Dependencies

 - *asn1crypto*
 - *oscrypto*
 - Python 2.6, 2.7, 3.2, 3.3, 3.4, 3.5, pypy or pypy3

## Installation

```bash
pip install certvalidator
```

## License

*certvalidator* is licensed under the terms of the MIT license. See the
[LICENSE](LICENSE) file for the exact license text.

## Documentation

[*certvalidator* documentation](docs/readme.md)

## Continuous Integration

 - [Windows](https://ci.appveyor.com/project/wbond/certvalidator/history) via AppVeyor
 - [OS X & Linux](https://travis-ci.org/wbond/certvalidator/builds) via Travis CI

## Testing

Tests are written using `unittest` and require no third-party packages:

```bash
python run.py tests
```

To run only some tests, pass a regular expression as a parameter to `tests`.

```bash
python run.py tests path
```

### Test Cases

The test cases for the library are comprised of:

 - [Public Key Interoperability Test Suite from NIST](http://csrc.nist.gov/groups/ST/crypto_apps_infra/pki/pkitesting.html)
 - [OCSP tests from OpenSSL](https://github.com/openssl/openssl/blob/master/test/recipes/80-test_ocsp.t)
 - Various certificates generated for TLS certificate validation

## Development

To install required development dependencies, execute:

```bash
pip install -r dev-requirements.txt
```

The following commands will run the linter and test coverage:

```bash
python run.py lint
python run.py coverage
```

The following will regenerate the API documentation:

```bash
python run.py api_docs
```

The following will run a test that connects to all (non-adult) sites in the
Alexa top 1000 that respond on port 443:

```bash
python run.py stress_test
```

Once the script is complete, results that differ between the OS validation and
the *certvalidator* validation will be listed for further debugging.

After creating a [semver](http://semver.org/) git tag, a `.tar.gz` and `.whl`
of the package can be created and uploaded to
[PyPi](https://pypi.python.org/pypi/certvalidator) by executing:

```bash
python run.py release
```
