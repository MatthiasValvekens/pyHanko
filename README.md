![pyHanko](docs/images/pyhanko-logo.svg)

![status](https://github.com/MatthiasValvekens/pyHanko/workflows/pytest/badge.svg)
![Codecov](https://img.shields.io/codecov/c/github/MatthiasValvekens/pyHanko)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/MatthiasValvekens/pyHanko.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/MatthiasValvekens/pyHanko/context:python)
![pypi](https://img.shields.io/pypi/v/pyHanko.svg)



The lack of open-source CLI tooling to handle digitally signing and stamping PDF files was bothering me, so I went ahead and rolled my own.

*Note:* The working title of this project (and former name of the repository on GitHub) was `pdf-stamp`, which might still linger in some references.

*Note:* This project is currently in alpha, and not yet production-ready.

### Installing

PyHanko is hosted on [PyPI](https://pypi.org/project/pyHanko/),
and can be installed using `pip`:

```bash
   pip install 'pyHanko[pkcs11,image-support]'
```

This `pip` invocation includes the optional dependencies required for PKCS#11 and image support.


### Overview
The code in this repository functions both as a library and as a command-line tool.
It's nowhere near complete, but here is a short overview of the features.
Note that not all of these are necessarily exposed through the CLI.

 - Stamping
    - Simple text-based stamps
    - QR stamps
    - Font can be monospaced, or embedded from an OTF font (experimental)
 - Document preparation 
    - Add empty signature fields to existing PDFs
    - Add seed values to signature fields, with or without constraints
 - Signing
    - Signatures can be invisible, or with an appearance based on the stamping tools
    - LTV-enabled signatures are supported
        - PAdES baseline profiles B-B, B-T, B-LT and B-LTA are all supported.
        - Adobe-style revocation info embedding is also supported.
    - RFC 3161 timestamp server support
    - Support for multiple signatures (all modifications are executed using incremental updates to 
      preserve cryptographic integrity)
    - Supports both RSA & ECDSA
      - RSA padding modes: PKCS#1 v1.5 and RSASSA-PSS
      - ECDSA curves: anything supported by the `cryptography` library, 
        see [here](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/#elliptic-curves).
    - PKCS11 support
        - Available both from the library and through the CLI
        - Extra convenience wrapper for Belgian eID cards
 - Signature validation
    - Cryptographic integrity check
    - Authentication through X.509 chain of trust validation
    - LTV validation
    - Difference analysis on files with multiple signatures and/or incremental 
      updates made after signing (experimental)
    - Signature seed value constraint validation
 - Encryption
    - All encryption methods in PDF 2.0 are supported.
 - CLI & configuration
    - YAML-based configuration (optional for most features)
    - CLI based on `click` 
        - Available as `pyhanko` (when installed) or `python -m pyhanko` when running from
          the source directory
        - Built-in help: run `pyhanko --help` to get started


### Some TODOs and known limitations

See the [known issues](https://pyhanko.readthedocs.io/en/latest/known-issues.html)
page in the documentation.
 

### Documentation

Documentation is built using Sphinx, and hosted [here](https://pyhanko.readthedocs.io/en/latest/)
on ReadTheDocs.


### Acknowledgement

This repository includes code from `PyPDF2` (with both minor and major modifications); the original license has been included [here](pyhanko/pdf_utils/LICENSE.PyPDF2).


## License

MIT License, see [LICENSE](LICENSE).
