![pyHanko](docs/images/pyhanko-logo.svg)

![status](https://github.com/MatthiasValvekens/pyHanko/workflows/pytest/badge.svg)
![Codecov](https://img.shields.io/codecov/c/github/MatthiasValvekens/pyHanko)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/MatthiasValvekens/pyHanko.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/MatthiasValvekens/pyHanko/context:python)



The lack of open-source CLI tooling to handle digitally signing and stamping PDF files was bothering me, so I went ahead and rolled my own.

*Note:* The working title of this project (and former name of the repository on GitHub) was `pdf-stamp`, which might still linger in some references.

*Note:* This project is not yet production-ready, and is currently in a pre-alpha stage.

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
    - Support for multiple signatures (all modifications are executed using incremental updates to preserve
      cryptographic integrity)
    - PKCS11 support
        - Extra convenience wrapper for Belgian eID cards
 - Signature validation
    - Cryptographic integrity check
    - Authentication through X.509 chain of trust validation
    - LTV validation
    - Difference analysis on files with multiple signatures and/or incremental 
      updates made after signing (experimental)
    - Signature seed value constraint validation
 - Encryption
    - Only legacy RC4-based encryption is currently supported (based on what PyPDF2 offers).
      This should not be used for new files, since it has been broken for quite some time.
    - Modern AES-based PDF encryption is on the roadmap.
 - CLI & configuration
    - YAML-based configuration (optional for most features)
    - CLI based on `click` 
        - Available as `pyhanko` (when installed) or `python -m pyhanko` when running from
          the source directory
        - Built-in help: run `pyhanko --help` to get started


### Some TODOs and known limitations

 - Expand, polish and rigorously test the validation functionality. The test suite covers a variety
   of scenarios already, but the difference checker in particular is still far from perfect.
 - The most lenient document modification policy (i.e. addition of comments and annotations) is not supported. Comments added to a signed PDF will therefore be considered "unsafe" changes, regardless of the policy set by the signer.
 - For now, only signatures using the "RSA with PKCS#1 v1.5" mechanism are effectively supported.
   Expanding this to include the full gamut of what `oscrypto` supports is on the roadmap.
 - There is currently no support for signing and stamping PDF/A and PDF/UA files. That is to say, pyHanko treats these as any other PDF file and will produce output that may not comply with the provisions of these standards.
 
### Documentation

Documentation is built using Sphinx, and hosted [here](https://pyhanko.readthedocs.io/en/latest/)
on ReadTheDocs.

Given the fact that this project is still in pre-alpha, the documentation is still under construction.
Coverage for the API docs is fairly complete, but code examples, CLI documentation and configuration
examples are still lacking.


### Acknowledgement

This repository includes code from `PyPDF2` (with both minor and major modifications); the original license has been included [here](pyhanko/pdf_utils/LICENSE.PyPDF2).


## License

MIT License, see [LICENSE](LICENSE).
