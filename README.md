pdf-stamp
--------
![status](https://github.com/MatthiasValvekens/pdf-stamp/workflows/pytest/badge.svg)
![Codecov](https://img.shields.io/codecov/c/github/MatthiasValvekens/pdf-stamp)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/MatthiasValvekens/pdf-stamp.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/MatthiasValvekens/pdf-stamp/context:python)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FMatthiasValvekens%2Fpdf-stamp.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2FMatthiasValvekens%2Fpdf-stamp?ref=badge_shield)



The lack of open-source CLI tooling to handle digitally signing and stamping PDF files was bothering me, so I went ahead and rolled my own.

### Overview
The code in this repository functions both as a library and as a command-line tool.
It's nowhere near complete, but here is a short overview of the features:

 - Invisible signatures (both certifying and non-certifying) should work.
 - Adding empty signature fields to existing PDFs is also possible.
 - Visible signatures are still a bit primitive, and include only basic information about the signature in a simple monospace font.
 - Through fontTools, we have (experimental) support for auto-subsetting and embedding CFF fonts (more testing needed). These features are not available in the CLI as of yet.
 - The tool can (optionally) generate LTV-enabled signatures. The revocation information for the chain of trust can be embedded PAdES-style or Adobe-style.
 - The tool offers support for PDF signature seed values when creating, filling and validating signature fields---although not all configurations have been implemented as of yet.
 - There is support for field locking.
 - All operations on PDF files are executed in append-only mode, to minimise the risk of unintentional mangling. This is also necessary to provide support for adding multiple signatures to a given document.
 - The signer supports PKCS11 devices too. For Belgian eID cards, this has been integrated into the CLI.
 - Through the CLI, it is possible to syntactically and cryptographically verify the validity of a signature. This means that it is possible to verify whether or not a signature is intact, cryptographically sound and whether it covers the entire document. However, the semantics are not yet fully checked (see below).
 - There is limited support for encrypted files, based on what is available in PyPDF2 (i.e. rudimentary RC4-based encryption)
 - The signer can request and embed timestamps from RFC 3161-compliant Time Stamping Authorities. The degree to which this feature is exposed in the CLI is limited: only TSAs that don't require authentication can be used.
 - The tool is also capable of validating PDF signatures, including the following criteria:
    - Cryptographic validity
    - Coverage (i.e. whether the signature covers the entire file)
    - Chain of trust (for the signer and any timestamps, if present)
    - Modification vetting: if the file was updated through incremental updates, the validator will attempt to (conservatively) judge whether or not the modifications made are permissible, taking into account the document/field modification policy of any signatures present.
    - LTV validation (note: the PAdES B-LT baseline profile is supported, but PAdES B-LTA isn't available yet)
 
 The CLI was implemented using `click`, so it comes with a built-in help function.
 Launch `python -m pdfstamp` to get started.


### Some TODOs and known limitations

 - Expand, polish and rigorously test the validation functionality. The test suite covers a variety of scenarios already, but obviously one can't cover everything.
 - The most lenient document modification policy (i.e. addition of comments and annotations) is not supported. Comments added to a signed PDF will therefore be considered "unsafe" changes, regardless of the policy set by the signer.
 - Improve image support, which is extremely limited right now.

### Acknowledgement

This repository includes code from `PyPDF2` (with both minor and major modifications); the original license has been included [here](pdf_utils/LICENSE.PyPDF2).


## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FMatthiasValvekens%2Fpdf-stamp.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2FMatthiasValvekens%2Fpdf-stamp?ref=badge_large)