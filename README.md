pdfstamp
--------
![status](https://github.com/MatthiasValvekens/pdf-stamp/workflows/pytest/badge.svg)
![Codecov](https://img.shields.io/codecov/c/github/MatthiasValvekens/pdf-stamp)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/MatthiasValvekens/pdf-stamp.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/MatthiasValvekens/pdf-stamp/context:python)



The lack of open-source CLI tooling to handle digitally signing and stamping PDF files was bothering me, so I went ahead and rolled my own.

### Overview
The code in this repository functions both as a library and as a command-line tool.
It's nowhere near complete, but here is a short overview of the features:

 - Invisible signatures (both certifying and non-certifying) should work.
 - Adding empty signature fields to existing PDFs is also possible.
 - Visible signatures are still a bit primitive.
 - Through fontTools, we have (experimental) support for auto-subsetting and embedding CFF fonts (more testing needed). These features are not available in the CLI as of yet.
 - All operations on PDF files are executed in append-only mode, to minimise the risk of unintentional mangling. This is also necessary to provide support for adding multiple signatures to a given document.
 - The signer supports PKCS11 devices too. For Belgian eID cards, this has been integrated into the CLI.
 - Through the CLI, it is possible to syntactically and cryptographically verify the validity of a signature. This means that it is possible to verify whether or not a signature is intact, cryptographically sound and whether it covers the entire document. However, the semantics are not checked (see below).
 - There is limited support for encrypted files, based on what is available in PyPDF2 (i.e. rudimentary RC4-based encryption)
 - The signer can request and embed timestamps from RFC 3161-compliant Time Stamping Authorities. The degree to which this feature is exposed in the CLI is limited: only TSA's that don't require authentication can be used.
 
 The CLI was implemented using `click`, so it comes with a built-in help function.
 Launch `python -m pdfstamp` to get started.


### Some TODOs and known limitations

 - Expand signature validation functionality. In case the document has been modified through incremental updates, we should judge whether these changes are allowed by the signature's document modification protection policy.
 - Prevent the user from shooting themselves in the foot to some degree, by explicitly disallowing obviously destructive operations on signed documents.
 - Add systematic tests, both with real-world PDF files and minimal examples from the spec.

### Acknowledgement

This repository includes code from `PyPDF2` (with both minor and major modifications); the original license has been included [here](pdf_utils/LICENSE.PyPDF2).
