pdfstamp
--------
The lack of open-source CLI tooling to handle digitally signing and stamping PDF files was bothering me, so I went ahead and rolled my own.

### Overview
The code in this repository functions both as a library and as a command-line tool.
It's nowhere near complete, but here is a short overview of the features:

 - Invisible signatures (both certifying and non-certifying) should work.
 - Adding empty signature fields to existing PDFs is also possible.
 - Visible signatures are still a bit primitive.
 - Through fontTools, we have (experimental) support for auto-subsetting and embedding CFF fonts (more testing needed). These features are not available in the CLI as of yet.
 - Support for handling encrypted files has been added in, but is untested.
 - All operations on PDF files are executed in append-only mode, to minimise the risk of unintentional mangling. This is also necessary to provide support for adding multiple signatures to a given document.
 - The signer supports PKCS11 devices too. For Belgian eID cards, this has been integrated into the CLI.
 
 The CLI was implemented using `click`, so it comes with a built-in help function.
 Launch `python -m pdfstamp` to get started.


### Some TODOs and known limitations

 - The signing/stamping code currently only works on PDF files with a flat page tree (which fortunately covers the vast majority of real-life examples). For the signer, this is relatively easy to work around, but the resource dictionary handling logic in the stamper needs to be reworked a little to cover the general case.
 - Add validation functionality.
 - Add support for timestamping servers.
 - Add the stamping functionality the CLI.
 - Prevent the user from shooting themselves in the foot to some degree, by explicitly disallowing obviously destructive operations on signed documents.
 - Add systematic tests, both with real-world PDF files and minimal examples from the spec.

### Acknowledgement

This repository includes some code from `PyPDF2` (with modifications); the original license has been included [here](pdf_utils/LICENSE.PyPDF2).
