Known issues
============

This page lists some TODOs and known limitations of pyHanko.

* Expand, polish and rigorously test the validation functionality.
  The test suite covers a variety of scenarios already, but the difference
  checker in particular is still far from perfect.
* The most lenient document modification policy (i.e. addition of comments and
  annotations) is not supported.
  Comments added to a signed PDF will therefore be considered "unsafe" changes,
  regardless of the policy set by the signer.
* For now, only signatures using the "RSA with PKCS#1 v1.5" mechanism and ECDSA
  are effectively supported.
  Expanding this to include the full gamut of what `oscrypto` supports is on the
  roadmap.
* There is currently no support for signing and stamping PDF/A and PDF/UA files.
  That is to say, pyHanko treats these as any other PDF file and will produce
  output that may not comply with the provisions of these standards.
* PKCS#11 support (esp. in the CLI) is limited to Belgian RSA-based cards,
  because my experience with (generic) PKCS#11 is very limited. Discussion
  and pull requests are certainly welcome, though!
