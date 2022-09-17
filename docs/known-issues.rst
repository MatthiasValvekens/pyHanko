Known issues
============

This page lists some TODOs and known limitations of pyHanko.

* Expand, polish and rigorously test the validation functionality.
  The test suite covers a variety of scenarios already, but the difference
  checker in particular is still far from perfect.
* LTV validation was implemented ad-hoc, and likely does not fully adhere to
  the PAdES specification. This will require some effort to implement correctly.
  In the meantime, you should treat the result as a pyHanko-specific
  interpretation of the validity of the chain of trust based on the validation
  info present in the file, not as a final judgment on whether the signature
  complies with any particular PAdES profile.
* The most lenient document modification policy (i.e. addition of comments and
  annotations) is not supported.
  Comments added to a signed PDF will therefore be considered "unsafe" changes,
  regardless of the policy set by the signer.
* There is currently no explicit support for signing and stamping PDF/A and
  PDF/UA files. That is to say, pyHanko treats these as any other PDF file
  and will produce output that may not comply with the provisions of these
  standards. As of ``0.14.0``, it is possible to generate compliant output
  using pyHanko in most cases, but pyHanko itself will not attempt to enforce
  any additional restrictions.
* CLI support for signing files encrypted using PDF's public-key encryption
  functionality is limited.