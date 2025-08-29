Known issues
============

This page lists some TODOs and known limitations of pyHanko.

* LTV validation was implemented ad-hoc, and does not fully adhere to
  the PAdES specification. This will require some effort to implement correctly.
  In the meantime, you should treat the result as a pyHanko-specific
  interpretation of the validity of the chain of trust based on the validation
  info present in the file, not as a final judgment on whether the signature
  complies with any particular PAdES profile.

  .. note::
    Starting from version ``0.17.0``, pyHanko ships with an experimental
    implementation of AdES validation according to ETSI EN 319 102-1.
    Relevant entry points can be found in :mod:`pyhanko.sign.validation.ades`.
    Note that the API is currently incubating, and the implementation is still
    incomplete in several respects.

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
* The signature appearance generation code in pyHanko is quite primitive, since
  pyHanko's principal focus is on the signing process itself.
  If the appearance generation code behaves in ways you do not expect,
  or you have very specific layout requirements, have a look at
  :ref:`the section on static content stamps <static-content-stamps>`
  for some pointers on how to "outsource" the appearance generation process
  to more capable graphics toolkits.
* Several library features are only exposed in the CLI in limited ways.