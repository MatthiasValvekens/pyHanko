Known issues
============

This page lists some TODOs and known limitations of pyHanko.

* The most lenient document modification policy (i.e. addition of comments and
  annotations) is not supported.
  Comments added to a signed PDF will therefore be considered "unsafe" changes,
  regardless of the policy set by the signer.
* There is currently no explicit support for signing and stamping PDF/A and
  PDF/UA files. That is to say, pyHanko treats these as any other PDF file
  and will produce output that may not comply with the provisions of these
  standards. This doesn't mean that signing PDF/A (or PDF/UA) files in
  a compliant manner is impossible (in fact, generating a signature
  with an embedded font is often sufficient), but pyHanko itself
  will not attempt to enforce any additional restrictions.
  It is, however, a design goal of pyHanko to not unnecessarily break conformance
  with these standards when the API is used reasonably. When in doubt,
  feel free to start a thread
  on `the discussion forum <https://github.com/MatthiasValvekens/pyHanko/discussions>`_.
* The signature appearance generation code in pyHanko is quite primitive, since
  pyHanko's principal focus is on the signing process itself.
  If the appearance generation code behaves in ways you do not expect,
  or you have very specific layout requirements, have a look at
  :ref:`the section on static content stamps <static-content-stamps>`
  for some pointers on how to "outsource" the appearance generation process
  to more capable graphics toolkits.
* Several library features are only exposed in the CLI in limited ways.