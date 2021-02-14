***************
Release history
***************

0.4.0
=====

*Release date:* 2021-02-14


New features and enhancements
-----------------------------

Encryption
^^^^^^^^^^

* Expose permission flags outside security handler
* Make file encryption key straightforward to grab

Signing
^^^^^^^

* Mildly refactor `PdfSignedData` for non-signing uses
* Make DSS API more flexible
   * Allow direct input of cert/ocsp/CRL objects as opposed to only certvalidator output
   * Allow input to not be associated with any concrete VRI.
* Greatly improved PKCS#11 support
   * Added support for RSASSA-PSS and ECDSA.
   * Added tests for RSA functionality using SoftHSMv2.
   * Added a command to the CLI for generic PKCS#11.
   * *Note:* Tests don't run in CI, and ECDSA is not included in the test suite yet (SoftHSMv2 doesn't seem to expose all the necessary mechanisms).
* Factor out `unsigned_attrs` in signer, added a `digest_algorithm` parameter to `signed_attrs`.
* Allow signing with any `BasePdfFileWriter` (in particular, this allows creating signatures in the initial revision of a PDF file)
* Add `CMSAlgorithmProtection` attribute when possible
  * *Note:* Not added to PAdES signatures for the time being.
* Improved support for deep fields in the form hierarchy (arguably orthogonal to the standard, but it doesn't hurt to be flexible)


Validation
^^^^^^^^^^

* Path handling improvements:
   * Paths in the structure tree are also simplified.
   * Paths can be resolved relative to objects in a file.
* Limited support for tagged PDF in the validator.
   * Existing form fields can be filled in without tripping up the modification analysis module.
   * Adding new form fields to the structure tree after signing is not allowed for the time being.
* Internal refactoring in CMS validation logic:
   * Isolate cryptographic integrity validation from trust validation
   * Rename `externally_invalid` API parameter to `encap_data_invalid`
   * Validate `CMSAlgorithmProtection` when present.
* Improved support for deep fields in the form hierarchy (arguably orthogonal to the standard, but it doesn't hurt to be flexible).
* Added

Miscellaneous
^^^^^^^^^^^^^

* Export `copy_into_new_writer`.
* Transparently handle non-seekable output streams in the signer.
* Remove unused `__iadd__` implementation from VRI class.
* Clean up some corner cases in `container_ref` handling.
* Refactored `SignatureFormField` initialisation (internal API).

Bugs fixed
----------

* Deal with some XRef processing edge cases.
* Make `signed_revision` on embedded signatures more robust.
* Fix an issue where DocTimeStamp additions would trigger `/All`-type field locks.
* Fix some issues with `modification_level` handling in validation status reports.
* Fix a few logging calls.
* Fix some minor issues with signing API input validation logic.


0.3.0
=====

*Release date:* 2021-01-26

New features and enhancements
-----------------------------

Encryption
^^^^^^^^^^

* Reworked internal crypto API.
* Added support for PDF 2.0 encryption.
* Added support for public key encryption.
* Got rid of the homegrown `RC4` class (not that it matters all to much, `RC4` isn't secure anyhow); all cryptographic operations in `crypt.py` are now delegated to `oscrypto`.


Signing
^^^^^^^

* Encrypted files can now be signed from the CLI.
* With the optional `cryptography` dependency, pyHanko can now create RSASSA-PSS signatures.
* Factored out a low-level `PdfCMSEmbedder` API to cater to remote signing needs.

Miscellaneous
^^^^^^^^^^^^^

* The document ID can now be accessed more conveniently.
* The version number is now single-sourced in `version.py`.
* Initialising the page tree in a `PdfFileWriter` is now optional.
* Added a convenience function for copying files.

Validation
^^^^^^^^^^

* With the optional `cryptography` dependency, pyHanko can now validate RSASSA-PSS signatures.
* Difference analysis checker was upgraded with capabilities to handle multiply referenced objects in a more straightforward way. This required API changes, and it comes at a significant performance cost, but the added cost is probably justified. The changes to the API are limited to the `diff_analysis` module itself, and do not impact the general validation API whatsoever.


Bugs fixed
----------

* Allow `/DR` and `/Version` updates in diff analysis
* Fix revision handling in `trailer.flatten()`



0.2.0
=====

*Release date:* 2021-01-10

New features and enhancements
-----------------------------

Signing
^^^^^^^

* Allow the caller to specify an output stream when signing.

Validation
^^^^^^^^^^

* The incremental update analysis functionality has been heavily refactored
  into something more rule-based and modular. The new difference analysis system
  is also much more user-configurable, and a (sufficiently motivated) library
  user could even plug in their own implementation.
* The new validation system treats ``/Metadata`` updates more correctly, and fixes
  a number of other minor stability problems.
* Improved validation logging and status reporting mechanisms.
* Improved seed value constraint enforcement support: this includes added
  support for  ``/V``, ``/MDP``, ``/LockDocument``, ``/KeyUsage``
  and (passive) support for ``/AppearanceFilter`` and  ``/LegalAttestation``.

CLI
^^^

* You can now specify negative page numbers on the command line to refer to the
  pages of a document in reverse order.

General PDF API
^^^^^^^^^^^^^^^

* Added convenience functions to retrieve references from dictionaries and
  arrays.
* Tweaked handling of object freeing operations; these now produce PDF ``null``
  objects instead of (Python) ``None``.


Bugs fixed
----------

* ``root_ref`` now consistently returns a ``Reference`` object
* Corrected wrong usage of ``@freeze_time`` in tests that caused some failures
  due to certificate expiry issues.
* Fixed a gnarly caching bug in ``HistoricalResolver`` that sometimes leaked
  state from later revisions into older ones.
* Prevented cross-reference stream updates from accidentally being saved with
  the same settings as their predecessor in the file. This was a problem when
  updating files generated by other PDF processing software.


0.1.0
=====

*Release date:* 2020-12-30

Initial release.