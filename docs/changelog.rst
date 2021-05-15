***************
Release history
***************

0.6.0
=====

*Release date:* 2021-05-15


Dependency changes
------------------

.. warning::
    pyHanko's ``0.6.0`` release includes quite a few changes to dependencies, some of which may
    break compatibility with existing code. Review this section carefully before updating.

The ``pyhanko-certvalidator`` dependency was updated to ``0.15.1``.
This update adds support for name constraints, RSASSA-PSS and EdDSA for the purposes of X.509 path
validation, OCSP checking and CRL validation.

.. warning::
    Since ``pyhanko-certvalidator`` has considerably diverged from "mainline" ``certvalidator``,
    the Python package containing its modules was also renamed from ``certvalidator`` to
    ``pyhanko_certvalidator``, to avoid potential namespace conflicts down the line. You should
    update your code to reflect this change.

    Concretely,

    .. code-block:: python

        from certvalidator import ValidationContext

    turns into

    .. code-block:: python

        from pyhanko_certvalidator import ValidationContext

    in the new release.

There were several changes to dependencies with native binary components:

 * The Pillow dependency has been relaxed to ``>=7.2.0``, and is now optional.
   The same goes for ``python-barcode``. Image & 1D barcode support now needs to be installed
   explicitly using the ``[image-support]`` installation parameter.

 * PKCS#11 support has also been made optional, and can be added using the ``[pkcs11]``
   installation parameter.

The test suite now makes use of `Certomancer <https://github.com/MatthiasValvekens/certomancer>`_.
This also removed the dependency on ``ocspbuilder``.


New features and enhancements
-----------------------------


Signing
^^^^^^^

 * Make preferred hash inference more robust.
 * Populate ``/AP`` when creating an empty visible signature field (necessary in PDF 2.0)


Validation
^^^^^^^^^^

 * Timestamp and DSS handling tweaks:

   * Preserve OCSP resps / CRLs from validation kwargs when reading the DSS.
   * Gracefully process revisions that don't have a DSS.
   * When creating document timestamps, the ``validation_context`` parameter is now optional.

 * Enforce ``certvalidator``'s ``weak_hash_algos`` when validating PDF signatures as well.
   Previously, this setting only applied to certificate validation.
   By default, MD5 and SHA-1 are considered weak (for digital signing purposes).

 * Expose ``DocTimeStamp``/``Sig`` distinction in a more user-friendly manner.

    * The ``sig_object_type`` property on :class:`~pyhanko.sign.validation.EmbeddedPdfSignature`
      now returns the signature's type as a PDF name object.
    * :class:`~pyhanko.pdf_utils.reader.PdfFileReader` now has two extra convenience properties
      named ``embedded_regular_signatures`` and ``embedded_timestamp_signatures``, that return a
      list of all regular signatures and document timestamps, respectively.


Encryption
^^^^^^^^^^

 * Refactor internal APIs in pyHanko's security handler implementation to make them easier to
   extend. Note that while anyone is free to register their own crypt filters for whatever purpose,
   pyHanko's security handler is still considered internal API, so behaviour is subject to change
   between minor version upgrades (even after ``1.0.0``).

Miscellaneous
^^^^^^^^^^^^^

 * Broaden the scope of ``--soft-revocation-check``.
 * Corrected a typo in the signature of ``validate_sig_integrity``.
 * Less opaque error message on missing PKCS#11 key handle.
 * Ad-hoc hash selection now relies on ``pyca/cryptography`` rather than ``hashlib``.


Bugs fixed
----------

 * Correct handling of DocMDP permissions in approval signatures.
 * Refactor & correct handling of SigFlags when signing prepared form fields in unsigned files.
 * Fixed issue with trailing whitespace and/or ``NUL`` bytes in array literals.
 * Corrected the export lists of various modules.


0.5.1
=====

*Release date:* 2021-03-24

Bugs fixed
----------

  * Fixed a packaging blunder that caused an import error on fresh installs.


0.5.0
=====

*Release date:* 2021-03-22

Dependency changes
------------------

Update ``pyhanko-certvalidator`` dependency to ``0.13.0``.
Dependency on ``cryptography`` is now mandatory, and ``oscrypto`` has been marked optional.
This is because we now use the ``cryptography`` library for all signing and encryption operations,
but some cryptographic algorithms listed in the PDF standard are not available in ``cryptography``,
so we rely on ``oscrypto`` for those. This is only relevant for the *decryption* of files encrypted
with a public-key security handler that uses DES, triple DES or RC2 to encrypt the key seed.

In the public API, we exclusively work with ``asn1crypto`` representations of ASN.1 objects, to
remain as backend-independent as possible.

*Note:* While ``oscrypto`` is listed as optional in pyHanko's dependency list, it is still
required in practice, since ``pyhanko-certvalidator`` depends on it.


New features and enhancements
-----------------------------


Encryption
^^^^^^^^^^

 * Enforce ``keyEncipherment`` key extension by default when using public-key encryption
 * Show a warning when signing a document using public-key encryption through the CLI.
   We currently don't support using separate encryption credentials in the CLI, and using the same
   key pair for decryption and signing is bad practice.
 * Several minor CLI updates.


Signing
^^^^^^^

 * Allow customisation of key usage requirements in signer & validator, also in the CLI.
 * Actively preserve document timestamp chain in new PAdES-LTA signatures.
 * Support setups where fields and annotations are separate (i.e. unmerged).
 * Set the ``lock`` bit in the annotation flags by default.
 * Tolerate signing fields that don't have any annotation associated with them.
 * Broader support for PAdES / CAdES signed attributes.


Validation
^^^^^^^^^^

 * Support validating PKCS #7 signatures that don't use ``signedAttrs``. Nowadays, those are rare in
   the wild, but there's at least one common commercial PDF library that outputs such signatures by
   default (vendor name redacted to protect the guilty).
 * Timestamp-related fixes:
     * Improve signature vs. document timestamp handling in the validation CLI.
     * Improve & test handling of malformed signature dictionaries in PDF files.
     * Align document timestamp updating logic with validation logic.
     * Correct key usage check for time stamp validation.
 * Allow customisation of key usage requirements in signer & validator, also in the CLI.
 * Allow LTA update function to be used to start the timestamp chain as well as continue it.
 * Tolerate indirect references in signature reference dictionaries.
 * Improve some potential ambiguities in the PAdES-LT and PAdES-LTA validation logic.
 * Revocation info handling changes:
    * Support "retroactive" mode for revocation info (i.e. treat revocation info as valid in the
      past).
    * Added functionality to append current revocation information to existing signatures.
    * Related CLI updates.


Miscellaneous
^^^^^^^^^^^^^

 * Some key material loading functions were cleaned up a little to make them easier to use.
 * I/O tweaks: use chunked writes with a fixed buffer when copying data for an incremental update
 * Warn when revocation info is embedded with an offline validation context.
 * Improve SV validation reporting.


Bugs fixed
----------

 * Fix issue with ``/Certs`` not being properly dereferenced in the DSS (#4).
 * Fix loss of precision on :class:`~pyhanko.pdf_utils.generic.FloatObject` serialisation (#5).
 * Add missing dunders to :class:`~pyhanko.pdf_utils.generic.BooleanObject`.
 * Do not use ``.dump()`` with ``force=True`` in validation.
 * Corrected digest algorithm selection in timestamp validation.
 * Correct handling of writes with empty user password.
 * Do not automatically add xref streams to the object cache. This avoids a class of bugs with
   some kinds of updates to files with broken xref streams.
 * Due to a typo, the ``/Annots`` array of a page would not get updated correctly if it was an
   indirect object. This has been corrected.


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
