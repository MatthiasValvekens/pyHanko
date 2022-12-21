***************
Release history
***************


.. _release-0.16.0:

0.16.0
======

*Release date:* 2022-12-21


Dependency updates
------------------

 * ``pyhanko-certvalidator`` updated to ``0.19.8``


Breaking changes
----------------

This release includes breaking changes to the difference analysis engine.
Unless you're implementing your own difference analysis policies, this
change should break your API usage.


New features and enhancements
-----------------------------

Signing
^^^^^^^

 * Add support for **Prop_Build** metadata in signatures.
   See `PR #192 <https://github.com/MatthiasValvekens/pyHanko/issues/192>`_


Validation
^^^^^^^^^^

 * Improvements to the difference analysis engine that allow more
   nuance to be expressed in the rule system.


Bugs fixed
----------

 * Tolerate an indirect **Extensions** and **MarkInfo** dictionary in
   difference analysis. See `PR #177 <https://github.com/MatthiasValvekens/pyHanko/issues/177>`_.
 * Gracefully handle unreadable/undecodable producer strings.


.. _release-0.15.1:

0.15.1
======

*Release date:* 2022-10-27


Note
----

This release adds Python 3.11 to the list of supported Python versions.


Dependency updates
------------------

 * ``pyhanko-certvalidator`` updated to ``0.19.6``
 * ``certomancer`` updated to ``0.9.1``


Bugs fixed
----------

 * Be more tolerant towards deviations from DER restrictions in
   signed attributes when validating signatures.


.. _release-0.15.0:

0.15.0
======


*Release date:* 2022-10-11


Note
----

Other than a few bug fixes, the highlight of this release is the addition of
support for two very recently published PDF extension standards, ISO/TS 32001
and ISO/TS 32002.


Bugs fixed
----------

 * Fix metadata handling in encrypted documents
   see `issue #160 <https://github.com/MatthiasValvekens/pyHanko/issues/160>`_.
 * Make sure XMP stream dictionaries contain the required typing entries.
 * Respect ``visible_sig_settings`` on field autocreation.
 * Fix a division by zero corner case in the stamp layout code;
   see `issue #170 <https://github.com/MatthiasValvekens/pyHanko/issues/170>`_.


New features and enhancements
-----------------------------

Signing
^^^^^^^

 * Add support for the new PDF extensions defined by ISO/TS 32001 and ISO/TS 32002;
   see `PR #169 <https://github.com/MatthiasValvekens/pyHanko/issues/169>`_.

    * SHA-3 support
    * EdDSA support for both the PKCS#11 signer and the in-memory signer
    * Auto-register developer extensions in the file

 * Make it easier to extract keys from ``bytes`` objects.


Validation
^^^^^^^^^^

 * Add support for validating EdDSA signatures (as defined in ISO/TS 32002)


.. _release-0.14.0:

0.14.0
======


*Release date:* 2022-09-17


Note
----

This release contains a mixture of minor and major changes.
Of particular note is the addition of automated metadata management support,
including XMP metadata. This change affects almost every PDF write operation
in the background. While pyHanko has very good test coverage, some instability
and regressions may ensue. Bug reports are obviously welcome.


Breaking changes
----------------

The breaking changes in this release are all relatively minor.
Chances are that your code isn't affected at all, other than perhaps by
the change to
:class:`~pyhanko.sign.signers.pdf_byterange.PreparedByteRangeDigest`.


 * ``md_algorithm`` attribute removed from
   :class:`~pyhanko.sign.signers.pdf_byterange.PreparedByteRangeDigest` since
   it wasn't necessary for further processing.
 * Low-level change in ``raw_get`` for PDF container object types
   (:class:`~pyhanko.pdf_utils.generic.ArrayObject` and
   :class:`~pyhanko.pdf_utils.generic.DictionaryObject`): the ``decrypt``
   parameter is no longer a boolean, but a tri-state enum value of type
   :class:`~pyhanko.pdf_utils.generic.EncryptedObjAccess`.
 * Developer extension management API moved into :mod:`pyhanko.pdf_utils.extensions`.
 * :func:`~pyhanko.pdf_utils.font.basic.get_courier` convenience function moved into
   :mod:`pyhanko.pdf_utils.font.basic` and now takes a mandatory writer argument.
 * The ``token_label`` attribute was removed from
   :class:`~pyhanko.config.PKCS11SignatureConfig`, but will still be parsed
   (with a deprecation warning).
 * The :attr:`~pyhanko.config.PKCS11SignatureConfig.prompt_pin` attribute in
   :class:`~pyhanko.config.PKCS11SignatureConfig` was changed from a bool to
   an enum. See :class:`~pyhanko.config.PKCS11PinEntryMode`.


Dependency updates
------------------

 * ``pytest-aiohttp`` updated to ``1.0.4``
 * ``certomancer`` updated to ``0.9.0``
 * ``certomancer-csc-dummy`` updated to ``0.2.1``
 * Relax bounds on ``uharfbuzz`` to allow everything up to the current version
   (i.e. ``0.30.0``) as well.
 * New optional dependency group ``xmp``, which for now only contains ``defusedxml``


Bugs fixed
----------

 * Allow certificates with no ``CN`` in the certificate subject.
 * The extension dictionary handling logic can now deal with encrypted
   documents without actually decrypting the document contents.
 * Fix processing error when passing empty strings to ``uharfbuzz``;
   see `issue #132 <https://github.com/MatthiasValvekens/pyHanko/issues/132>`_.
 * Use proper PDF text string serialisation routine in simple font handler, to ensure
   everything is escaped correctly.
 * Ensure that ``output_version`` is set to at least the input version in
   incrementally updated files.


New features and enhancements
-----------------------------

Signing
^^^^^^^

 * Drop the requirement for :attr:`~pyhanko.sign.signers.pdf_cms.Signer.signing_cert`
   to be set from the start of the signing process in an interrupted signing workflow.
   This has come up on several occasions in the past, since it's necessary in remote
   signing scenarios where the certificate is generated or provided on-demand when
   submitting the document digest to the signing service.
   See `pull #141 <https://github.com/MatthiasValvekens/pyHanko/pull/141>`_ for details.
 * Add convenience API to set the ``/TU`` entry on a signature field;
   see :attr:`~pyhanko.sign.fields.SigFieldSpec.readable_field_name`.
 * Allow greater control over the initialisation of document timestamp fields.
 * New class hierarchy for (un)signed attribute provisioning;
   see :class:`~pyhanko.sign.attributes.SignedAttributeProviderSpec`
   and :class:`~pyhanko.sign.attributes.UnsignedAttributeProviderSpec`.
 * Allow greater control over annotation flags for visible signatures.
   This is implemented using :class:`~pyhanko.sign.fields.VisibleSigSettings`.
   See `discussion #150 <https://github.com/MatthiasValvekens/pyHanko/discussions/150>`_.
 * Factor out and improve PKCS#11 token finding; see
   :class:`~pyhanko.config.TokenCriteria`
   and `issue #149 <https://github.com/MatthiasValvekens/pyHanko/issues/149>`_.
 * Factor out and improve PKCS#11 mechanism selection, allowing more raw modes.
 * Change pin entry settings for PKCS#11 to be more granular, in order to also
   allow ``PROTECTED_AUTH``;
   see `issue #133 <https://github.com/MatthiasValvekens/pyHanko/issues/133>`_.
 * Allow the PKCS#11 PIN to be sourced from an environment variable when
   pyHanko is invoked through the CLI and no PIN is provided in the configuration.
   PyHanko will now first check the ``PYHANKO_PKCS11_PIN`` variable before
   prompting for a PIN. This also works when prompting for PIN entry is
   disabled altogether.


.. note::

    The PKCS#11 code is now also tested in CI, using
    `SoftHSMv2 <https://github.com/opendnssec/SoftHSMv2>`_.


Validation
^^^^^^^^^^

 * Allow validation time overrides in the CLI. Passing in the special value
   ``claimed`` tells pyHanko to take the stated signing time in the file at
   face value.
   See `issue #130 <https://github.com/MatthiasValvekens/pyHanko/issues/130>`_.


Encryption
^^^^^^^^^^

 * Also return permissions on owner access to allow for easier inspection.
 * Better version enforcement for security handlers.


Layout
^^^^^^

 * Allow metrics to be specified for simple fonts.
 * Provide metrics for default Courier font.
 * Experimental option that allows graphics to be embedded in the central area
   of the QR code; see :attr:`~pyhanko.stamp.QRStampStyle.qr_inner_content`.


Miscellaneous
^^^^^^^^^^^^^

 * Basic XMP metadata support with optional ``xmp`` dependency group.
 * Automated metadata management (document info dictionary, XMP metadata).
 * Refactor some low-level digesting and CMS validation code.
 * Make the CLI print a warning when the key passphrase is left empty.
 * Tweak configuration management utilities to better cope with fallback
   logic for deprecated configuration parameters.
 * Move all cross-reference writing logic into :mod:`pyhanko.pdf_utils.xref`.
 * Improve error classes and error reporting in the CLI so that errors in non-verbose mode
   still provide a little more info.


.. _release-0.13.2:

0.13.2
======

*Release date:* 2022-07-02

Note
----

This is a patch release to address some dependency issues and bugs.


Dependency updates
------------------

 * ``python-barcode`` updated and pinned to ``0.14.0``.


Bugs fixed
----------

 * Fix lack of newline after XRef stream header.
 * Do not write **DigestMethod** in signature reference dictionaries
   (deprecated/nonfunctional entry).
 * Make :func:`pyhanko.pdf_utils.writer.copy_into_new_writer` more flexible by allowing
   caller-specified keyword arguments for the writer object.
 * Refine settings for invisible signature fields (see :class:`pyhanko.sign.fields.InvisSigSettings`).
 * Correctly read objects from object streams in encrypted documents.


.. _release-0.13.1:

0.13.1
======

*Release date:* 2022-05-01

Note
----

This is a patch release to update ``fontTools`` and ``uharfbuzz`` to address
a conflict between the latest ``fontTools`` and older ``uharfbuzz`` versions.


Dependency updates
------------------

 * ``fontTools`` updated to ``4.33.3``
 * ``uharfbuzz`` updated to ``0.25.0``


.. _release-0.13.0:

0.13.0
======

*Release date:* 2022-04-25


Note
----

Like the previous two releases, this is largely a maintenance release.


Dependency updates
------------------

 * ``asn1crypto`` updated to ``1.5.1``
 * ``pyhanko-certvalidator`` updated to ``0.19.5``
 * ``certomancer`` updated to ``0.8.2``
 * Depend on ``certomancer-csc-dummy`` for tests;
   get rid of ``python-pae`` test dependency.

Bugs fixed
----------

 * Various parsing robustness improvements.
 * Be consistent with security handler version bounds.
 * Improve coverage of encryption code.
 * Ensure owner password gets prioritised in the legacy security handler.


New features and enhancements
-----------------------------


Miscellaneous
^^^^^^^^^^^^^

 * Replaced some ``ValueError`` usages with ``PdfError``
 * Improvements to error handling in strict mode.
 * Make CLI stack traces less noisy by default.

Encryption
^^^^^^^^^^

 * Refactor internal ``crypt`` module into package.
 * Add support for serialising credentials.
 * Cleaner credential inheritance for incremental writers.

Signing
^^^^^^^

 * Allow post-signing actions on encrypted files with serialised credentials.
 * Improve ``--use-pades-lta`` ergonomics in CLI.
 * Add ``--no-pass`` parameter to ``pemder`` CLI.


Validation
^^^^^^^^^^

 * Preparatory scaffolding for AdES status reporting.
 * Provide some tolerance against malformed ACs.
 * Increase robustness against invalid DNs.


.. _release-0.12.1:

0.12.1
======

*Release date:* 2022-02-26


Dependency updates
------------------

 * ``uharfbuzz`` updated to ``0.19.0``
 * ``pyhanko-certvalidator`` updated to ``0.19.4``
 * ``certomancer`` updated to ``0.8.1``


Bugs fixed
----------

 * Fix typing issue in DSS reading logic (see
   `issue #81 <https://github.com/MatthiasValvekens/pyHanko/issues/81>`_)


.. _release-0.12.0:

0.12.0
======

*Release date:* 2022-01-26

Note
----

This is largely a maintenance release, and contains no new high-level features or public
API changes. As such, upgrading is strongly recommended.

The most significant change is the (rather minimalistic) support for hybrid reference files.
Since working with hybrid reference files means dealing with potential ambiguity (which is dangerous
when dealing with signatures), creation and validation of signatures in hybrid reference documents
is only enabled in nonstrict mode. Hybrid reference files are relatively rare these days, but the
internals need to be able to cope with them either way, in order to be able to update such files
safely.


New features and enhancements
-----------------------------

Miscellaneous
^^^^^^^^^^^^^

 * Significant refactor of cross-reference parsing internals. This doesn't affect any public API
   entrypoints, but read the reference documentation for :mod:`pyhanko.pdf_utils.xref` if you happen
   to have code that directly relies on that internal logic.
 * Minimal support for hybrid reference files.
 * Add ``strict`` flag to :class:`~pyhanko.pdf_utils.incremental_writer.IncrementalPdfFileWriter`.
 * Expose ``--no-strict-syntax`` CLI flag in the ``addsig`` subcommand.


Bugs fixed
----------

 * Ensure that signature appearance bounding boxes are rounded to a reasonable precision.
   Failure to do so caused issues with some viewers.
 * To be consistent with the purpose of the strictness flag, non-essential xref consistency
   checking is now only enabled when running in strict mode (which is the default).
 * The hybrid reference support indirectly fixes some potential silent file corruption issues
   that could arise when working on particularly ill-behaved hybrid reference files.


.. _release-0.11.0:

0.11.0
======

*Release date:* 2021-12-23

Dependency changes
------------------

 * Update ``pyhanko-certvalidator`` to ``0.19.2``
 * Bump ``fontTools`` to ``4.28.2``
 * Update ``certomancer`` test dependency to ``0.7.1``


.. _release-0.11.0-breaking:

Breaking changes
----------------

Due to import order issues resulting from refactoring of the validation code, some classes
and class hierarchies in the higher-level API had to be moved. The affected classes are listed
below, with links to their respective new locations in the API reference.

 * :class:`~pyhanko.sign.validation.settings.KeyUsageConstraints`
 * :class:`~pyhanko.sign.validation.errors.SignatureValidationError`
 * :class:`~pyhanko.sign.validation.errors.WeakHashAlgorithmError`
 * :class:`~pyhanko.sign.validation.errors.SigSeedValueValidationError`
 * :class:`~pyhanko.sign.validation.status.SignatureStatus`
 * :class:`~pyhanko.sign.validation.status.StandardCMSSignatureStatus`
 * :class:`~pyhanko.sign.validation.status.PdfSignatureStatus`
 * :class:`~pyhanko.sign.validation.status.TimestampSignatureStatus`
 * :class:`~pyhanko.sign.validation.status.DocumentTimestampStatus`

The low-level function :func:`~pyhanko.sign.validation.generic_cms.validate_sig_integrity` was also
moved.


New features and enhancements
-----------------------------

Signing
^^^^^^^

 * Support embedding attribute certificates into CMS signatures, either in the ``certificates``
   field or using the CAdES ``signer-attrs-v2`` attribute.
 * More explicit errors on unfulfilled text parameters
 * Better use of ``asyncio`` when collecting validation information for timestamps
 * Internally disambiguate PAdES and CAdES for the purpose of attribute handling.


Validation
^^^^^^^^^^

 * Refactor ``diff_analysis`` module into sub-package
 * Refactor ``validation`` module into sub-package
   (together with portions of :mod:`pyhanko.sign.general`); see :ref:`release-0.11.0-breaking`.
 * Make extracted certificate information more easily accessible.
 * Integrated attribute certificate validation (requires a separate validation context with trust
   roots for attribute authorities)
 * Report on signer attributes as supplied by the CAdES ``signer-attrs-v2`` attribute.

Miscellaneous
^^^^^^^^^^^^^

 * Various parsing and error handling improvements to xref processing, object streams, and object
   header handling.
 * Use :class:`NotImplementedError` for unimplemented stream filters instead of
   less-appropriate exceptions
 * Always drop GPOS/GDEF/GSUB when subsetting OpenType and TrueType fonts
 * Initial support for string-keyed CFF fonts as CIDFonts (subsetting is still inefficient)
 * :func:`~pyhanko.pdf_utils.writer.copy_into_new_writer` is now smarter about how it deals with the
   ``/Producer`` line
 * Fix a typo in the ASN.1 definition of ``signature-policy-store``
 * Various, largely aesthetic, cleanup & docstring fixes in internal APIs

Bugs fixed
----------

 * Fix a critical bug in content timestamp generation causing the wrong message imprint to be sent
   to the timestamping service. The bug only affected the signed ``content-time-stamp`` attribute
   from CAdES, not the (much more widely used) ``signature-time-stamp`` attribute. The former
   timestamps the content (and is part of the signed data), while the latter timestamps the
   signature (and is therefore not part of the signed data).
 * Fix a bug causing an empty unsigned attribute sequence to be written if there were no
   unsigned attributes. This is not allowed (although many validators accept it), and was a
   regression introduced in ``0.9.0``.
 * Ensure non-PDF CAdES signatures always have ``signingTime`` set.
 * Fix and improve timestamp summary reporting
 * Corrected TrueType subtype handling
 * Properly set :attr:`~pyhanko.sign.signers.pdf_signer.PreSignValidationStatus.ts_validation_paths`
 * Gracefully deal with unsupported certificate types in CMS
 * Ensure attribute inspection internals can deal with ``SignerInfo`` without ``signedAttrs``.

.. _release-0.10.0:

0.10.0
======

*Release date:* 2021-11-28

Dependency changes
------------------

 * Update ``pyhanko-certvalidator`` to ``0.18.0``
 * Update ``aiohttp`` to ``3.8.0`` (optional dependency)
 * Introduce ``python-pae==0.1.0`` (tests)


New features and enhancements
-----------------------------

Signing
^^^^^^^

 * There's a new :class:`~pyhanko.sign.signers.pdf_cms.Signer` implementation
   that allows pyHanko to be used with remote signing services that implement the
   Cloud Signature Consortium API. Since auth handling differs from vendor to vendor, using
   this feature requires still the caller to supply an authentication handler implementation;
   see :mod:`pyhanko.sign.signers.csc_signer` for more information.
   *This feature is currently incubating.*

Validation
^^^^^^^^^^

 * Add CLI option to skip diff analysis.
 * Add CLI flag to disable strict syntax checks.
 * Use chunked digests while validating.
 * Improved difference analysis logging.

Miscellaneous
^^^^^^^^^^^^^

 * Better handling of nonexistent objects: clearer errors in strict mode, better fallback behaviour
   in nonstrict mode. This applies to both regular object dereferencing and xref history analysis.
 * Added many new tests for various edge cases, mainly in validation code.
 * Added ``Python :: 3`` and ``Python :: 3.10`` classifiers to distribution.

Bugs fixed
----------

 * Fix bug in output handler in timestamp updater that caused empty output in some configurations.
 * Fix a config parsing error when no stamp styles are defined in the configuration file.


.. _release-0.9.0:

0.9.0
=====

*Release date:* 2021-10-31

Dependency changes
------------------

 * Update ``pyhanko-certvalidator`` to ``0.17.3``
 * Update ``fontTools`` to ``4.27.1``
 * Update ``certomancer`` to ``0.6.0`` (tests)
 * Introduce ``pytest-aiohttp~=0.3.0`` and ``aiohttp>=3.7.4`` (tests)

API-breaking changes
--------------------

This is a pretty big release, with a number of far-reaching changes in the
lower levels of the API that may cause breakage.
Much of pyHanko's internal logic has been refactored to prefer asynchronous I/O
wherever possible (``pyhanko-certvalidator`` was also refactored accordingly).
Some compromises were made to allow non-async-aware code to continue working as-is.

If you'd like a quick overview of how you can take advantage of the new
asynchronous library functions, take a look at
:ref:`this section in the signing docs <async-resource-management>`.


Here's an overview of low-level functionality that changed:

 * CMS signing logic was refactored and made asynchronous
   (only relevant if you implemented your own custom signers)
 * Time stamp client API was refactored and made asynchronous
   (only relevant if you implemented your own time stamping clients)
 * The :ref:`interrupted signing <interrupted-signing>` workflow now involves more
   asyncio as well.
 * :meth:`~pyhanko.sign.signers.pdf_signer.PdfSigningSession.perform_presign_validation`
   was made asynchronous.
 * :meth:`~pyhanko.sign.signers.pdf_signer.PdfSigningSession.prepare_tbs_document`: the
   ``bytes_reserved`` parameter is mandatory now.

 * :meth:`~pyhanko.sign.signers.pdf_signer.PdfPostSignatureDocument.post_signature_processing`
   was made asynchronous.
 * :func:`~pyhanko.sign.validation.collect_validation_info` was made asynchronous

Other functions have been deprecated in favour of asynchronous equivalents;
such deprecations are documented in :ref:`the API reference <api-reference>`.
The section on extending :class:`~pyhanko.sign.signers.pdf_cms.Signer`
:ref:`has also been updated <extending-signer>`.

.. warning::
    Even though we have pretty good test coverage, due to the volume of changes,
    some instability may ensue. Please do not hesitate to report bugs on
    `the issue tracker <https://github.com/MatthiasValvekens/pyHanko/issues>`_!


New features and enhancements
-----------------------------

Signing
^^^^^^^

 * Async-first signing API
 * Relax ``token-label`` requirements in PKCS#11 config, allowing ``slot-no``
   as an alternative
 * Allow selecting keys and certificates by ID in the PKCS#11 signer
 * Allow the signer's certificate to be sourced from a file in the PKCS#11 signer
 * Allow BeID module path to be specified in config
 * Tweak cert querying logic in PKCS#11 signer
 * Add support for raw ECDSA to the PKCS#11 signer
 * Basic DSA support (for completeness w.r.t. ISO 32000)
 * Choose a default message digest more cleverly, based on the signing algorithm
   and key size
 * Fail loudly when trying to add a certifying signature to an already-signed
   document using the high-level signing API
 * Provide a flag to skip embedding root certificates

Validation
^^^^^^^^^^

 * Async-first validation API
 * Use non-zero exit code on failed CLI validation


Miscellaneous
^^^^^^^^^^^^^

 * Minor reorganisation of ``config.py`` functions
 * Move PKCS#11 pin prompt logic to ``cli.py``
 * Improve font embedding efficiency (better stream management)
 * Ensure idempotence of object stream flushing
 * Improve PKCS#11 signer logging
 * Make ``stream_xrefs=False`` by default in ``copy_into_new_writer()``
 * Removed a piece of fallback logic for ``md_algorithm`` that relied on
   obsolete parts of the standard
 * Fixed a number of issues related to unexpected cycles in PDF structures


Bugs fixed
----------

 * Treat ASCII form feed (``\f``) as PDF whitespace
 * Fix a corner case with null incremental updates
 * Fix some font compatibility issues (relax assumptions about the presence of
   certain tables/entries)
 * Be more tolerant when parsing name objects
 * Correct some issues related to DSS update validation
 * Correct :func:`~pyhanko.pdf_utils.generic.pdf_date` output for negative
   UTC offsets


.. _release-0.8.0:

0.8.0
=====

*Release date:* 2021-08-23

Dependency changes
------------------

 * Update ``pyhanko-certvalidator`` to ``0.16.0``.

API-breaking changes
--------------------

Some fields and method names in the config API misspelled ``pkcs11` as ``pcks11``. This has been
corrected in this release. This is unlikely to cause issues for library users (since the config API
is primarily used by the CLI code), but it's a breaking change all the same.
If you do have code that relies on the config API, simply substituting ``s/pcks/pkcs/g`` should fix
things.

New features and enhancements
-----------------------------

Signing
^^^^^^^

 * Make certificate fetching in the PKCS#11 signer more flexible.

   * Allow passing in the signer's certificate from outside the token.
   * Improve certificate registry initialisation.

 * Give more control over updating the DSS in complex signature workflows.
   By default, pyHanko now tries to update the DSS in the revision that adds a document timestamp,
   after the signature (if applicable). In the absence of a timestamp, the old behaviour persists.

 * Added a flag to (attempt to) produce CMS signature containers without any padding.
 * Use ``signing-certificate-v2`` instead of ``signing-certificate`` when producing signatures.
 * Default to empty appearance streams for empty signature fields.
 * Much like the ``pkcs11-setups`` config entry, there are now ``pemder-setups`` and
   ``pkcs12-setups`` at the top level of pyHanko's config file. You can use those to store arguments
   for the ``pemder`` and ``pkcs12`` subcommands of pyHanko's ``addsig`` command, together with
   passphrases for non-interactive use. See :ref:`ondisk-setup-conf`.

Validation
^^^^^^^^^^

 * Enforce the end-entity cert constraint imposed by the ``signing-certificate`` or
   ``signing-certificate-v2`` attribute (if present).
 * Improve issuer-serial matching logic.
 * Improve CMS attribute lookup routines.


Encryption
^^^^^^^^^^

 * Add a flag to suppress creating "legacy compatibility" entries in the encryption dictionary
   if they aren't actually required or meaningful (for now, this only applies to ``/Length``).

Miscellaneous
^^^^^^^^^^^^^

 * Lazily load the version entry in the catalog.
 * Minor internal I/O handling improvements.
 * Allow constructing an :class:`~pyhanko.pdf_utils.incremental_writer.IncrementalPdfFileWriter`
   from a :class:`~pyhanko.pdf_utils.reader.PdfFileReader` object.
 * Expose common API to modify (most) trailer entries.
 * Automatically recurse into all configurable fields when processing configuration data.
 * Replace some certificate storage/indexing classes by references to their corresponding classes
   in ``pyhanko-certvalidator``.

Bugs fixed
----------

 * Add ``/NeedAppearances`` in the AcroForm dictionary to the whitelist for incremental update
   analysis.
 * Fixed several bugs related to difference analysis on encrypted files.
 * Improve behaviour of dev extensions in difference analysis.
 * Fix encoding issues with ``SignedDigestAlgorithm``, in particular ensuring that the signature
   mechanism encodes the relevant digest when using ECDSA.
 * Process passfile contents more robustly in the CLI.
 * Correct timestamp revinfo fetching (by ensuring that a dummy response is present)


.. _release-0.7.0:

0.7.0
=====

*Release date:* 2021-07-25

Dependency changes
------------------

.. warning::
    If you used OTF/TTF fonts with pyHanko prior to the ``0.7.0`` release, you'll need HarfBuzz
    going forward. Install pyHanko with the ``[opentype]`` optional dependency group to grab
    everything you need.

* Update ``pyhanko-certvalidator`` to ``0.15.3``
* TrueType/OpenType support moved to new optional dependency group labelled ``[opentype]``.

  * Dependency on ``fontTools`` moved from core dependencies to ``[opentype]`` group.
  * We now use HarfBuzz (``uharfbuzz==0.16.1``) for text shaping with OTF/TTF fonts.


API-breaking changes
--------------------

.. warning::
    If you use any of pyHanko's lower-level APIs, review this section carefully before updating.

Signing code refactor
^^^^^^^^^^^^^^^^^^^^^

This release includes a refactor of the ``pyhanko.sign.signers`` module into a
:ref:`package <signers-package-docs>` with several submodules. The original API exposed by this
module is reexported in full at the package level, so existing code using pyHanko's publicly
documented signing APIs *should* continue to work **without modification**.

There is one notable exception: as part of this refactor, the low-level
:class:`~pyhanko.sign.signers.cms_embedder.PdfCMSEmbedder` protocol was tweaked slightly, to support
the new interrupted signing workflow (see below). The required changes to existing code should be
minimal; have a look at :ref:`the relevant section <pdf-cms-embedder-protocol>` in the library
documentation for a concrete description of the changes, and an updated usage example.

In addition, if you extended the :class:`~pyhanko.sign.signers.pdf_signer.PdfSigner`
class, then you'll have to adapt to the new internal signing workflow as well. This may be
tricky due to the fact that the separation of concerns between different steps in the signing
process is now enforced more strictly.
I'm not aware of use cases requiring :class:`~pyhanko.sign.signers.pdf_signer.PdfSigner`
to be extended, but if you're having trouble migrating your custom subclass to the new API
structure, feel free to open `an issue <https://github.com/MatthiasValvekens/pyHanko/issues>`_.
Merely having subclassed :class:`~pyhanko.sign.signers.pdf_cms.Signer` shouldn't require
you to change anything.


Fonts
^^^^^

The low-level font loading API has been refactored to make font resource handling less painful,
to provide smoother HarfBuzz integration and to expose more OpenType tweaks in the API.

To this end, the old ``pyhanko.pdf_utils.font`` module was turned into a package containing three
modules: :mod:`~pyhanko.pdf_utils.font.api`, :mod:`~pyhanko.pdf_utils.font.basic` and
:mod:`~pyhanko.pdf_utils.font.opentype`. The :mod:`~pyhanko.pdf_utils.font.api`
module contains the definitions for the general ``FontEngine`` and ``FontEngineFactory`` classes,
together with some other general plumbing logic.
The :mod:`~pyhanko.pdf_utils.font.basic` module provides a minimalist implementation with a
(non-embedded) monospaced font.
If you need TrueType/OpenType support, you'll need the :mod:`~pyhanko.pdf_utils.font.opentype`
module together with the optional dependencies in the ``[opentype]`` dependency group (currently
``fontTools`` and ``uharfbuzz``, see above).
Take a look at the section for ``pyhanko.pdf_utils.font`` in
:ref:`the API reference documentation <font-api-docs>` for further details.

For the time being, there are no plans to support embedding **Type1** fonts, or to offer support for
**Type3** fonts at all.

Miscellaneous
^^^^^^^^^^^^^

 * The ``content_stream`` parameter was removed from
   :meth:`~pyhanko.pdf_utils.writer.BasePdfFileWriter.import_page_as_xobject`.
   Content streams are now merged automatically, since treating a page content stream array
   non-atomically is a bad idea.
 * :class:`~pyhanko.sign.signers.pdf_signer.PdfSigner` is no longer a subclass of
   :class:`~pyhanko.sign.signers.pdf_signer.PdfTimeStamper`.


New features and enhancements
-----------------------------

Signing
^^^^^^^

 * :ref:`Interrupted signing <interrupted-signing>` workflow: segmented signing workflow that can be
   interrupted partway through and resumed later (possibly in a different process or on a different
   machine). Useful for dealing with signing processes that rely on user interaction and/or remote
   signing services.
 * :ref:`Generic data signing <generic-signing>` support: construct CMS ``signedData`` objects for
   arbitrary data (not necessarily for use in PDF signature fields).
 * Experimental API for signing individual embedded files (nonstandard).
 * PKCS#11 settings can now be set in the configuration file.


Validation
^^^^^^^^^^

 * Add support for validating CMS ``signedData`` structures against arbitrary payloads
   (see also: :ref:`generic-signing`)
 * Streamline CMS timestamp validation.
 * Support reporting on (CAdES) content timestamps in addition to signature timestamps.
 * Allow signer certificates to be identified by the ``subjectKeyIdentifier`` extension.

Encryption
^^^^^^^^^^

 * Support granular crypt filters for embedded files
 * Add convenient API to encrypt and wrap a PDF document as a binary blob. The resulting file
   will open as usual in a viewer that supports PDF collections; a fallback page with alternative
   instructions is shown otherwise.

Miscellaneous
^^^^^^^^^^^^^

 * Complete overhaul of appearance generation & layout system. Most of these changes are internal,
   except for some font loading mechanics (see above). All use of OpenType / TrueType fonts now
   requires the ``[opentype]`` optional dependency group. New features:

     * Use HarfBuzz for shaping (incl. complex scripts)
     * Support TrueType fonts and OpenType fonts without a CFF table.
     * Support vertical writing (among other OpenType features).
     * Use ActualText marked content in addition to ToUnicode.
     * Introduce simple box layout & alignment rules, and apply them uniformly across all layout
       decisions where possible. See :mod:`pyhanko.stamp` and :mod:`pyhanko.pdf_utils.layout` for
       API documentation.

 * Refactored stamp style dataclass hierarchy. This should not affect existing code.
 * Allow externally generated PDF content to be used as a stamp appearance.
 * Utility API for embedding files into PDF documents.
 * Added support for PDF developer extension declarations.


Bugs fixed
----------

Signing
^^^^^^^

 * Declare ESIC extension when producing a PAdES signature on a PDF 1.x file.

Validation
^^^^^^^^^^

 * Fix handling of orphaned objects in diff analysis.
 * Tighten up tolerances for (visible) signature field creation.
 * Fix typo in ``BaseFieldModificationRule``
 * Deal with some VRI-related corner cases in the DSS diffing logic.

Encryption
^^^^^^^^^^

 * Improve identity crypt filter behaviour when applied to text strings.
 * Correct handling of non-default public-key crypt filters.

Miscellaneous
^^^^^^^^^^^^^

 * Promote stream manipulation methods to base writer.
 * Correct some edge cases w.r.t. PDF content import
 * Use floats for MediaBox.
 * Handle escapes in PDF name objects.
 * Correct ToUnicode CMap formatting.
 * Do not close over GSUB when computing font subsets.
 * Fix ``output_version`` handling oversight.
 * Misc. export list & type annotation corrections.


.. _release-0.6.1:

0.6.1
=====

*Release date:* 2021-05-22


Dependency changes
------------------

 - Update ``pyhanko-certvalidator`` to ``0.15.2``
 - Replace constraint on ``certomancer`` and ``pyhanko-certvalidator`` by
   soft minor version constraint (``~=``)
 - Set version bound for ``freezegun``


Bugs fixed
----------

 - Add ``/Q`` and ``/DA`` keys to the whitelist for incremental update analysis
   on form fields.

.. _release-0.6.0:

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


.. _release-0.5.1:

0.5.1
=====

*Release date:* 2021-03-24

Bugs fixed
----------

  * Fixed a packaging blunder that caused an import error on fresh installs.

.. _release-0.5.0:

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

.. _release-0.4.0:

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

.. _release-0.3.0:

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


.. _release-0.2.0:

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

.. _release-0.1.0:

0.1.0
=====

*Release date:* 2020-12-30

Initial release.
