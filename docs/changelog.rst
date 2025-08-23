***************
Release history
***************

-------
pyHanko
-------

.. _release-0.29.1:

0.29.1
======

*Release date:* 2025-06-20


Dependency changes
------------------

 * Bump ``python-pkcs11`` to ``0.8.0``.
 * Relax ``aiohttp`` upper bound to allow ``3.12.x`` and make
   sure we test against the most recent version.


Bugs fixed
----------

 * Correct buggy behaviour when reauthenticating with a security handler.
 * Fix registration of multiple extensions in encrypted files.
 * Tolerate key usage violations when the signer is a trust anchor.
 * Remove unnecessary 3.8 compatibility code.
 * Make it easier to customise PKCS#11 queries


.. _release-0.29.0:

0.29.0
======

*Release date:* 2025-05-27


Breaking changes
----------------

 * The root ``pyhanko`` package is now a namespace package.
    * The ``pyhanko.keys`` and ``pyhanko.stamp`` modules were turned into packages, exposing the same API in their
      respective ``__init__.py``, so this change is source-compatible.
    * The ``__version__`` and ``__version_info__`` attributes are no longer exposed at the root package
      level, but have been moved into ``pyhanko.version`` (which was also turned into a subpackage).
 * Drop dependency on ``click`` in ``pyhanko`` distribution, move CLI code into ``pyhanko-cli`` instead.
    * The CLI code still installs as ``pyhanko.cli`` in the package hierarchy.
    * There are no code-level changes for CLI plugins other than the requirement to add a dependency on ``pyhanko-cli``.
      In principle, this allows "old" plugins to keep working without needing a re-release as long as ``pyhanko-cli``
      is installed together with ``pyhanko``.
 * Make the dependency on ``qrcode`` optional (in the new ``[qr]`` dependency group)
 * Replace ``defusedxml`` with a dependency on ``lxml``, configured appropriately. This was done in anticipation of
   some future feature work that will require a dependency on ``lxml`` either way.


.. _release-0.28.0:

0.28.0
======

*Release date:* 2025-05-24


Breaking changes
----------------

 * Drop support for Python 3.8


Dependency changes
------------------

 * Retool repository structure as ``uv`` multi-project workspace.
 * Include ``pyhanko-certvalidator`` as subproject.
 * Remove dev-only & testing dependencies from package metadata.


Bugs fixed
----------

 * Fix error in SHA-3 detection when determining whether to include
   the ISO/TS 32001 extension metadata.


.. _release-0.27.1:

0.27.1
======

*Release date:* 2025-05-14


New features and enhancements
-----------------------------

 * Reinstated support for decrypting files using public-key encryption
   where 3DES or RC2 are used as the envelope encryption algorithm.
   The new integration uses ``pyca/cryptography``'s ``decrepit`` subpackage
   instead of ``oscrypto``.


.. _release-0.27.0:

0.27.0
======

*Release date:* 2025-05-12


Dependency changes
------------------

 * Relax ``uharfbuzz`` upper bound to ``<0.51.0``.
 * Constrain ``click`` to ``<8.2.0`` while we address breaking changes.
 * Bump test dependencies.


New features and enhancements
-----------------------------

Layout
^^^^^^

 * Allow choosing whether to apply stamps in the page's default coordinate system, or
   in the frame of reference that is active at the end of the page's content stream.
   The former is now the default.


Bugs fixed
----------

 * Fix handling of "plugin unavailable" error.
 * Clear ``/NeedAppearances`` when putting in a signature.


.. _release-0.26.0:

0.26.0
======

*Release date:* 2025-03-08


Breaking changes
----------------

 * Some outdated algos for encrypting the security handler seed in
   a public-key encrypted PDF were dropped to get rid of ``oscrypto``
   as a direct dependency of ``pyhanko``. It is still pulled in
   via ``pyhanko-certvalidator``, but it is no longer used for
   any cryptographic operations (which is significant, because
   of compatibility issues on systems that no longer ship OpenSSL 1.1.1)


Dependency changes
------------------

 * Relax ``uharfbuzz`` upper bound to ``<0.47.0``.
 * Make ``defusedxml`` a regular dependency, remove ``[xmp]`` dependency group.
 * Remove ``[extra-pubkey-algs]`` dependency group (see breaking change list)



New features and enhancements
-----------------------------

 * Expose ``signature_mechanism`` parameter in PKCS#11 API.


.. _release-0.25.3:

0.25.3
======

*Release date:* 2024-11-17

Dependency changes
------------------

 * Workflow dependency bumps
 * Set ``aiohttp`` upper bound to ``3.12``
 * Bump ``pyhanko-certvalidator`` to ``0.26.5``
 * Bump ``certomancer`` to ``0.12.3``

Note: these changes make pyHanko compatible with the (unreleased) API change in
`asn1crypto #230 <https://github.com/wbond/asn1crypto/issues/230>`_,
which is nevertheless already being shipped in some distros.


.. _release-0.25.2:

0.25.2
======


*Release date:* 2024-11-11


Dependency changes
------------------

 * Bump minimal ``cryptography`` version to ``43.0.3``.
 * Update ``uharfbuzz`` upper bound to ``0.42.0``.
 * Add Python 3.13 to the package metadata & include it in CI.
 * Some test dependencies bumped.

Bugs fixed
----------

 * Properly propagate ``strict=False`` in post-signing instructions.


.. _release-0.25.1:

0.25.1
======


*Release date:* 2024-07-18


Bugs fixed
----------

 * Align usage of SHAKE256 OIDs with Ed448 with RFC 8419


.. _release-0.25.0:

0.25.0
======


*Release date:* 2024-05-06


New features and enhancements
-----------------------------


Encryption
^^^^^^^^^^

 * Implement ISO/TS 32003 and ISO/TS 32004, to support AES-GCM streams and
   MAC authentication in encrypted PDF 2.0 documents, respectively.
   MACs are turned on by default when creating documents with PDF 2.0-style
   encryption.


.. _release-0.24.0:

0.24.0
======


*Release date:* 2024-04-27


Breaking changes
----------------

  * Setting & retrieving permission flags for encrypted files now
    comes with an ergonomic API that is much less error-prone.
    You no longer have to manually convert your permission bits
    to their signed integer representation.
    See :mod:`pyhanko.pdf_utils.crypt.permissions`.

Dependency changes
------------------

 * Upgraded ``xsdata`` (optional) to ``24.4``.


Bugs fixed
----------

 * Several issues with copying objects from encrypted documents
   (in particular, encrypted documents with signatures) have been fixed.
 * Tolerate unpadded empty ciphertext.
 * Improve error messages on malformed keys.


.. _release-0.23.2:

0.23.2
======


*Release date:* 2024-03-25


Dependency changes
------------------

 * Upgraded ``certomancer`` dependency for tests to ``0.12.0``.
 * Upgraded ``pytest-asyncio`` tot ``0.23.6``.


Bugs fixed
----------

 * Fix handling of "OAEP preferred" flag when encrypting documents with a public key.
 * Fix endianness issue when reading & writing permissions in documents encrypted with a public key.
 * Tolerate **AcroForm**s without a **Fields** entry.
 * Increase resilience against issues with ``oscrypto``.


.. _release-0.23.1:

0.23.1
======


*Release date:* 2024-03-14


Bugs fixed
----------

 * Fix a regression in the way PKCS#11 objects are loaded.


.. _release-0.23.0:

0.23.0
======

*Release date:* 2024-03-10


Breaking changes
----------------

 * The BeID signer implementation and CLI command was moved into a separate
   package; see
   `pyhanko-beid-plugin <https://github.com/MatthiasValvekens/pyhanko-beid-plugin>`_.
   While this integration was so far preserved in the core tree for
   historical reasons, pyHanko has matured beyond this kind of vendor/country-specific
   code. Note that CLI invocations will continue to work unchanged as long as
   ``pyhanko-beid-plugin`` is installed alongside pyHanko, thanks to Python's
   package entry point mechanism.



.. _release-0.22.0:

0.22.0
======

*Release date:* 2024-03-07


Dependency changes
------------------

 * Relax upper bounds on ``xsdata`` and ``uharfbuzz``.
 * ``cryptography` to ``42.0.1``
 * Get rid of ``pytest-runner``


New features and enhancements
-----------------------------

Signing
^^^^^^^

 * Relax processing of PKCS#11 options, setting better defaults so
   users have to write less config to select their key/certificate.
   (see `PR #296 <https://github.com/MatthiasValvekens/pyHanko/issues/296>`_)


CLI
^^^

 * Add ``timestamp`` command to CLI to add a document timestamp without
   performing any PAdES validation.


Bugs fixed
----------

 * Gracefully handle lack of ``/Type`` entry in signature objects vailidation.

.. _release-0.21.0:

0.21.0
======

*Release date:* 2023-11-26


Dependency changes
------------------

 * Bumped the minimal supported Python version to 3.8 (dropping 3.7).
 * Bumped the lower bound on ``qrcode`` to ``7.3.1``.
 * Bumped ``pyhanko-certvalidator`` to ``0.26.x``.
 * Bumped the lower bound on ``click`` to ``8.1.3``.
 * Bumped the lower bound on ``requests`` to ``2.31.0``.
 * Bumped the lower bound on ``pyyaml`` to ``6.0``.
 * Bumped the lower bound on ``cryptography`` to ``41.0.5``.
 * Bumped ``aiohttp`` to ``3.9.x``.
 * Bumped ``certomancer-csc-dummy`` test dependency to ``0.2.3``.
 * Introduced new dependency group ``etsi`` with ``xsdata`` for features
   implementing functionality from AdES and related ETSI standards.


New features and enhancements
-----------------------------

Signing
^^^^^^^

 * Add support for ``/ContactInfo``, ``/Prop_AuthTime`` and ``/Prop_AuthType``.


Validation
^^^^^^^^^^

 * Experimental support for AdES validation reports (requires new ``etsi`` optional deps)
 * New API function for simulating PAdES-LTA validation at a time in the future;
   see :func:`~pyhanko.sign.validation.ades.simulate_future_ades_lta_validation`.
 * Add support for asserting the nonrevoked status of a certificate chain.


CLI
^^^

 * Add ``--resave`` flag to ``addfields`` subcommand.


Bugs fixed
----------

 * Fixed an oversight in the serialisation of the ``/ByteRange`` entry
   in a signature that prevented large documents from being signed correctly.
 * Various adjustments to the (still experimental) AdES validation API.
 * Various local documentation fixes.
 * PDF signatures that do not omit the ``eContent`` field in their encapsulated
   content info are now rejected as invalid.


Miscellaneous
-------------

 * Include PyPDF2 licence file in package metadata.
 * Cleaned up loading logic in :class:`~pyhanko.pdf_utils.reader.PdfFileReader`.
   The most important impact of this change is that structural errors in the
   encryption dictionary will now cause exceptions to be thrown when decryption
   is attempted, not in the ``__init__`` function.


.. _release-0.20.1:

0.20.1
======

*Release date:* 2023-09-17

Dependency changes
------------------

 * Upgrade ``pyhanko-certvalidator`` to ``0.24.x``


Miscellaneous
-------------

 * Tolerate missing ``D:`` in date strings (see `PR #296 <https://github.com/MatthiasValvekens/pyHanko/issues/296>`_).
 * Various minor documentation improvements.
 * Release workflow dependency bumps and minor improvements.


.. _release-0.20.0:

0.20.0
======

*Release date:* 2023-07-28


Dependency changes
------------------

 * Relax upper bound on ``uharfbuzz`` to ``<0.38.0`` (allows more users to benefit from prebuilt wheels)
 * Bump ``python-barcode`` from ``0.14.0`` to ``0.15.1``.
 * Bump ``pytest-asyncio`` from ``0.21.0`` to ``0.21.1``.
 * Relax ``pytest-cov`` bound to allow ``4.1.x``


Miscellaneous
-------------

 * Various minor documentation improvements.
 * Improved unit test coverage, especially for error handling.


.. _release-0.19.0:

0.19.0
======

*Release date:* 2023-06-18


Dependency changes
------------------

 * Bump ``pyhanko-certvalidator`` to ``0.23.0``
 * ``certomancer`` updated to ``0.11.0``, ``certomancer-csc-dummy`` to ``0.2.2``


Breaking changes
----------------

 * Minor reorganisation of the :class:`~pyhanko.pdf_utils.crypt.pubkey.EnvelopeKeyDecrypter`.
   The change moves the ``cert`` property from an attribute to an abstract property, and adds
   a method to allow us to handle protocols based on key agreement in addition to key transport.
   Implementations need not implement both.
 * Move ``ignore_key_usage`` into to new
   :class:`~pyhanko.pdf_utils.crypt.pubkey.RecipientEncryptionPolicy` class.


New features and enhancements
-----------------------------

Encryption
^^^^^^^^^^

 * Support RSAES-OAEP for file encryption with the public-key security handler.
   This is not widely supported by PDF viewers in the wild.
 * Support some ECDH-based key exchange methods for file encryption with the
   public-key security handler. Concretely, pyHanko now supports
   the ``dhSinglePass-stdDH-sha*kdf`` family from RFC 5753, which is also implemented in
   Acrobat (for NIST curves). X25519 and X448 are also included.


CLI
^^^

 * Better UX for argument errors relating to visible signature creation.


Bugs fixed
----------

 * Allow processing OCSP responses without ``nextUpdate``.
 * Run non-cryptographic CLI commands in nonstrict mode.
 * Treat nulls the same as missing entries in dictionaries, as required by
   the standard.
 * Fix several default stamp style selection issues in CLI


.. _release-0.18.1:

0.18.1
======

*Release date:* 2023-04-29


Dependency changes
------------------

 * Remove dependency on ``pytz`` with fallback to ``backports.zoneinfo``
 * Bump ``tzlocal`` version to ``4.3``.
 * Do not rely on deprecated timezone API anymore in the tests.
   See `PR #257 <https://github.com/MatthiasValvekens/pyHanko/pull/257>`_.

.. _release-0.18.0:

0.18.0
======

*Release date:* 2023-04-26

Note
----

This is largely a maintenance release in the sense that it adds relatively little
in the way of core features, but it nevertheless comes with some major
reorganisation and work to address technical debt.

This release also marks pyHanko's move to beta status. That doesn't mean that
it's feature-complete in every respect, but it does mean that we've now entered
a stabilisation phase in anticipation of the ``1.0.0`` release, so until then
the focus will be on fixing bugs and clearing up issues in the documentation (in
particular regarding the API contract). After the ``1.0.0`` release, pyHanko
will simply follow SemVer.


Breaking changes
----------------

Some changes have been made to the :class:`~pyhanko.sign.signers.pdf_cms.Signer` class.
For all practical purposes, these are mostly relevant for custom
:class:`~pyhanko.sign.signers.pdf_cms.Signer` implementations. Regular users should see
fairly little impact.

 * The arguments to ``__init__`` have been made keyword-only.

 * Several attributes have been turned into read-only properties:

    * :attr:`~pyhanko.sign.signers.pdf_cms.Signer.signing_cert`
    * :attr:`~pyhanko.sign.signers.pdf_cms.Signer.cert_registry`
    * :attr:`~pyhanko.sign.signers.pdf_cms.Signer.attribute_certs`
    * :attr:`~pyhanko.sign.signers.pdf_cms.Signer.signature_mechanism`

   This change was made to better reflect the way the properties were used internally, and made it easier to set
   expectations for the API: it doesn't make sense to allow arbitrary modifications to these properties for all
   :class:`~pyhanko.sign.signers.pdf_cms.Signer` implementations.
   The parameters to ``__init__`` have been extended to allow setting defaults more cleanly.
   Implementation-wise, the properties are backed by an underscored internal variable
   (e.g. ``_signing_cert`` for ``signing_cert``).
   Subclasses can of course still elect to make some of these read-only properties writable by declaring setters.

 * ``get_signature_mechanism`` was renamed to
   :meth:`~pyhanko.sign.signers.pdf_cms.Signer.get_signature_mechanism_for_digest`
   to make it more clear that it does more than just fetch the underlying value of
   :attr:`~pyhanko.sign.signers.pdf_cms.Signer.signature_mechanism`.


Concretely, this means that init logic of the form

.. code-block:: python

    class MySigner(Signer):
        def __init__(
            self,
            signing_cert: x509.Certificate,
            cert_registry: CertificateStore,
            *args, **kwargs
        ):
            self.signing_cert = signing_cert
            self.cert_registry = cert_registry
            self.signature_mechanism = signature_mechanism
            super().__init__()

needs to be rewritten as

.. code-block:: python

    class MySigner(Signer):
        def __init__(
            self,
            signing_cert: x509.Certificate,
            cert_registry: CertificateStore,
            *args, **kwargs
        ):
            self._signing_cert = signing_cert
            self._cert_registry = cert_registry
            self._signature_mechanism = signature_mechanism
            super().__init__()

or, alternatively, as

.. code-block:: python

    class MySigner(Signer):
        def __init__(
            self,
            signing_cert: x509.Certificate,
            cert_registry: CertificateStore,
            *args, **kwargs
        ):
            super().__init__(
                signing_cert=signing_cert,
                cert_registry=cert_registry,
                signature_mechanism=signature_mechanism
            )


Other than these, there have been some miscellaneous changes.

 * The CLI no longer allows signing files encrypted using public-key encryption targeted towards the signer's
   certificate, because that feature didn't make much sense in key management terms, was rarely used, and hard to
   integrate with the new plugin system.
 * APIs with ``status_cls`` parameters have made certain args keyword-only for strict type checking purposes.
 * Move ``add_content_to_page`` to :meth:`~pyhanko.pdf_utils.content.PdfContent.add_to_page` to deal with a
   (conceptual) circular dependency between modules.
 * :class:`~pyhanko_certvalidator.registry.CertificateStore` is no longer reexported by :mod:`pyhanko.sign.general`.
 * The ``BEIDSigner`` no longer allows convenient access to the authentication certificate.
 * Packaging-wise, underscores have been replaced with hyphens in optional dependency groups.
 * In ``pyhanko_certvalidator``, :class:`~pyhanko_certvalidator.errors.InvalidCertificateError`
   is no longer a subclass of :class:`~pyhanko_certvalidator.errors.PathValidationError`.

Finally, some internal refactoring took place as well:

 * The ``cli.py`` module was refactored into a new subpackage (:mod:`pyhanko.cli`) and is now
   also tested systematically.
 * CLI config classes have been refactored, some configuration was moved to the new :mod:`pyhanko.config` package.
 * Time tolerance config now passes around timedelta objects instead of second values.
 * The :func:`~pyhanko.sign.diff_analysis.commons.qualify` function in the difference analysis
   has been split into :func:`~pyhanko.sign.diff_analysis.commons.qualify` and
   :func:`~pyhanko.sign.diff_analysis.commons.qualify_transforming`.


Organisational changes
----------------------

 * Certificate and key loading was moved to a new :mod:`pyhanko.keys` module, but :mod:`pyhanko.sign.general`
   still reexports the relevant functions for backwards compatibility.
   Concretely, the affected functions are

    * :func:`pyhanko.keys.load_cert_from_pemder`,
    * :func:`pyhanko.keys.load_certs_from_pemder`,
    * :func:`pyhanko.keys.load_certs_from_pemder_data`,
    * :func:`pyhanko.keys.load_private_key_from_pemder`,
    * :func:`pyhanko.keys.load_private_key_from_pemder_data`.

  * Onboarded ``mypy`` and flag pyHanko as a typed library by adding ``py.typed``.

  * Package metadata and tooling settings have now been centralised to ``pyproject.toml``.
    Other configuration files like ``setup.py``, ``requirements.txt`` and most tool-specific config
    have been eliminated.

  * The docstring-based documentation for ``pyhanko_certvalidator`` was added to the API reference.

  * Some non-autogenerated API reference documentation pages were consolidated to reduce the sprawl.

  * Heavily reworked the CI/CD pipeline. PyHanko releases are now published via GitHub Actions
    and signed with Sigstore. GPG signatures will continue to be provided for the time being.


Dependency changes
------------------

 * Bump ``pyhanko-certvalidator`` to ``0.22.0``.
 * Relax the upper bound on ``uharfbuzz`` for better Python 3.11 support

Bugs fixed
----------

 * The AdES LTA validator now tolerates documents that don't have a DSS (assuming
   that all the required information is otherwise present).
 * Ensure that the :attr:`~pyhanko.sign.validation.status.SignatureStatus.trusted`
   attribute on :class:`~pyhanko.sign.validation.status.SignatureStatus` is not set
   if the validation path is not actually available.
 * Correct the typing on
   :attr:`~pyhanko.sign.validation.status.SignatureStatus.validation_path`.
 * Fix several result presentation bugs in the AdES code.
 * Fix overeager sharing of :class:`~pyhanko_certvalidator.ltv.poe.POEManager` objects in AdES code.
 * Correct algo policy handling in AdES-with-time validation.
 * Ensure that ``container_ref`` is also populated on past versions of the
   trailer dictionary.


New features and enhancements
-----------------------------

Signing
^^^^^^^

 * :ref:`The CLI now features plugins <cli-plugin-dev>`!
   All current ``addsig`` subcommands have been reimplemented to use the plugin
   interface. Other plugins will be auto-detected through package entry points.


Validation
^^^^^^^^^^

 * Refine algorithm policy handling; put in place a subclass of
   :class:`~pyhanko_certvalidator.policy_decl.AlgorithmUsagePolicy` specifically
   for CMS validation;
   see :class:`~pyhanko.sign.validation.utils.CMSAlgorithmUsagePolicy`.
 * Try to remember paths when validation fails.
 * Make certificates from local CMS context available during path building
   for past certificate validation (subject to PoE checks).
 * Move :attr:`~pyhanko.sign.validation.status.ModificationInfo.docmdp_ok` up in
   the hierarchy to :class:`~pyhanko.sign.validation.status.ModificationInfo`.



.. _release-0.17.2:

0.17.2
======


*Release date:* 2023-03-10


Note
----

This is a follow-up on yesterday's bugfix release, addressing a number of similar issues.


Bugs fixed
----------

 * Address another potential infinite loop in the comment processing logic.
 * Fix some (rather esoteric) correctness issues w.r.t. PDF whitespace.


.. _release-0.17.1:

0.17.1
======


*Release date:* 2023-03-09


Note
----

This is a maintenance release without significant functionality changes.
It contains a bugfix, addresses some documentation issues and applies the Black
formatter to the codebase.


Bugs fixed
----------

 * Address a potential infinite loop in the PDF parsing logic.
   See `PR #237 <https://github.com/MatthiasValvekens/pyHanko/issues/237>`_.


.. _release-0.17.0:

0.17.0
======


*Release date:* 2023-01-31


Note
----

This is a bit of an odd release. It comes with relatively few functional
changes or enhancements to existing features, but it has nevertheless been
in the works for quite a long time.

In early 2022, I decided that the time was right to equip pyHanko with its
own AdES validation engine, implementing the machinery specified by
ETSI EN 319 102-1. I knew ahead of time that this would not be an easy task:

 * PyHanko's own validation code was put together in a fairly ad-hoc manner
   starting from the provisions in the CMS specification, so some refactoring
   would be necessary.
 * ``pyhanko-certvalidator`` also was never designed to be anything more than an
   RFC 5280 validation engine, and retrofitting the fine-tuning required by the
   AdES spec definitely wasn't easy.

Initially, I estimated that this effort would take a few months tops. Yet here
we are, approximately one year down the road: :mod:`pyhanko.sign.validation.ades`.

Truth be told, the implementation isn't yet ready for prime time, but it is in
a state where it's at least useful for experimentation purposes, and can be
iterated on.
Also, given the volume of subtle changes and far-reaching refactoring in the
internals of both the ``pyhanko`` and ``pyhanko-certvalidator`` packages,
continually rebasing the ``feature/ades-validation`` feature branch turned
into a chore quite quickly.

So, if you're keen to start playing around with AdES validation: please do so,
and let me know what you think. If standards-based validation is not something
you care about, feel free to disregard everything I wrote above, it almost
certainly won't affect any of your code.

My plan is to incrementally build upon and polish the code in
:mod:`pyhanko.sign.validation.ades`, and eventually deprecate the current
ad-hoc LTV validation logic in
:func:`pyhanko.sign.validation.ltv.async_validate_pdf_ltv_signature`.
That's still a ways off from now, though.


Dependency updates
------------------

 * ``pyhanko-certvalidator`` updated to ``0.20.0``


Breaking changes
----------------

 * There are various changes in the validation internals that are not
   backwards compatible, but all of those concern internal APIs.
 * There are some noteworthy changes to the ``pyhanko-certvalidator`` API.
   Those are documented in
   :ref:`the change log <certvalidator-release-0.20.0>`.
   Most of these do not affect basic usage.


New features and enhancements
-----------------------------

Validation
^^^^^^^^^^

 * Experimental AdES validation engine :mod:`pyhanko.sign.validation.ades`.
 * In the status API, make a more meaningful distinction between ``valid`` and
   ``intact``, and document that distinction.


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
   :class:`~pyhanko.cli.config.PKCS11SignatureConfig`, but will still be parsed
   (with a deprecation warning).
 * The :attr:`~pyhanko.cli.config.PKCS11SignatureConfig.prompt_pin` attribute in
   :class:`~pyhanko.cli.config.PKCS11SignatureConfig` was changed from a bool to
   an enum. See :class:`~pyhanko.cli.config.PKCS11PinEntryMode`.


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
   :class:`~pyhanko.cli.config.TokenCriteria`
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


---------------------
pyhanko-certvalidator
---------------------


.. _certvalidator-release-0.27.0:

0.27.0
======

*Release date:* 2025-05-24

 * Integrated into pyHanko repository as separate sub-package.
 * No functional changes.


.. _certvalidator-release-0.26.8:

0.26.8
======

*Release date:* 2025-03-15

 * Fixed bug where an HTTP(S) CRL URI appearing next to
   an LDAP one as part of the same DP entry would not
   always be picked up.
 * Dramatically improved processing speed for large CRLs.


.. _certvalidator-release-0.26.7:

0.26.7
======

*Release date:* 2025-03-12

 * No functional changes.


.. _certvalidator-release-0.26.6:

0.26.6
======

*Release date:* 2025-03-12

 * Drop Python 3.7
 * List ``qcStatements`` as a known extension


.. _certvalidator-release-0.26.5:

0.26.5
======

*Release date:* 2024-11-17

 * Future-proofing against an upcoming ``asn1crypto``
   that is already being shipped in some distro
   packages.
 * Address some timing issues in tests.


.. _certvalidator-release-0.26.4:

0.26.4
======

*Release date:* 2024-11-12

 * Bump ``aiohttp`` requirement to ``>=3.8,<3.11``.
 * Declare support for Python 3.12 and 3.13


.. _certvalidator-release-0.26.3:

0.26.3
======

*Release date:* 2023-12-13

 * Bump ``aiohttp`` requirement to ``>=3.8,<3.10``.
 * Address two certificate fetching issues.
 * Tolerate CMS certificate-only message in response
   without ``Content-Type``.
 * Deal with implicit reliance on order of certs when
   processing such messages.


.. _certvalidator-release-0.26.2:

0.26.2
======

*Release date:* 2023-11-18

 * Bump some dependency versions.


.. _certvalidator-release-0.26.1:

0.26.1
======

*Release date:* 2023-11-18

 * Handle nonspecific OCSP validation errors cleanly during validation.


.. _certvalidator-release-0.26.0:

0.26.0
======

*Release date:* 2023-11-14


 * Fix error reporting on banned algorithms in some cases
 * Allow caller to assert revocation status of a cert
 * More refined POE information tracking in experimental AdES API


.. _certvalidator-release-0.25.0:

0.25.0
======

*Release date:* 2023-10-06

 * Introduce a more precise error type to signal stale revocation
   information.


.. _certvalidator-release-0.24.1:

0.24.1
======

*Release date:* 2023-09-17


 * Ignore content types altogether when fetching certificates
   and the response payload is PEM.


.. _certvalidator-release-0.24.0:

0.24.0
======

*Release date:* 2023-09-07

 * Further increase leniency regarding content types when fetching
   certificates on-the-fly
 * Add SLSA provenance data to releases
 * Various updates in test dependencies and CI workflow dependencies.


.. _certvalidator-release-0.23.0:

0.23.0
======

*Release date:* 2023-05-14

 * Improve processing of OCSP responses without ``nextUpdate``
 * Some more package metadata & release flow tweaks


.. _certvalidator-release-0.22.0:

0.22.0
======

*Release date:* 2023-04-23

 * No implementation changes compared to ``0.21.2``
 * Renamed ``async_http`` dependency group to ``async-http``.
 * Move towards automated GitHub Actions-based release flow
   as a move towards better process standardisation.
 * Sign release artifacts with Sigstore.


.. _certvalidator-release-0.21.2:

0.21.2
======

*Release date:* 2023-04-17

 * Fix a typing issue caused by a typo in the ``requests`` cert fetcher.
 * Removed a piece of misbehaving and duplicative logic in the
   revocation freshness checker.


.. _certvalidator-release-0.21.1:

0.21.1
======

*Release date:* 2023-04-02

 * Fix ``DisallowedAlgorithmError`` parameters.
 * Preserve timestamp info in expiration-related errors.
 * Disable algo enforcement in prima facie past validation checks.
 * Correct a misunderstanding in the interaction between the AdES code and
   the old "retroactive revinfo" setting.


.. _certvalidator-release-0.21.0:

0.21.0
======

*Release date:* 2023-04-01

 * Switch to ``pyproject.toml`` to manage project metadata.
 * Path validation errors now carry information about the paths that triggered them.
 * ``InvalidCertificateError`` is no longer a subclass of ``PathValidationError``, only of
   ``ValidationError``. This is a minor but nonetheless breaking change.


.. _certvalidator-release-0.20.1:

0.20.1
======

*Release date:* 2023-02-21

Minor maintenance release without functional changes, only to metadata, documentation and typing.

.. _certvalidator-release-0.20.0:

0.20.0
======

*Release date:* 2023-01-23

This is a big release, with many breaking changes in the "deeper" APIs.
The impact on the high-level API should be small to nonexistent, but caution when upgrading is advised.

 * More uniform and machine-processable errors.
 * Move towards a setup using "policy objects" that can be used to
   construct ``ValidationContext`` objects in a systematic way.
 * Move revinfo gathering to a separate revinfo manager class. Some arguably
   internal methods on ``ValidationContext`` were moved to the ``RevinfoManager`` class.
 * Incubating API for AdES validation primitives (freshness, POE handling, more
   sophisticated revinfo gathering, time slide) and some certificate-related
   validation routines.
 * Introduce a more fully-fledged API to manage permissible algorithms.
 * Broaden trust root provisioning beyond certificates: trust roots
   can now have qualifiers, and be provisioned as a name-key pair as opposed
   to a (self-signed) certificate. This implies breaking changes for
   ``ValidationPath``.
   In general, issuance semantics in the internals are now expressed through
   the ``Authority`` API as much as possible.
 * In the same vein, ``CertificateRegistry`` was refactored into ``TrustManager``,
   ``CertificateRegistry`` and ``PathBuilder``. These are respectively responsible
   for managing trust, maintaining the certificate cache, and building paths.
 * Thorough clean-up of legacy dev tooling; put in place ``mypy`` and ``black``,
   move to ``pytest``, get rid of ``pretty_message`` in favour of f-strings.


.. _certvalidator-release-0.19.8:

0.19.8
======

*Release date:* 2022-12-20

 * Fix double encoding when generating OCSP nonces


.. _certvalidator-release-0.19.7:

0.19.7
======

*Release date:* 2022-12-11

 * Make certificate fetcher more tolerant (see #2)


.. _certvalidator-release-0.19.6:

0.19.6
======

*Release date:* 2022-10-27

 * Update ``asn1crypto`` to ``1.5.1``
 * Declare Python 3.11 support


.. _certvalidator-release-0.19.5:

0.19.5
======

*Release date:* 2022-03-08

 * Maintenance update to bump ``asn1crypto`` to ``1.5.0`` and get rid of a number of
   compatibility shims for fixes that were upstreamed to ``asn1crypto``.


.. _certvalidator-release-0.19.4:

0.19.4
======

*Release date:* 2022-02-10

 * Fix improper error handling when dealing with expired or not-yet-valid
   attribute certificates.


.. _certvalidator-release-0.19.3:

0.19.3
======

*Release date:* 2022-02-03

 * Correct and improve behaviour of certificate fetcher when the
   server does not supply a Content-Type header.

.. _certvalidator-release-0.19.2:

0.19.2
======

*Release date:* 2021-12-22

 * Patch ``asn1crypto`` to work around tagging issue in AC issuer field


.. _certvalidator-release-0.19.1:

0.19.1
======

*Release date:* 2021-12-22

 * Properly enforce algo matching in AC validation


.. _certvalidator-release-0.19.0:

0.19.0
======

*Release date:* 2021-12-14

 * Attribute certificate validation support
 * Support for ``AAControls`` extension
 * Refactored OCSP and CRL logic to work with attribute certificate validation
 * Many nominal type checks removed in favour of type annotations
 * Many API entry points now accept both ``asn1crypto.x509.Certificate`` and ``asn1crypto.cms.AttributeCertificateV2``
 * Minor breaking change: ``bytes`` is no longer acceptable as a substitute for ``asn1crypto.x509.Certificate`` in the public API


.. _certvalidator-release-0.18.1:

0.18.1
======

*Release date:* 2021-12-04

 * Various improvements to error handling in certificate fetchers


.. _certvalidator-release-0.18.0:

0.18.0
======

*Release date:* 2021-11-26

 * Replace ``revocation_mode`` with more flexible revocation policy controls,
   aligned with ETSI TS 119 172. Old ``revocation_mode`` params will be transparently
   translated to corresponding 'refined' policies, but the ``revocation_mode`` property
   on ``ValidationContext`` was removed.
 * Handle soft fails as part of revocation policies. Concretely, this means that the
   ``SoftFailError`` exception type was removed. Exceptions arising from quashed
   'soft' failures can still be retrieved via the ``soft_fail_exceptions`` property
   on ``ValidationContext`` instances; the resulting list can contain any exception type.
 * Fix various hiccups in CRL and OCSP handling.


.. _certvalidator-release-0.17.4:

0.17.4
======

*Release date:* 2021-11-13

 * Fix mistaken assumption when a certificate's MIME type is announced as ``application/x-x509-ca-cert``.
 * Update aiohttp to 3.8.0


.. _certvalidator-release-0.17.3:

0.17.3
======

*Release date:* 2021-10-28

 * Fix a deadlocking bug caused by improper exception handling
   in the fetcher code.
 * Exceptions are now communicated to fetch jobs waiting for results.


.. _certvalidator-release-0.17.2:

0.17.2
======

*Release date:* 2021-10-19

 * Replace ``run_until_complete()`` with ``asyncio.run()`` for better
   event loop state management.


.. _certvalidator-release-0.17.1:

0.17.1
======

*Release date:* 2021-10-11

 * Fixes a packaging error in ``0.17.0``


.. _certvalidator-release-0.17.0:

0.17.0
======

*Release date:* 2021-10-11

.. warning::
    **This release contains breaking changes in lower-level APIs.**
    High-level API functions should continue to work as-is, although some have been deprecated.
    However, the rewrite of the CRL & OCSP fetch logic breaks compatibility with the previous
    version's API.

 * Refactor OCSP/certificate/CRL fetch logic to be more modular and swappable.
 * Automatically fetch missing issuer certificates if there is an AIA record indicating where to
   find them
 * Favour asynchronous I/O throughout the API. ``CertificateValidator.validate_usage``,
   ``CertificateValidator.validate_tls`` and the ``ValidationContext.retrieve_XYZ`` methods were
   deprecated in favour of their asynchronous equivalents.
 * Support two backends for fetching revocation information and certificates: ``requests`` (legacy)
   and ``aiohttp`` (via the ``async-http`` optional dependency group).
 * It is expected that using ``aiohttp`` fetchers will yield better performance with the
     asynchronous APIs, but as these require some resource management on the caller's part,
     ``requests`` is still the default.
 * Fetcher backends can be swapped out by means of the ``fetcher_backend`` argument to
     ``ValidationContext``.


.. _certvalidator-release-0.16.0:

0.16.0
======

*Release date:* 2021-08-22

 * Refactor CertificateRegistry
 * Change OCSP responder cert selection procedure to give priority to certificates embedded into
   the response data (if there are any).


.. _certvalidator-release-0.15.3:

0.15.3
======

*Release date:* 2021-07-25

 * Short-circuit anyPolicy when reporting policies
 * Export PKIXValidationParams
 * Limit CRL client to HTTP-based URLs


.. _certvalidator-release-0.15.2:

0.15.2
======

*Release date:* 2021-05-22

 * Properly handle missing Content-Type header in server response when fetching CA certificates
   referenced in a CRL.


.. _certvalidator-release-0.15.1:

0.15.1
======

*Release date:* 2021-05-12

 * Gracefully handle lack of thisUpdate / nextUpdate in OCSP responses.


.. _certvalidator-release-0.15.0:

0.15.0
======

*Release date:* 2021-05-09

 * Use ``pyca/cryptography`` for signature validation. ``oscrypto`` is still included
   to access the system trust list.
 * Support RSASSA-PSS and EdDSA certificates.
 * Support name constraints.
 * Support all input parameters to the PKIX validation algorithm (acceptable policy set, policy mapping inhibition, ...).
 * Further increase PKITS coverage.

.. _certvalidator-release-0.14.1:

0.14.1
======

*Release date:* 2021-04-03

 * No code changes, rerelease because distribution package was polluted due to improper build
   cache cleanup.


.. _certvalidator-release-0.14.0:

0.14.0
======

*Release date:* 2021-04-03

 * Raise RequestError if CRL / OCSP client returns a status code other than 200.
   Previously, this would fail with a cryptic ASN.1 deserialisation error instead.
 * Rename Python package to ``pyhanko_certvalidator`` to avoid the potential name conflict
   with the upstream ``certvalidator`` package.


.. _certvalidator-release-0.13.1:

0.13.1
======

*Release date:* 2021-03-24

 * Consider SHA-1 weak by default, and do not hard-code the list of potential weak hash algos.


.. _certvalidator-release-0.13.0:

0.13.0
======

*Release date:* 2021-03-19

 * Added an optional ``retroactive_revinfo`` flag to ``ValidationContext`` to ignore the
   ``thisUpdate`` field in OCSP responses and CRLs.
   The effect of this is that CRLs and OCSP responses are also considered valid
   for point-in-time validation with respect to a time in the past.
   This is useful for some validation profiles. The default state of the flag
   remains ``False`` nonetheless.


.. _certvalidator-release-0.12.1:

0.12.1
======

*Release date:* 2020-12-05

 * Fixed a packaging error.


.. _certvalidator-release-0.12.0:

0.12.0
======

*Release date:* 2020-12-05

 * Forked from `certvalidator <https://github.com/wbond/certvalidator>`_.
   to add patches for pyHanko.
 * Replaced urllib calls with ``requests`` library for universal mocking.
 * Added a ``time_tolerance`` parameter to the validation context to allow for
   some time drift on CRLs and OCSP responses.
 * Deal with no-matches on OCSP and CRLs strictly in hard-fail mode.
 * Drop support for Python 2, and all Python 3 versions prior to 3.7.
   It is likely that the code still runs on older Python 3 versions, but I have
   no interest in maintaining support for those.


-----------
pyhanko-cli
-----------


.. _cli-release-0.1.2:

0.1.2
=====

*Release date:* 2025-06-20


New features and enhancements
-----------------------------

 * Auto-open document when validating an encrypted document using the CLI
   and there is no user password.
 * Support ``--text-param`` argument for stamps.


.. _cli-release-0.1.1:

0.1.1
=====

*Release date:* 2025-05-29


Dependency changes
------------------

 * Remove upper bound on ``click`` (excluding version ``8.2.0`` as incompatible)

.. _cli-release-0.1.0:

0.1.0
=====

*Release date:* 2025-05-27

Initial release split off from main pyHanko distribution artifact.
