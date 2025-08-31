Validation functionality
========================


.. note::

    Before reading this, you may want to take a look at
    :ref:`validation-factors` for some background on the validation process.


.. danger::
    In addition to the caveats outlined in :doc:`../cli-guide/validation`,
    you should be aware that the validation API is still very much in flux,
    and likely to change by the time pyHanko reaches its beta stage.


.. |EmbeddedPdfSignature| replace:: :class:`~.pyhanko.sign.validation.pdf_embedded.EmbeddedPdfSignature`
.. |SignatureStatus| replace:: :class:`~.pyhanko.sign.validation.status.SignatureStatus`
.. |PdfSignatureStatus| replace:: :class:`~.pyhanko.sign.validation.status.PdfSignatureStatus`
.. |DocumentSecurityStore| replace:: :class:`~.pyhanko.sign.validation.dss.DocumentSecurityStore`
.. |ValidationContext| replace:: :class:`~.pyhanko_certvalidator.ValidationContext`
.. |AdESLTAValidationResult| replace:: :class:`~.pyhanko.sign.validation.ades.AdESLTAValidationResult`

General API design
------------------

PyHanko's validation functionality resides in the
:mod:`~.pyhanko.sign.validation` module.
Its most important components are

* the |EmbeddedPdfSignature| class (responsible for modelling existing
  signatures in PDF documents);
* the various subclasses of |SignatureStatus| (encoding the validity status
  of signatures and timestamps);
* :func:`~.pyhanko.sign.validation.validate_pdf_signature` and
  the more advanced functions in :mod:`pyhanko.sign.validation.ades`
  for running the actual validation logic.
* the |DocumentSecurityStore| class and surrounding auxiliary classes
  (responsible for handling DSS updates in documents).

While you probably won't need to interface with |DocumentSecurityStore| directly,
knowing a little about |EmbeddedPdfSignature| and |SignatureStatus| is useful.


Accessing signatures in a document
----------------------------------

There is a convenience property on
:class:`~.pyhanko.pdf_utils.reader.PdfFileReader`, aptly named
:attr:`~.pyhanko.pdf_utils.reader.PdfFileReader.embedded_signatures`.
This property produces an array of |EmbeddedPdfSignature| objects, in the order
that they were applied to the document. The result is cached on the reader
object.

These objects can be used to inspect the signature manually, if necessary,
but they are mainly intended to be used as input for validation APIs.


Validating a PDF signature
--------------------------

All validation in pyHanko is done with respect to a certain *validation context*
(an object of type :class:`.pyhanko_certvalidator.ValidationContext`).
This object tells pyHanko what the trusted certificates are, and transparently
provides mechanisms to request and keep track of revocation data.
For LTV validation purposes, a |ValidationContext| can also specify a point in
time at which the validation should be carried out.

.. warning::
    PyHanko currently uses a forked version of the ``certvalidator`` library,
    registered as ``pyhanko-certvalidator`` on PyPI. The forked version
    has over time diverged considerably from the original, but should be
    largely backwards-compatible as far as basic usage is concerned.

Originally, the principal purpose of the |ValidationContext| was to let the
user explicitly specify their own trust settings, but |ValidationContext| objects
are stateful: they also accumulate revocation data and validation results.
It may be necessary to juggle several *different* validation contexts
over the course of a validation operation. For example, when performing LTV
validation, pyHanko will first validate the signature's timestamp against the
user-specified validation context, and then build a new validation context
relative to the signing time specified in the timestamp.


Here's a simple example to illustrate the process of validating a PDF signature
w.r.t. a specific trust root.


.. code-block:: python

    from pyhanko.keys import load_cert_from_pemder
    from pyhanko_certvalidator import ValidationContext
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature

    root_cert = load_cert_from_pemder('path/to/certfile')
    vc = ValidationContext(trust_roots=[root_cert])

    with open('document.pdf', 'rb') as doc:
        r = PdfFileReader(doc)
        sig = r.embedded_signatures[0]
        status = validate_pdf_signature(sig, vc)
        print(status.pretty_print_details())


Validating signatures against EU trusted lists
----------------------------------------------

.. versionadded:: 0.30.0

With the optional ``[etsi]`` dependency group installed,
pyHanko also supports using EU trusted lists as trust roots.
PyHanko will verify the XML signatures on the lists while collecting
them--default bootstrap keys for the EU list-of-the-lists (LOTL) are
bundled with the library.


.. code-block:: python

    import asyncio
    import aiohttp
    from datetime import timedelta
    from pyhanko_certvalidator import ValidationContext
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import async_validate_pdf_signature
    from pyhanko.sign.validation.qualified.eutl_fetch import (
        FileSystemTLCache,
        lotl_to_registry,
    )
    from pyhanko.sign.validation.qualified.tsp import TSPTrustManager


    async def prepare_registry():
        async with aiohttp.ClientSession() as client:
            tl_cache = FileSystemTLCache(
                '/var/cache/trust-lists',
                expire_after=timedelta(days=14)
            )
            registry, errors = await lotl_to_registry(
                # 'None' => bootstrap from the list-of-the-lists
                # Note: downloading the full EUTL for all member states
                # on a cold cache can take a while
                # pass only_territories='be,fr,de' if you want to
                # limit the number of lists to take into account.
                lotl_xml=None,
                client=client,
                cache=tl_cache,
            )

            # the 'errors' are recoverable errors, they generally
            # mean that the collected data may be incomplete
            return registry


    async def run():
        registry = await prepare_registry()
        trust_manager = TSPTrustManager(tsp_registry=registry)
        vc = ValidationContext(
            trust_manager=trust_manager,
            allow_fetching=True,
            revocation_mode='require'
        )

        with open('document.pdf', 'rb') as doc:
            r = PdfFileReader(doc)
            sig = r.embedded_signatures[0]
            status = await async_validate_pdf_signature(sig, vc)
            print(status.pretty_print_details())


Long-term verifiability checking
--------------------------------

.. versionchanged:: 0.31.0

    The :func:`~.pyhanko.sign.validation.validate_pdf_ltv_signature`
    function was deprecated in favour of the newer AdES-based
    functionality in :mod:`pyhanko.sign.validation.ades`.


As explained :ref:`here <pdf-signing-background>` and
:ref:`here <ltv-signing>` in the CLI documentation, making sure that PDF
signatures remain verifiable over long time scales requires special care.
Signatures that have this property are called "LTV enabled" in some
implementations, where LTV is short for *long-term verifiable*.

The notion of what it means to be "LTV enabled" is not entirely well-defined
(since it inherently depends on the set of trust roots and policies
used by the validator). PyHanko exposes the (now deprecated)
:func:`~.pyhanko.sign.validation.validate_pdf_ltv_signature` function
to make this assessment, but the implementation is quite ad-hoc and
therefore overly opinionated. See
:func:`~.pyhanko.sign.validation.ades.simulate_future_ades_lta_validation`
for a similar but more standards-based approach.


To validate a signature while taking into account embedded historical
validation data, we recommend using
:func:`~.pyhanko.sign.validation.ades.ades_lta_validation`.
This function is part of pyHanko's AdES validation API, which
aims to implement the validation methodology laid out in
ETSI EN 319 102-1. Here's what that looks like.

.. code-block:: python

    from pyhanko.keys import load_cert_from_pemder
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation.ades import ades_lta_validation
    from pyhanko.sign.validation.policy_decl import (
        PdfSignatureValidationSpec,
        SignatureValidationSpec
    )
    from pyhanko_certvalidator.context import CertValidationPolicySpec
    from pyhanko_certvalidator.policy_decl import REQUIRE_REVINFO
    from pyhanko_certvalidator.registry import SimpleTrustManager

    async def run():
        root_cert = load_cert_from_pemder('path/to/certfile')

        trust_manager = SimpleTrustManager.build(
            trust_roots=[root_cert],
        )
        validation_spec = PdfSignatureValidationSpec(
            SignatureValidationSpec(
                cert_validation_policy=CertValidationPolicySpec(
                    trust_manager=trust_manager,
                    revinfo_policy=REQUIRE_REVINFO,
                ),
            )
        )
        with open('document.pdf', 'rb') as doc:
            r = PdfFileReader(doc)
            sig = r.embedded_signatures[0]
            ades_status = await ades_lta_validation(
                sig, validation_spec
            )
            print(ades_status.ades_subindic)
            print(ades_status.api_status.pretty_print_details())


Notice how, rather than passing a |ValidationContext| object directly, the
example code supplies a declarative "validation spec" instead. The AdES
validator will internally create |ValidationContext| objects as necessary,
and supply them with revocation data in accordance with the rules around
proof-of-existence management.

The status object returned also includes more information than just
the "regular" |PdfSignatureStatus|: |AdESLTAValidationResult| also contains
some AdES-specific status codes and structured validation outputs; the
pyHanko-specific |PdfSignatureStatus| is included as an attribute.


Incremental update analysis
---------------------------

.. versionchanged:: 0.2.0

    The initial ad-hoc approach was replaced by a more extensible and
    maintainable rule-based validation system. See
    :mod:`pyhanko.sign.diff_analysis`.

As explained in :ref:`the CLI documentation <validation-general-incremental-updates>`,
the PDF standard has provisions that allow files to be updated by appending
so-called "incremental updates". This also works for signed documents, since
appending data does not destroy the cryptographic integrity of the signed data.

That being said, since incremental updates can change essentially any aspect of
the resulting document, validators need to be careful to evaluate whether
these updates were added for a legitimate reason.
Examples of such legitimate reasons could include the following:

* adding a second signature,
* adding comments,
* filling in (part of) a form,
* updating document metadata,
* performing cryptographic "bookkeeping work" such as appending fresh document
  timestamps and/or revocation information to ensure the long-term verifiability
  of a signature.

Not all of these reasons are necessarily always valid: the signer can tell
the validator which modifications they allow to go ahead without invalidating
their signature. This can either be done through the "DocMDP" setting (see
:class:`~.pyhanko.sign.fields.MDPPerm`), or for form fields, more granularly
using FieldMDP settings (see :class:`~.pyhanko.sign.fields.FieldMDPSpec`).

That being said, the standard does not specify a concrete procedure for
validating any of this. PyHanko takes a reject-by-default approach: the
difference analysis tool uses rules to compare document revisions, and judge
which object updating operations are legitimate (at a given
:class:`~.pyhanko.sign.fields.MDPPerm` level). Any modifications for which
there is no justification invalidate the signature.

The default diff policy is defined in
:const:`~pyhanko.sign.diff_analysis.DEFAULT_DIFF_POLICY`, but you can define
your own, either by implementing your own subclass of
:class:`~.pyhanko.sign.diff_analysis.DiffPolicy`, or by defining your own rules
and passing those to an instance of :class:`~.pyhanko.sign.diff_analysis.StandardDiffPolicy`.
:class:`~.pyhanko.sign.diff_analysis.StandardDiffPolicy` takes care of some
boilerplate for you, and is the mechanism backing
:const:`~pyhanko.sign.diff_analysis.DEFAULT_DIFF_POLICY`.
Explaining precisely how to implement custom diff rules is beyond the scope
of this guide, but you can take a look at the source of
the :mod:`~pyhanko.sign.diff_analysis` module for more information.

To actually use a custom diff policy, you can proceed as follows.

.. code-block:: python

    from pyhanko.keys import load_cert_from_pemder
    from pyhanko_certvalidator import ValidationContext
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature

    from my_awesome_module import CustomDiffPolicy

    root_cert = load_cert_from_pemder('path/to/certfile')
    vc = ValidationContext(trust_roots=[root_cert])

    with open('document.pdf', 'rb') as doc:
        r = PdfFileReader(doc)
        sig = r.embedded_signatures[0]
        status = validate_pdf_signature(sig, vc, diff_policy=CustomDiffPolicy())
        print(status.pretty_print_details())


The :attr:`~.pyhanko.sign.validation.status.PdfSignatureStatus.modification_level`
and :attr:`~.pyhanko.sign.validation.status.PdfSignatureStatus.docmdp_ok` attributes
on |PdfSignatureStatus| will tell you to what degree the signed file has been
modified after signing (according to the diff policy used).


.. warning::
    The most lenient MDP level,
    :attr:`~.pyhanko.sign.fields.MDPPerm.ANNOTATE`, is currently not
    supported by the default diff policy.

.. danger::
    Due to the lack of standardisation when it comes to signature validation,
    correctly adjudicating incremental updates is inherently somewhat risky
    and ill-defined, so until pyHanko matures, you probably shouldn't rely
    on its judgments too heavily.

    Should you run into unexpected results, by all means file an issue.
    All information helps!

If necessary, you can opt to turn off difference analysis altogether.
This is sometimes a very reasonable thing to do, e.g. in the following cases:

* you don't trust pyHanko to correctly evaluate the changes;
* the (sometimes rather large) performance cost of doing the diff analysis
  is not worth the benefits;
* you need validate only one signature, after which the document shouldn't
  change at all.

In these cases, you might want to rely on the
:attr:`~.pyhanko.sign.validation.ModificationInfo.coverage` property
of |PdfSignatureStatus| instead. This property describes the degree to which
a given signature covers a file, and is much cheaper/easier to compute.

Anyhow, to disable diff analysis completely, it suffices to pass the
``skip_diff`` parameter to
:func:`~.pyhanko.sign.validation.validate_pdf_signature`.


.. code-block:: python

    from pyhanko.keys import load_cert_from_pemder
    from pyhanko_certvalidator import ValidationContext
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature

    root_cert = load_cert_from_pemder('path/to/certfile')
    vc = ValidationContext(trust_roots=[root_cert])

    with open('document.pdf', 'rb') as doc:
        r = PdfFileReader(doc)
        sig = r.embedded_signatures[0]
        status = validate_pdf_signature(sig, vc, skip_diff=True)
        print(status.pretty_print_details())


Probing different aspects of the validity of a signature
--------------------------------------------------------


The |PdfSignatureStatus| objects returned by
:func:`~.pyhanko.sign.validation.validate_pdf_signature`
and other validation API functions provide a fairly granular
account of the validity of the signature.

You can print a human-readable validity report by calling
:meth:`~.pyhanko.sign.validation.status.StandardCMSSignatureStatus.pretty_print_details`, and
if all you're interested in is a yes/no judgment, use the the
:attr:`~.pyhanko.sign.validation.status.PdfSignatureStatus.bottom_line` property.

Should you ever need to know more, a |PdfSignatureStatus| object also
includes information on things like

* the certificates making up the chain of trust,
* the validity of the embedded timestamp token (if present),
* the invasiveness of incremental updates applied after signing,
* seed value constraint compliance.

For more information, take a look at |PdfSignatureStatus| in the API reference.
