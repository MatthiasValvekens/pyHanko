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
  :func:`~.pyhanko.sign.validation.validate_pdf_ltv_signature`, for running
  the actual validation logic.
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
but they are mainly intended to be used as input for
:func:`~.pyhanko.sign.validation.validate_pdf_signature` and
:func:`~.pyhanko.sign.validation.validate_pdf_ltv_signature`.


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
    registered as ``pyhanko-certvalidator`` on PyPI. The changes in the forked
    version are minor, and the API is intended to be backwards-compatible with
    the "mainline" version.

The principal purpose of the |ValidationContext| is to let the user explicitly
specify their own trust settings.
However, it may be necessary to juggle several *different* validation contexts
over the course of a validation operation. For example, when performing LTV
validation, pyHanko will first validate the signature's timestamp against the
user-specified validation context, and then build a new validation context
relative to the signing time specified in the timestamp.


Here's a simple example to illustrate the process of validating a PDF signature
w.r.t. a specific trust root.


.. code-block:: python

    from pyhanko.sign.general import load_cert_from_pemder
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


Long-term verifiability checking
--------------------------------

As explained :ref:`here <pdf-signing-background>` and
:ref:`here <ltv-signing>` in the CLI documentation, making sure that PDF
signatures remain verifiable over long time scales requires special care.
Signatures that have this property are often called "LTV enabled", where LTV
is short for *long-term verifiable*.

To verify a LTV-enabled signature, you should use
:func:`~.pyhanko.sign.validation.validate_pdf_ltv_signature` instead of
:func:`~.pyhanko.sign.validation.validate_pdf_signature`.
The API is essentially the same, but
:func:`~.pyhanko.sign.validation.validate_pdf_ltv_signature` takes
a required ``validation_type`` parameter. The ``validation_type`` is an instance
of the enum :class:`.pyhanko.sign.validation.RevocationInfoValidationType` that
tells pyHanko where to find and how to process the revocation data for the
signature(s) involved\ [#profilesniff]_.
See the documentation for :class:`.pyhanko.sign.validation.RevocationInfoValidationType`
for more information on the available profiles.

In the initial |ValidationContext| passed to
:func:`~.pyhanko.sign.validation.validate_pdf_ltv_signature` via
``bootstrap_validation_context``, you typically want to leave ``moment``
unset (i.e. verify the signature at the current time).

This is the validation context that will be used to establish the time of
signing. When this step is done, pyHanko will construct a new validation
context pointed towards that point in time.
You can specify keyword arguments to the |ValidationContext| constructor using
the ``validation_context_kwargs`` parameter of
:func:`~.pyhanko.sign.validation.validate_pdf_ltv_signature`.
In typical situations, you can leave the ``bootstrap_validation_context``
parameter off entirely, and let pyHanko construct an initial validation context
using ``validation_context_kwargs`` as input.

The PAdES B-LTA validation example below should clarify that.

.. code-block:: python

    from pyhanko.sign.general import load_cert_from_pemder
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import (
        validate_pdf_ltv_signature, RevocationInfoValidationType
    )

    root_cert = load_cert_from_pemder('path/to/certfile')

    with open('document.pdf', 'rb') as doc:
        r = PdfFileReader(doc)
        sig = r.embedded_signatures[0]
        status = validate_pdf_ltv_signature(
            sig, RevocationInfoValidationType.PADES_LTA,
            validation_context_kwargs={'trust_roots': [root_cert]}
        )
        print(status.pretty_print_details())

Notice how, rather than passing a |ValidationContext| object directly, the
example code only supplies ``validation_context_kwargs``. These keyword arguments
will be used both to construct an initial validation context (at the current time),
and to construct any subsequent validation contexts for point-of-time validation
once the signing time is known.

In the example, the ``validation_context_kwargs`` parameter
ensures that all validation will happen w.r.t. one specific
trust root.

If all this sounds confusing, that's because it is. You may want to take a look
at the source of :func:`~.pyhanko.sign.validation.validate_pdf_ltv_signature`
and its tests, and/or play around a little.


.. warning::
    Even outside the LTV context, pyHanko always distinguishes between
    validation of the signing time and validation of the signature itself.
    In fact, :func:`~.pyhanko.sign.validation.validate_pdf_signature` reports both
    (see the docs for
    :attr:`~.pyhanko.sign.validation.status.StandardCMSSignatureStatus.timestamp_validity`).

    However, since the LTV adjudication process is entirely moot without a trusted record
    of the signing time, :func:`~.pyhanko.sign.validation.validate_pdf_ltv_signature`
    will raise a :class:`~.pyhanko.sign.validation.errors.SignatureValidationError`
    if the timestamp token (or timestamp chain) fails to validate.
    Otherwise, :func:`~.pyhanko.sign.validation.validate_pdf_ltv_signature`
    returns a |PdfSignatureStatus| as usual.


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

    from pyhanko.sign.general import load_cert_from_pemder
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

    from pyhanko.sign.general import load_cert_from_pemder
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
:func:`~.pyhanko.sign.validation.validate_pdf_signature` and
:func:`~.pyhanko.sign.validation.validate_pdf_ltv_signature` provide a fairly
granular account of the validity of the signature.

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


.. rubric:: Footnotes

.. [#profilesniff]
   Currently, pyHanko can't figure out by itself which LTV strategy is being
   used, so the caller has to specify it explicitly.
