Validation functionality
========================


.. note::

    Before reading this, you may want to take a look at
    :ref:`validation-factors` for some background on the validation process.


.. danger::
    In addition to the caveats outlined in :doc:`../cli-guide/validation`,
    you should be aware that the validation API is still very much in flux,
    and likely to change by the time pyHanko reaches its beta stage.


.. |EmbeddedPdfSignature| replace:: :class:`~.pyhanko.sign.validation.EmbeddedPdfSignature`
.. |SignatureStatus| replace:: :class:`~.pyhanko.sign.general.SignatureStatus`
.. |PdfSignatureStatus| replace:: :class:`~.pyhanko.sign.validation.PdfSignatureStatus`
.. |DocumentSecurityStore| replace:: :class:`~.pyhanko.sign.validation.DocumentSecurityStore`
.. |ValidationContext| replace:: :class:`~.certvalidator.ValidationContext`

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
(an object of type :class:`.certvalidator.ValidationContext`).
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

    from oscrypto import keys
    from certvalidator import ValidationContext
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature

    root_cert = keys.parse_certificate(b'<certificate data goes here>')
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

    from oscrypto import keys
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import (
        validate_pdf_ltv_signature, RevocationInfoValidationType
    )

    root_cert = keys.parse_certificate(b'<certificate data goes here>')

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
    (see the docs for :attr:`~.pyhanko.sign.validation.PdfSignatureStatus.timestamp_validity`).

    However, since the LTV adjudication process is entirely moot without a trusted record
    of the signing time, :func:`~.pyhanko.sign.validation.validate_pdf_ltv_signature`
    will raise a :class:`~.pyhanko.sign.validation.SignatureValidationError`
    if the timestamp token (or timestamp chain) fails to validate.
    Otherwise, :func:`~.pyhanko.sign.validation.validate_pdf_ltv_signature`
    returns a |PdfSignatureStatus| as usual.


Probing different aspects of the validity of a signature
--------------------------------------------------------


The |PdfSignatureStatus| objects returned by
:func:`~.pyhanko.sign.validation.validate_pdf_signature` and
:func:`~.pyhanko.sign.validation.validate_pdf_ltv_signature` provide a fairly
granular account of the validity of the signature.

You can print a human-readable validity report by calling
:meth:`~.pyhanko.sign.validation.PdfSignatureStatus.pretty_print_details`, and
if all you're interested in is a yes/no judgment, use the the
:attr:`~.pyhanko.sign.validation.PdfSignatureStatus.bottom_line` property.

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