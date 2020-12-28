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


Probing different aspects of the validity of a signature
--------------------------------------------------------

TODO