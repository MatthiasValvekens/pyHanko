Signing functionality
=====================

.. |---| unicode:: U+02014 .. em dash
   :trim:

This page describes pyHanko's signing API.

.. note::
    Before continuing, you may want to take a look at the
    :ref:`background on PDF signatures <pdf-signing-background>` in the CLI
    documentation.


General API design
------------------

The value entry (``/V``) of a signature field in a PDF file is given by a PDF
dictionary: the "signature object".
This signature object in turn contains a ``/Contents`` key (a byte string)
with a DER-encoded rendition of the CMS object (see :rfc:`5652`) containing the
actual cryptographic signature.
To avoid confusion, the latter will be referred to as the "signature CMS object",
and we'll reserve the term "signature object" for the PDF dictionary that is the
value of the signature field.

The signature object contains a ``/ByteRange`` key outlining the bytes of the
document that should be hashed to validate the signature.
As a general rule, the hash of the PDF file used in the signature is computed
over all bytes in the file, except those under the ``/Contents`` key.
In particular, the ``/ByteRange`` key of the signature object is actually
part of the signed data, which implies that the size of the signature
CMS object needs to be estimated ahead of time. As we'll see soon, this has
some minor implications for the API design.


.. |PdfSignatureMetadata| replace:: :class:`~.pyhanko.sign.signers.PdfSignatureMetadata`
.. |Signer| replace:: :class:`~.pyhanko.sign.signers.Signer`
.. |PdfSigner| replace:: :class:`~.pyhanko.sign.signers.PdfSigner`


The pyHanko signing API is spread across sevaral modules in the
:mod:`.pyhanko.sign` package. Broadly speaking, it has three aspects:

* |PdfSignatureMetadata| specifies high-level metadata & structural requirements
  for the signature object and the signature CMS object.
* |Signer| and its subclasses are responsible for the construction of the
  signature CMS object, but are in principle "PDF-agnostic".
* |PdfSigner| is the "steering" class that invokes the |Signer| on an
  :class:`~.pyhanko.pdf_utils.incremental_writer.IncrementalPdfFileWriter`
  and takes care of formatting the resulting signature object according
  to the specifications of a |PdfSignatureMetadata| object.


This summary, while a bit of an oversimplification, provides a
decent enough picture of the separation of concerns in the signing API.
In particular, the fact that construction of the CMS object is delegated to
another class that doesn't need to bother with any of the PDF-specific
minutiae makes it relatively easy to support other signing technology
(e.g. particular HSMs).


A simple example
----------------

TODO


|PdfSignatureMetadata| options
------------------------------

TODO


Extending |Signer|
------------------

TODO