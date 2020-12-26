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
some minor implications for the API design (see
:ref:`this subsection <extending-signer>` in particular).


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


Timestamp handling
------------------

TODO


.. _extending-signer:

Extending |Signer|
------------------

Providing detailed guidance on how to implement your own |Signer| subclass
is beyond the scope of this guide |---| the implementations
of :class:`~.pyhanko.sign.signers.SimpleSigner` and
:class:`~.pyhanko.sign.signers.PKCS11Signer` should help.
This subsection merely highlights some of the issues you should keep in mind.

First, if all you want to do is implement a signing device or technique that's
not supported by pyHanko\ [#cryptoparams]_, it should be sufficient to implement
:meth:`~.pyhanko.sign.signers.Signer.sign_raw`.
This method computes the raw cryptographic signature of some data (typically
a document hash) with the appropriate key material.
It also takes a ``dry_run`` flag, signifying that the returned object should
merely have the correct size, but the content doesn't matter\ [#signerdryrun]_.

If your requirements necessitate further modifications to the structure of the
CMS object, you'll most likely have to override
:meth:`~.pyhanko.sign.signers.Signer.sign`, which is responsible for the
construction of the CMS object itself.




.. rubric:: Footnotes

.. [#cryptoparams]
   ... and doesn't require any cryptographic parameters. Signature mechanisms
   with parameters (such as RSA-PSS) are a bit more tricky.
   RSA-PSS is on the roadmap for pyHanko; once that has been implemented, using
   custom signature mechanisms with parameters should also become a bit more
   straightforward.

.. [#signerdryrun]
   The ``dry_run`` flag is used in the estimation of the CMS object's size.
   With key material held in memory it doesn't really matter all that much,
   but if the signature is provided by a HSM, or requires additional input
   on the user's end (such as a PIN), you typically don't want to use the "real"
   signing method in dry-run mode.