General API design
==================

.. testsetup:: *

    globals().update(make_doc_env(DocEnvSpec(
        files={},
        signers=(),
        signed_documents=(
            SignedDocSpec(profile=SignatureProfile.PADES_LTA),
        ),
        trust=TrustSpec(fetch_revocation=True),
    )))

.. testcleanup:: *

    teardown_doc_env(_doc_env)


.. |EmbeddedPdfSignature| replace:: :class:`~.pyhanko.sign.validation.pdf_embedded.EmbeddedPdfSignature`
.. |SignatureStatus| replace:: :class:`~.pyhanko.sign.validation.status.SignatureStatus`
.. |PdfSignatureStatus| replace:: :class:`~.pyhanko.sign.validation.status.PdfSignatureStatus`
.. |DocumentSecurityStore| replace:: :class:`~.pyhanko.sign.validation.dss.DocumentSecurityStore`
.. |ValidationContext| replace:: :class:`~.pyhanko_certvalidator.ValidationContext`
.. |AdESLTAValidationResult| replace:: :class:`~.pyhanko.sign.validation.ades.AdESLTAValidationResult`

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
-----------------------------------

There is a convenience property on
:class:`~.pyhanko.pdf_utils.reader.PdfFileReader`, aptly named
:attr:`~.pyhanko.pdf_utils.reader.PdfFileReader.embedded_signatures`.
This property produces an array of |EmbeddedPdfSignature| objects, in the order
that they were applied to the document. The result is cached on the reader
object.

These objects can be used to inspect the signature manually, if necessary,
but they are mainly intended to be used as input for validation APIs.


Validating a PDF signature
---------------------------

All validation in pyHanko is done with respect to a certain *validation context*
(an object of type :class:`.pyhanko_certvalidator.ValidationContext`).
This object tells pyHanko what the trusted certificates are, and transparently
provides mechanisms to request and keep track of revocation data.
For LTV validation purposes, a |ValidationContext| can also specify a point in
time at which the validation should be carried out.

Originally, the principal purpose of the |ValidationContext| was to let the
user explicitly specify their own trust settings, but |ValidationContext| objects
are stateful: they also accumulate revocation data and validation results.
It may be necessary to juggle several *different* validation contexts
over the course of a validation operation. For example, when performing LTV
validation, pyHanko will first validate the signature's timestamp against the
user-specified validation context, and then build a new validation context
relative to the signing time specified in the timestamp.


.. note::

    For a more systematic and declarative approach to validation that
    abstracts away the |ValidationContext| juggling, see
    :ref:`ades-validation`.


Here's a simple example to illustrate the process of validating a PDF signature
w.r.t. a specific trust root.


.. testcode::

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

.. testoutput::
    :hide:

    ...
    The signature is judged VALID.


.. _os-trust-deprecation:

Deprecation of OS trust list
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. warning::

    Specifying ``trust_roots`` (or a ``trust_manager``) is optional today: if
    you leave it out, the |ValidationContext| falls back to the operating
    system's trust list. This is for historical reasons: it's a behaviour
    that stems from the library that ``pyhanko-certvalidator`` was forked from.

    **This fallback is deprecated** and will be removed in a future
    ``pyhanko-certvalidator`` release, at which point trust roots will
    have to be supplied explicitly.
    The ``extra_trust_roots`` parameter, which exists to supplement the
    platform's trust list, is deprecated along with it.

    The reason is that the platform trust list is maintained for TLS purposes,
    which makes it a nonsensical source of trust for document signature validation.

    If you do want to keep validating against a set of TLS roots for one
    reason or another, load them explicitly from a PEM bundle:

    .. code-block:: python

        from pyhanko.keys import load_certs_from_pemder

        vc = ValidationContext(
            trust_roots=list(
                load_certs_from_pemder(['/path/to/ca-bundle.pem'])
            )
        )

