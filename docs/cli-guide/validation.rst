Validating PDF signatures
=========================


Basic use
---------

Validating signatures in a PDF file is done through the
``validate`` subcommand of ``pyhanko sign``.

A simple use case might look like this:

.. code-block:: bash

    pyhanko sign validate --pretty-print document.pdf

This will print a human-readable overview of the validity status of the
signatures in ``document.pdf``.
The trust setup can be configured using the
:ref:`same command-line parameters <cli-embedding-revinfo>`
and :ref:`configuration options <config-validation-context>`
as for creating LTV signatures.


.. warning::
    By default, pyHanko requires signer certificates to have the non-repudiation key usage extension
    bit set on signer certificates. If this is not suitable for your use case, take a look at
    :ref:`key-usage-conf`.


.. _validation-factors:

Factors in play when validating a signature
-------------------------------------------

In this subsection, we go over the various factors considered by pyHanko when
evaluating the validity of a PDF signature.


Cryptographic integrity
^^^^^^^^^^^^^^^^^^^^^^^

The most fundamental aspect of any digital signature: verify that the bytes
of the file covered by the signature produce the correct hash value, and that
the signature object is a valid signature of that hash.
By 'valid', we mean that the cryptographic signature should be verifiable using
the public key in the certificate that is marked as the signer's in the
signature object.
In other words, we need to check that the *purported* signer's certificate
actually produced the signature.


Authenticity: trust settings
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Having verified that the signature was produced by the (claimed) signer's
certificate, we next have to validate the binding between the certificate
and its owner.
That is to say, we have to convince ourselves that the entity whose name is on
the certificate is in control of the private key, i.e. that the signer is
who they claim to be.

Technically, this is done by establishing a *chain of trust* to a trust anchor,
which we rely on to judge the validity of cryptographic identity claims.
This is where the :ref:`trust <cli-embedding-revinfo>`
:ref:`settings <config-validation-context>` mentioned above come into play.


.. _validation-general-incremental-updates:

Incremental updates: difference analysis
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

PDF files can be modified, even when signed, by appending data to the end of the
previous revision. These are *incremental updates*. In particular, this is how
forms with multiple signatures are implemented in PDF.
These incremental updates can essentially modify the original document in
arbitrary ways, which is a problem, since they are (by definition) not covered
by any earlier signatures.

In short, validators have two options: either reject all incremental updates
(and decline to support multiple-signer scenarios of any kind), or police
incremental updates by itself. The exact way in which this is supposed to be
done is not specified precisely in the PDF standard.

.. warning::
    PyHanko attempts to run a difference analysis on incremental updates,
    and processes modifications on a reject-by-default basis (i.e. all updates
    that can't be vetted as OK are considered suspect). However, this feature
    is (very) experimental, and shouldn't be relied on too much.


Establishing the time of signing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

There are a number of ways to indicate when a signature was made.
These broadly fall into two categories:

* Self-reported timestamps: those are based on the signer's word, and shouldn't
  necessarily be trusted as accurate.
* Trusted timestamps: these derive from timestamp tokens issued by a trusted
  timestamping authority at the time of signing.

Especially in the context of long-term verifiability of signatures and
preventing things like backdating of documents, having an accurate measure
of when the timestamp was made can be of crucial importance.
PyHanko will tell you when a signature includes a timestamp token, and validate
it along with the signature.

.. note::
    Strictly speaking, a timestamp token only provides proof that the signature
    existed when the timestamp token was created. The signature itself may have
    been generated long before that!

    If you also need a "lower bound" on the signing time, you might want to
    look into signed content timestamps (see
    :attr:`~pyhanko.sign.signers.PdfSignatureMetadata.cades_signed_attr_spec`
    and :attr:`~pyhanko.sign.ades.api.CAdESSignedAttrSpec.timestamp_content`).

    Right now, pyHanko supports these when signing, but does not take them into
    account in the validation process. They are also not available in the CLI
    yet.


Evaluating seed value constraints
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Finally, the document author can put certain restrictions on future signatures
when setting up the form fields. These are known as *seed values* in the PDF
standard. Not all seed values represent constraints (some are intended as
suggestions), but one especially useful use of them is to earmark signature
fields for use by specific signers.
When validating signatures, pyHanko will also report on whether (mandatory)
seed value constraints were respected.

.. warning::
    Not all digital signing software is capable of processing seed values, so
    some false positives are to be expected.

    Obviously, seed value constraints are only *truly* reliable if the document
    author secures the document with a certification signature before sending
    it for signing. Otherwise, later signers can modify the seed values *before*
    putting their signatures in place.
    See :ref:`here <sig-field-seed-value-usage-warning>` for other concerns to
    keep in mind when relying on seed values.


.. warning::
    PyHanko currently does *not* offer validation of structural PAdES profile
    requirements, in the sense that it can't tell you if a signature
    complies with all the provisions required by a particular PAdES profile.
    Note that these are requirements on the signature itself, and have no
    bearing on possible later modifications to the document.


.. _ltv-fix:

Adding validation data to an existing signature
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Sometimes, the validation data on a signature that was meant to have
a long lifetime can be incomplete. This can have many causes, ranging
from implementation problems to simple, temporary network issues.

To remedy this problem, pyHanko can fetch and append current validation
information through the ``ltvfix`` command.

.. code-block:: bash

    pyhanko sign ltvfix --field Sig1 document.pdf

The ``ltvfix`` command supports the same arguments as ``validate`` to select
a validation context and specify trust settings.

.. warning::
    By default, pyHanko's point-in-time validation requires OCSP responses
    and CRLs to be valid at the time of signing. This is often problematic
    when revocation information is added after the fact.

    To emulate the default behaviour of Acrobat and other PDF viewers,
    use the ``--retroactive-revinfo`` switch when validating.
    This will cause pyHanko to treat CRLs and OCSP responses as valid
    infinitely far back into the past.

    *Note:* This *will* cause incorrect behaviour when validating signatures
    backed by CAs that make use of certificate holds, but given that
    content timestamps (i.e. timestamps proving that a signature was created
    *after* some given time) aren't accounted for in pyHanko's trust model,
    this is somewhat unavoidable for the time being.
