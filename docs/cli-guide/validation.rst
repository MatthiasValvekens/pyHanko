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


Incremental updates: difference analysis
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

TODO


Establishing the time of signing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

TODO


Evaluating seed value constraints
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

TODO