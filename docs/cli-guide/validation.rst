Validating PDF signatures
=========================

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

