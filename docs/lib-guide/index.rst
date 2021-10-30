.. _lib-user-guide:

**************************
Library (SDK) user's guide
**************************

This guide offers a high-level overview of pyHanko as a Python library.
For the API reference docs generated from the source, see the
:ref:`API reference <api-reference>`.


The pyHanko library roughly consists of the following components.

* The :mod:`.pyhanko.pdf_utils` package, which is essentially a (gutted and
  heavily modified) fork of PyPDF2, with various additions to support the kind
  of low-level operations that pyHanko needs to support its various signing
  and validation workflows.
* The :mod:`.pyhanko.sign` package, which implements the general
  signature API supplied by pyHanko.
* The :mod:`.pyhanko.stamp` module, which implements the signature appearance
  rendering & stamping functionality.
* Support modules to handle CLI and configuration: :mod:`.pyhanko.config` and
  :mod:`.pyhanko.cli`. These mostly consist of very thin wrappers around library
  functionality, and shouldn't really be considered public API.

.. toctree::
    :maxdepth: 3
    :caption: pyHanko library topics

    reading-writing
    sig-fields
    signing
    validation
    pdf-utils
    adv-examples
