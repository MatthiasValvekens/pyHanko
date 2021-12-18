pyhanko.sign.validation module
==============================

.. toctree::
   :maxdepth: 4

   pyhanko.sign.validation.dss
   pyhanko.sign.validation.errors
   pyhanko.sign.validation.generic_cms
   pyhanko.sign.validation.ltv
   pyhanko.sign.validation.pdf_embedded
   pyhanko.sign.validation.settings
   pyhanko.sign.validation.status
   pyhanko.sign.validation.utils


Direct members
--------------

This package also exports a number of convenience functions at the package level.
These are all synchronous wrappers around asynchronous functions. Some are
deprecated and preserved only for compatibility reasons.


.. automodule:: pyhanko.sign.validation
   :members:
    validate_pdf_signature, validate_pdf_ltv_signature, validate_cms_signature,
    validate_detached_cms, validate_pdf_timestamp, add_validation_info
   :show-inheritance:
