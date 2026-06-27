.. |PdfSignatureStatus| replace:: :class:`~.pyhanko.sign.validation.status.PdfSignatureStatus`

Probing different aspects of the validity of a signature
=========================================================


The |PdfSignatureStatus| objects returned by
:func:`~.pyhanko.sign.validation.validate_pdf_signature`
and other validation API functions provide a fairly granular
account of the validity of the signature.

You can print a human-readable validity report by calling
:meth:`~.pyhanko.sign.validation.status.StandardCMSSignatureStatus.pretty_print_details`, and
if all you're interested in is a yes/no judgment, use the the
:attr:`~.pyhanko.sign.validation.status.PdfSignatureStatus.bottom_line` property.

Should you ever need to know more, a |PdfSignatureStatus| object also
includes information on things like

* the certificates making up the chain of trust,
* the validity of the embedded timestamp token (if present),
* the invasiveness of incremental updates applied after signing,
* seed value constraint compliance.

For more information, take a look at |PdfSignatureStatus| in the API reference.
