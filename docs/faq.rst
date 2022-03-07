.. _faq:

Frequently asked questions (FAQ)
================================


Read these before filing bug reports.


Errors and other unexpected behaviour
-------------------------------------


I'm getting an error about hybrid reference files when trying to sign / validate a file. What gives?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This is explained in the :ref:`release notes <release-0.12.0>` for version ``0.12.0``.

Hybrid reference files were introduced as a transitional compatibility measure between PDF 1.4 and
PDF 1.5. Since PDF 1.5 support is all but universal now, they're no longer useful these days, and
therefore relatively rare. Nevertheless, some tools still routinely generate such files.

Prior to 0.12.0, pyHanko would actually not process hybrid files correctly and would sometimes even
accidentally corrupt them. That bug has been fixed, but there's more to it than that.
The problem with hybrid files is that *by design* there's no single unambiguous way to parse them,
which makes them inherently less secure than non-hybrid PDFs. That's a problem when dealing with
document signatures, and also the reason why pyHanko ``0.12.0`` makes hybrid files an "opt-in"
feature: you have to disable strict parsing mode to be able to use them.

For API users, that means passing ``strict=False`` to any
:class:`~pyhanko.pdf_utils.incremental_writer.IncrementalPdfFileWriter` or
:class:`~pyhanko.pdf_utils.reader.PdfFileReader` objects that could touch hybrid files.

For CLI users, there's the ``--no-strict-syntax`` switch, which is available for both signing
and validation subcommands.


Why am I getting path building errors?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

There are many reasons why path building could fail, but the most common ones are

 - missing intermediate certificates that pyHanko is not aware of;
 - a certificate pathing up to a root that is not a trust anchor.

In either case, you probably need to review your
:ref:`validation context settings <config-validation-context>`.