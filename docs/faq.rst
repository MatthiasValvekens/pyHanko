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

Prior to ``0.12.0``, pyHanko would actually not process hybrid files correctly and would sometimes even
accidentally corrupt them. That bug has been fixed, but there's more to it than that.
The problem with hybrid files is that *by design* there's no single unambiguous way to parse them,
which makes them inherently less secure than non-hybrid PDFs. That's a problem when dealing with
document signatures, and also the reason why pyHanko ``0.12.0`` makes hybrid files an "opt-in"
feature: you have to disable strict parsing mode to be able to use them.

For API users, that means passing ``strict=False`` to any
:class:`~pyhanko.pdf_utils.incremental_writer.IncrementalPdfFileWriter` or
:class:`~pyhanko.pdf_utils.reader.PdfFileReader` objects that could touch hybrid files.

For CLI users, there's the ``--no-strict-syntax`` switch, which is available for both signing
and validation subcommands. Non-cryptographic CLI subcommands (e.g. ``stamp`` and ``addfields``)
always open files in nonstrict mode.


Why am I getting path building errors?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

There are many reasons why path building could fail, but the most common ones are

 - missing intermediate certificates that pyHanko is not aware of;
 - a certificate pathing up to a root that is not a trust anchor.

In either case, you probably need to review your
:ref:`validation context settings <config-validation-context>`.



Features & customisation
------------------------


How do I use pyHanko to sign PDFs with a remote signing service?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

It depends. Does your signing service return "raw" signed hashes? If so,
read :ref:`the section on custom Signers <extending-signer>`. Does it return fully-fledged
CMS/PKCS#7 objects? Then have a look at :ref:`the PdfCMSEmbedder API <pdf-cms-embedder-protocol>`
and :ref:`the section on interrupted signing <interrupted-signing>`. The interrupted signing
pattern is actually relevant in all remote signing scenarios, so give it a read either way.

PyHanko ships with built-in support for the CSC API (see the API docs for :mod:`~pyhanko.sign.signers.csc_signer`).
There's also an example illustrating how to use pyHanko with the AWS KMS API on
:ref:`the advanced examples page <async-aws-kms>`.


I can't get pyHanko to work with <insert PKCS#11 device here>. Can you help me?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If pyHanko's generic :class:`~pyhanko.sign.pkcs11.PKCS11Signer` doesn't work
with your favourite PKCS#11 device out of the box, that could be due to any
number of reasons, including but not limited to

 * nonconformities in the PKCS#11 implementation for your device;
 * bugs in your device's drivers or PKCS#11 middleware;
 * interop with `the PKCS#11 library that pyHanko uses under the hood <https://github.com/danni/python-pkcs11>`_;
 * bugs in pyHanko itself;
 * pyHanko using different defaults than <insert PKCS#11 client in other language>;
 * hardware issues;
 * user error.

When facing an issue with PKCS#11, please *never* file a bug report on the issue tracker unless
you're very sure you've correctly identified the root cause.
Posting your question on `the discussion forum <https://github.com/MatthiasValvekens/pyHanko/discussions>`_
is of course allowed, but bear in mind that PKCS#11 usage issues are generally difficult to
diagnose remotely without access to the hardware in question.
Be prepared to do your own troubleshooting.


I want to put Unicode text in my signatures, but I'm only seeing blanks. What gives?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

By default, when generating visible signatures, pyHanko will declare a font that's almost
guaranteed to be available in all PDF viewers, but (essentially) only supports Latin characters.
When trying to set something up to work with minimal config, some compromises have to be made.

If you need a non-Western character set, or simply want to customise the appearance of the text,
then you'll need to supply your own OpenType/TrueType font, and install pyHanko with the
``[opentype]`` optional dependency group. Have a look at the examples
:ref:`in the library documentation <text-based-stamps>` or :ref:`in the CLI docs <style-definitions>`.
