Reading and writing PDF files
=============================

.. note::
    This page only describes the read/write functionality of the
    :mod:`~.pyhanko.pdf_utils` package. See :doc:`pdf-utils` for further
    information.



Reading files
-------------

Opening PDF files for reading and writing in pyHanko is easy.

For example, to instantiate a :class:`~.pyhanko.pdf_utils.reader.PdfFileReader`
reading from ``document.pdf``, it suffices to do the following.

.. code-block:: python

    from pyhanko.pdf_utils.reader import PdfFileReader

    with open('document.pdf', 'rb') as doc:
        r = PdfFileReader(doc)
        # ... do stuff ...


In-memory data can be read in a similar way: if ``buf`` is a :class:`bytes`
object containing data from a PDF file, you can use it in a
:class:`~.pyhanko.pdf_utils.reader.PdfFileReader` as follows.

.. code-block:: python

    from pyhanko.pdf_utils.reader import PdfFileReader
    from io import BytesIO

    buf = b'<PDF file data goes here>'
    doc = BytesIO(buf)
    r = PdfFileReader(doc)
    # ... do stuff ...


Modifying files
---------------

If you want to modify a PDF file, use
:class:`~.pyhanko.pdf_utils.incremental_writer.IncrementalPdfFileWriter`,
like so.

.. code-block:: python

    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

    with open('document.pdf', 'rb+') as doc:
        w = IncrementalPdfFileWriter(doc)
        # ... do stuff ...
        w.write_in_place()

Using
:meth:`~.pyhanko.pdf_utils.incremental_writer.IncrementalPdfFileWriter.write_in_place`
will cause the generated update to be appended to the same stream as the input
stream; this is why we open the file with ``'rb+'``.
If you want the output to be written to a different file or buffer, use
:meth:`~.pyhanko.pdf_utils.incremental_writer.IncrementalPdfFileWriter.write`
instead.
Obviously, opening the input file with ``'rb'`` is sufficient in this case.

.. note::
    Due to the way PDF signing works, pyHanko's signing API will usually
    take care of calling ``write`` or ``write_in_place`` as appropriate,
    and do its own processing of the results.
    In most standard use cases, you probably don't need to worry about explicit
    writes too much.

    Any
    :class:`~.pyhanko.pdf_utils.incremental_writer.IncrementalPdfFileWriter`
    objects used in a signing operation should be discarded afterwards.
    If you want to continue appending updates to a signed document, create
    a new
    :class:`~.pyhanko.pdf_utils.incremental_writer.IncrementalPdfFileWriter`
    on top of the output.

This should suffice to get you started with pyHanko's signing and validation
functionality, but the reader/writer classes can do a lot more.
To learn more about the inner workings of the low-level PDF
manipulation layer of the library, take a look at :doc:`pdf-utils` or
:ref:`the API reference <api-reference>`.

.. warning::
    While the :mod:`.pyhanko.pdf_utils` module is very powerful in that
    it allows you to modify objects in the PDF file in essentially arbitrary
    ways, and with a lot of control over the output, actually using it in this
    way requires some degree of familiarity with the PDF standard.

    As things are now, pyHanko does *not* offer any facilities to help you
    format documents neatly, or to do any kind of layout work beyond the most
    basic operations.
    This may or may not change in the future. In the meantime, you're probably
    better off using typesetting software or a HTML to PDF converter for your
    more complex layout needs, and let pyHanko handle the signing step at
    the end.

