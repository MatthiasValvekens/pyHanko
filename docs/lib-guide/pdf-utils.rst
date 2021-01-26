The ``pdf-utils`` package
=========================

The :mod:`~.pyhanko.pdf_utils` package is the part of pyHanko that implements
the logic for reading & writing PDF files.

Background and future perspectives
----------------------------------

The core of the :mod:`~.pyhanko.pdf_utils` package is based on code from PyPDF2.
I forked/vendored PyPDF2 because it was the Python PDF library that would
be the easiest to adapt to the low-level needs of a digital signing tool
like pyHanko.

The "inherited" parts mostly consist of the PDF parsing logic, filter
implementations (though they've been heavily rewritten) and RC4 cryptography
support. I stripped out most of the functionality that I considered "fluff"
for the purposes of designing a DigSig tool, for several reasons:

* When I started working on pyHanko, the PyPDF2 project was all but dead,
  the codebase largely untested and the internet was rife with complaints about
  all kinds of bugs. Removing code that I didn't need served primarily as a way
  to reduce my maintenance burden, and to avoid attaching my name to potential
  bugs that I wasn't willing to fix myself.
* PyPDF2 included a lot of compatibility logic to deal with Python 2. I never
  had any interest in supporting Python versions prior to 3.7, so I ditched all
  that.
* Stripping out unnecessary code left me with greater freedom to deviate from
  the PyPDF2 API where I considered it necessary to do so.

I may or may not split off the :mod:`~.pyhanko.pdf_utils` package into a
fully-fledged Python PDF library at some point, but for now, it merely
serves as pyHanko's PDF toolbox.
That said, if you need bare-bones access to PDF structures outside pyHanko's
digital signing context, you might find some use for it even in its current
state.

This page is intended as a companion to the API reference for
:mod:`.pyhanko.pdf_utils`, rather than a detailed standalone guide.

.. danger::
    For the reasons specified above, most of :mod:`.pyhanko.pdf_utils`
    should be considered private API.

    The internal data model for PDF objects isn't particularly likely to change,
    but the text handling and layout code is rather primitive and immature,
    so I'm not willing to commit to freezing that API (yet).


.. danger::
    There are a number of stream encoding schemes (or "filters") that aren't
    supported (yet), most notably the LZW compression scheme.
    Additionally, we don't have support for all PNG predictors in the Flate
    decoder/encoder.


PDF object model
----------------

The :mod:`.pyhanko.pdf_utils.generic` module maps PDF data structures to
Python objects.
PDF arrays, dictionaries and strings are largely interoperable with their native
Python counterparts, and can (usually) be interfaced with in the same manner.

When dealing with indirect references, the package distinguishes between the
following two kinds:

* :class:`~.pyhanko.pdf_utils.generic.IndirectObject`: this represents an
  indirect reference as embedded into another PDF object (e.g. a dictionary
  value given by an indirect object);
* :class:`~.pyhanko.pdf_utils.generic.Reference`: this class represents an
  indirect reference by itself, i.e. not as a PDF object.

This distinction is rarely relevant, but the fact that
:class:`~.pyhanko.pdf_utils.generic.IndirectObject` inherits from
:class:`~.pyhanko.pdf_utils.generic.PdfObject` means that it supports the
:attr:`~.pyhanko.pdf_utils.generic.PdfObject.container_ref` API, which is
meaningless for "bare" :class:`~.pyhanko.pdf_utils.generic.Reference` objects.

As a general rule, use :class:`~.pyhanko.pdf_utils.generic.Reference` whenever
you're using indirect objects as keys in a Python dictionary or collecting them
into a set, but use :class:`~.pyhanko.pdf_utils.generic.IndirectObject` if
you're writing indirect objects into PDF output.


PDF content abstractions
------------------------

The :mod:`.pyhanko.pdf_utils.content` module provides a fairly bare-bones
abstraction for handling content that "compiles down" to PDF graphics operators,
namely the :class:`~.pyhanko.pdf_utils.content.PdfContent` class.
Among other things, it takes care of some of the PDF resource management
boilerplate.
It also allows you to easily encapsulate content into form XObjects when
necessary.

Below, we briefly go over the uses of
:class:`~.pyhanko.pdf_utils.content.PdfContent` within the library itself.
These also serve as a template for implementing your own
:class:`~.pyhanko.pdf_utils.content.PdfContent` subclasses.


Images
^^^^^^

PyHanko relies on Pillow for image support.
In particular, we currently support pretty much all RGB bitmap types that
Pillow can handle. Other colour spaces are not (yet) available.
Additionally, we currently don't take advantage of PDF's native JPEG support, or
some of its more clever image compression techniques.

The :mod:`.pyhanko.pdf_utils.images` module provides a
:class:`~.pyhanko.pdf_utils.content.PdfContent` subclass
(aptly named :class:`.pyhanko.pdf_utils.images.PdfImage`) as a convenience.


Text & layout
^^^^^^^^^^^^^

The layout code in pyHanko is currently very, very primitive, fragile and likely
to change significantly going forward.
That said, pyHanko can do some basic text box rendering, and is capable
of embedding CID-keyed OTF fonts for use with CJK text, for example.
Given the (for now) volatile state of the API, I won't document it here,
but you can take a look
at :mod:`.pyhanko.pdf_utils.text` and :mod:`.pyhanko.pdf_utils.font`,
or the code in :mod:`.pyhanko.stamp`.
