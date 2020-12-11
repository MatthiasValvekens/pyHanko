Stamping PDF files
==================

Besides signing, pyHanko can also apply its signature appearance styles as
stamps to a PDF file.
Essentially, this renders a small overlay on top of the existing PDF content,
without involving any of the signing logic.

.. warning::
    The usefulness of this feature is currently rather limited,
    since visual stamp styles are still quite primitive.
    Additionally, the current version of pyHanko's CLI doesn't make it easy to
    take advantage of the customisation features available in the API.


The basic syntax of a stamping command is the following:

.. code-block:: bash

    pyhanko stamp --style-name some-style --page 2 input.pdf output.pdf 50 100

This will render a stamp in the named style ``some-style`` at coordinates
``(50, 100)`` on the second page of ``input.pdf``, and write the output to
``output.pdf``.
For details on how to define named styles, see :ref:`style-definitions`.


.. note::
    In terms of rendering, there is one important difference between signatures
    and stamps: stamps added through the CLI are rendered at their "natural"
    size/aspect ratio, while signature appearances need to fit inside the
    predefined box of their corresponding form field widget.
    This may cause unexpected behaviour.
