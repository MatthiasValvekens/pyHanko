.. _cli-user-guide:

****************
CLI user's guide
****************

This guide offers a high-level overview of pyHanko as a command-line tool.

*(Under construction)*

If you installed pyHanko using ``pip``, you should be able to invoke pyHanko
using the ``pyhanko`` command, like so::

    pyhanko --help

If the ``pyhanko`` package is on your ``PYTHONPATH`` buth the ``pyhanko``
executable isn't on your ``PATH`` for whatever reason, you can also invoke the
CLI through ::

    python -m pyhanko --help

This guide will adopt the former calling convention.

.. note::
    The CLI portion of pyHanko was implemented using
    `Click <https://click.palletsprojects.com>`_. In particular, this means that
    it comes with a built-in help function, which can be accessed through
    ``pyhanko --help``.


.. toctree::
    :maxdepth: 3
    :caption: CLI topics

    signing
    validation
    stamping
    config
