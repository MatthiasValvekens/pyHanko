.. _cli-user-guide:

****************
CLI user's guide
****************

This guide offers a high-level overview of pyHanko as a command-line tool.

.. warning::
    Starting from version ``0.29.0``, the pyHanko CLI is no longer installed automatically
    with the ``pyhanko`` distributable. You'll need to install ``pyhanko-cli`` separately.


If you installed ``pyhanko-cli`` using ``pip``, you should be able to invoke pyHanko
using the ``pyhanko`` command, like so::

    pyhanko --help

If the ``pyhanko`` package is on your ``PYTHONPATH`` but the ``pyhanko``
executable isn't on your ``PATH`` for whatever reason, you can also invoke the
CLI through ::

    python -m pyhanko --help

This guide will adopt the former calling convention.

You can run ``pyhanko`` in verbose mode by passing the ``--verbose`` flag
before specifying the subcommand to invoke. ::

    pyhanko --verbose <subcommand>

.. note::
    The CLI portion of pyHanko was implemented using
    `Click <https://click.palletsprojects.com>`_. In particular, this means that
    it comes with a built-in help function, which can be accessed through
    ``pyhanko --help``.

.. caution::
    The pyHanko CLI makes heavy use of Click's subcommand functionality.
    Due to the way this works, the precise position of a command-line parameter
    sometimes matters. In general, double-dash options (e.g. ``--option``)
    should appear after the subcommand to which they apply, but before the next
    one.


The pyHanko CLI offers subcommands for :doc:`signing <signing>` and
:doc:`validating <validation>` PDF signatures, applying visual
:doc:`stamps <stamping>`, and :doc:`encrypting and decrypting <encryption>`
PDF files. Additional configuration options are available in an optional YAML
:doc:`config file <config>`.


.. toctree::
    :maxdepth: 3
    :caption: CLI topics

    signing
    validation
    stamping
    encryption
    config
