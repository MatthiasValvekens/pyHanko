Configuration options
=====================

Config file location
--------------------

PyHanko reads its configuration from a YAML file.
By default, if a file named ``pyhanko.yml`` exists in the current directory,
pyHanko will attempt to read and process it.
You can manually specify a configuration file location via the ``--config``
parameter to ``pyhanko``.

Note that a configuration file is usually not required, although some
of pyHanko's behaviour cannot be fully customised using command line options.
In these cases, the configuration must be sourced from a config file.


Configuration options
---------------------


Logging options
^^^^^^^^^^^^^^^

Under the ``logging`` key in the configuration file, you can set up the
configuration for Python's logging module.
Here's an example.

.. code-block:: yaml

    logging:
        root-level: ERROR
        root-output: stderr
        by-module:
            pyhanko_certvalidator:
                level: DEBUG
                output: pyhanko_certvalidator.log
            pyhanko.sign:
                level: DEBUG


The keys ``root-level`` and ``root-ouput`` allow you to set the log level
and the output stream (respectively) for the root logger.
The default log level is ``INFO``, and the default output stream is ``stderr``.
The keys under ``by-module`` allow you to specify more granular
per-module logging configuration. The ``level`` key is mandatory in this case.

.. note::
    If ``pyhanko`` is invoked with ``--verbose``, the root logger will have its
    log level set to ``DEBUG``, irrespective of the value specified
    in the configuration.


.. _config-validation-context:

Named validation contexts
^^^^^^^^^^^^^^^^^^^^^^^^^

Validation contexts can be configured under the ``validation-contexts``
top-level key.
The example below defines two validation configs named ``default`` and
``special-setup``, respectively:

.. code-block:: yaml

    validation-contexts:
        default:
            other-certs: some-cert.pem.cert
        special-setup:
            trust: customca.pem.cert
            trust-replace: true
            other-certs: some-cert.pem.cert

The parameters are the same as those used to define validation contexts
in the CLI. This is how they are interpreted:

* ``trust``: One or more paths to trust anchor(s) to be used.
* ``trust-replace``: Flag indicating whether the ``trust`` setting should
  override the system trust (default ``false``).
* ``other-certs``: One or more paths to other certificate(s) that may be needed
  to validate an end entity certificate.

The certificates should be specified in DER or PEM-encoded form.
Currently, pyHanko can only read trust information from files on disk, not
from other sources.

Selecting a named validation context from the CLI can be done using the
``--validation-context`` parameter.
Applied to the example from :ref:`here <cli-embedding-revinfo>`, this is how
it works:

.. code-block:: bash

    pyhanko sign addsig --field Sig1 --timestamp-url http://tsa.example.com \
        --with-validation-info --validation-context special-setup \
        --use-pades pemder --key key.pem --cert cert.pem input.pdf output.pdf

In general, you're free to choose whichever names you like.
However, if a validation context named ``default`` exists in the configuration
file, it will be used implicitly if ``--validation-context`` is absent.
You can override the name of the default validation context using
the ``default-validation-context`` top-level key, like so:

.. code-block:: yaml

    default-validation-context: setup-a
    validation-contexts:
        setup-a:
            trust: customca.pem.cert
            trust-replace: true
            other-certs: some-cert.pem.cert
        setup-b:
            trust: customca.pem.cert
            trust-replace: false


.. _key-usage-conf:

Key usage settings
^^^^^^^^^^^^^^^^^^

.. versionadded:: 0.5.0

There are two additional keys that can be added to a named validation context: ``signer-key-usage``
and ``signer-extd-key-usage``. Both either take a string argument, or an array of strings.
These define the necessary key usage (resp. extended key usage) extensions that need to be present
in signer certificates.
For ``signer-key-usage``, the possible values are as follows:

* ``digital_signature``
* ``non_repudiation``
* ``key_encipherment``
* ``data_encipherment``
* ``key_agreement``
* ``key_cert_sign``
* ``crl_sign``
* ``encipher_only``
* ``decipher_only``

We refer to § 4.2.1.3 in :rfc:`5280` for an explanation of what these values mean. By default,
pyHanko requires signer certificates to have at least the ``non_repudiation`` extension, but you may
want to change that depending on your requirements.

Values for extended key usage extensions can be specified as human-readable names, or as OIDs.
The human-readable names are derived from the names in :class:`asn1crypto.x509.KeyPurposeId` in
``asn1crypto``. If you need a key usage extension that doesn't appear in the list, you can specify
it as a dotted OID value instead. By default, pyHanko does not require any specific extended key
usage extensions to be present on the signer's certificate.

This is an example showcasing key usage settings for a validation context named ``setup-a``:

.. code-block:: yaml

    validation-contexts:
        setup-a:
            trust: customca.pem.cert
            trust-replace: true
            other-certs: some-cert.pem.cert
            signer-key-usage: ["digital_signature", "non_repudiation"]
            signer-extd-key-usage: ["code_signing", "2.999"]

.. note::

    These key usage settings are mainly intended for use with validation, but are also checked when
    signing with an active validation context.


.. _style-definitions:

Styles for stamping and signature appearances
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In order to use a style other than the default for a PDF stamp or (visible)
signature, you'll have to write some configuration.
New styles can be defined under the ``stamp-styles`` top-level key.
Here are some examples:

.. code-block:: yaml

    stamp-styles:
        default:
            type: text
            background: __stamp__
            stamp-text: "Signed by %(signer)s\nTimestamp: %(ts)s"
            text-box-style:
                font: NotoSerif-Regular.otf
        noto-qr:
            type: qr
            background: background.png
            stamp-text: "Signed by %(signer)s\nTimestamp: %(ts)s\n%(url)s"
            text-box-style:
                font: NotoSerif-Regular.otf
                leading: 13

To select a named style at runtime, pass the ``--style-name`` parameter to
``addsig`` (when signing) or ``stamp`` (when stamping).
As was the case for validation contexts, the style named ``default`` will be
chosen if the ``--style-name`` parameter is absent.
Similarly, the default style's name can be overridden using the
``default-stamp-style`` top-level key.

Let us now briefly go over the configuration parameters in the above example.
All parameters have sane defaults.

* ``type``: This can be either ``text`` or ``qr``, for a simple text box
  or a stamp with a QR code, respectively. The default is ``text``.
  Note that QR stamps require the ``--stamp-url`` parameter on the command line.
* ``background``: Here, you can either specify a path to a bitmap image, or the
  special value ``__stamp__``, which will render a simplified version of the
  pyHanko logo in the background of the stamp (using PDF graphics operators
  directly). Any bitmap file format natively supported by
  `Pillow <https://pillow.readthedocs.io>`_ should be OK.
  If not specified, the stamp will not have a background.
* ``stamp-text``: A template string that will be used to render the text inside
  the stamp's text box. Currently, the following variables can be used:

    * ``signer``: the signer's name (only for signatures);
    * ``ts``: the time of signing/stamping;
    * ``url``: the URL associated with the stamp (only for QR stamps).

* ``text-box-style``: With this parameter, you can fine-tune the text box's
  style parameters. The most important one is ``font``, which allows you to
  specify an OTF font that will be used to render the text\ [#fontdisclaimer]_.
  If not specified, pyHanko will use a standard monospaced Courier font.
  See :class:`~pyhanko.pdf_utils.text.TextBoxStyle` in the API reference for
  other customisable parameters.

.. rubric:: Footnotes
.. [#fontdisclaimer]
    Custom font use is somewhat experimental, so please file an issue if you
    encounter problems. An appropriate subset of the font will always be
    embedded into the output file by pyHanko.
    The text rendering is currently fairly basic: pyHanko only takes character
    width into account, but ignores things like kerning pairs and ligatures.
    In particular, rendering of complex scripts (Myanmar, Indic scripts, ...)
    is not supported (but may be in the future).
    CJK fonts should work fine, though.
