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


.. _time-tolerance:

Time drift tolerance
^^^^^^^^^^^^^^^^^^^^

.. versionchanged:: 0.5.0
    Allow overriding the global value locally.

By default, pyHanko allows a drift of 10 seconds when comparing times.
This value can be overridden in two ways: using the top-level ``time-tolerance``
configuration option, or by setting ``time-tolerance`` in a
:ref:`named validation context <config-validation-context>`.

Given the example config below, using ``setup-a`` would set the time drift
tolerance to 180 seconds. Since the global ``time-tolerance`` setting
is set to 30 seconds, this value would be used with ``setup-b``, or with
any trust settings specified on the command line.


.. code-block:: yaml

    time-tolerance: 30
    validation-contexts:
        setup-a:
            time-tolerance: 180
            trust: customca.pem.cert
            trust-replace: true
            other-certs: some-cert.pem.cert
        setup-b:
            trust: customca.pem.cert
            trust-replace: false


.. retroactive-revinfo:

Allow revocation information to apply retroactively
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. versionadded:: 0.5.0

By default, ``pyhanko-certvalidator`` applies OCSP and CRL validity windows
very strictly. For an OCSP response or a CRL to be considered valid,
the validation time must fall within this window. In other words, with the
default settings, an OCSP response fetched at some later date does not count
for the purposes of establishing the revocation status of a certificate used
with an earlier signature.
However, pyHanko's conservative default position is often more strict than
what's practically useful, so this behaviour can be overridden with a
configuration setting (or the ``--retroactive-revinfo`` command line flag).


In the example config below, ``retroactive-revinfo`` is set to ``true``
globally, but to ``false`` in ``setup-a`` specifically.
In either case, the ``--retroactive-revinfo`` flag can override this setting.


.. code-block:: yaml

    retroactive-revinfo: true
    validation-contexts:
        setup-a:
            retroactive-revinfo: false
            trust: customca.pem.cert
            trust-replace: true
            other-certs: some-cert.pem.cert
        setup-b:
            trust: customca.pem.cert
            trust-replace: false


.. _pkcs11-setup-conf:

Named PKCS#11 setups
^^^^^^^^^^^^^^^^^^^^

.. versionadded:: 0.7.0

Since the CLI parameters for signing files with a PKCS#11 token can get quite verbose, you might
want to put the parameters in the configuration file. You can declare named PKCS#11 setups under the
``pkcs11-setups`` top-level key in pyHanko's configuration. Here's a minimal example:

.. code-block:: yaml

    pkcs11-setups:
        test-setup:
            module-path: /usr/lib/libsofthsm2.so
            token-criteria:
                label: testrsa
            cert-label: signer

If you need to, you can also put the user PIN right in the configuration:

.. code-block:: yaml

    pkcs11-setups:
        test-setup:
            module-path: /usr/lib/libsofthsm2.so
            token-criteria:
                label: testrsa
            cert-label: signer
            user-pin: 1234

.. danger::
    If you do this, you should obviously take care to keep your configuration file in a safe place.


To use a named PKCS#11 configuration from the command line, invoke pyHanko like this:

.. code-block:: bash

    pyhanko sign addsig pkcs11 --p11-setup test-setup input.pdf output.pdf


Named PKCS#11 setups also allow you to access certain advanced features that otherwise aren't
available from the CLI directly. Here is an example.

.. code-block:: yaml

   pkcs11-setups:
      test-setup:
          module-path: /path/to/module.so
          token-criteria:
              serial: 17aa21784b9f
          cert-id: 1382391af78ac390
          key-id: 1382391af78ac390


This configuration will select a token based on the serial number instead of the label,
and use PKCS#11 object IDs to select the certificate and the private key. All of these
are represented as hex strings.

For a full overview of the parameters you can set on a PKCS#11 configuration, see the API reference
documentation for :class:`~pyhanko.config.PKCS11SignatureConfig`.


.. note::
    Using the ``--p11-setup`` argument to ``pkcs11`` will cause pyHanko to ignore all other
    parameters to the ``pkcs11`` subcommand. In other words, you have to put everything in the
    configuration.


.. _ondisk-setup-conf:

Named setups for on-disk key material
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. versionadded:: 0.8.0

Starting from version 0.8.0, you can also put parameters for on-disk key material into the
configuration file in much the same way as for PKCS#11 tokens (see :ref:`pkcs11-setup-conf` above).
This is done using the ``pkcs12-setups`` and ``pemder-setups`` top-level keys, depending on whether
the key material is made available as a PKCS#12 file, or as individual PEM/DER-encoded files.

Here are some examples.

.. code-block:: yaml

    pkcs12-setups:
        foo:
            pfx-file: path/to/signer.pfx
            other-certs: path/to/more/certs.chain.pem
    pemder-setups:
        bar:
            key-file: path/to/signer.key.pem
            cert-file: path/to/signer.cert.pem
            other-certs: path/to/more/certs.chain.pem

For non-interactive use, you can also put the passphrase into the configuration file (again, take
care to set up your file access permissions correctly).

.. code-block:: yaml

    pkcs12-setups:
        foo:
            pfx-file: path/to/signer.pfx
            other-certs: path/to/more/certs.chain.pem
            pfx-passphrase: secret
    pemder-setups:
        bar:
            key-file: path/to/signer.key.pem
            cert-file: path/to/signer.cert.pem
            other-certs: path/to/more/certs.chain.pem
            key-passphrase: secret


On the command line, you can use these named setups like this:

.. code-block:: bash

    pyhanko sign addsig pkcs12 --p12-setup foo input.pdf output.pdf
    pyhanko sign addsig pemder --pemder-setup bar input.pdf output.pdf

For a full overview of the parameters you can set in these configuration dictionaries,
see the API reference documentation for :class:`~pyhanko.config.PKCS12SignatureConfig` and
:class:`~pyhanko.config.PemDerSignatureConfig`.


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
* ``background``: Here, you can specify any of the following:

    * a path to a bitmap image;
    * a path to a PDF file (the first page will be used as the stamp background);
    * the special value ``__stamp__``, which will render a simplified version of the
      pyHanko logo in the background of the stamp (using PDF graphics operators
      directly).

  When using bitmap images, any file format natively supported by
  `Pillow <https://pillow.readthedocs.io>`_ should be OK. If not specified, the stamp will not have
  a background.
* ``stamp-text``: A template string that will be used to render the text inside
  the stamp's text box. Currently, the following variables can be used:

    * ``signer``: the signer's name (only for signatures);
    * ``ts``: the time of signing/stamping;
    * ``url``: the URL associated with the stamp (only for QR stamps).

* ``text-box-style``: With this parameter, you can fine-tune the text box's
  style parameters. The most important one is ``font``, which allows you to
  specify an OTF font that will be used to render the text.
  If not specified, pyHanko will use a standard monospaced Courier font.
  See :class:`~pyhanko.pdf_utils.text.TextBoxStyle` in the API reference for
  other customisable parameters.


The parameters used in the example styles shown above are not the only ones.
The :ref:`dynamic configuration mechanism <pyhanko-config-api-ref>` used by pyHanko automatically
exposes virtually all styling settings that are available to users of the (high-level) library API.
For example, to use a stamp style where the text box is shifted to the right, and the background
image is displayed on the left with custom margins, you could write something like the following:

.. code-block:: yaml

    stamp-styles:
        more-complex-demo:
            type: text
            stamp-text: "Test Test Test\n%(ts)s"
            background: image.png
            background-opacity: 1
            background-layout:
              x-align: left
              margins:
                left: 10
                top: 10
                bottom: 10
            inner-content-layout:
              x-align: right
              margins:
                right: 10

These settings are documented in the API reference documentation for
:class:`~pyhanko.stamp.BaseStampStyle` and its subclasses.

.. note::
    In general, the following rules apply when working with these "autoconfigurable" classes
    from within YAML.

        * Underscores in field names (at the Python level) can be replaced with hyphens in YAML.
        * Some fields will in turn be of an autoconfigurable type, e.g.
          :attr:`~pyhanko.stamp.BaseStampStyle.background_layout` is a
          :class:`~pyhanko.pdf_utils.layout.SimpleBoxLayoutRule`, which can also be configured
          using a YAML dictionary (as shown in the example above).
        * In other cases, custom logic is provided to initialise certain fields, which is
          then documented on the (overridden)
          :meth:`~pyhanko.pdf_utils.config_utils.ConfigurableMixin.process_entries` method of the
          relevant class.
