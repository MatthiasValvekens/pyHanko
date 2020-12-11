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

* ``trust``: one or more paths to trust anchor(s) to be used;
* ``trust-replace``: flag indicating whether the ``trust`` setting should
  override the system trust (default ``false``);
* ``other-certs``: one or more paths to other certificate(s) that may be needed
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


Styles for stamping and signature appearances
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

TODO
