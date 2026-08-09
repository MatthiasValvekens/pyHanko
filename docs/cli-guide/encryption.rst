Encrypting and decrypting PDF files
===================================

In addition to its signing functionality, pyHanko's CLI can encrypt and
decrypt PDF files using the standard PDF encryption schemes. Both
password-based encryption and public-key (certificate-based) encryption are
supported.

.. note::
    These commands operate on the document as a whole; they are independent of
    pyHanko's signing functionality. For background on how encryption interacts
    with signing, see the API documentation for
    :mod:`pyhanko.pdf_utils.crypt`.


Encrypting a file
-----------------

Encryption is handled by the ``encrypt`` command. PyHanko always uses AES-256
for the actual content encryption.

To encrypt a file with a password, use the ``--password`` option:

.. code-block:: bash

    pyhanko encrypt --password secret input.pdf output.pdf

If you leave off ``--password``, pyHanko will prompt for one interactively.

To encrypt a file so that it can be decrypted by the holders of one or more
specific certificates (public-key encryption), use ``--recipient`` instead.
The option may be repeated to grant access to multiple recipients:

.. code-block:: bash

    pyhanko encrypt --recipient alice.cert.pem --recipient bob.cert.pem \
        input.pdf output.pdf

The recipient certificates should be supplied in PEM or DER form.

.. note::
    You must choose either password-based or public-key encryption;
    ``--password`` and ``--recipient`` are mutually exclusive.


Decrypting a file
-----------------

Decryption is handled by the ``decrypt`` command group, which has one
subcommand per credential type.

To decrypt a password-protected file, use the ``password`` subcommand:

.. code-block:: bash

    pyhanko decrypt password input.pdf output.pdf

You will be prompted for the password unless you pass it via ``--password``.

.. warning::
    The standard PDF security handler distinguishes between the *owner*
    password (full access) and the *user* password (restricted access).
    If the password you supply is only the user password, pyHanko will refuse
    to decrypt the file unless you also pass ``--force``, since removing
    encryption is normally an owner-level operation.

    Note that the distinction between user and owner passwords is only
    a gentleman's agreement. Cryptographically, there is obviously no
    real security barrier between user-level and owner-level access
    (hence the ``--force`` option).

To decrypt a file that was encrypted towards a certificate (public-key
encryption), use the ``pemder`` subcommand with loose key material:

.. code-block:: bash

    pyhanko decrypt pemder --key key.pem --cert cert.pem input.pdf output.pdf

By default, pyHanko will prompt for the passphrase protecting the private key.
You can read it from a file with ``--passfile``, or pass ``--no-pass`` if the
key is not encrypted.

The same operation can be performed using a PKCS#12 file with the ``pkcs12``
subcommand:

.. code-block:: bash

    pyhanko decrypt pkcs12 input.pdf output.pdf secrets.pfx
