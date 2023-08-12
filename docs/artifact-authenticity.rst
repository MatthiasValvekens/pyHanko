.. _release-authenticity:

*****************************
Release artifact authenticity
*****************************

Overview
========

PyHanko uses several mechanisms to provide assurances regarding the authenticity of
its release artifacts, with the goal of mitigating its exposure to downstream software
supply chain issues.


.. note::

    For the purposes of all security checks described here (except PGP signatures),
    GitHub effectively acts as the trust root.
    In case of doubt, cross-reference the content of this page with
    `its source on GitHub <https://github.com/MatthiasValvekens/pyHanko/blob/master/docs/artifact-authenticity.rst>`_.


PGP signatures
==============

Scope
-----

All pyHanko releases are signed using `the maintainer's PGP key <https://mvalvekens.be/contact.html>`_.
These signatures are uploaded together with the release artifacts on GitHub.
Whether validating releases in this way makes sense to you depends on your software supply chain trust
model, but it should support at least simple TOFU-style usage.


.. warning::

    Due to the manual nature of this signing process, there's a small time lag between the release
    artifacts being uploaded to GitHub/PyPI and the PGP signatures being added to the release.

.. note::

    If you need more in-depth validation of the identity tied to the key used to sign releases,
    use the contact information in the `security policy on GitHub <https://github.com/MatthiasValvekens/pyHanko/security/policy>`_.
    We may be able to arrange something (within reasonable parameters).


Verifying PGP signatures using GnuPG
------------------------------------

 #. Install a GnuPG-compatible PGP implementation
 #. Import the key with fingerprint ``9C41 44F3 5E74 2C88 A5D2 563C 15F4 2BEF A159 BA54`` and establish trust
    using whatever mechanism is appropriate to your use case.
 #. Download the release artifacts you are interested in through whichever channel you prefer
    (e.g. using ``pip wheel``, or manual download from GitHub/PyPI)
 #. Download the PGP signature files (``.sig``) from the GitHub release page.
 #. Validate the signatures: ``gpg --verify *.whl.sig``, ``gpg --verify *.tar.gz.sig``.


.. warning::

    The procedure described here is appropriate for all current releases with version
    number ``0.10.0`` or later.
    Older releases were signed with a now-discontinued key. If you really need one of these
    very old builds, `review the key rotation statement here <https://mvalvekens.be/blog/2021/pgp-key-rotation-statement.html>`_


Sigstore signatures
===================

Scope
-----

PyHanko's release pipeline in GitHub Actions uses the Github Actions OIDC token
to certify release artifacts as originating from a specific repository or ref.
It does so using the public `Sigstore <https://sigstore.dev>`_ instance.
The following are important to keep in mind:

 * The machine identity used to obtain the Sigstore signature is also the one
   used to authenticate to PyPI.
 * While Sigstore's OIDC-based keyless signing procedure does not rely on any
   maintainer-controlled secrets, deploying cannot be done without manual
   maintainer review, and only repository admins can push ``v*`` tags.

Long story short, as long as you trust GitHub's security controls, these checks
are appropriate.


Verifying Sigstore signatures issued through GitHub Actions OIDC
----------------------------------------------------------------

 #. Install ``sigstore``
 #. Download the ``.sigstore`` bundles from the GitHub release page
 #. Download the release artifacts you are interested in through whichever channel you prefer
    (e.g. using ``pip wheel``, or manual download from GitHub/PyPI)

.. code-block:: bash

    #!/bin/bash

    export EXPECTED_VERSION=<version number goes here>
    export REPO=MatthiasValvekens/pyHanko
    sigstore verify github \
        --cert-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/v$EXPECTED_VERSION" \
        --ref "refs/tags/v$EXPECTED_VERSION" \
        --repo "$REPO" \
        pyHanko-$EXPECTED_VERSION-*.whl pyHanko-$EXPECTED_VERSION.tar.gz


SLSA provenance data
====================

Scope
-----

The idea behind supplying SLSA provenance data is to allow people to validate that
a given artifact was built using the expected parameters on some pre-agreed
build platform (in casu GitHub Actions).

The SLSA provenance data is also backed by Sigstore.


.. warning::

    At the time of writing (August 2023), PyPI does not integrate SLSA support natively,
    so the provenance data is only added to GitHub releases and will not be automatically
    checked by your package manager (e.g. ``pip``).
    Also, pyHanko's SLSA scope does **not** include any guarantees about transitive dependencies
    that your package manager may or may not pull in.


.. note::

    The security guarantees of this process largely coincide with those of the
    Sigstore-based signatures from the previous section, but the packaging/tooling
    is slightly different.
    Until the Python ecosystem integrates SLSA more closely, either mechanism
    gets you pretty much the same thing if you validate using the methods
    described on this page. Of course, YMMV if you apply additional controls on the
    authenticated metadata.


Verifying SLSA provenance data on release builds
------------------------------------------------

Starting from version ``0.20.1``, pyHanko releases will include `SLSA provenance data <https://slsa.dev/>`_.
To verify one or more pyHanko release artifacts, perform the following steps:

 #. Install ``slsa-verifier``
 #. Download the ``multiple.intoto.json`` provenance file from the GitHub release page
 #. Download the release artifacts you are interested in through whichever channel you prefer
    (e.g. using ``pip wheel``, or manual download from GitHub/PyPI)
 #. Run the snippet below.


.. code-block:: bash

    export EXPECTED_VERSION=<version number goes here>
    export REPO=MatthiasValvekens/pyHanko
    slsa-verifier verify-artifact \
        --source-tag "v$EXPECTED_VERSION" \
        --provenance-path ./multiple.intoto.jsonl \
        --source-uri "github.com/$REPO" \
        pyHanko-$EXPECTED_VERSION-*.whl pyHanko-$EXPECTED_VERSION.tar.gz

You can of course inspect the validated provenance data for any other authenticated metadata
that you think might be useful.
