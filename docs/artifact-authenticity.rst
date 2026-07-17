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

    For the purposes of all security checks described here,
    GitHub effectively acts as the trust root.
    In case of doubt, cross-reference the content of this page with
    `its source on GitHub <https://github.com/MatthiasValvekens/pyHanko/blob/master/docs/artifact-authenticity.rst>`_.


.. warning::

    PGP signing of releases has been discontinued. If the methods of release validation described here do not
    meet your needs, please start a thread on the
    `discussion forum <https://github.com/MatthiasValvekens/pyHanko/discussions>`_.


Build provenance attestations
=============================

Scope
-----

PyHanko's release pipeline in GitHub Actions uses the GitHub Actions OIDC token
to certify release artifacts as originating from a specific repository, ref and
build workflow. It does so using `GitHub artifact attestations
<https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations>`_,
which produce `SLSA <https://slsa.dev/>`_ build provenance backed by the public
`Sigstore <https://sigstore.dev>`_ instance.

The following are important to keep in mind:

 * The machine identity used to obtain the attestation is also the one
   used to authenticate to PyPI.
 * While Sigstore's OIDC-based keyless signing procedure does not rely on any
   maintainer-controlled secrets, deploying cannot be done without manual
   maintainer review, and only repository admins can push ``v*`` tags.
 * The provenance attestation covers the pyHanko release artifacts themselves.
   It does **not** make any guarantees about transitive dependencies that your
   package manager may or may not pull in.
 * The ``gh attestation verify`` flow below checks the repository, ref and
   workflow, but not the GitHub Actions deployment environment behind which the
   maintainer approval sits. That claim is signed too; see
   :ref:`verifying-deployment-environment` for how to check it.

Long story short, as long as you trust GitHub's security controls, these checks
are appropriate.


Verifying build provenance
--------------------------

 #. Install the `GitHub CLI <https://cli.github.com/>`_ (``gh``, version 2.49 or later)
 #. Download the release artifacts you are interested in through whichever channel you prefer
    (e.g. using ``pip download``, or manual download from GitHub/PyPI)
 #. Run the snippet below.

Note that ``gh attestation verify`` takes a single artifact per invocation, so we
loop over the files we want to check.

.. code-block:: bash

    #!/bin/bash

    EXPECTED_VERSION=<version number goes here>
    REPO=MatthiasValvekens/pyHanko
    for artifact in pyhanko-$EXPECTED_VERSION-*.whl pyhanko-$EXPECTED_VERSION.tar.gz; do
        gh attestation verify "$artifact" \
            --repo "$REPO" \
            --signer-workflow "$REPO/.github/workflows/package.yml" \
            --source-ref "refs/tags/v$EXPECTED_VERSION"
    done


The two identity-pinning flags are what make this check meaningful, and both are
worth understanding:

``--signer-workflow``
    Requires the attestation to have been signed by pyHanko's packaging workflow.
    Without this flag, any workflow in the repository would be an acceptable
    signer.

``--source-ref``
    Requires the build to have run from the release tag you expect, rather than
    from some other branch or tag in the repository.

For ``pyhanko-certvalidator`` (and subprojects other than ``pyhanko`` in general) you need to
make sure the tag is prefixed correctly.

.. code-block:: bash

    #!/bin/bash

    EXPECTED_VERSION=<version number goes here>
    REPO=MatthiasValvekens/pyHanko
    TAG="pyhanko-certvalidator/v$EXPECTED_VERSION"
    for artifact in pyhanko_certvalidator-$EXPECTED_VERSION-*.whl \
                    pyhanko_certvalidator-$EXPECTED_VERSION.tar.gz; do
        gh attestation verify "$artifact" \
            --repo "$REPO" \
            --signer-workflow "$REPO/.github/workflows/package.yml" \
            --source-ref "refs/tags/$TAG"
    done


You can of course inspect the validated provenance data for any other authenticated metadata
that you think might be useful; ``--format json`` will print the full verification
result, including the provenance predicate.


Attestations on PyPI
====================

PyHanko is published to PyPI using PyPI's trusted publisher model, and the
publishing step also uploads :pep:`740` attestations for the distributions it
uploads. These are served by PyPI itself, and are visible through
`PyPI's integrity API <https://docs.pypi.org/api/integrity/>`_.

These attestations share the same trust root (Sigstore) and the same family of
GitHub Actions OIDC identity as the build provenance described above.

They can also be used to audit PyPI's trusted publisher mechanism,
as described in :ref:`verifying-deployment-environment`.


.. _verifying-deployment-environment:

Verifying the deployment environment
====================================

The pyHanko release pipeline signs its provenance from inside a GitHub Actions
deployment environment. Deploying into that environment requires a manual
maintainer approval, so the name of the environment is a meaningful part of the
release identity: it distinguishes a genuine production upload from, say, a build
that a fork or a stray workflow managed to sign with the same repository's
identity. This deployment environment is also part of the trusted publisher
data that PyPI checks when releases are uploaded: only artifacts from the ``release``
environment are accepted.


.. note::

    PyHanko's build pipeline actually uses two types of approval-gated envs.

    * There's a release build environment, which is there to ensure that
      all attested production artifacts produced by the packaging workflow
      are gated behind maintainer approval.
    * There's a separate release publishing environment for publishing these
      artifacts to PyPI. The reason why they are kept separate is to minimise
      the amount of code that runs with PyPI publish privileges.

    For production releases, the ``build-release`` environment is used
    to build the artifacts, and the ``release`` environment is used
    to publish to PyPI.


The environment name is encoded in the signing certificate itself, as a Fulcio
X.509 extension with OID ``1.3.6.1.4.1.57264.1.23`` ("Deployment Environment").
Because it is part of the signed certificate, it can be verified with the same
degree of confidence as the repository, ref and workflow.

.. note::

    At the time of writing (July 2026), none of ``gh attestation verify``,
    ``slsa-verifier``, or GitHub's attestation web UI surface the deployment
    environment, even though it is present in the certificate. Verifying it
    therefore requires a small amount of scripting, shown below. This may change
    as the tooling matures.

The `attest_provenance.py <https://github.com/MatthiasValvekens/pyHanko/blob/master/dev/attest_provenance.py>`_
script verifies the environment (together with the repository, ref and
workflow(s)) against the signature, using the ``sigstore`` Python
package directly.

It works against either provenance source: a downloaded
``provenance.sigstore.json`` bundle, or a response from PyPI's integrity API.


.. note::

    The examples below show how to validate the provenance of a source tarball
    of the main library (``pyhanko*.tar.gz``), but the process
    is the same for wheels, also those built for other pyHanko components
    (``pyhanko-certvalidator``, ``pyhanko-cli``)
    in this repository.

Against a downloaded ``provenance.sigstore.json`` bundle:

.. code-block:: bash

    EXPECTED_VERSION=<version number goes here>
    REPO=MatthiasValvekens/pyHanko
    uv sync --group provenance-check
    uv run dev/attest_provenance.py pyhanko-$EXPECTED_VERSION.tar.gz \
        --source-ref "refs/tags/v$EXPECTED_VERSION" \
        --bundle provenance.sigstore.json

Against PyPI's integrity API (download the provenance response first):

.. code-block:: bash

    EXPECTED_VERSION=<version number goes here>
    REPO=MatthiasValvekens/pyHanko
    curl -sL \
        "https://pypi.org/integrity/pyhanko/v$EXPECTED_VERSION/pyhanko-$EXPECTED_VERSION.tar.gz/provenance" \
        -o provenance.json
    uv sync --group provenance-check
    uv run dev/attest_provenance.py pyhanko-$EXPECTED_VERSION.tar.gz \
        --source-ref "refs/tags/v$EXPECTED_VERSION" \
        --pypi-provenance provenance.json

For subprojects other than ``pyhanko``, adjust the filenames and use a prefixed
tag as the ``--source-ref`` (e.g. ``refs/tags/pyhanko-certvalidator/v$EXPECTED_VERSION``).


Legacy releases
===============

Releases up to and including pyHanko ``0.36.0``, and the contemporaneous releases
of the other packages in the pyHanko suite, predate the move to GitHub artifact
attestations. Their release pages carry two different sets of artifacts, which
remain valid and are documented here for archival purposes:

 * ``*.sigstore.json`` bundles, one per artifact, verifiable with the ``sigstore``
   Python package;
 * a ``multiple.intoto.jsonl`` SLSA provenance file, verifiable with ``slsa-verifier``.

Both mechanisms were backed by Sigstore and by the same GitHub Actions OIDC
identity, and their security guarantees largely coincided with each other and with
those of the current attestations.

To verify the Sigstore bundles on such a release:

.. code-block:: bash

    #!/bin/bash

    EXPECTED_VERSION=<version number goes here>
    REPO=MatthiasValvekens/pyHanko
    sigstore verify github \
        --cert-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/v$EXPECTED_VERSION" \
        --ref "refs/tags/v$EXPECTED_VERSION" \
        --repo "$REPO" \
        pyhanko-$EXPECTED_VERSION-*.whl pyhanko-$EXPECTED_VERSION.tar.gz


To verify the SLSA provenance on such a release:

.. code-block:: bash

    EXPECTED_VERSION=<version number goes here>
    REPO=MatthiasValvekens/pyHanko
    slsa-verifier verify-artifact \
        --source-tag "v$EXPECTED_VERSION" \
        --provenance-path ./multiple.intoto.jsonl \
        --source-uri "github.com/$REPO" \
        pyhanko-$EXPECTED_VERSION-*.whl pyhanko-$EXPECTED_VERSION.tar.gz


In both cases, subprojects other than ``pyhanko`` use a prefixed tag, e.g.
``pyhanko-certvalidator/v$EXPECTED_VERSION``.
