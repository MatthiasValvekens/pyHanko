from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.x509 import ExtensionNotFound, ObjectIdentifier
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.type.char import UTF8String
from sigstore.errors import VerificationError
from sigstore.models import Bundle
from sigstore.verify import Verifier
from sigstore.verify import policy as pol

_GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
# Fulcio "Deployment Environment" claim: the GitHub Actions environment the
# signing job ran in. Only present when the job declared `environment:`.
_DEPLOYMENT_ENVIRONMENT_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.23")

# The default package in the monorepo is released under a bare ``v<version>``
# tag; every other subpackage is released under a ``<package>/v<version>`` tag.
_DEFAULT_PACKAGE = "pyhanko"


class DeploymentEnvironment(pol.VerificationPolicy):
    """Assert the signed Fulcio deployment-environment claim (OID .1.23).

    A missing extension is a failure: it means the signing job did not run
    in a GitHub Actions deployment environment, so no guarantee exists.
    """

    def __init__(self, environment: str) -> None:
        self._environment = environment

    def verify(self, cert) -> None:
        try:
            ext = cert.extensions.get_extension_for_oid(
                _DEPLOYMENT_ENVIRONMENT_OID
            ).value
        except ExtensionNotFound:
            raise VerificationError(
                "certificate carries no deployment-environment claim "
                f"({_DEPLOYMENT_ENVIRONMENT_OID.dotted_string}); the signing "
                "job did not run in a GitHub Actions environment"
            )
        got = str(der_decode(ext.value, asn1Spec=UTF8String())[0])
        if got != self._environment:
            raise VerificationError(
                f"deployment environment mismatch (got {got!r}, "
                f"expected {self._environment!r})"
            )


def derive_source_ref(package: str, version: str) -> str:
    """Derive the Git ref of the release tag for a package/version pair.

    The default package (``pyhanko``) is tagged as ``v<version>``; every other
    subpackage in the monorepo is tagged as ``<package>/v<version>``.
    """
    if package == _DEFAULT_PACKAGE:
        return f"refs/tags/v{version}"
    return f"refs/tags/{package}/v{version}"


def build_policy(
    repository, ref, environment, builder_workflow, signer_workflow, signer_ref
):
    builder_workflow_uri = f"https://github.com/{repository}/.github/workflows/{builder_workflow}@{ref}"
    signer_workflow_uri = f"https://github.com/{repository}/.github/workflows/{signer_workflow}@{signer_ref}"
    return pol.AllOf(
        [
            pol.OIDCIssuerV2(_GITHUB_OIDC_ISSUER),
            pol.OIDCSourceRepositoryURI(f"https://github.com/{repository}"),
            pol.OIDCSourceRepositoryRef(ref),
            pol.OIDCBuildConfigURI(builder_workflow_uri),
            pol.OIDCBuildSignerURI(signer_workflow_uri),
            DeploymentEnvironment(environment),
        ]
    )


def _pep740_to_bundle(attestation):
    """Repackage a PEP 740 attestation (as served by PyPI's integrity API)
    into a Sigstore bundle. The transparency-log entries already use the
    Sigstore field names, so this is a mechanical remapping."""
    material = attestation["verification_material"]
    return Bundle.from_json(
        json.dumps(
            {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {
                    "certificate": {"rawBytes": material["certificate"]},
                    "tlogEntries": material["transparency_entries"],
                },
                "dsseEnvelope": {
                    "payload": attestation["envelope"]["statement"],
                    "payloadType": "application/vnd.in-toto+json",
                    "signatures": [
                        {"sig": attestation["envelope"]["signature"]}
                    ],
                },
            }
        )
    )


def bundles_from_pypi(provenance_json):
    provenance = json.loads(provenance_json)
    for bundle in provenance["attestation_bundles"]:
        for attestation in bundle["attestations"]:
            yield _pep740_to_bundle(attestation)


def bundles_from_file(bundle_json):
    yield Bundle.from_json(bundle_json)


def bundles_from_github(repository, digest):
    """Download attestation bundles for an artifact from the GitHub attestation
    API, keyed by the artifact's SHA-256 subject digest.

    A ``GITHUB_TOKEN`` in the environment is used if present, which
    raises the API rate limit above the unauthenticated ceiling.
    """
    url = (
        f"https://api.github.com/repos/{repository}"
        f"/attestations/sha256:{digest}?per_page=100"
    )
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "attest_provenance",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.load(resp)
    except urllib.error.HTTPError as exc:
        raise SystemExit(
            f"GitHub attestation API returned {exc.code} for "
            f"sha256:{digest}: {exc.reason}"
        )
    for attestation in data.get("attestations", []):
        yield Bundle.from_json(json.dumps(attestation["bundle"]))


def download_pypi_provenance(package, version, filename):
    """Download the :pep:`740` provenance for a distribution from PyPI's
    integrity API. Returns the raw JSON response as text, suitable for
    :func:`bundles_from_pypi`.
    """
    url = (
        f"https://pypi.org/integrity/{package}/{version}/{filename}/provenance"
    )
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.pypi.integrity.v1+json",
            "User-Agent": "attest_provenance",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.read().decode()
    except urllib.error.HTTPError as exc:
        raise SystemExit(
            f"PyPI integrity API returned {exc.code} for "
            f"{package} {version} ({filename}): {exc.reason}"
        )


def verify_source(
    verifier,
    bundles,
    *,
    repository,
    source_ref,
    workflow,
    signer_workflow,
    signer_ref,
    environment,
    artifact,
    digest,
):
    """Verify one provenance source against the expected identity and report
    the outcome on stdout/stderr. Returns ``True`` iff an attestation covering
    the artifact passed verification.
    """
    policy = build_policy(
        repository,
        source_ref,
        environment,
        workflow,
        signer_workflow,
        signer_ref,
    )
    matched = False
    checked = 0
    for bundle in bundles:
        _, payload = verifier.verify_dsse(bundle, policy)
        checked += 1
        subjects = json.loads(payload).get("subject", [])
        if any(s.get("digest", {}).get("sha256") == digest for s in subjects):
            matched = True

    if checked == 0:
        print("no attestations found", file=sys.stderr)
        return False
    if not matched:
        print(
            f"signature/environment verified, but no attestation covers "
            f"{artifact.name} (sha256:{digest})",
            file=sys.stderr,
        )
        return False
    print(
        f"OK: {artifact.name} attested by {repository} "
        f"({workflow} @ {source_ref}) / "
        f"[signed by: {signer_workflow} @ {signer_ref}] "
        f"in environment {environment!r} "
        f"[{checked} attestation(s) checked]"
    )
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("artifact", type=Path, help="distribution file to check")
    ap.add_argument(
        "--repository",
        help="owner/name slug",
        default="MatthiasValvekens/pyHanko",
    )
    ap.add_argument("--environment", help="expected GHA env", default=None)

    ref = ap.add_mutually_exclusive_group(required=True)
    ref.add_argument(
        "--source-ref",
        help="expected ref, e.g. refs/tags/v1.2.3 "
        "(mutually exclusive with --version)",
    )
    ref.add_argument(
        "--version",
        help="expected release version; the source ref is derived from this "
        "and --package (mutually exclusive with --source-ref)",
    )
    ap.add_argument(
        "--package",
        default=_DEFAULT_PACKAGE,
        help="package name used together with --version to derive the source "
        f"ref [default: {_DEFAULT_PACKAGE}]",
    )

    ap.add_argument(
        "--workflow",
        default="release.yml",
        help="initiating (build-config) workflow [default: release.yml]",
    )
    ap.add_argument(
        "--signer-workflow",
        default="package.yml",
        help="package-signing workflow -- ignored for PyPI provenance sources [default: package.yml]",
    )
    ap.add_argument(
        "--signer-workflow-source-ref",
        default="refs/heads/master",
        help="package-signing workflow ref -- ignored for PyPI provenance sources [default: refs/heads/master]",
    )
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--bundle", type=Path, help="a provenance.sigstore.json")
    src.add_argument(
        "--pypi-provenance-bundle", type=Path, help="a PyPI integrity-API response"
    )
    src.add_argument(
        "--gh-attestations",
        action="store_true",
        help="download build provenance from the GitHub attestation API, "
        "keyed by the artifact's SHA-256 digest",
    )
    src.add_argument(
        "--pypi-integrity",
        action="store_true",
        help="download the PyPI provenance from PyPI's integrity API "
        "(requires --version)",
    )
    src.add_argument(
        "--all",
        action="store_true",
        help="run both the GitHub build-provenance check and the PyPI "
        "provenance check, downloading each (requires --version)",
    )
    args = ap.parse_args()

    if (args.pypi_integrity or args.all) and args.version is None:
        ap.error(
            "--pypi-integrity and --all require --version (with --package)"
        )

    if args.version is not None:
        source_ref = derive_source_ref(args.package, args.version)
    else:
        source_ref = args.source_ref

    digest = hashlib.sha256(args.artifact.read_bytes()).hexdigest()

    # Each check is described by the bundles to verify plus the signer identity
    # and deployment environment expected for that provenance source. The
    # GitHub build provenance is signed by the packaging workflow off master
    # under the build gate; the PyPI provenance is signed by the initiating
    # release workflow at the release tag under the publish gate.
    def build_provenance_check(bundles):
        return {
            "bundles": bundles,
            "signer_workflow": args.signer_workflow,
            "signer_ref": args.signer_workflow_source_ref,
            "environment": args.environment or "build-release",
        }

    def pypi_provenance_check(bundles):
        return {
            "bundles": bundles,
            "signer_workflow": args.workflow,
            "signer_ref": source_ref,
            "environment": args.environment or "release",
        }

    checks = []
    if args.pypi_provenance_bundle:
        checks.append(
            pypi_provenance_check(
                bundles_from_pypi(args.pypi_provenance_bundle.read_text())
            )
        )
    elif args.bundle:
        checks.append(
            build_provenance_check(bundles_from_file(args.bundle.read_text()))
        )
    elif args.gh_attestations:
        checks.append(
            build_provenance_check(bundles_from_github(args.repository, digest))
        )
    elif args.pypi_integrity:
        provenance = download_pypi_provenance(
            args.package, args.version, args.artifact.name
        )
        checks.append(pypi_provenance_check(bundles_from_pypi(provenance)))
    elif args.all:
        provenance = download_pypi_provenance(
            args.package, args.version, args.artifact.name
        )
        checks.append(
            build_provenance_check(bundles_from_github(args.repository, digest))
        )
        checks.append(pypi_provenance_check(bundles_from_pypi(provenance)))
    else:
        print(
            "one of --bundle, --pypi-provenance, --gh-attestations, "
            "--pypi-integrity or --all is required"
        )
        return 1

    verifier = Verifier.production()
    all_ok = True
    for check in checks:
        ok = verify_source(
            verifier,
            check["bundles"],
            repository=args.repository,
            source_ref=source_ref,
            workflow=args.workflow,
            signer_workflow=check["signer_workflow"],
            signer_ref=check["signer_ref"],
            environment=check["environment"],
            artifact=args.artifact,
            digest=digest,
        )
        all_ok = all_ok and ok

    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
