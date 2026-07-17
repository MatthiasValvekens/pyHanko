from __future__ import annotations

import argparse
import hashlib
import json
import sys
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


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("artifact", type=Path, help="distribution file to check")
    ap.add_argument(
        "--repository",
        help="owner/name slug",
        default="MatthiasValvekens/pyHanko",
    )
    ap.add_argument("--environment", help="expected GHA env", default=None)
    ap.add_argument(
        "--source-ref",
        required=True,
        help="expected ref, e.g. refs/tags/v1.2.3",
    )
    ap.add_argument(
        "--workflow",
        default="release.yml",
        help="initiating (build-config) workflow [default: release.yml]",
    )
    ap.add_argument(
        "--signer-workflow",
        default="package.yml",
        help="package-signing workflow -- ignored when --pypi-provenance is specified [default: package.yml]",
    )
    ap.add_argument(
        "--signer-workflow-source-ref",
        default="refs/heads/master",
        help="package-signing workflow -- ignored when --pypi-provenance is specified [default: refs/heads/master]",
    )
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--bundle", type=Path, help="a provenance.sigstore.json")
    src.add_argument(
        "--pypi-provenance", type=Path, help="a PyPI integrity-API response"
    )
    args = ap.parse_args()

    digest = hashlib.sha256(args.artifact.read_bytes()).hexdigest()
    if args.pypi_provenance:
        bundles = bundles_from_pypi(args.pypi_provenance.read_text())
        signer_workflow = args.workflow
        signer_ref = args.source_ref
        environment = args.environment or "release"
    elif args.bundle:
        bundles = bundles_from_file(args.bundle.read_text())
        signer_workflow = args.signer_workflow
        signer_ref = args.signer_workflow_source_ref
        environment = args.environment or "build-release"
    else:
        print("either of --bundle or --pypi-provenance is required")
        return 1
    policy = build_policy(
        args.repository,
        args.source_ref,
        environment,
        args.workflow,
        signer_workflow,
        signer_ref,
    )
    verifier = Verifier.production()

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
        return 1
    if not matched:
        print(
            f"signature/environment verified, but no attestation covers "
            f"{args.artifact.name} (sha256:{digest})",
            file=sys.stderr,
        )
        return 1
    print(
        f"OK: {args.artifact.name} attested by {args.repository} "
        f"({args.workflow} @ {args.source_ref}) / "
        f"[signed by: {signer_workflow} @ {signer_ref}] "
        f"in environment {environment!r} "
        f"[{checked} attestation(s) checked]"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
