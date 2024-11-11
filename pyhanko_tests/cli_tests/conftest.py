import datetime
import logging
import os

import pytest
import requests_mock
import tzlocal
import yaml
from asn1crypto import pem
from certomancer import PKIArchitecture
from certomancer.integrations.illusionist import Illusionist
from certomancer.registry import CertLabel, ServiceLabel
from click.testing import CliRunner
from freezegun import freeze_time
from pyhanko_certvalidator import ValidationContext

from pyhanko.pdf_utils.misc import PdfStrictReadError
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import (
    RevocationInfoValidationType,
    validate_pdf_ltv_signature,
    validate_pdf_signature,
)
from pyhanko_tests.samples import (
    MINIMAL,
    TESTING_CA,
    TESTING_CA_ECDSA,
    TESTING_CA_ED448,
    TESTING_CA_ED25519,
)

INPUT_PATH = 'input.pdf'
SIGNED_OUTPUT_PATH = 'output.pdf'
DUMMY_PASSPHRASE = "secret"


def _const(v):
    def f(*_args, **_kwargs):
        return v

    return f


CERTOMANCER_ARCHITECTURES = {
    "rsa": TESTING_CA,
    "ecdsa": TESTING_CA_ECDSA,
    "ed25519": TESTING_CA_ED25519,
    "ed448": TESTING_CA_ED448,
}
FREEZE_DT = datetime.datetime(2020, 8, 1, tzinfo=tzlocal.get_localzone())


@pytest.fixture(scope="module", params=list(CERTOMANCER_ARCHITECTURES))
def pki_arch_name(request):
    return request.param


@pytest.fixture(scope="module")
def pki_arch(pki_arch_name):
    with freeze_time(FREEZE_DT):
        arch = CERTOMANCER_ARCHITECTURES[pki_arch_name]
        with requests_mock.Mocker() as m:
            Illusionist(arch).register(m)
            yield arch


# cli_runner is autouse to ensure it gets priority in the dependency graph
@pytest.fixture(scope="function", autouse=True)
def cli_runner():
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open(INPUT_PATH, 'wb') as outf:
            outf.write(MINIMAL)
        yield runner


def _write_cert(
    arch: PKIArchitecture, label: CertLabel, fname: str, use_pem: bool = True
) -> str:
    cert = arch.get_cert(label)
    with open(fname, 'wb') as outf:
        if use_pem:
            outf.write(pem.armor('CERTIFICATE', cert.dump()))
        else:
            outf.write(cert.dump())
    return fname


@pytest.fixture
def root_cert(pki_arch):
    return _write_cert(pki_arch, CertLabel('root'), 'root.cert.pem')


@pytest.fixture
def user_cert(pki_arch):
    return _write_cert(
        pki_arch, CertLabel('signer1'), 'signer.crt', use_pem=False
    )


@pytest.fixture
def cert_chain(pki_arch, root_cert, user_cert):
    return (
        root_cert,
        _write_cert(pki_arch, CertLabel('interm'), 'interm.cert.pem'),
        user_cert,
    )


@pytest.fixture
def timestamp_url(pki_arch: PKIArchitecture) -> str:
    tsa = pki_arch.service_registry.get_tsa_info(ServiceLabel('tsa'))
    return tsa.url


@pytest.fixture
def p12_keys(pki_arch, post_validate):
    p12_bytes = pki_arch.package_pkcs12(
        CertLabel("signer1"), password=DUMMY_PASSPHRASE.encode("utf8")
    )
    fname = 'signer.p12'
    with open(fname, 'wb') as outf:
        outf.write(p12_bytes)
    return fname


def _write_config(config: dict, fname: str = 'pyhanko.yml'):
    with open(fname, 'w') as outf:
        yaml.dump(config, outf)


logger = logging.getLogger(__name__)


def _validate_last_sig_in(arch: PKIArchitecture, pdf_file, *, strict):
    vc_kwargs = dict(trust_roots=[arch.get_cert(CertLabel('root'))])
    vc = ValidationContext(**vc_kwargs, allow_fetching=True)
    with open(pdf_file, 'rb') as result:
        logger.info(f"Validating last signature in {pdf_file}...")
        r = PdfFileReader(result, strict=strict)
        # Little hack for the tests with encrypted files
        if r.security_handler is not None:
            r.decrypt("ownersecret")
        last_sig = r.embedded_regular_signatures[-1]
        # if there's a docts, we assume it's PAdES
        if r.embedded_timestamp_signatures:
            # TODO once we move the CLI over to the new AdES engine,
            #  use that as the baseline for testing
            status = validate_pdf_ltv_signature(
                last_sig,
                validation_context_kwargs=vc_kwargs,
                validation_type=RevocationInfoValidationType.PADES_LTA,
                bootstrap_validation_context=vc,
                force_revinfo=True,
            )
        else:
            status = validate_pdf_signature(
                last_sig, signer_validation_context=vc
            )
        assert status.bottom_line, status.pretty_print_details()
        logger.info(f"Validation successful")


@pytest.fixture
def post_validate(pki_arch):
    yield
    input_passes_strict = True
    if os.path.isfile(INPUT_PATH):
        try:
            with open(INPUT_PATH, 'rb') as inf:
                PdfFileReader(inf)
        except PdfStrictReadError:
            logger.info(
                f"Input file {INPUT_PATH} can't be opened in strict mode, "
                f"will validate output {SIGNED_OUTPUT_PATH} in "
                f"nonstrict mode as well"
            )
            input_passes_strict = False

    if os.path.isfile(SIGNED_OUTPUT_PATH):
        _validate_last_sig_in(
            pki_arch, SIGNED_OUTPUT_PATH, strict=input_passes_strict
        )
