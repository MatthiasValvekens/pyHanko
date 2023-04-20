import datetime
import warnings

import pytest
import requests_mock
import tzlocal
import yaml
from asn1crypto import pem
from certomancer import PKIArchitecture
from certomancer.integrations.illusionist import Illusionist
from certomancer.registry import CertLabel
from click.testing import CliRunner
from freezegun import freeze_time

from pyhanko_tests.samples import (
    MINIMAL,
    TESTING_CA,
    TESTING_CA_ECDSA,
    TESTING_CA_ED448,
    TESTING_CA_ED25519,
)

INPUT_PATH = 'input.pdf'


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
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    FREEZE_DT = tzlocal.get_localzone().localize(datetime.datetime(2020, 8, 1))


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


def _write_config(config: dict):
    with open('pyhanko.yml', 'w') as outf:
        yaml.dump(config, outf)


class _DummyManager:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return
