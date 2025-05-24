import base64
import os

from asn1crypto import crl, ocsp, pem, x509
from pyhanko_certvalidator import authority
from pyhanko_certvalidator.path import ValidationPath

TESTS_ROOT = os.path.dirname(__file__)
FIXTURES_DIR = os.path.join(TESTS_ROOT, 'fixtures')


def load_cert_object(*path_components) -> x509.Certificate:
    with open(os.path.join(FIXTURES_DIR, *path_components), 'rb') as f:
        cert_bytes = f.read()
        if pem.detect(cert_bytes):
            _, _, cert_bytes = pem.unarmor(cert_bytes)
        cert = x509.Certificate.load(cert_bytes)
    return cert


def load_path(base_dir, *cert_files) -> ValidationPath:
    certs_collected = []
    for cert_file in cert_files:
        certs_collected.append(load_cert_object(base_dir, cert_file))
    return ValidationPath(
        trust_anchor=authority.CertTrustAnchor(certs_collected[0]),
        interm=certs_collected[1:-1],
        leaf=certs_collected[-1],
    )


def load_nist_cert(filename):
    return load_cert_object('nist_pkits', 'certs', filename)


def load_crl(*path_components) -> crl.CertificateList:
    with open(os.path.join(FIXTURES_DIR, *path_components), 'rb') as inf:
        return crl.CertificateList.load(inf.read())


def load_ocsp_response(*path_components) -> ocsp.OCSPResponse:
    with open(os.path.join(FIXTURES_DIR, *path_components), 'rb') as inf:
        return ocsp.OCSPResponse.load(inf.read())


def load_nist_crl(filename):
    return load_crl(FIXTURES_DIR, 'nist_pkits', 'crls', filename)


def load_openssl_ors(filename):
    with open(os.path.join(FIXTURES_DIR, 'openssl-ocsp', filename), 'rb') as f:
        return ocsp.OCSPResponse.load(base64.b64decode(f.read()))
