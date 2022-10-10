import hashlib

from asn1crypto import ocsp
from asn1crypto.algos import DigestAlgorithm, DigestInfo
from certomancer.integrations.illusionist import Illusionist
from certomancer.registry import ArchLabel, CertLabel, KeyLabel
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.registry import SimpleCertificateStore

from pyhanko.sign import signers, timestamps
from pyhanko.sign.ades.cades_asn1 import SignaturePolicyId
from pyhanko.sign.diff_analysis import ModificationLevel
from pyhanko.sign.validation import (
    EmbeddedPdfSignature,
    SignatureCoverageLevel,
    async_validate_pdf_signature,
    validate_pdf_signature,
)
from pyhanko_tests.samples import (
    CERTOMANCER,
    CRYPTO_DATA_DIR,
    TESTING_CA,
    TESTING_CA_DIR,
    TESTING_CA_DSA,
    TESTING_CA_ECDSA,
    TESTING_CA_ED448,
    TESTING_CA_ED25519,
    UNRELATED_TSA,
    read_all,
)

SELF_SIGN = signers.SimpleSigner.load(
    CRYPTO_DATA_DIR + '/selfsigned.key.pem',
    CRYPTO_DATA_DIR + '/selfsigned.cert.pem',
    key_passphrase=b'secret'
)
ROOT_CERT = TESTING_CA.get_cert(CertLabel('root'))
ECC_ROOT_CERT = TESTING_CA_ECDSA.get_cert(CertLabel('root'))
DSA_ROOT_CERT = TESTING_CA_DSA.get_cert(CertLabel('root'))
ED25519_ROOT_CERT = TESTING_CA_ED25519.get_cert(CertLabel('root'))
ED448_ROOT_CERT = TESTING_CA_ED448.get_cert(CertLabel('root'))
INTERM_CERT = TESTING_CA.get_cert(CertLabel('interm'))
ECC_INTERM_CERT = TESTING_CA_ECDSA.get_cert(CertLabel('interm'))
DSA_INTERM_CERT = TESTING_CA_DSA.get_cert(CertLabel('interm'))
ED25519_INTERM_CERT = TESTING_CA_ED25519.get_cert(CertLabel('interm'))
ED448_INTERM_CERT = TESTING_CA_ED448.get_cert(CertLabel('interm'))
OCSP_CERT = TESTING_CA.get_cert(CertLabel('interm-ocsp'))
REVOKED_CERT = TESTING_CA.get_cert(CertLabel('signer2'))
TSA_CERT = TESTING_CA.get_cert(CertLabel('tsa'))
TSA2_CERT = TESTING_CA.get_cert(CertLabel('tsa2'))
FROM_CA = signers.SimpleSigner(
    signing_cert=TESTING_CA.get_cert(CertLabel('signer1')),
    signing_key=TESTING_CA.key_set.get_private_key(KeyLabel('signer1')),
    cert_registry=SimpleCertificateStore.from_certs([ROOT_CERT, INTERM_CERT])
)
FROM_ECC_CA = signers.SimpleSigner(
    signing_cert=TESTING_CA_ECDSA.get_cert(CertLabel('signer1')),
    signing_key=TESTING_CA_ECDSA.key_set.get_private_key(KeyLabel('signer1')),
    cert_registry=SimpleCertificateStore.from_certs(
        [ECC_ROOT_CERT, ECC_INTERM_CERT]
    )
)
FROM_DSA_CA = signers.SimpleSigner(
    signing_cert=TESTING_CA_DSA.get_cert(CertLabel('signer1')),
    signing_key=TESTING_CA_DSA.key_set.get_private_key(KeyLabel('signer1')),
    cert_registry=SimpleCertificateStore.from_certs(
        [DSA_ROOT_CERT, DSA_INTERM_CERT]
    )
)
FROM_ED25519_CA = signers.SimpleSigner(
    signing_cert=TESTING_CA_ED25519.get_cert(CertLabel('signer1')),
    signing_key=TESTING_CA_ED25519.key_set.get_private_key(KeyLabel('signer1')),
    cert_registry=SimpleCertificateStore.from_certs(
        [ED25519_ROOT_CERT, ED25519_INTERM_CERT]
    )
)
FROM_ED448_CA = signers.SimpleSigner(
    signing_cert=TESTING_CA_ED448.get_cert(CertLabel('signer1')),
    signing_key=TESTING_CA_ED448.key_set.get_private_key(KeyLabel('signer1')),
    cert_registry=SimpleCertificateStore.from_certs(
        [ED448_ROOT_CERT, ED448_INTERM_CERT]
    )
)
REVOKED_SIGNER = signers.SimpleSigner(
    signing_cert=TESTING_CA.get_cert(CertLabel('signer2')),
    signing_key=TESTING_CA.key_set.get_private_key(KeyLabel('signer2')),
    cert_registry=SimpleCertificateStore.from_certs([ROOT_CERT, INTERM_CERT])
)
TRUST_ROOTS = [TESTING_CA.get_cert(CertLabel('root'))]
FROM_CA_PKCS12 = signers.SimpleSigner.load_pkcs12(
    TESTING_CA_DIR + '/interm/signer1.pfx', passphrase=None
)
NOTRUST_V_CONTEXT = lambda: ValidationContext(trust_roots=[])
SIMPLE_V_CONTEXT = lambda: ValidationContext(trust_roots=[ROOT_CERT])
SIMPLE_ECC_V_CONTEXT = lambda: ValidationContext(trust_roots=[ECC_ROOT_CERT])
SIMPLE_DSA_V_CONTEXT = lambda: ValidationContext(trust_roots=[DSA_ROOT_CERT])
SIMPLE_ED25519_V_CONTEXT = lambda: ValidationContext(
    trust_roots=[ED25519_ROOT_CERT]
)
SIMPLE_ED448_V_CONTEXT = lambda: ValidationContext(
    trust_roots=[ED448_ROOT_CERT]
)
OCSP_KEY = TESTING_CA.key_set.get_private_key('interm-ocsp')
DUMMY_TS = timestamps.DummyTimeStamper(
    tsa_cert=TSA_CERT,
    tsa_key=TESTING_CA.key_set.get_private_key('tsa'),
    certs_to_embed=FROM_CA.cert_registry
)
DUMMY_TS2 = timestamps.DummyTimeStamper(
    tsa_cert=TSA2_CERT,
    tsa_key=TESTING_CA.key_set.get_private_key('tsa2'),
    certs_to_embed=FROM_CA.cert_registry
)
DUMMY_HTTP_TS = timestamps.HTTPTimeStamper(
    'http://pyhanko.tests/testing-ca/tsa/tsa', https=False
)
DUMMY_HTTP_TS_VARIANT = timestamps.HTTPTimeStamper(
    'http://pyhanko.tests/unrelated-tsa/tsa/tsa', https=False
)

# with the testing CA setup update, this OCSP response is totally
#  unrelated to the keys being used, so it should fail any sort of real
#  validation

FIXED_OCSP = ocsp.OCSPResponse.load(
    read_all(CRYPTO_DATA_DIR + '/ocsp.resp.der')
)
DUMMY_POLICY_ID = SignaturePolicyId({
    'sig_policy_id': '2.999',
    'sig_policy_hash': DigestInfo({
        'digest_algorithm': DigestAlgorithm({'algorithm': 'sha256'}),
        'digest': hashlib.sha256().digest()
    })
})


def dummy_ocsp_vc():
    cr = FROM_CA.cert_registry
    assert isinstance(cr, SimpleCertificateStore)
    vc = ValidationContext(
        trust_roots=TRUST_ROOTS, crls=[], ocsps=[FIXED_OCSP],
        other_certs=list(), allow_fetching=False,
        weak_hash_algos=set()
    )
    return vc


def live_testing_vc(requests_mock, with_extra_tsa=False, **kwargs):
    if with_extra_tsa:
        trust_roots = TRUST_ROOTS + [UNRELATED_TSA.get_cert(CertLabel('root'))]
    else:
        trust_roots = TRUST_ROOTS
    vc = ValidationContext(
        trust_roots=trust_roots, allow_fetching=True,
        other_certs=[], **kwargs
    )
    Illusionist(TESTING_CA).register(requests_mock)
    if with_extra_tsa:
        Illusionist(UNRELATED_TSA).register(requests_mock)
    return vc


def live_ac_vcs(requests_mock, with_authorities=False):
    pki_arch = CERTOMANCER.get_pki_arch(ArchLabel('testing-ca-with-aa'))
    if with_authorities:
        other_certs = [
            pki_arch.get_cert('interm'), pki_arch.get_cert('interm-aa'),
            pki_arch.get_cert('leaf-aa')
        ]
    else:
        other_certs = []
    main_vc = ValidationContext(
        trust_roots=[pki_arch.get_cert(CertLabel('root'))],
        allow_fetching=True, other_certs=other_certs,
    )
    ac_vc = ValidationContext(
        trust_roots=[pki_arch.get_cert(CertLabel('root-aa'))],
        allow_fetching=True, other_certs=other_certs,
    )
    Illusionist(pki_arch).register(requests_mock)
    return main_vc, ac_vc


def val_trusted(embedded_sig: EmbeddedPdfSignature, extd=False,
                vc=None):
    if vc is None:
        vc = SIMPLE_V_CONTEXT()
    val_status = validate_pdf_signature(embedded_sig, vc, skip_diff=not extd)
    return _val_trusted_check_status(val_status, extd)


async def async_val_trusted(embedded_sig: EmbeddedPdfSignature,
                            extd=False, vc=None):
    if vc is None:
        vc = SIMPLE_V_CONTEXT()
    val_status = await async_validate_pdf_signature(
        embedded_sig, vc, skip_diff=not extd
    )
    return _val_trusted_check_status(val_status, extd)


def _val_trusted_check_status(val_status, extd):
    assert val_status.intact
    assert val_status.valid
    assert val_status.trusted
    val_status.pretty_print_details()
    summ = val_status.summary()
    assert 'INTACT' in summ
    assert 'TRUSTED' in summ
    if not extd:
        assert val_status.coverage == SignatureCoverageLevel.ENTIRE_FILE
        assert val_status.modification_level == ModificationLevel.NONE
    else:
        assert val_status.coverage == SignatureCoverageLevel.ENTIRE_REVISION
        assert val_status.modification_level <= ModificationLevel.FORM_FILLING
    assert val_status.bottom_line
    return val_status


def val_untrusted(embedded_sig: EmbeddedPdfSignature, extd=False):
    val_status = validate_pdf_signature(embedded_sig, NOTRUST_V_CONTEXT())
    assert val_status.intact
    assert val_status.valid
    if not extd:
        assert val_status.coverage == SignatureCoverageLevel.ENTIRE_FILE
        assert val_status.modification_level == ModificationLevel.NONE
    else:
        assert val_status.coverage == SignatureCoverageLevel.ENTIRE_REVISION
        assert val_status.modification_level <= ModificationLevel.FORM_FILLING
    summ = val_status.summary()
    val_status.pretty_print_details()
    assert 'INTACT' in summ
    return val_status


def val_trusted_but_modified(embedded_sig: EmbeddedPdfSignature):
    val_status = validate_pdf_signature(embedded_sig, SIMPLE_V_CONTEXT())
    assert val_status.intact
    assert val_status.valid
    assert val_status.trusted
    assert val_status.coverage == SignatureCoverageLevel.ENTIRE_REVISION
    assert val_status.modification_level == ModificationLevel.OTHER
    assert not val_status.docmdp_ok
    assert not val_status.bottom_line
    return val_status