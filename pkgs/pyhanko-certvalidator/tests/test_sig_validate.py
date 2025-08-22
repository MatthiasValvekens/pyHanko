import pytest
from asn1crypto import algos, keys

from pyhanko_certvalidator.errors import (
    AlgorithmNotSupported,
    DSAParametersUnavailable,
    PSSParameterMismatch,
)
from pyhanko_certvalidator.sig_validate import DefaultSignatureValidator

from .common import load_cert_object, load_nist_cert


def test_dsa_inheritance_missing_params():
    pubkey = load_nist_cert('DSACACert.crt').public_key
    pubkey_stripped = keys.PublicKeyInfo(
        {
            'algorithm': {
                'algorithm': pubkey['algorithm']['algorithm'],
            },
            'public_key': pubkey['public_key'],
        }
    )
    issued_cert = load_nist_cert('InvalidDSASignatureTest6EE.crt')
    payload = issued_cert['tbs_certificate'].dump()
    signature = issued_cert['signature_value'].native
    algo_stripped = algos.SignedDigestAlgorithm(
        {'algorithm': issued_cert['signature_algorithm']['algorithm']}
    )
    with pytest.raises(DSAParametersUnavailable):
        DefaultSignatureValidator().validate_signature(
            signature, payload, pubkey_stripped, algo_stripped
        )


def test_pss_parameter_mismatch():
    pubkey = load_cert_object('testing-ca-pss', 'root.cert.pem').public_key
    pubkey_mangled = keys.PublicKeyInfo(
        {
            'algorithm': {
                'algorithm': 'rsassa_pss',
                'parameters': keys.RSASSAPSSParams(
                    {'hash_algorithm': {'algorithm': 'sha3_256'}}
                ),
            },
            'public_key': pubkey['public_key'],
        }
    )

    issued_cert = load_cert_object('testing-ca-pss', 'interm.cert.pem')
    payload = issued_cert['tbs_certificate'].dump()
    signature = issued_cert['signature_value'].native
    with pytest.raises(PSSParameterMismatch):
        DefaultSignatureValidator().validate_signature(
            signature,
            payload,
            pubkey_mangled,
            issued_cert['signature_algorithm'],
        )


def test_algorithm_not_supported():
    pubkey = load_cert_object('testing-ca-pss', 'root.cert.pem').public_key
    issued_cert = load_cert_object('testing-ca-pss', 'interm.cert.pem')
    payload = issued_cert['tbs_certificate'].dump()
    signature = issued_cert['signature_value'].native
    algo = algos.SignedDigestAlgorithm(
        {'algorithm': algos.SignedDigestAlgorithmId('2.999')}
    )
    with pytest.raises(AlgorithmNotSupported):
        DefaultSignatureValidator().validate_signature(
            signature, payload, pubkey, algo
        )
