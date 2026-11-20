import pytest
from asn1crypto import algos, keys
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from pyhanko_certvalidator.errors import (
    AlgorithmNotSupported,
    DSAParametersUnavailable,
    KeyTypeMismatch,
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


def _to_public_key_info(pub_key) -> keys.PublicKeyInfo:
    return keys.PublicKeyInfo.load(
        pub_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def test_ecdsa_signature_labeled_as_rsa():
    # Regression test: a valid ECDSA signature that is (incorrectly)
    # labeled as sha256WithRSAEncryption used to trigger an AssertionError.
    payload = b'Hello world'
    priv_key = ec.generate_private_key(ec.SECP256R1())
    signature = priv_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    pubkey = _to_public_key_info(priv_key.public_key())

    ecdsa_algo = algos.SignedDigestAlgorithm({'algorithm': 'sha256_ecdsa'})
    # sanity check: the signature is fine if the algorithm is labeled properly
    DefaultSignatureValidator().validate_signature(
        signature, payload, pubkey, ecdsa_algo
    )

    rsa_algo = algos.SignedDigestAlgorithm({'algorithm': 'sha256_rsa'})
    with pytest.raises(KeyTypeMismatch):
        DefaultSignatureValidator().validate_signature(
            signature, payload, pubkey, rsa_algo
        )


@pytest.mark.parametrize(
    'sig_algo,key_factory',
    [
        ('sha256_rsa', lambda: ec.generate_private_key(ec.SECP256R1())),
        ('sha256_dsa', lambda: ec.generate_private_key(ec.SECP256R1())),
        ('sha256_ecdsa', lambda: rsa.generate_private_key(65537, 2048)),
        ('ed25519', lambda: ec.generate_private_key(ec.SECP256R1())),
        ('ed448', lambda: ed25519.Ed25519PrivateKey.generate()),
        ('rsassa_pss', lambda: ec.generate_private_key(ec.SECP256R1())),
        ('mldsa44', lambda: ec.generate_private_key(ec.SECP256R1())),
        ('mldsa65', lambda: ec.generate_private_key(ec.SECP256R1())),
        ('mldsa87', lambda: ec.generate_private_key(ec.SECP256R1())),
    ],
)
def test_key_type_does_not_match_signature_algorithm(sig_algo, key_factory):
    pubkey = _to_public_key_info(key_factory().public_key())
    algo_dict = {'algorithm': sig_algo}
    if sig_algo == 'rsassa_pss':
        algo_dict['parameters'] = algos.RSASSAPSSParams(
            {'hash_algorithm': {'algorithm': 'sha256'}}
        )
    algo = algos.SignedDigestAlgorithm(algo_dict)
    # KeyTypeMismatch is an InvalidSignature, so that callers
    # treat the signature as invalid instead of crashing
    with pytest.raises(InvalidSignature) as exc_info:
        DefaultSignatureValidator().validate_signature(
            b'\x00' * 64, b'Hello world', pubkey, algo
        )
    assert isinstance(exc_info.value, KeyTypeMismatch)


@pytest.mark.parametrize('sig_algo', ['sha256_rsa', 'sha256_ecdsa', 'ed25519'])
def test_pss_only_key_with_non_pss_signature_algorithm(sig_algo):
    rsa_key = rsa.generate_private_key(65537, 2048).public_key()
    rsa_info = _to_public_key_info(rsa_key)
    pubkey = keys.PublicKeyInfo(
        {
            'algorithm': {'algorithm': 'rsassa_pss'},
            'public_key': rsa_info['public_key'],
        }
    )
    algo = algos.SignedDigestAlgorithm({'algorithm': sig_algo})
    with pytest.raises(InvalidSignature) as exc_info:
        DefaultSignatureValidator().validate_signature(
            b'\x00' * 64, b'Hello world', pubkey, algo
        )
    assert isinstance(exc_info.value, KeyTypeMismatch)
