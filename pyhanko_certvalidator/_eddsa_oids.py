# Shim module that makes asn1crypto aware of OIDs relevant for EdDSA support
# Will be removed once asn1crypto supports these OIDs natively

from asn1crypto import algos, core, keys
from asn1crypto._errors import unwrap


PRIVATE_KEY_SPECS = {
    'rsa': keys.RSAPrivateKey,
    'rsassa_pss': keys.RSAPrivateKey,
    'dsa': core.Integer,
    'ec': keys.ECPrivateKey,
    'ed25519': core.OctetString,
    'ed448': core.OctetString,
}


def _private_key_spec(self):
    algorithm = self['private_key_algorithm']['algorithm'].native
    return PRIVATE_KEY_SPECS[algorithm]


PUBLIC_KEY_SPECS = {
    'rsa': keys.RSAPublicKey,
    'rsaes_oaep': keys.RSAPublicKey,
    'rsassa_pss': keys.RSAPublicKey,
    'dsa': core.Integer,
    # We override the field spec with ECPoint so that users can easily
    # decompose the byte string into the constituent X and Y coords
    'ec': (keys.ECPointBitString, None),
    'ed25519': (core.OctetBitString, None),
    'ed448': (core.OctetBitString, None),
    'dh': core.Integer,
}


def _public_key_spec(self):
    algorithm = self['algorithm']['algorithm'].native
    return PUBLIC_KEY_SPECS[algorithm]


SIG_ALGO_MAP = {
    'md2_rsa': 'rsassa_pkcs1v15',
    'md5_rsa': 'rsassa_pkcs1v15',
    'sha1_rsa': 'rsassa_pkcs1v15',
    'sha224_rsa': 'rsassa_pkcs1v15',
    'sha256_rsa': 'rsassa_pkcs1v15',
    'sha384_rsa': 'rsassa_pkcs1v15',
    'sha512_rsa': 'rsassa_pkcs1v15',
    'rsassa_pkcs1v15': 'rsassa_pkcs1v15',
    'rsassa_pss': 'rsassa_pss',
    'sha1_dsa': 'dsa',
    'sha224_dsa': 'dsa',
    'sha256_dsa': 'dsa',
    'dsa': 'dsa',
    'sha1_ecdsa': 'ecdsa',
    'sha224_ecdsa': 'ecdsa',
    'sha256_ecdsa': 'ecdsa',
    'sha384_ecdsa': 'ecdsa',
    'sha512_ecdsa': 'ecdsa',
    'sha3_224_ecdsa': 'ecdsa',
    'sha3_256_ecdsa': 'ecdsa',
    'sha3_384_ecdsa': 'ecdsa',
    'sha3_512_ecdsa': 'ecdsa',
    'ecdsa': 'ecdsa',
    'ed448': 'ed448',
    'ed25519': 'ed25519'
}


def _signature_algo(self):
    algorithm = self['algorithm'].native

    if algorithm in SIG_ALGO_MAP:
        return SIG_ALGO_MAP[algorithm]

    raise ValueError(unwrap(
        '''
        Signature algorithm not known for %s
        ''',
        algorithm
    ))


HASH_ALGO_MAP = {
    'md2_rsa': 'md2',
    'md5_rsa': 'md5',
    'sha1_rsa': 'sha1',
    'sha224_rsa': 'sha224',
    'sha256_rsa': 'sha256',
    'sha384_rsa': 'sha384',
    'sha512_rsa': 'sha512',
    'sha1_dsa': 'sha1',
    'sha224_dsa': 'sha224',
    'sha256_dsa': 'sha256',
    'sha1_ecdsa': 'sha1',
    'sha224_ecdsa': 'sha224',
    'sha256_ecdsa': 'sha256',
    'sha384_ecdsa': 'sha384',
    'sha512_ecdsa': 'sha512',
    # baked into the signing algorithm
    'ed25519': 'sha512',
    # idem
    'ed448': 'shake256',
}


def _hash_algo(self):
    """
    :return:
        A unicode string of "md2", "md5", "sha1", "sha224", "sha256",
        "sha384", "sha512", "sha512_224", "sha512_256"
    """

    algorithm = self['algorithm'].native
    if algorithm in HASH_ALGO_MAP:
        return HASH_ALGO_MAP[algorithm]

    if algorithm == 'rsassa_pss':
        return self['parameters']['hash_algorithm']['algorithm'].native

    raise ValueError(unwrap(
        '''
        Hash algorithm not known for %s
        ''',
        algorithm
    ))


_registered = False


def register_eddsa_oids():
    global _registered
    if _registered:
        return
    ed25519_oid = '1.3.101.112'
    ed448_oid = '1.3.101.113'

    algos.SignedDigestAlgorithmId._map[ed25519_oid] = 'ed25519'
    algos.SignedDigestAlgorithmId._map[ed448_oid] = 'ed448'
    algos.SignedDigestAlgorithmId._reverse_map = None

    # override the signature_algo and hash_algo properties
    setattr(algos.SignedDigestAlgorithm,
            'signature_algo', property(_signature_algo))
    setattr(algos.SignedDigestAlgorithm, 'hash_algo', property(_hash_algo))

    keys.PublicKeyAlgorithmId._map[ed25519_oid] = 'ed25519'
    keys.PublicKeyAlgorithmId._map[ed448_oid] = 'ed448'
    keys.PublicKeyAlgorithmId._reverse_map = None

    keys.PrivateKeyAlgorithmId._map[ed25519_oid] = 'ed25519'
    keys.PrivateKeyAlgorithmId._map[ed448_oid] = 'ed448'
    keys.PrivateKeyAlgorithmId._reverse_map = None

    # need to patch in these callback methods as well
    keys.PrivateKeyInfo._spec_callbacks['private_key'] = _private_key_spec
    keys.PublicKeyInfo._spec_callbacks['public_key'] = _public_key_spec

    _registered = True
