from typing import Optional

from asn1crypto import keys, pem, x509
from cryptography.hazmat.primitives import serialization

from .internal import translate_pyca_cryptography_key_to_asn1

__all__ = [
    'load_cert_from_pemder',
    'load_certs_from_pemder',
    'load_certs_from_pemder_data',
    'load_private_key_from_pemder',
    'load_private_key_from_pemder_data',
]


def load_certs_from_pemder(cert_files):
    """
    A convenience function to load PEM/DER-encoded certificates from files.

    :param cert_files:
        An iterable of file names.
    :return:
        A generator producing :class:`.asn1crypto.x509.Certificate` objects.
    """
    for cert_file in cert_files:
        with open(cert_file, 'rb') as f:
            cert_data_bytes = f.read()
        yield from load_certs_from_pemder_data(cert_data_bytes)


def load_certs_from_pemder_data(cert_data_bytes: bytes):
    """
    A convenience function to load PEM/DER-encoded certificates from
    binary data.

    :param cert_data_bytes:
        ``bytes`` object from which to extract certificates.
    :return:
        A generator producing :class:`.asn1crypto.x509.Certificate` objects.
    """
    # use the pattern from the asn1crypto docs
    # to distinguish PEM/DER and read multiple certs
    # from one PEM file (if necessary)
    if pem.detect(cert_data_bytes):
        pems = pem.unarmor(cert_data_bytes, multiple=True)
        for type_name, _, der in pems:
            if type_name is None or type_name.lower() == 'certificate':
                yield x509.Certificate.load(der)
    else:
        # no need to unarmor, just try to load it immediately
        yield x509.Certificate.load(cert_data_bytes)


def load_cert_from_pemder(cert_file):
    """
    A convenience function to load a single PEM/DER-encoded certificate
    from a file.

    :param cert_file:
        A file name.
    :return:
        An :class:`.asn1crypto.x509.Certificate` object.
    """
    certs = list(load_certs_from_pemder([cert_file]))
    if len(certs) != 1:
        raise ValueError(f"Number of certs in {cert_file} should be exactly 1")
    return certs[0]


def load_private_key_from_pemder(
    key_file, passphrase: Optional[bytes]
) -> keys.PrivateKeyInfo:
    """
    A convenience function to load PEM/DER-encoded keys from files.

    :param key_file:
        File to read the key from.
    :param passphrase:
        Key passphrase.
    :return:
        A private key encoded as an unencrypted PKCS#8 PrivateKeyInfo object.
    """
    with open(key_file, 'rb') as f:
        key_bytes = f.read()
    return load_private_key_from_pemder_data(key_bytes, passphrase=passphrase)


def load_private_key_from_pemder_data(
    key_bytes: bytes, passphrase: Optional[bytes]
) -> keys.PrivateKeyInfo:
    """
    A convenience function to load PEM/DER-encoded keys from binary data.

    :param key_bytes:
        ``bytes`` object to read the key from.
    :param passphrase:
        Key passphrase.
    :return:
        A private key encoded as an unencrypted PKCS#8 PrivateKeyInfo object.
    """
    load_fun = (
        serialization.load_pem_private_key
        if pem.detect(key_bytes)
        else serialization.load_der_private_key
    )
    return translate_pyca_cryptography_key_to_asn1(
        load_fun(key_bytes, password=passphrase)
    )
