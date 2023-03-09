import secrets
import struct

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def as_signed(val: int):
    # converts an integer to a signed int
    return struct.unpack('<i', struct.pack('<I', val & 0xFFFFFFFF))[0]


def aes_cbc_decrypt(key, data, iv, use_padding=True):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(data) + decryptor.finalize()

    if use_padding:
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(plaintext) + unpadder.finalize()
    else:
        return plaintext


def aes_cbc_encrypt(key, data, iv, use_padding=True):
    if iv is None:
        iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    if use_padding:
        padder = padding.PKCS7(128).padder()
        data = padder.update(data) + padder.finalize()
    return iv, encryptor.update(data) + encryptor.finalize()


def rc4_encrypt(key, data):
    cipher = Cipher(algorithms.ARC4(key), mode=None)
    encryptor = cipher.encryptor()
    # NOTE: Suppress LGTM warning here, we have to do what the spec says
    return encryptor.update(data) + encryptor.finalize()  # lgtm
