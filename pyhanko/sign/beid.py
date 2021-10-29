"""
Sign PDF files using a Belgian eID card.

This module defines a very thin convenience wrapper around
:mod:`.pyhanko.sign.pkcs11` to set up a PKCS#11 session with an eID card and
read the appropriate certificates on the device.
"""

from pkcs11 import Session

from . import pkcs11 as sign_pkcs11

__all__ = ['open_beid_session', 'BEIDSigner']


def open_beid_session(lib_location, slot_no=None) -> Session:
    """
    Open a PKCS#11 session

    :param lib_location:
        Path to the shared library file containing the eID PKCS#11 module.
        Usually, the file is named ``libbeidpkcs11.so``,
        ``libbeidpkcs11.dylib`` or ``beidpkcs11.dll``, depending on your
        operating system.
    :param slot_no:
        Slot number to use. If not specified, the first slot containing a token
        labelled ``BELPIC`` will be used.
    :return:
        An open PKCS#11 session object.
    """
    # the middleware will prompt for the user's PIN when we attempt
    # to sign later, so there's no need to specify it here
    return sign_pkcs11.open_pkcs11_session(
        lib_location, slot_no=slot_no, token_label='BELPIC'
    )


class BEIDSigner(sign_pkcs11.PKCS11Signer):
    """
    Belgian eID-specific signer implementation that automatically populates
    the (trustless) certificate list with the relevant certificates stored
    on the card.
    This includes the government's (self-signed) root certificate and the
    certificate of the appropriate intermediate CA.
    """

    def __init__(self, pkcs11_session: Session, use_auth_cert: bool = False,
                 bulk_fetch: bool = False, embed_roots=True):
        super().__init__(
            pkcs11_session=pkcs11_session,
            cert_label='Authentication' if use_auth_cert else 'Signature',
            other_certs_to_pull=('Root', 'CA'), bulk_fetch=bulk_fetch,
            embed_roots=embed_roots
        )
