"""
Sign PDF files using a Slovenian eID card.

This module defines a very thin convenience wrapper around
:mod:`.pyhanko.sign.pkcs11` to set up a PKCS#11 session with an eID card and
read the appropriate certificates on the device.
"""

from pkcs11 import Session,ObjectClass,KeyType

from . import pkcs11 as sign_pkcs11

__all__ = ['open_eoi_session', 'EOISigner']


def open_eoi_session(lib_location,token_label:str='Podpis in prijava (Sig PIN)',user_pin:str=None) -> Session:
    """
    Open a PKCS#11 session

    :param lib_location:
        Path to the shared library file containing the eID PKCS#11 module.        
    :param token_label:
        Token label to use. If not specified token
        labelled ``Podpis in prijava (Sig PIN)`` will be used.
    :return:
        An open PKCS#11 session object.
    """
    if user_pin:
        return sign_pkcs11.open_pkcs11_session(
            lib_location, user_pin=user_pin, token_label=token_label)
    else:
        return sign_pkcs11.open_pkcs11_session(
            lib_location, token_label=token_label)


class EOISigner(sign_pkcs11.PKCS11Signer):
    """
    Slovenian eID-specific signer implementation that automatically populates
    the (trustless) certificate list with the relevant certificates stored
    on the card.
    This includes the government's (self-signed) root certificate and the
    certificate of the appropriate intermediate CA.
    """

    def __init__(
        self,
        pkcs11_session: Session,        
        bulk_fetch: bool = False,
        embed_roots=True,
    ):
        priv = pkcs11_session.get_key(ObjectClass.PRIVATE_KEY,KeyType.EC)
        super().__init__(
            pkcs11_session=pkcs11_session,
            cert_label=priv.label,            
            bulk_fetch=bulk_fetch,
            embed_roots=embed_roots,
        )
