"""
Sign PDF files using a Belgian eID card.

This module defines a very thin convenience wrapper around
:mod:`.pyhanko.sign.pkcs11` to set up a PKCS#11 session with an eID card and
read the appropriate certificates on the device.
"""

from typing import Set

from asn1crypto import x509
from oscrypto import keys

from . import pkcs11 as sign_pkcs11
from pkcs11 import (
    Attribute, ObjectClass, PKCS11Error, lib as pkcs11_lib, Session
)

__all__ = ['open_beid_session', 'BEIDSigner']


# TODO double check DLL name (for the docstring)

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
    lib = pkcs11_lib(lib_location)

    slots = lib.get_slots()
    token = None
    if slot_no is None:
        for slot in slots:
            try:
                token = slot.get_token()
                if token.label == 'BELPIC':
                    break
            except PKCS11Error:
                continue
        if token is None:
            raise PKCS11Error('No BELPIC token found')
    else:
        token = slots[slot_no].get_token()
        if token.label != 'BELPIC':
            raise PKCS11Error('Token in slot %d is not BELPIC.' % slot_no)

    # the middleware will prompt for the user's PIN when we attempt
    # to sign later, so there's no need to specify it here
    return token.open()


class BEIDSigner(sign_pkcs11.PKCS11Signer):
    """
    Belgian eID-specific signer implementation that automatically populates
    the (trustless) certificate list with the relevant certificates stored
    on the card.
    This includes the government's (self-signed) root certificate and the
    certificate of the appropriate intermediate CA.
    """

    def _load_ca_chain(self) -> Set[x509.Certificate]:

        q = self.pkcs11_session.get_objects({
            Attribute.LABEL: 'CA',
            Attribute.CLASS: ObjectClass.CERTIFICATE
        })
        cert_obj, = list(q)
        intermediate_ca = keys.parse_certificate(cert_obj[Attribute.VALUE])

        q = self.pkcs11_session.get_objects({
            Attribute.LABEL: 'Root',
            Attribute.CLASS: ObjectClass.CERTIFICATE
        })
        cert_obj, = list(q)
        root_ca = keys.parse_certificate(cert_obj[Attribute.VALUE])
        return {intermediate_ca, root_ca}
