"""
This module provides PKCS#11 integration for pyHanko, by providing a wrapper
for `python-pkcs11 <https://github.com/danni/python-pkcs11>`_ that can be
seamlessly plugged into a :class:`~.signers.PdfSigner`.
"""
import getpass
import logging

from asn1crypto.algos import RSASSAPSSParams

from pyhanko.config import PKCS11SignatureConfig
from typing import Set

from asn1crypto import x509

from pyhanko.sign.general import (
    CertificateStore, SimpleCertificateStore, SigningError
)
from pyhanko.sign.signers import Signer

try:
    from pkcs11 import (
        Session, ObjectClass, Attribute, lib as pkcs11_lib, PKCS11Error
    )
except ImportError as e:  # pragma: nocover
    raise ImportError(
        "pyhanko.sign.pkcs11 requires pyHanko to be installed with "
        "the [pkcs11] option. You can install missing "
        "dependencies by running \"pip install 'pyHanko[pkcs11]'\".", e
    )


__all__ = [
    'PKCS11Signer', 'open_pkcs11_session', 'PKCS11SigningContext'
]

logger = logging.getLogger(__name__)


def open_pkcs11_session(lib_location, slot_no=None, token_label=None,
                        user_pin=None) -> Session:
    """
    Open a PKCS#11 session

    :param lib_location:
        Path to the PKCS#11 module.
    :param slot_no:
        Slot number to use. If not specified, the first slot containing a token
        labelled ``token_label`` will be used.
    :param token_label:
        Label of the token to use. If ``None``, there is no constraint.
    :param user_pin:
        User PIN to use.

        .. note::
            Some PKCS#11 implementations do not require PIN when the token
            is opened, but will prompt for it out-of-band when signing.
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
                if token_label is None or token.label == token_label:
                    break
            except PKCS11Error:
                continue
        if token is None:
            raise PKCS11Error(
                f'No token with label {token_label} found'
                if token_label is not None else 'No token found'
            )
    else:
        token = slots[slot_no].get_token()
        if token_label is not None and token.label != token_label:
            raise PKCS11Error(f'Token in slot {slot_no} is not {token_label}.')

    kwargs = {}
    if user_pin is not None:
        kwargs['user_pin'] = user_pin

    return token.open(**kwargs)


def _pull_cert(pkcs11_session: Session, label: str):
    q = pkcs11_session.get_objects({
        Attribute.LABEL: label,
        Attribute.CLASS: ObjectClass.CERTIFICATE
    })

    # need to run through the full iterator to make sure the operation
    # terminates
    try:
        cert_obj, = list(q)
    except ValueError:
        raise PKCS11Error(
            f"Could not find (unique) cert with label '{label}'."
        )
    return x509.Certificate.load(cert_obj[Attribute.VALUE])


# TODO: perhaps attempt automatic key discovery if the labels aren't provided?

class PKCS11Signer(Signer):
    """
    Signer implementation for PKCS11 devices.

    :param pkcs11_session:
        The PKCS11 session object to use.
    :param cert_label:
        The label of the certificate that will be used for signing, to
        be pulled from the PKCS#11 token.
    :param signing_cert:
        The signer's certificate. If the signer's certificate is provided,
        the ``cert_label`` parameter will not be used to retrieve the
        signer's certificate.

        .. note::
            When using this parameter instead of ``cert_label``, ``key_label``
            becomes mandatory.
    :param ca_chain:
        Set of other relevant certificates
        (as :class:`.asn1crypto.x509.Certificate` objects).
    :param key_label:
        The label of the key that will be used for signing.
        Defaults to the value of ``cert_label`` if left unspecified.
    :param other_certs_to_pull:
        List labels of other certificates to pull from the PKCS#11 device.
        Defaults to the empty tuple. If ``None``, pull *all* certificates.
    :param bulk_fetch:
        Boolean indicating the fetching strategy.
        If ``True``, fetch all certs and filter the unneeded ones.
        If ``False``, fetch the requested certs one by one.
        Default value is ``True``, unless ``other_certs_to_pull`` has one or
        fewer elements, in which case it is always treated as ``False``.
    """

    def __init__(self, pkcs11_session: Session,
                 cert_label: str = None, signing_cert: x509.Certificate = None,
                 ca_chain=None, key_label=None, prefer_pss=False,
                 other_certs_to_pull=(), bulk_fetch=True):
        """
        Initialise a PKCS11 signer.
        """
        if cert_label is None:
            if signing_cert is None:
                raise SigningError(
                    "Either 'cert_label' or 'signing_cert' must be provided."
                )
            if key_label is None:
                raise SigningError(
                    "If 'cert_label' is None, then 'key_label' is mandatory."
                )
        self.cert_label = cert_label
        self._signing_cert = signing_cert
        self.key_label = key_label or cert_label
        self.pkcs11_session = pkcs11_session
        cs = SimpleCertificateStore()
        self._cert_registry: CertificateStore = cs
        if ca_chain is not None:
            cs.register_multiple(ca_chain)
            self._other_certs_loaded = True
        else:
            self._other_certs_loaded = False
        if signing_cert is not None:
            cs.register(signing_cert)
        self.other_certs = other_certs_to_pull
        if other_certs_to_pull is not None and len(other_certs_to_pull) <= 1:
            self.bulk_fetch = False
        else:
            self.bulk_fetch = bulk_fetch
        self._key_handle = None
        self._loaded = False
        super().__init__(prefer_pss=prefer_pss)

    def _init_cert_registry(self):
        # it's conceivable that one might want to load this separately from
        # the key data, so we allow for that.
        if not self._other_certs_loaded:
            certs = self._load_other_certs()
            self._cert_registry.register_multiple(certs)
            self._other_certs_loaded = True
        return self._cert_registry

    cert_registry = property(_init_cert_registry)

    @property
    def signing_cert(self):
        self._load_objects()
        return self._signing_cert

    def sign_raw(self, data: bytes, digest_algorithm: str, dry_run=False) \
            -> bytes:
        if dry_run:
            # allocate 4096 bits for the fake signature
            return b'0' * 512

        self._load_objects()
        from pkcs11 import Mechanism, SignMixin, MGF

        kh: SignMixin = self._key_handle
        kwargs = {}
        digest_algorithm = digest_algorithm.lower()
        signature_mechanism = self.get_signature_mechanism(digest_algorithm)
        signature_algo = signature_mechanism.signature_algo
        transform = None
        if signature_algo == 'rsassa_pkcs1v15':
            kwargs['mechanism'] = {
                'sha1': Mechanism.SHA1_RSA_PKCS,
                'sha256': Mechanism.SHA256_RSA_PKCS,
                'sha384': Mechanism.SHA384_RSA_PKCS,
                'sha512': Mechanism.SHA512_RSA_PKCS,
            }[digest_algorithm]
        elif signature_algo == 'ecdsa':
            # TODO test these, SoftHSM does not support these mechanisms
            #  apparently (only raw ECDSA)
            kwargs['mechanism'] = {
                'sha1': Mechanism.ECDSA_SHA1,
                'sha256': Mechanism.ECDSA_SHA256,
                'sha384': Mechanism.ECDSA_SHA384,
                'sha512': Mechanism.ECDSA_SHA512,
            }[digest_algorithm]
            from pkcs11.util.ec import encode_ecdsa_signature
            transform = encode_ecdsa_signature
        elif signature_algo == 'rsassa_pss':
            params: RSASSAPSSParams = signature_mechanism['parameters']
            assert digest_algorithm == \
                   params['hash_algorithm']['algorithm'].native

            # unpack PSS parameters into PKCS#11 language
            kwargs['mechanism'] = {
                'sha1': Mechanism.SHA1_RSA_PKCS_PSS,
                'sha256': Mechanism.SHA256_RSA_PKCS_PSS,
                'sha384': Mechanism.SHA384_RSA_PKCS_PSS,
                'sha512': Mechanism.SHA512_RSA_PKCS_PSS,
            }[digest_algorithm]

            pss_digest_param = {
                'sha1': Mechanism.SHA_1,
                'sha256': Mechanism.SHA256,
                'sha384': Mechanism.SHA384,
                'sha512': Mechanism.SHA512,
            }[digest_algorithm]

            pss_mgf_param = {
                'sha1': MGF.SHA1,
                'sha256': MGF.SHA256,
                'sha384': MGF.SHA384,
                'sha512': MGF.SHA512
            }[params['mask_gen_algorithm']['parameters']['algorithm'].native]
            pss_salt_len = params['salt_length'].native

            kwargs['mechanism_param'] = (
                pss_digest_param, pss_mgf_param, pss_salt_len
            )
        else:
            raise PKCS11Error(
                f"Signature algorithm '{signature_algo}' is not supported."
            )

        signature = kh.sign(data, **kwargs)
        if transform is not None:
            signature = transform(signature)

        return signature

    def _load_other_certs(self) -> Set[x509.Certificate]:
        return set(self.__pull())

    def __pull(self):

        other_certs = self.other_certs
        if other_certs is None or self.bulk_fetch:
            # first, query all certs
            q = self.pkcs11_session.get_objects({
                Attribute.CLASS: ObjectClass.CERTIFICATE
            })
            for cert_obj in q:
                label = cert_obj[Attribute.LABEL]
                if other_certs is None or label in other_certs:
                    yield x509.Certificate.load(cert_obj[Attribute.VALUE])
        else:
            # fetch certs one by one
            for label in other_certs:
                yield _pull_cert(self.pkcs11_session, label)

    def _load_objects(self):
        if self._loaded:
            return

        self._init_cert_registry()
        if self._signing_cert is None:
            self._signing_cert = _pull_cert(
                self.pkcs11_session, self.cert_label
            )

        q = self.pkcs11_session.get_objects({
            Attribute.LABEL: self.key_label,
            Attribute.CLASS: ObjectClass.PRIVATE_KEY
        })
        try:
            kh, = list(q)
        except ValueError as e:
            raise PKCS11Error(
                "Could not determine private key handle."
            ) from e
        if not kh[Attribute.SIGN]:
            logger.warning(
                f"The PKCS#11 device reports that the key with label "
                f"{self.key_label} cannot be used for signing!"
            )
        self._key_handle = kh

        self._loaded = True


class PKCS11SigningContext:
    """Context manager for PKCS#11 configurations."""

    def __init__(self, config: PKCS11SignatureConfig):
        self.config = config
        self._session = None

    def __enter__(self):
        config = self.config
        pin = config.user_pin
        if pin is None and config.prompt_pin:  # pragma: nocover
            pin = getpass.getpass(prompt='PKCS#11 user PIN: ')
        pin = str(pin)

        self._session = session = open_pkcs11_session(
            config.module_path, slot_no=config.slot_no,
            token_label=config.token_label,
            user_pin=pin
        )
        return PKCS11Signer(
            session, config.cert_label, ca_chain=config.other_certs,
            key_label=config.key_label, prefer_pss=config.prefer_pss,
            other_certs_to_pull=config.other_certs_to_pull,
            bulk_fetch=config.bulk_fetch
        )

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._session.close()
