from __future__ import annotations

import abc
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Generic, TypeVar

from asn1crypto import algos, cms, core, x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    padding,
)
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

logger = logging.getLogger(__name__)


def extract_dir_name(
    names: x509.GeneralNames, err_msg_prefix: str
) -> x509.Name:
    try:
        name: x509.Name = next(
            gname.chosen for gname in names if gname.name == 'directory_name'
        )
    except StopIteration:
        raise NotImplementedError(
            f"{err_msg_prefix}; only distinguished names are supported, "
            f"and none were found."
        )
    return name.untag()


def extract_ac_issuer_dir_name(
    attr_cert: cms.AttributeCertificateV2,
) -> x509.Name:
    issuer_rec = attr_cert['ac_info']['issuer']
    if issuer_rec.name == 'v1_form':
        aa_names = issuer_rec.chosen
    else:
        issuerv2: cms.V2Form = issuer_rec.chosen
        if not isinstance(issuerv2['issuer_name'], core.Void):
            aa_names = issuerv2['issuer_name']
        else:
            aa_names = x509.GeneralNames([])
    return extract_dir_name(aa_names, "Could not extract AC issuer name")


def get_issuer_dn(
    cert: x509.Certificate | cms.AttributeCertificateV2,
) -> x509.Name:
    if isinstance(cert, x509.Certificate):
        return cert.issuer
    else:
        return extract_ac_issuer_dir_name(cert)


def issuer_serial(
    cert: x509.Certificate | cms.AttributeCertificateV2,
) -> bytes:
    if isinstance(cert, x509.Certificate):
        return cert.issuer_serial
    else:
        issuer_name = extract_ac_issuer_dir_name(cert)
        result_bytes = b'%s:%d' % (
            issuer_name.sha256,
            cert['ac_info']['serial_number'].native,
        )
        return result_bytes


def get_ac_extension_value(
    attr_cert: cms.AttributeCertificateV2, ext_name: str
):
    try:
        return next(
            ext['extn_value'].parsed
            for ext in attr_cert['ac_info']['extensions']
            if ext['extn_id'].native == ext_name
        )
    except StopIteration:
        return None


def _get_http_ocsp_urls(aia_ext):
    if aia_ext is None:
        return

    for entry in aia_ext:
        # compare x509.Certificate.ocsp_urls
        if entry['access_method'].native == 'ocsp':
            location = entry['access_location']
            if location.name != 'uniform_resource_identifier':
                continue
            url = location.native
            if url.lower().startswith(
                (
                    'http://',
                    'https://',
                )
            ):
                yield url


def get_ocsp_urls(cert: x509.Certificate | cms.AttributeCertificateV2):
    if isinstance(cert, x509.Certificate):
        aia = cert.authority_information_access_value
    else:
        aia = get_ac_extension_value(cert, 'authority_information_access')

    return list(_get_http_ocsp_urls(aia))


def get_declared_revinfo(
    cert: x509.Certificate | cms.AttributeCertificateV2,
):
    if isinstance(cert, x509.Certificate):
        aia = cert.authority_information_access_value
        crl_dps = cert.crl_distribution_points_value
    else:
        aia = get_ac_extension_value(cert, 'authority_information_access')
        crl_dps = get_ac_extension_value(cert, 'crl_distribution_points')

    has_crl = crl_dps is not None

    # check if the AIA contains any OCSP entries (and here we include all
    #  entries, including those that we can't query)
    if aia is not None:
        has_ocsp = any(entry['access_method'].native == 'ocsp' for entry in aia)
    else:
        has_ocsp = False

    return has_crl, has_ocsp


def get_pyca_cryptography_hash(algorithm) -> hashes.HashAlgorithm:
    if algorithm.lower() in ('shake256', 'shake256_len'):
        # force the output length to 64 bytes = 512 bits. We don't
        # support any other lengths because those can't be valid in CMS
        return hashes.SHAKE256(digest_size=64)
    else:
        return getattr(hashes, algorithm.upper())()


def get_pyca_cryptography_hash_for_signing(
    algorithm, prehashed=False
) -> hashes.HashAlgorithm | Prehashed:
    hash_algo = get_pyca_cryptography_hash(algorithm)
    return Prehashed(hash_algo) if prehashed else hash_algo


def process_pss_params(params: algos.RSASSAPSSParams, prehashed: bool = False):
    """
    Extract PSS padding settings and message digest from an
    ``RSASSAPSSParams`` value.

    Internal API.
    """

    hash_algo: algos.DigestAlgorithm = params['hash_algorithm']
    md_name = hash_algo['algorithm'].native
    mga: algos.MaskGenAlgorithm = params['mask_gen_algorithm']
    if not mga['algorithm'].native == 'mgf1':
        raise NotImplementedError("Only MFG1 is supported")

    mgf_md_name = mga['parameters']['algorithm'].native

    if mgf_md_name != md_name:
        logger.warning(
            f"Message digest for MGF1 is {mgf_md_name}, and the one used for "
            f"signing is {md_name}. If these do not agree, some software may "
            f"refuse to validate the signature."
        )
    salt_len: int = params['salt_length'].native

    mgf_md = get_pyca_cryptography_hash(mgf_md_name)
    md = get_pyca_cryptography_hash_for_signing(md_name, prehashed=prehashed)
    pss_padding = padding.PSS(
        mgf=padding.MGF1(algorithm=mgf_md), salt_length=salt_len
    )
    return pss_padding, md


ListElem = TypeVar('ListElem')


@dataclass(frozen=True)
class ConsList(Generic[ListElem]):
    head: ListElem | None
    tail: ConsList[ListElem] | None = None

    @staticmethod
    def empty() -> ConsList[ListElem]:
        return ConsList(head=None)

    @staticmethod
    def sing(value: ListElem) -> ConsList[ListElem]:
        return ConsList(value, ConsList.empty())

    def __iter__(self):
        cur = self
        while cur.head is not None:
            yield cur.head
            cur = cur.tail

    @property
    def last(self) -> ListElem | None:
        cur = self
        result = None
        while cur.tail is not None:
            result = cur.head
            cur = cur.tail
        return result

    def cons(self, head: ListElem) -> ConsList[ListElem]:
        return ConsList(head, self)

    def __repr__(self):  # pragma: nocover
        return f"ConsList({list(reversed(list(self)))})"

    def __bool__(self):
        return self.head is not None


T = TypeVar('T')


class CancelableAsyncIterator(abc.ABC, AsyncIterator[T]):
    async def cancel(self):
        raise NotImplementedError
