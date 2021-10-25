"""
Module to handle the timestamping functionality in pyHanko.

Many PDF signature profiles require trusted timestamp tokens.
The tools in this module allow pyHanko to obtain such tokens from
:rfc:`3161`-compliant time stamping
authorities.
"""
from dataclasses import dataclass
from datetime import datetime

from asn1crypto import algos, cms, tsp
from pyhanko_certvalidator import CertificateValidator

from ..general import SignatureStatus, SimpleCertificateStore
from .common_utils import (
    dummy_digest,
    extract_ts_certs,
    get_nonce,
    handle_tsp_response,
)

__all__ = [
    'TimestampSignatureStatus', 'TimeStamper'
]


@dataclass(frozen=True)
class TimestampSignatureStatus(SignatureStatus):
    """
    Signature status class used when validating timestamp tokens.
    """
    key_usage = set()
    """
    There are no (non-extended) key usage requirements for TSA certificates.
    """

    extd_key_usage = {'time_stamping'}
    """
    TSA certificates must have the ``time_stamping`` extended key usage 
    extension (OID 1.3.6.1.5.5.7.3.8).
    """

    timestamp: datetime
    """
    Value of the timestamp token as a datetime object.
    """

    def describe_timestamp_trust(self):
        tsa = self.signing_cert

        return (
            "This timestamp is backed by a time stamping authority.\n"
            "The timestamp token is cryptographically "
            f"{'' if self.intact and self.valid else 'un'}sound.\n"
            f"TSA certificate subject: \"{tsa.subject.human_friendly}\"\n"
            f"TSA certificate SHA1 fingerprint: {tsa.sha1.hex()}\n"
            f"TSA certificate SHA256 fingerprint: {tsa.sha256.hex()}\n"
            f"TSA cert trust anchor: \"{self._trust_anchor}\"\n"
            "The TSA certificate is "
            f"{'' if self.trusted else 'un'}trusted."
        )


class TimeStamper:
    """
    .. versionchanged:: 0.9.0
        Made API more asyncio-friendly _(breaking change)_

    Class to make :rfc:`3161` timestamp requests.
    """

    def __init__(self, include_nonce=True):
        self._dummy_response_cache = {}
        self._certs = {}
        self.cert_registry = SimpleCertificateStore()
        self.include_nonce = include_nonce

    def request_cms(self, message_digest, md_algorithm):
        """
        Format the body of an :rfc:`3161` request as a CMS object.
        Subclasses with more specific needs may want to override this.

        :param message_digest:
            Message digest to which the timestamp will apply.
        :param md_algorithm:
            Message digest algorithm to use.

            .. note::
                As per :rfc:`8933`, ``md_algorithm`` should also be the
                algorithm used to compute ``message_digest``.
        :return:
            An :class:`.asn1crypto.tsp.TimeStampReq` object.
        """
        req = {
            'version': 1,
            'message_imprint': tsp.MessageImprint({
                'hash_algorithm': algos.DigestAlgorithm({
                    'algorithm': md_algorithm
                }),
                'hashed_message': message_digest
            }),
            # we want the server to send along its certs
            'cert_req': True
        }
        if self.include_nonce:
            nonce = get_nonce()
            req['nonce'] = cms.Integer(nonce)
        else:
            nonce = None
        return nonce, tsp.TimeStampReq(req)

    async def validation_paths(self, validation_context):
        """
        Produce validation paths for the certificates gathered by this
        :class:`.TimeStamper`.

        This is internal API.

        :param validation_context:
            The validation context to apply.
        :return:
            An asynchronous generator of validation paths.
        """
        await self._ensure_dummy()
        for cert in self._certs.values():
            validator = CertificateValidator(
                cert,
                intermediate_certs=self.cert_registry,
                validation_context=validation_context
            )
            yield await validator.async_validate_usage(
                set(), {"time_stamping"}
            )

    def _register_dummy(self, md_algorithm, dummy):
        self._dummy_response_cache[md_algorithm] = dummy
        for cert in extract_ts_certs(dummy, self.cert_registry):
            self._certs[cert.issuer_serial] = cert

    async def _ensure_dummy(self):
        # if no dummy responses are available, fetch some
        if not self._dummy_response_cache:
            from pyhanko.sign import DEFAULT_MD
            await self.async_dummy_response(DEFAULT_MD)

    async def async_dummy_response(self, md_algorithm) -> cms.ContentInfo:
        """
        Return a dummy response for use in CMS object size estimation.

        For every new ``md_algorithm`` passed in, this method will call
        the :meth:`timestamp` method exactly once, with a dummy digest.
        The resulting object will be cached and reused for future invocations
        of :meth:`dummy_response` with the same ``md_algorithm`` value.

        :param md_algorithm:
            Message digest algorithm to use.
        :return:
            A timestamp token, encoded as an
            :class:`.asn1crypto.cms.ContentInfo` object.
        """

        # different hashes have different sizes, so the dummy responses
        # might differ in size
        try:
            return self._dummy_response_cache[md_algorithm]
        except KeyError:
            dummy = await self.async_timestamp(
                dummy_digest(md_algorithm), md_algorithm
            )
        self._register_dummy(md_algorithm, dummy)
        return dummy

    async def async_request_tsa_response(self, req: tsp.TimeStampReq) \
            -> tsp.TimeStampResp:
        """
        Submit the specified timestamp request to the server.

        :param req:
            Request body to submit.
        :return:
            A timestamp response from the server.
        :raises IOError:
            Raised in case of an I/O issue in the communication with the
            timestamping server.
        """
        raise NotImplementedError

    async def async_timestamp(self, message_digest, md_algorithm) \
            -> cms.ContentInfo:
        """
        Request a timestamp for the given message digest.

        :param message_digest:
            Message digest to which the timestamp will apply.
        :param md_algorithm:
            Message digest algorithm to use.

            .. note::
                As per :rfc:`8933`, ``md_algorithm`` should also be the
                algorithm used to compute ``message_digest``.
        :return:
            A timestamp token, encoded as an
            :class:`.asn1crypto.cms.ContentInfo` object.
        :raises IOError:
            Raised in case of an I/O issue in the communication with the
            timestamping server.
        :raises TimestampRequestError:
            Raised if the timestamp server did not return a success response,
            or if the server's response is invalid.
        """

        nonce, req = self.request_cms(message_digest, md_algorithm)
        res = await self.async_request_tsa_response(req)
        return handle_tsp_response(res, nonce)
