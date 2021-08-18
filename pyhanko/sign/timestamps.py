"""
Module to handle the timestamping functionality in pyHanko.

Many PDF signature profiles require trusted timestamp tokens.
The tools in this module allow pyHanko to obtain such tokens from
:rfc:`3161`-compliant time stamping
authorities.
"""

import struct
import os
from dataclasses import dataclass
from datetime import datetime

import requests
import tzlocal
from asn1crypto import tsp, algos, cms, x509, keys, core
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from pyhanko_certvalidator import CertificateValidator

from . import general
from .general import (
    SignatureStatus, simple_cms_attribute, CertificateStore,
    SimpleCertificateStore, get_pyca_cryptography_hash,
)

__all__ = [
    'TimestampSignatureStatus', 'TimeStamper', 'HTTPTimeStamper',
    'TimestampRequestError',
]


class TimestampRequestError(IOError):
    """
    Raised when an error occurs while requesting a timestamp.
    """
    pass


def get_nonce():
    # generate a random 8-byte integer
    # we initialise it like this to guarantee a fixed width
    return struct.unpack('>q', b'\x01' + os.urandom(7))[0]


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


def extract_ts_certs(ts_token, store: CertificateStore):
    ts_signed_data = ts_token['content']
    ts_certs = ts_signed_data['certificates']

    def extract_ts_sid(si):
        sid = si['sid'].chosen
        # FIXME handle subject key identifier
        assert isinstance(sid, cms.IssuerAndSerialNumber)
        return sid['issuer'].dump(), sid['serial_number'].native

    ts_leaves = set(
        extract_ts_sid(si) for si in ts_signed_data['signer_infos']
    )

    for wrapped_c in ts_certs:
        c: cms.Certificate = wrapped_c.chosen
        store.register(c)
        if (c.issuer.dump(), c.serial_number) in ts_leaves:
            yield c


class TimeStamper:
    """
    Class to make :rfc:`3161` timestamp requests.
    """

    def __init__(self):
        self._dummy_response_cache = {}
        self._certs = {}
        self.cert_registry = SimpleCertificateStore()

    def dummy_response(self, md_algorithm) -> cms.ContentInfo:
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
            pass
        md_spec = get_pyca_cryptography_hash(md_algorithm)
        md = hashes.Hash(md_spec)
        dummy = self.timestamp(md.finalize(), md_algorithm)
        self._dummy_response_cache[md_algorithm] = dummy
        for cert in extract_ts_certs(dummy, self.cert_registry):
            self._certs[cert.issuer_serial] = cert
        return dummy

    def validation_paths(self, validation_context):
        """
        Produce validation paths for the certificates gathered by this
        :class:`.TimeStamper`.

        This is internal API.

        :param validation_context:
            The validation context to apply.
        :return:
            A generator producing validation paths.
        """
        # if no dummy responses are available, fetch some
        if not self._dummy_response_cache:
            from pyhanko.sign import DEFAULT_MD
            self.dummy_response(DEFAULT_MD)
        for cert in self._certs.values():
            validator = CertificateValidator(
                cert,
                intermediate_certs=self.cert_registry,
                validation_context=validation_context
            )
            yield validator.validate_usage(set(), {"time_stamping"})

    # noinspection PyMethodMayBeStatic
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
        nonce = get_nonce()
        req = tsp.TimeStampReq({
            'version': 1,
            'message_imprint': tsp.MessageImprint({
                'hash_algorithm': algos.DigestAlgorithm({
                    'algorithm': md_algorithm
                }),
                'hashed_message': message_digest
            }),
            'nonce': cms.Integer(nonce),
            # we want the server to send along its certs
            'cert_req': True
        })
        return nonce, req

    def request_tsa_response(self, req: tsp.TimeStampReq) -> tsp.TimeStampResp:
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

    def timestamp(self, message_digest, md_algorithm) -> cms.ContentInfo:
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
        res = self.request_tsa_response(req)
        pki_status_info = res['status']
        if pki_status_info['status'].native != 'granted':
            try:
                status_string = pki_status_info['status_string'].native
            except KeyError:
                status_string = ''
            try:
                fail_info = pki_status_info['fail_info'].native
            except KeyError:
                fail_info = ''
            raise TimestampRequestError(
                f'Timestamp server refused our request: statusString '
                f'\"{status_string}\", failInfo \"{fail_info}\"'
            )
        tst = res['time_stamp_token']
        tst_info = tst['content']['encap_content_info']['content']
        nonce_received = tst_info.parsed['nonce'].native
        if nonce_received != nonce:
            raise TimestampRequestError(
                f'Time stamping authority sent back bad nonce value. Expected '
                f'{nonce}, but got {nonce_received}.'
            )
        return tst


class DummyTimeStamper(TimeStamper):
    """
    Timestamper that acts as its own TSA. It accepts all requests and
    signs them using the certificate provided.
    Used for testing purposes.
    """

    def __init__(self, tsa_cert: x509.Certificate,
                 tsa_key: keys.PrivateKeyInfo,
                 certs_to_embed: CertificateStore = None,
                 fixed_dt: datetime = None,
                 override_md=None):
        self.tsa_cert = tsa_cert
        self.tsa_key = tsa_key
        self.certs_to_embed = list(certs_to_embed or ())
        self.fixed_dt = fixed_dt
        self.override_md = override_md
        super().__init__()

    def request_tsa_response(self, req: tsp.TimeStampReq) -> tsp.TimeStampResp:
        # We pretend that certReq is always true in the request

        # TODO generalise my detached signature logic to include cases like this
        #  (see § 5.4 in RFC 5652)
        # TODO does the RFC
        status = tsp.PKIStatusInfo({'status': tsp.PKIStatus('granted')})
        message_imprint: tsp.MessageImprint = req['message_imprint']
        md_algorithm = self.override_md
        if md_algorithm is None:
            md_algorithm = message_imprint['hash_algorithm']['algorithm'].native
        digest_algorithm_obj = algos.DigestAlgorithm({
            'algorithm': md_algorithm
        })
        dt = self.fixed_dt or datetime.now(tz=tzlocal.get_localzone())
        tst_info = {
            'version': 'v1',
            # See http://oidref.com/1.3.6.1.4.1.4146.2.2
            # I don't really care too much, this is a testing device anyway
            'policy': tsp.ObjectIdentifier('1.3.6.1.4.1.4146.2.2'),
            'message_imprint': message_imprint,
            # should be sufficiently random (again, this is a testing class)
            'serial_number': get_nonce(),
            'gen_time': dt,
            'tsa': x509.GeneralName(
                name='directory_name', value=self.tsa_cert.subject
            )
        }
        try:
            tst_info['nonce'] = req['nonce']
        except KeyError:
            pass

        tst_info = tsp.TSTInfo(tst_info)
        tst_info_data = tst_info.dump()
        md_spec = get_pyca_cryptography_hash(md_algorithm)
        md = hashes.Hash(md_spec)
        md.update(tst_info_data)
        message_digest_value = md.finalize()
        signed_attrs = cms.CMSAttributes([
            simple_cms_attribute('content_type', 'tst_info'),
            simple_cms_attribute(
                'signing_time', cms.Time({'utc_time': core.UTCTime(dt)})
            ),
            simple_cms_attribute(
                'signing_certificate_v2',
                general.as_signing_certificate_v2(self.tsa_cert)
            ),
            simple_cms_attribute('message_digest', message_digest_value),
        ])
        priv_key = serialization.load_der_private_key(
            self.tsa_key.dump(), password=None
        )
        if not isinstance(priv_key, RSAPrivateKey):
            raise NotImplementedError("Dummy timestamper is RSA-only.")
        signature = priv_key.sign(
            signed_attrs.dump(), PKCS1v15(),
            get_pyca_cryptography_hash(md_algorithm.upper())
        )
        sig_info = cms.SignerInfo({
            'version': 'v1',
            'sid': cms.SignerIdentifier({
                'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                    'issuer': self.tsa_cert.issuer,
                    'serial_number': self.tsa_cert.serial_number,
                })
            }),
            'digest_algorithm': digest_algorithm_obj,
            'signature_algorithm': algos.SignedDigestAlgorithm(
                {'algorithm': 'rsassa_pkcs1v15'}
            ),
            'signed_attrs': signed_attrs,
            'signature': signature
        })
        certs = set(self.certs_to_embed)
        certs.add(self.tsa_cert)
        signed_data = {
            # must use v3 to get access to the EncapsulatedContentInfo construct
            'version': 'v3',
            'digest_algorithms': cms.DigestAlgorithms((digest_algorithm_obj,)),
            'encap_content_info': cms.EncapsulatedContentInfo({
                'content_type': cms.ContentType('tst_info'),
                'content': cms.ParsableOctetString(tst_info_data)
            }),
            'certificates': certs,
            'signer_infos': [sig_info]
        }
        tst = cms.ContentInfo({
            'content_type': cms.ContentType('signed_data'),
            'content': cms.SignedData(signed_data)
        })
        return tsp.TimeStampResp({'status': status, 'time_stamp_token': tst})


class HTTPTimeStamper(TimeStamper):
    """
    Standard HTTP-based timestamp client.
    """

    def __init__(self, url, https=False, timeout=5, auth=None, headers=None):
        """
        Initialise the timestamp client.

        :param url:
            URL where the server listens for timestamp requests.
        :param https:
            Enforce HTTPS.
        :param timeout:
            Timeout (in seconds)
        :param auth:
            Value of HTTP ``Authorization`` header
        :param headers:
            Other headers to include.
        """
        self.url = url
        self.https = https
        self.timeout = timeout
        self.auth = auth
        self.headers = headers
        super().__init__()

    def request_headers(self) -> dict:
        """
        Format the HTTP request headers.

        :return:
            Header dictionary.
        """
        headers = self.headers or {}
        headers['Content-Type'] = 'application/timestamp-query'
        return headers

    def timestamp(self, message_digest, md_algorithm) -> cms.ContentInfo:
        if self.https and not self.url.startswith('https:'):  # pragma: nocover
            raise ValueError('Timestamp URL is not HTTPS.')
        return super().timestamp(message_digest, md_algorithm)

    def request_tsa_response(self, req: tsp.TimeStampReq) -> tsp.TimeStampResp:
        raw_res = requests.post(
            self.url, req.dump(), headers=self.request_headers(),
            auth=self.auth, timeout=self.timeout
        )
        if raw_res.headers.get('Content-Type') != 'application/timestamp-reply':
            raise TimestampRequestError(
                'Timestamp server response is malformed.', raw_res
            )
        return tsp.TimeStampResp.load(raw_res.content)
