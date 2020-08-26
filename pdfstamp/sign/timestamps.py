import hashlib
import struct
import os
from base64 import b64encode
from dataclasses import dataclass
from datetime import datetime
from typing import List

import requests
import tzlocal
from asn1crypto import tsp, algos, cms, x509, keys, core
from oscrypto import asymmetric

from .general import SignatureStatus, simple_cms_attribute

__all__ = [
    'TimestampSignatureStatus', 'TimeStamper', 'HTTPTimeStamper',
    'BasicAuthTimeStamper', 'BearerAuthTimeStamper'
]


def get_nonce():
    # generate a random 8-byte integer
    # we initialise it like this to guarantee a fixed width
    return struct.unpack('>q', b'\x01' + os.urandom(7))[0]


@dataclass(frozen=True)
class TimestampSignatureStatus(SignatureStatus):
    extd_key_usage = {'time_stamping'}
    timestamp: datetime


class TimeStamper:
    """
    Class to make RFC3161 timestamp requests
    """

    def request_cms(self, message_digest, md_algorithm):
        # see also
        # https://github.com/m32/endesive/blob/5e38809387b8bdb218d02cdcaa8f17b89a8a16fc/endesive/signer.py#L161

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
        raise NotImplementedError

    def timestamp(self, message_digest, md_algorithm):
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
            raise IOError(
                f'Timestamp server refused our request: statusString '
                f'\"{status_string}\", failInfo \"{fail_info}\"'
            )
        tst = res['time_stamp_token']
        tst_info = tst['content']['encap_content_info']['content']
        nonce_received = tst_info.parsed['nonce'].native
        if nonce_received != nonce:
            raise IOError(
                f'Time stamping authority sent back bad nonce value. Expected '
                f'{nonce}, but got {nonce_received}.'
            )
        return simple_cms_attribute('signature_time_stamp_token', tst)


class DummyTimeStamper(TimeStamper):
    """
    Timestamper that acts as its own TSA. It accepts all requests and
    signs them using the certificate provided.
    Used for testing purposes.
    """

    def __init__(self, tsa_cert: x509.Certificate,
                 tsa_key: keys.PrivateKeyInfo,
                 ca_chain: List[x509.Certificate] = None,
                 md_algorithm='sha512', fixed_dt: datetime = None):
        self.tsa_cert = tsa_cert
        self.tsa_key = tsa_key
        self.md_algorithm = md_algorithm
        self.ca_chain = ca_chain or []
        self.fixed_dt = fixed_dt

    def request_tsa_response(self, req: tsp.TimeStampReq) -> tsp.TimeStampResp:
        # We pretend that certReq is always true in the request

        # TODO generalise my detached signature logic to include cases like this
        #  (see § 5.4 in RFC 5652)
        status = tsp.PKIStatusInfo({'status': tsp.PKIStatus('granted')})
        md_algorithm = self.md_algorithm.lower()
        digest_algorithm_obj = algos.DigestAlgorithm({
            'algorithm': md_algorithm
        })
        dt = self.fixed_dt or datetime.now(tz=tzlocal.get_localzone())
        tst_info = {
            'version': 'v1',
            # See http://oidref.com/1.3.6.1.4.1.4146.2.2
            # I don't really care too much, this is a testing device anyway
            'policy': tsp.ObjectIdentifier('1.3.6.1.4.1.4146.2.2'),
            'message_imprint': req['message_imprint'],
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
        message_digest = getattr(hashlib, md_algorithm)(tst_info_data).digest()
        signed_attrs = cms.CMSAttributes([
            simple_cms_attribute('content_type', 'tst_info'),
            simple_cms_attribute(
                'signing_time', cms.Time({'utc_time': core.UTCTime(dt)})
            ),
            simple_cms_attribute(
                'signing_certificate', tsp.SigningCertificate({
                    'certs': [
                        # see RFC 2634, § 5.4.1
                        tsp.ESSCertID({
                            'cert_hash':
                                hashlib.sha1(self.tsa_cert.dump()).digest()
                        })
                    ]
                })
            ),
            simple_cms_attribute('message_digest', message_digest),
        ])
        signature = asymmetric.rsa_pkcs1v15_sign(
            asymmetric.load_private_key(self.tsa_key),
            signed_attrs.dump(), md_algorithm
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
        signed_data = {
            # must use v3 to get access to the EncapsulatedContentInfo construct
            'version': 'v3',
            'digest_algorithms': cms.DigestAlgorithms((digest_algorithm_obj,)),
            'encap_content_info': cms.EncapsulatedContentInfo({
                'content_type': cms.ContentType('tst_info'),
                'content': cms.ParsableOctetString(tst_info_data)
            }),
            'certificates': [self.tsa_cert] + self.ca_chain,
            'signer_infos': [sig_info]
        }
        tst = cms.ContentInfo({
            'content_type': cms.ContentType('signed_data'),
            'content': cms.SignedData(signed_data)
        })
        return tsp.TimeStampResp({'status': status, 'time_stamp_token': tst})


class HTTPTimeStamper(TimeStamper):

    def __init__(self, url, https=False, timeout=5):
        self.url = url
        self.https = https
        self.timeout = timeout

    def request_headers(self):
        return {'Content-Type': 'application/timestamp-query'}

    def timestamp(self, message_digest, md_algorithm):
        if self.https and not self.url.startswith('https://'):
            raise ValueError('Timestamp URL is not HTTPS.')
        return super().timestamp(message_digest, md_algorithm)

    def request_tsa_response(self, req: tsp.TimeStampReq) -> tsp.TimeStampResp:
        raw_res = requests.post(
            self.url, req.dump(), headers=self.request_headers(),
        )
        if raw_res.headers.get('Content-Type') != 'application/timestamp-reply':
            raise IOError('Timestamp server response is malformed.', raw_res)
        return tsp.TimeStampResp.load(raw_res.content)


class BasicAuthTimeStamper(HTTPTimeStamper):
    def __init__(self, url, username, password, https=True):
        super().__init__(url, https)
        self.username = username
        self.password = password

    def request_headers(self):
        h = super().request_headers()
        b64 = b64encode('%s:%s' % (self.username, self.password))
        h['Authorization'] = 'Basic ' + b64.decode('ascii')
        return h


class BearerAuthTimeStamper(HTTPTimeStamper):
    def __init__(self, url, token, https=True):
        super().__init__(url, https)
        self.token = token

    def request_headers(self):
        h = super().request_headers()
        h['Authorization'] = 'Bearer ' + self.token
        return h
