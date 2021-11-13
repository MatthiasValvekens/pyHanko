"""
Dummy CSC server implementation.

This is a testing tool, and it omits all sorts of essential security features:

 - Requests are not authenticated
 - No SAD replay prevention of any sort, other than the standard hash pinning
   supported by the CSC protocol
 - All keys in the Certomancer config can be used to sign hashes in CSC calls

It goes without saying that you should never use this implementation, or any
derivative thereof, with production keys.
"""

import base64
from dataclasses import dataclass, field
from io import BytesIO
from typing import List, Optional

import python_pae
from aiohttp import web
from asn1crypto import algos, keys
from certomancer import registry
from certomancer.config_utils import ConfigurationError
from certomancer.registry import (
    ArchLabel,
    CertLabel,
    CertomancerObjectNotFoundError,
)
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from python_pae.encode import PAEListSettings, read_pae_coro
from python_pae.pae_types import (
    PAE_UCHAR,
    PAE_UINT,
    PAE_USHORT,
    PAEBytes,
    PAEHeterogeneousList,
    PAEHomogeneousList,
    PAEString,
)

# FIXME machine-readable error messages

# TODO implement extendTransaction since it is relevant for PDF


API_VERSION = '1.0.3.0'
DEFAULT_NAME = 'Certomancer CSC test'
DEFAULT_DESCRIPTION = """
Dummy CSC implementation for integration testing purposes.
"""

# FIXME use a url that actually resolves to an image
DEFAULT_LOGO = 'http://example.com/logo.png'


@dataclass(frozen=True)
class GeneralServiceInfo:
    api_version: str = API_VERSION
    name: str = DEFAULT_NAME
    logo: str = DEFAULT_LOGO
    region_code: str = 'XX'
    lang_code: str = 'en'
    description: str = DEFAULT_DESCRIPTION.strip()
    auth_type: List[str] = field(default_factory=lambda: ['external'])
    oauth_uri: Optional[str] = None


@dataclass(frozen=True)
class DummyServiceParams:
    hash_pinning_required: bool = True
    multisign: int = 10
    sad_secret: bytes = b'secret'


_CSC_AUTH_HASHES_LIST_PAE_TYPE = PAEHomogeneousList(
    child_type=PAEBytes(),
    settings=PAEListSettings(size_type=PAE_USHORT)
)

_CSC_AUTH_FULL_TOKEN_PAE_TYPE = PAEHeterogeneousList(
    [PAEString(), PAEBytes()],
    settings=PAEListSettings(
        size_type=PAE_UCHAR,
        length_type=PAE_UINT
    )
)


def _csc_auth_pae_embedded(obj: 'CSCAuthorization'):
    # this travels with the token
    embedded_parts = [(obj.num_signatures, PAE_USHORT)]
    if obj.hashes is not None:
        embedded_parts.append((obj.hashes, _CSC_AUTH_HASHES_LIST_PAE_TYPE))
    return python_pae.pae_encode_multiple(
        embedded_parts, size_t=PAE_UINT
    )


def _csc_auth_pae_parse(embedded_payload: bytes, credential_id: str):
    reader = read_pae_coro(
        BytesIO(embedded_payload),
        settings=PAEListSettings(size_type=PAE_UINT)
    )
    elements = next(reader)
    if elements not in (1, 2):
        raise python_pae.PAEDecodeError("Expected one or two elements")

    num_signatures = reader.send(PAE_USHORT)
    if elements == 2:
        hashes_list = reader.send(_CSC_AUTH_HASHES_LIST_PAE_TYPE)
        if len(hashes_list) != num_signatures:
            raise ValueError("Length of hashes does not match signature")
    else:
        hashes_list = None
    return CSCAuthorization(
        credential_id=credential_id,
        num_signatures=num_signatures,
        hashes=hashes_list
    )


def _csc_auth_pae(credential_id: str, embedded_payload: bytes):
    return python_pae.marshal(
        [credential_id, embedded_payload], _CSC_AUTH_FULL_TOKEN_PAE_TYPE
    )


@dataclass(frozen=True)
class CSCAuthorization:
    # TODO implement expiry

    credential_id: str
    num_signatures: int
    hashes: Optional[List[bytes]]

    @property
    def as_dict(self) -> dict:
        result = {
            'credential_id': self.credential_id,
            'num_signatures': self.num_signatures,
        }
        if self.hashes is not None:
            result['hashes'] = [
                base64.b64encode(x).decode('ascii') for x in self.hashes
            ]
        return result

    def derive_sad(self, secret: bytes) -> str:
        # noinspection PyTypeChecker
        h = hmac.HMAC(secret, hashes.SHA256())
        embedded_payload = _csc_auth_pae_embedded(self)
        input_for_mac = _csc_auth_pae(self.credential_id, embedded_payload)
        h.update(input_for_mac)
        mac_token = h.finalize()

        # Put the token together with the embedded payload
        full_token = python_pae.pae_encode(
            [embedded_payload, mac_token],
            size_t=PAE_UINT
        )
        # ...and base64 the lot
        return base64.b64encode(full_token).decode('ascii')

    @classmethod
    def verify_sad(cls, sad: str, secret: bytes, credential_id: str) \
            -> 'CSCAuthorization':
        decoded = base64.b64decode(sad)
        try:
            embedded_auth_data, mac_token = python_pae.unmarshal(
                decoded, PAEHomogeneousList(
                    child_type=PAEBytes(),
                    settings=PAEListSettings(size_type=PAE_UINT)
                )
            )
        except ValueError:
            raise web.HTTPBadRequest()
        # validate the MAC first, before trying to process the auth data
        # noinspection PyTypeChecker
        h = hmac.HMAC(secret, hashes.SHA256())
        h.update(_csc_auth_pae(credential_id, embedded_auth_data))
        try:
            h.verify(mac_token)
        except InvalidSignature:
            raise web.HTTPBadRequest()
        try:
            auth_data_obj = \
                _csc_auth_pae_parse(embedded_auth_data, credential_id)
        except ValueError:
            raise web.HTTPBadRequest()
        return auth_data_obj


ALGO_SUPPORT = {
    'rsa': {
        'rsassa_pkcs1v15', 'rsassa_pss',
        'sha256_rsa', 'sha384_rsa', 'sha512_rsa'
    },
    'ec': {'sha256_ecdsa', 'sha384_ecdsa', 'sha512_ecdsa'},
}


def b64_der(obj) -> str:
    return base64.b64encode(obj.dump()).decode('ascii')


# noinspection PyUnusedLocal
class CSCWithCertomancer:

    def __init__(self, certomancer_config: registry.CertomancerConfig,
                 svc_info: GeneralServiceInfo = GeneralServiceInfo(),
                 service_params: DummyServiceParams = DummyServiceParams()):
        self.app = web.Application()
        self.app['certomancer_config'] = certomancer_config
        self.app['svc_info'] = svc_info
        self.app['service_params'] = service_params

    def register_routes(self):
        self.app.add_routes([
            web.get('/info', self.info),
            web.post('/csc/v1/info', self.info),
            # we don't implement the auth/... endpoints
            web.post('/csc/v1/credentials/list', self.credentials_list),
            web.post('/csc/v1/credentials/info', self.credentials_info),
            web.post('/csc/v1/credentials/authorize', self.credentials_authorize),
            # we don't do extendTransaction and sendOTP
            web.post('/csc/v1/signatures/signHash', self.signatures_sign_hash),
            # TODO implement /signatures/timestamp
        ])

    @property
    def svc_info(self) -> GeneralServiceInfo:
        return self.app['svc_info']

    @property
    def service_params(self) -> DummyServiceParams:
        return self.app['service_params']

    @property
    def certomancer_config(self) -> registry.CertomancerConfig:
        return self.app['certomancer_config']

    async def info(self, request: web.Request):
        svc_info = self.svc_info
        result = {
            'specs': API_VERSION,
            'name': svc_info.name, 'logo': svc_info.logo,
            'region': svc_info.region_code, 'lang': svc_info.lang_code,
            'description': svc_info.description,
            'authType': svc_info.auth_type,
            'methods': [
                'credentials/info', 'credentials/list', 'credentials/authorize',
                'signatures/signHash', 'signatures/timestamp'
            ]
        }
        if svc_info.oauth_uri:
            result['oauth2'] = svc_info.oauth_uri
        return web.json_response(result)

    async def credentials_list(self, request: web.Request):
        params = await request.json()
        config = self.certomancer_config

        def enumerate_arch(arch_label: ArchLabel):
            try:
                pki_arch = config.get_pki_arch(arch_label)
            except ConfigurationError:
                raise web.HTTPBadRequest()
            for iss, certs in pki_arch.enumerate_certs_by_issuer():
                for cert_spec in certs:
                    yield cert_spec.label

        # we don't do pagination
        arch = params.get('clientData', None)
        if arch is None:
            archs = config.pki_archs.keys()
        else:
            archs = (arch,)
        all_credentials = [
            f"{arch_label}/{cert_label}"
            for arch_label in archs for cert_label in enumerate_arch(arch_label)
        ]
        return web.json_response({'credentialIDs': all_credentials})

    def _parse_credential_id(self, cred_id):
        splits = cred_id.split(sep='/', maxsplit=1)
        arch_label = ArchLabel(splits[0])
        try:
            cert_label = CertLabel(splits[1])
        except IndexError:
            raise web.HTTPNotFound()

        config = self.certomancer_config
        try:
            pki_arch = config.get_pki_arch(arch_label)
            cert_spec = pki_arch.get_cert_spec(cert_label)
        except CertomancerObjectNotFoundError:
            raise web.HTTPNotFound()
        return pki_arch, cert_spec

    async def credentials_info(self, request: web.Request):
        params = await request.json()
        cert_info_req = params.get('certInfo', False)

        # TODO implement certInfo
        #  (biggest roadblock: asn1crypto doesn't implement RFC 4514)
        if cert_info_req:
            raise web.HTTPNotImplemented()
        config = self.certomancer_config
        try:
            cred_id = str(params['credentialID'])
        except KeyError:
            raise web.HTTPBadRequest()

        pki_arch, cert_spec = self._parse_credential_id(cred_id)
        cert = pki_arch.get_cert(cert_spec.label)
        subj_pub_key: keys.PublicKeyInfo = cert.public_key
        enabled = pki_arch.is_subject_key_available(cert_spec.label)
        key_info = {
            'status': "enabled" if enabled else "disabled",
            'algo': [
                algos.SignedDigestAlgorithmId(algo).dotted
                for algo in ALGO_SUPPORT.get(subj_pub_key.algorithm, ())
            ],
            'len': subj_pub_key.bit_size,
        }
        if subj_pub_key.algorithm == 'ec':
            ec_params: keys.ECDomainParameters = \
                subj_pub_key['algorithm']['parameters']
            if ec_params.name == 'named':
                key_info['curve'] = ec_params.chosen.dotted

        certificates_req = params.get('certificates', 'single')
        if certificates_req not in ('none', 'chain', 'single'):
            raise web.HTTPBadRequest()
        response = {'key': key_info}
        if certificates_req != 'none':
            certs = [b64_der(cert)]
            if certificates_req == 'chain':
                certs.extend(
                    b64_der(pki_arch.get_cert(ca_cert_lbl))
                    for ca_cert_lbl in pki_arch.get_chain(cert_spec.label)
                )
            response['cert'] = {'certificates': certs}
        response['authMode'] = 'implicit'
        service_params = self.service_params
        scal = "2" if service_params.hash_pinning_required else "1"
        response['SCAL'] = scal
        response['multisign'] = service_params.multisign
        return web.json_response(response)

    async def credentials_authorize(self, request: web.Request):
        config = self.certomancer_config

        params = await request.json()
        try:
            cred_id = str(params['credentialID'])
            num_signatures = int(params['numSignatures'])
        except (KeyError, ValueError):
            raise web.HTTPBadRequest()

        pki_arch, cert_spec = self._parse_credential_id(cred_id)
        if not pki_arch.is_subject_key_available(cert_spec.label):
            raise web.HTTPBadRequest()

        hashes_list = params.get('hash', None)
        if hashes_list is None:
            if self.service_params.hash_pinning_required:
                raise web.HTTPBadRequest()
        else:
            if len(hashes_list) != num_signatures:
                raise web.HTTPBadRequest()
            hashes_list = [base64.b64decode(x) for x in hashes_list]

        auth_obj = CSCAuthorization(
            credential_id=cred_id, num_signatures=num_signatures,
            hashes=hashes_list
        )
        sad = auth_obj.derive_sad(self.service_params.sad_secret)
        return web.json_response({'SAD': sad})

    async def signatures_sign_hash(self, request: web.Request):
        config = self.certomancer_config

        params = await request.json()
        try:
            cred_id = str(params['credentialID'])
            sad = params['SAD']
        except KeyError:
            raise web.HTTPBadRequest()

        csc_auth_obj = CSCAuthorization.verify_sad(
            sad, secret=self.service_params.sad_secret, credential_id=cred_id
        )

        pki_arch, cert_spec = self._parse_credential_id(cred_id)
        try:
            priv_key_info = pki_arch.key_set.get_private_key(
                cert_spec.subject_key
            )
        except ConfigurationError as e:
            raise web.HTTPBadRequest()

        try:
            hash_list = [base64.b64decode(x) for x in params['hash']]
            sign_algo_id = algos.SignedDigestAlgorithmId(params['signAlgo'])
        except (KeyError, ValueError):
            raise web.HTTPBadRequest()

        if csc_auth_obj.hashes is not None:
            if not set(hash_list).issubset(csc_auth_obj.hashes):
                raise web.HTTPBadRequest()
        else:
            if not len(hash_list) <= csc_auth_obj.num_signatures:
                raise web.HTTPBadRequest()

        sign_algo_params = params.get('signAlgoParams', None)
        if sign_algo_params is not None:
            if sign_algo_id.native != 'rsassa_pss':
                raise web.HTTPNotImplemented()
            try:
                sign_algo_params = algos.RSASSAPSSParams.load(
                    base64.b64decode(sign_algo_params)
                )
            except ValueError:
                raise web.HTTPBadRequest()
        try:
            sign_algo = algos.SignedDigestAlgorithm({
                'algorithm': sign_algo_id,
                'parameters': sign_algo_params
            })
        except ValueError:
            raise web.HTTPBadRequest()

        hash_algo_oid = params.get('hashAlgo', None)
        try:
            hash_algo = sign_algo.hash_algo
        except ValueError:
            if hash_algo_oid is None:
                raise web.HTTPBadRequest()
            hash_algo = algos.DigestAlgorithmId(hash_algo_oid).native

        def _sign_hash(x):
            signed = generic_sign_prehashed(
                priv_key_info, x, sign_algo,
                digest_algorithm=hash_algo
            )
            return base64.b64encode(signed).decode('ascii')

        result = list(map(_sign_hash, hash_list))
        return web.json_response({'signatures': result})


def generic_sign_prehashed(private_key: keys.PrivateKeyInfo,
                           tbs_digest: bytes,
                           sd_algo: algos.SignedDigestAlgorithm,
                           digest_algorithm) -> bytes:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

    if private_key.algorithm == 'rsassa_pss':
        # as usual, we need to pretend it's a normal RSA key
        # for pyca_cryptography to be able to load it
        private_key_copy = private_key.copy()
        private_key_copy['private_key_algorithm'] = {'algorithm': 'rsa'}
        priv_key_bytes = private_key_copy.dump()
    else:
        priv_key_bytes = private_key.dump()

    priv_key = serialization.load_der_private_key(
        priv_key_bytes, password=None
    )
    sig_algo = sd_algo.signature_algo
    if sig_algo == 'rsassa_pkcs1v15':
        padding: padding.AsymmetricPadding = padding.PKCS1v15()
        hash_algo = getattr(hashes, digest_algorithm.upper())()
        assert isinstance(priv_key, rsa.RSAPrivateKey)
        return priv_key.sign(tbs_digest, padding, Prehashed(hash_algo))
    elif sig_algo == 'rsassa_pss':
        parameters = None
        if private_key.algorithm == 'rsassa_pss':
            key_params = \
                private_key['private_key_algorithm']['parameters']
            # if the key is parameterised, we must use those params
            if key_params.native is not None:
                parameters = key_params
        if parameters is None:
            parameters = sd_algo['parameters']

        mga: algos.MaskGenAlgorithm = parameters['mask_gen_algorithm']
        if not mga['algorithm'].native == 'mgf1':
            raise NotImplementedError("Only MFG1 is supported")

        mgf_md_name = mga['parameters']['algorithm'].native

        salt_len: int = parameters['salt_length'].native

        mgf_md = getattr(hashes, mgf_md_name.upper())()
        pss_padding: padding.AsymmetricPadding = padding.PSS(
            mgf=padding.MGF1(algorithm=mgf_md),
            salt_length=salt_len
        )
        hash_algo = getattr(hashes, digest_algorithm.upper())()
        assert isinstance(priv_key, rsa.RSAPrivateKey)
        return priv_key.sign(tbs_digest, pss_padding, Prehashed(hash_algo))
    elif sig_algo == 'dsa':
        assert isinstance(priv_key, dsa.DSAPrivateKey)
        hash_algo = getattr(hashes, digest_algorithm.upper())()
        return priv_key.sign(tbs_digest, Prehashed(hash_algo))
    elif sig_algo == 'ecdsa':
        hash_algo = getattr(hashes, digest_algorithm.upper())()
        assert isinstance(priv_key, ec.EllipticCurvePrivateKey)
        return priv_key.sign(
            tbs_digest, signature_algorithm=ec.ECDSA(Prehashed(hash_algo))
        )
    else:  # pragma: nocover
        raise NotImplementedError(
            f"The signature signature_algo {sig_algo} "
            f"is unsupported"
        )


def run_from_file(cfg_path, port, require_hash_pinning=True):
    cfg = registry.CertomancerConfig.from_file(cfg_path)
    csc_app = CSCWithCertomancer(
        cfg, service_params=DummyServiceParams(
            hash_pinning_required=require_hash_pinning
        )
    )
    csc_app.register_routes()
    web.run_app(
        csc_app.app, host='localhost', port=port,
    )


if __name__ == '__main__':
    import sys
    scal = int(sys.argv[3])
    run_from_file(
        sys.argv[1], port=int(sys.argv[2]), require_hash_pinning=scal >= 2
    )
