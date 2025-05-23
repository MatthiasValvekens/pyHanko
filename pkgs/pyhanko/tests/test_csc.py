import asyncio
import base64
from datetime import datetime

import aiohttp
import pytest
from aiohttp import web
from asn1crypto import algos
from certomancer.registry import CertLabel
from csc_dummy.csc_dummy_server import CSCWithCertomancer, DummyServiceParams
from freezegun import freeze_time
from pyhanko.sign.general import SigningError
from pyhanko.sign.signers import csc_signer
from pyhanko.sign.validation.utils import validate_raw

from .csc_utils.csc_dummy_client import CSCDummyClientAuthManager
from .samples import CERTOMANCER, TESTING_CA

SIGNER_B64 = """
MIIEMDCCAxigAwIBAgICEAEwDQYJKoZIhvcNAQELBQAwWTELMAkGA1UEBhMCQkUxFDASBgNVBAoM
C0V4YW1wbGUgSW5jMRowGAYDVQQLDBFUZXN0aW5nIEF1dGhvcml0eTEYMBYGA1UEAwwPSW50ZXJt
ZWRpYXRlIENBMCIYDzIwMjAwMTAxMDAwMDAwWhgPMjAyMjAxMDEwMDAwMDBaMHExCzAJBgNVBAYT
AkJFMRQwEgYDVQQKDAtFeGFtcGxlIEluYzEaMBgGA1UECwwRVGVzdGluZyBBdXRob3JpdHkxDjAM
BgNVBAMMBUFsaWNlMSAwHgYJKoZIhvcNAQkBFhFhbGljZUBleGFtcGxlLmNvbTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAOFzgm4eL34uvUYrX4akyEBi+sn0gCYo8UOthApfluxF4cca
GhCHdjZa1PwRpV3bDGFQpUbhNu0juCBkYbRGxasQOn1CUDF7DCCjztNEd779WwRlA5dnqWMFU5Ij
toavSYl+CA1Ase2edxq7UjEZr4kIm7ADlUVpdKxLItJFEP4QOjqv5sENuiGCKpMqb/JGmvnLxRev
xDZQ8hIDV2s07krCog8hRChie39mDNmZ/RH/JbgME6mGY99bDAnhu8xH41iBo8GemEmmFesx8YPr
MivcXHk3QNt2LsKCAGZlG51fsrtiC31732W0+dc09PoITS0NMvP8/38dQmod3ktJBusCAwEAAaOB
5TCB4jAdBgNVHQ4EFgQUXsenutQKZ62drno9rRRqOLVzCrgwHwYDVR0jBBgwFoAU7796UYsupC5K
XdLO52F4zmo2SU8wDgYDVR0PAQH/BAQDAgbAMEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly9weWhh
bmtvLnRlc3RzL3Rlc3RpbmctY2EvY3Jscy9pbnRlcm0vbGF0ZXN0LmNybDBHBggrBgEFBQcBAQQ7
MDkwNwYIKwYBBQUHMAGGK2h0dHA6Ly9weWhhbmtvLnRlc3RzL3Rlc3RpbmctY2Evb2NzcC9pbnRl
cm0wDQYJKoZIhvcNAQELBQADggEBACwIBhziVaZdlWg5S7PCjnL2yEeDnJWW3c1DXzKz8++mjDR0
GNsMgy1+XxKBR7gqaIDCUIPvgWko6UNfvt74txy1eBI4KHfWG/J3R9S54MTm+jZc/ctR9ma2kqcp
nz5p6HjfgdN/ejY3Fop+dZSvapbQumk27/3boKjzftXJP1VD6LSpINBDEX4kw9w4xZDpgZOcxB+s
k36fJ/cT50B7dYFFfSfKWCU7cpOYtkwnytfOBc4PxodIjrv1Y5ZSELyC8mY+U3zTlDLdG364BMSV
x4AzyPTjm252vITdbnsFZTPkpEz2gfQnh0Ee5jq+vkPfUyB0tgGju0yu9EgFIu2pzGY=
"""

INTERM_B64 = """
MIID2TCCAsGgAwIBAgICEAEwDQYJKoZIhvcNAQELBQAwUTELMAkGA1UEBhMCQkUxFDASBgNVBAoM
C0V4YW1wbGUgSW5jMRowGAYDVQQLDBFUZXN0aW5nIEF1dGhvcml0eTEQMA4GA1UEAwwHUm9vdCBD
QTAiGA8yMDAwMDEwMTAwMDAwMFoYDzIxMDAwMTAxMDAwMDAwWjBZMQswCQYDVQQGEwJCRTEUMBIG
A1UECgwLRXhhbXBsZSBJbmMxGjAYBgNVBAsMEVRlc3RpbmcgQXV0aG9yaXR5MRgwFgYDVQQDDA9J
bnRlcm1lZGlhdGUgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDB6drP3ogV8UnY
2YM0GREPUCCEe7FX905/Ocl2MjyPyh3/vaf542LGQWdC1mf3fNQsMu2dqaZTwUQrKJwIs07QV7r1
now3rKUNG8YyGtdZfKyt6jgOsfaZ5KB54sUtWGy4LKT4cPq0vEWnm8lFo91kvJqVOjFXWpUSKwTP
YJV+riBmKg25C+8D2L5oKdMzQxd8o9K0kAI0fDF1CPbqtCB/GIzwN2Cq20bX9dpzTbZOlvIundA4
hLYBNcfXnigPLylc3x3YxypoBotQ5L9MxKceBgrv1SfgtEAqxeYgUZe/UQdEG7jRy0JIYFKS/EWv
HcJ6jAX+v64hKeIAslO/67TbAgMBAAGjga4wgaswHQYDVR0OBBYEFO+/elGLLqQuSl3SzudheM5q
NklPMB8GA1UdIwQYMBaAFPG0eZUCsrRfOXL9sI/CX69bmlC1MBIGA1UdEwEB/wQIMAYBAf8CAQAw
DgYDVR0PAQH/BAQDAgGGMEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9weWhhbmtvLnRlc3RzL3Rl
c3RpbmctY2EvY3Jscy9yb290L2xhdGVzdC5jcmwwDQYJKoZIhvcNAQELBQADggEBAAx7qZLSOIk4
B7w6ymmPF3cKrafdJg83NhWAJZHOie9E23hhOV0uOLoaab2m+TbpqUXXpeuxCC3t2duLueSceHUX
Y+UhZGF4LdTojK5yVnyHynJVwbAAzRyO1hIjI9SFW+NMsFNwN6t50RAhTGY7jZvvv2y3mMwUHE2u
lgsQNax0Tyoh6yOtb752IWm0Yj+cEMQ36cjxkcFZgYTiziuYkYJM8wL+kADG+HUsnfdYJWMM/lJ7
YEkSIm0lhec3xR6siySnZI2whU3twY37WcnxwjkAczSdHZJpyzrSyjp8rCwk0zOF4HGQr3WuJhHo
kS0gHz5+cFMDBZxeP5Oq5UFvFtU=
"""


def test_proc_cert_info_response():
    cred_info = csc_signer._process_certificate_info_response(
        {
            'cert': {'certificates': [SIGNER_B64, INTERM_B64]},
            'key': {
                'algo': ['1.2.840.113549.1.1.11'],
                'len': 2048,
            },
            'multisign': 10,
            'authMode': 'implicit',
            'SCAL': 2,
        }
    )
    assert cred_info.max_batch_size == 10
    assert cred_info.hash_pinning_required
    assert 'sha256_rsa' in cred_info.supported_mechanisms
    assert 'Alice' in cred_info.signing_cert.subject.human_friendly


@pytest.mark.parametrize(
    'response_data,err_msg',
    [
        (
            {
                'cert': {},
                'key': {
                    'algo': ['1.2.840.113549.1.1.11'],
                    'len': 2048,
                },
                'multisign': 10,
                'authMode': 'implicit',
                'SCAL': 2,
            },
            "Could not retrieve certificates from response",
        ),
        (
            {
                'key': {
                    'algo': ['1.2.840.113549.1.1.11'],
                    'len': 2048,
                },
                'multisign': 10,
                'authMode': 'implicit',
                'SCAL': 2,
            },
            "Could not retrieve certificates from response",
        ),
        (
            {
                'cert': {'certificates': [SIGNER_B64.replace('M', 'Z')]},
                'key': {
                    'algo': ['1.2.840.113549.1.1.11'],
                    'len': 2048,
                },
                'multisign': 10,
                'authMode': 'implicit',
                'SCAL': 2,
            },
            "Could not decode certificates in response",
        ),
        (
            {
                'cert': {'certificates': [SIGNER_B64, INTERM_B64]},
                'key': {
                    'algo': '1.2.840.113549.1.1.11',
                    'len': 2048,
                },
                'multisign': 10,
                'authMode': 'implicit',
                'SCAL': 2,
            },
            "Could not retrieve supported signing mechanisms",
        ),
        (
            {
                'cert': {'certificates': [SIGNER_B64, INTERM_B64]},
                'key': {
                    'algo': ['zzz1.2.840.113549.1.1.11'],
                    'len': 2048,
                },
                'multisign': 10,
                'authMode': 'implicit',
                'SCAL': 2,
            },
            "Could not retrieve supported signing mechanisms",
        ),
        (
            {
                'cert': {'certificates': [SIGNER_B64, INTERM_B64]},
                'key': {
                    'len': 2048,
                },
                'multisign': 10,
                'authMode': 'implicit',
                'SCAL': 2,
            },
            "Could not retrieve supported signing mechanisms",
        ),
        (
            {
                'cert': {'certificates': [SIGNER_B64, INTERM_B64]},
                'key': {
                    'algo': ['1.2.840.113549.1.1.11'],
                    'len': 2048,
                },
                'authMode': 'implicit',
                'SCAL': 2,
            },
            "Could not retrieve max batch size",
        ),
        (
            {
                'cert': {'certificates': [SIGNER_B64, INTERM_B64]},
                'key': {
                    'algo': ['1.2.840.113549.1.1.11'],
                    'len': 2048,
                },
                'multisign': 'foobar',
                'authMode': 'implicit',
                'SCAL': 2,
            },
            "Could not retrieve max batch size",
        ),
        (
            {
                'cert': {'certificates': [SIGNER_B64, INTERM_B64]},
                'key': {
                    'algo': ['1.2.840.113549.1.1.11'],
                    'len': 2048,
                },
                'multisign': 10,
                'authMode': 'implicit',
                'SCAL': 3,
            },
            "SCAL value must be",
        ),
        (
            {
                'cert': {'certificates': [SIGNER_B64, INTERM_B64]},
                'key': {
                    'algo': ['1.2.840.113549.1.1.11'],
                    'len': 2048,
                },
                'multisign': 10,
                'authMode': 'implicit',
                'SCAL': "zzz",
            },
            "SCAL value must be",
        ),
    ],
)
def test_proc_cert_info_response_errors(response_data, err_msg):
    with pytest.raises(SigningError, match=err_msg):
        csc_signer._process_certificate_info_response(response_data)


def test_format_csc_auth_request():
    # any old auth manager will do
    auth_man = csc_signer.PrefetchedSADAuthorizationManager(
        csc_session_info=csc_signer.CSCServiceSessionInfo(
            'https://example.com', 'foobar'
        ),
        credential_info=csc_signer.CSCCredentialInfo(
            signing_cert=TESTING_CA.get_cert(CertLabel('signer1')),
            chain=[],
            supported_mechanisms=frozenset(),
            max_batch_size=10,
            hash_pinning_required=False,
            response_data={},
        ),
        csc_auth_info=csc_signer.CSCAuthorizationInfo(sad=''),
    )
    result = auth_man.format_csc_auth_request(
        pin='1234',
        otp='123456',
        hash_b64s=[
            'Sa6Tcy/PjWP+HM51lmSYLb1bIxYfAH26hWGGKtyW0GM=',
            'Sa6Tcy/PjWP+HM51lmSYLb1bIxYfAH26hWGGKtyW0GM=',
        ],
        description='baz',
        client_data='quux',
    )
    assert result == {
        'credentialID': 'foobar',
        'numSignatures': 2,
        'hash': [
            'Sa6Tcy/PjWP+HM51lmSYLb1bIxYfAH26hWGGKtyW0GM=',
            'Sa6Tcy/PjWP+HM51lmSYLb1bIxYfAH26hWGGKtyW0GM=',
        ],
        'PIN': '1234',
        'OTP': '123456',
        'description': 'baz',
        'clientData': 'quux',
    }


@freeze_time('2021-11-01T00:00:00+00:00')
def test_parse_csc_auth_response():
    response_data = {'SAD': 'foobar', 'expiresIn': 300}

    expires_at = datetime.fromisoformat('2021-11-01T00:05:00+00:00')

    result = csc_signer.CSCAuthorizationManager.parse_csc_auth_response(
        response_data
    )
    assert result == csc_signer.CSCAuthorizationInfo(
        sad='foobar', expires_at=expires_at
    )


@freeze_time('2021-11-01T00:00:00+00:00')
def test_parse_csc_auth_response_default_expiry():
    response_data = {'SAD': 'foobar'}

    expires_at = datetime.fromisoformat('2021-11-01T01:00:00+00:00')

    result = csc_signer.CSCAuthorizationManager.parse_csc_auth_response(
        response_data
    )
    assert result == csc_signer.CSCAuthorizationInfo(
        sad='foobar', expires_at=expires_at
    )


@pytest.mark.parametrize(
    'response_data,err_msg',
    [
        ({}, "Could not extract SAD"),
        (
            {'SAD': 'foobar', 'expiresIn': 'nonsense'},
            "Could not process expiresIn",
        ),
    ],
)
def test_parse_csc_auth_response_error(response_data, err_msg):
    with pytest.raises(SigningError, match=err_msg):
        csc_signer.CSCAuthorizationManager.parse_csc_auth_response(
            response_data
        )


# network failure tests
@pytest.mark.asyncio
async def test_cert_provision_fail():
    csc_session_info = csc_signer.CSCServiceSessionInfo(
        'https://example.invalid', 'foobar'
    )
    with pytest.raises(SigningError, match='Credential info request failed'):
        async with aiohttp.ClientSession() as session:
            await csc_signer.fetch_certs_in_csc_credential(
                session, csc_session_info=csc_session_info
            )


@pytest.mark.asyncio
async def test_sign_mechanism_not_supported():
    csc_session_info = csc_signer.CSCServiceSessionInfo(
        'https://example.com', 'foobar'
    )
    auth_man = csc_signer.PrefetchedSADAuthorizationManager(
        csc_session_info=csc_session_info,
        credential_info=csc_signer.CSCCredentialInfo(
            signing_cert=TESTING_CA.get_cert(CertLabel('signer1')),
            chain=[],
            supported_mechanisms=frozenset({'is_nonsense'}),
            max_batch_size=10,
            hash_pinning_required=False,
            response_data={},
        ),
        csc_auth_info=csc_signer.CSCAuthorizationInfo(sad=''),
    )
    # check expected failure for a signing attempt
    with pytest.raises(SigningError, match='No signing results available'):
        async with aiohttp.ClientSession() as session:
            signer = csc_signer.CSCSigner(session, auth_manager=auth_man)
            await signer.async_sign_raw(b'foobarbazquux', 'sha256')

    # check expected failure when fetching the signature mechanism directly
    with pytest.raises(SigningError, match='must be one of'):
        # noinspection PyTypeChecker
        signer = csc_signer.CSCSigner(None, auth_manager=auth_man)
        signer.get_signature_mechanism_for_digest(digest_algorithm='sha256')

    # ...but overrides should still work
    # noinspection PyTypeChecker
    signer = csc_signer.CSCSigner(None, auth_manager=auth_man)
    signer._signature_mechanism = mech = algos.SignedDigestAlgorithm(
        {'algorithm': 'sha256_rsa'}
    )
    assert (
        signer.get_signature_mechanism_for_digest(digest_algorithm='sha256')
        == mech
    )


@pytest.mark.asyncio
async def test_sign_network_fail():
    csc_session_info = csc_signer.CSCServiceSessionInfo(
        'https://example.invalid', 'foobar'
    )
    auth_man = csc_signer.PrefetchedSADAuthorizationManager(
        csc_session_info=csc_session_info,
        credential_info=csc_signer.CSCCredentialInfo(
            signing_cert=TESTING_CA.get_cert(CertLabel('signer1')),
            chain=[],
            supported_mechanisms=frozenset({'sha256_rsa'}),
            max_batch_size=10,
            hash_pinning_required=False,
            response_data={},
        ),
        csc_auth_info=csc_signer.CSCAuthorizationInfo(sad=''),
    )

    with pytest.raises(SigningError, match='No signing results available'):
        async with aiohttp.ClientSession() as session:
            signer = csc_signer.CSCSigner(session, auth_manager=auth_man)
            await signer.async_sign_raw(b'foobarbazquux', 'sha256')


@pytest.mark.asyncio
async def test_sign_wrong_number_of_sigs(aiohttp_client):
    csc_session_info = csc_signer.CSCServiceSessionInfo('', 'foobar')
    auth_man = csc_signer.PrefetchedSADAuthorizationManager(
        csc_session_info=csc_session_info,
        credential_info=csc_signer.CSCCredentialInfo(
            signing_cert=TESTING_CA.get_cert(CertLabel('signer1')),
            chain=[],
            supported_mechanisms=frozenset({'sha256_rsa'}),
            max_batch_size=2,
            hash_pinning_required=False,
            response_data={},
        ),
        csc_auth_info=csc_signer.CSCAuthorizationInfo(sad=''),
    )

    async def fake_return(_request):
        return web.json_response(
            {
                'signatures': [
                    base64.b64encode(bytes(512)).decode('ascii'),
                ]
            }
        )

    app = web.Application()
    app.router.add_post('/csc/v1/signatures/signHash', fake_return)
    client = await aiohttp_client(app)
    # noinspection PyTypeChecker
    signer = csc_signer.CSCSigner(
        client, auth_manager=auth_man, batch_size=2, batch_autocommit=False
    )
    result = asyncio.gather(
        signer.async_sign_raw(b'foobarbaz', 'sha256'),
        signer.async_sign_raw(b'foobarbazquux', 'sha256'),
    )

    with pytest.raises(SigningError, match='Expected 2 signatures'):
        await asyncio.sleep(1)
        await signer.commit()
    try:
        result.cancel()
        await result
    except asyncio.CancelledError:
        pass


@pytest.mark.parametrize('response_obj', [{'signatures': [None]}, {}])
@pytest.mark.asyncio
async def test_sign_unreadable_sig(aiohttp_client, response_obj):
    csc_session_info = csc_signer.CSCServiceSessionInfo('', 'foobar')
    auth_man = csc_signer.PrefetchedSADAuthorizationManager(
        csc_session_info=csc_session_info,
        credential_info=csc_signer.CSCCredentialInfo(
            signing_cert=TESTING_CA.get_cert(CertLabel('signer1')),
            chain=[],
            supported_mechanisms=frozenset({'sha256_rsa'}),
            max_batch_size=1,
            hash_pinning_required=False,
            response_data={},
        ),
        csc_auth_info=csc_signer.CSCAuthorizationInfo(sad=''),
    )

    async def fake_return(_request):
        return web.json_response(response_obj)

    app = web.Application()
    app.router.add_post('/csc/v1/signatures/signHash', fake_return)
    client = await aiohttp_client(app)
    # noinspection PyTypeChecker
    signer = csc_signer.CSCSigner(
        client,
        auth_manager=auth_man,
        batch_size=1,
        batch_autocommit=False,
        client_data='Some client data, because why not',
    )
    result = asyncio.create_task(signer.async_sign_raw(b'foobarbaz', 'sha256'))
    with pytest.raises(SigningError, match='Expected response with b64'):
        await asyncio.sleep(1)
        await signer.commit()

    try:
        result.cancel()
        await result
    except asyncio.CancelledError:
        pass


@pytest.mark.asyncio
async def test_fail_different_digest():
    csc_session_info = csc_signer.CSCServiceSessionInfo('', 'foobar')
    auth_man = csc_signer.PrefetchedSADAuthorizationManager(
        csc_session_info=csc_session_info,
        credential_info=csc_signer.CSCCredentialInfo(
            signing_cert=TESTING_CA.get_cert(CertLabel('signer1')),
            chain=[],
            supported_mechanisms=frozenset({'sha256_rsa'}),
            max_batch_size=2,
            hash_pinning_required=False,
            response_data={},
        ),
        csc_auth_info=csc_signer.CSCAuthorizationInfo(sad=''),
    )
    # noinspection PyTypeChecker
    signer = csc_signer.CSCSigner(None, auth_manager=auth_man, batch_size=2)
    with pytest.raises(SigningError, match='same digest function'):
        result = asyncio.gather(
            signer.async_sign_raw(b'foobarbaz', 'sha256'),
            signer.async_sign_raw(b'foobarbazquux', 'sha512'),
        )
        await result


async def _set_up_dummy_client(aiohttp_client, require_hash_pinning=True):
    csc_session_info = csc_signer.CSCServiceSessionInfo(
        '', 'testing-ca/signer1'
    )
    csc_dummy = CSCWithCertomancer(
        certomancer_config=CERTOMANCER,
        service_params=DummyServiceParams(
            hash_pinning_required=require_hash_pinning
        ),
    )
    csc_dummy.register_routes()
    client = await aiohttp_client(csc_dummy.app)

    auth_man = CSCDummyClientAuthManager(
        client,
        session_info=csc_session_info,
        credential_info=await csc_signer.fetch_certs_in_csc_credential(
            client, csc_session_info
        ),
    )
    return client, auth_man, csc_dummy


@pytest.mark.asyncio
async def test_submit_job_during_commit(aiohttp_client):
    client, auth_man, csc_dummy = await _set_up_dummy_client(aiohttp_client)

    class SlowCommitter(csc_signer.CSCSigner):
        _committed_once = False

        async def _do_commit(self, batch):
            # waste time
            if not self._committed_once:
                await asyncio.sleep(5)
            self._committed_once = True
            await super()._do_commit(batch)

    signer = SlowCommitter(
        session=client,
        auth_manager=auth_man,
        batch_autocommit=True,
        batch_size=2,
    )

    async def make_first_sig():
        # submit an incomplete batch
        result = asyncio.create_task(
            signer.async_sign_raw(b'foobar1', 'sha256'),
        )
        await asyncio.sleep(1)
        await signer.commit()
        return await result

    async def make_other_sigs():
        await asyncio.sleep(2)
        return await asyncio.gather(
            signer.async_sign_raw(b'foobar2', 'sha256'),
            signer.async_sign_raw(b'foobar3', 'sha256'),
        )

    sig1, others = await asyncio.gather(make_first_sig(), make_other_sigs())

    signer_cert = TESTING_CA.get_cert(CertLabel('signer1'))
    for ix, sig in enumerate([sig1, *others]):
        validate_raw(
            sig,
            b'foobar%d' % (ix + 1),
            signer_cert,
            signature_algorithm=algos.SignedDigestAlgorithm(
                {'algorithm': 'sha256_rsa'}
            ),
            md_algorithm='sha256',
        )
    assert auth_man.authorizations_requested == 2


@pytest.mark.asyncio
async def test_multi_commit_failure(aiohttp_client):
    client, auth_man, csc_dummy = await _set_up_dummy_client(aiohttp_client)
    # deliberately pass a bogus SAD to make the commit fail
    auth_man = csc_signer.PrefetchedSADAuthorizationManager(
        csc_session_info=auth_man.csc_session_info,
        credential_info=auth_man.credential_info,
        csc_auth_info=csc_signer.CSCAuthorizationInfo(sad=''),
    )

    class SlowCommitter(csc_signer.CSCSigner):
        async def _do_commit(self, batch):
            # waste time
            await asyncio.sleep(3)
            await super()._do_commit(batch)

    signer = SlowCommitter(
        session=client,
        auth_manager=auth_man,
        batch_autocommit=False,
        batch_size=1,
    )

    async def produce_signature():
        result = asyncio.create_task(
            signer.async_sign_raw(b'foobar', 'sha256'),
        )
        await asyncio.sleep(1)
        with pytest.raises(SigningError, match='Signature request failed'):
            await signer.commit()
        with pytest.raises(SigningError, match='No signing results'):
            return await result

    async def commit_again():
        with pytest.raises(SigningError, match='Commit failed'):
            await asyncio.sleep(2)
            await signer.commit()

    await asyncio.gather(produce_signature(), commit_again())
    # this should now return immediately as there is no batch
    await signer.commit()


@pytest.mark.asyncio
async def test_csc_with_parameters(aiohttp_client):
    #  produce a signature with parameters

    client, auth_man, csc_dummy = await _set_up_dummy_client(aiohttp_client)

    signer = csc_signer.CSCSigner(
        session=client,
        auth_manager=auth_man,
        batch_autocommit=True,
        batch_size=1,
        prefer_pss=True,
    )

    result = await signer.async_sign_raw(b'foobar', digest_algorithm='sha256')
    signer_cert = TESTING_CA.get_cert(CertLabel('signer1'))
    mech = signer.get_signature_mechanism_for_digest('sha256')
    assert mech.signature_algo == 'rsassa_pss'
    validate_raw(
        result,
        b'foobar',
        signer_cert,
        signature_algorithm=mech,
        md_algorithm='sha256',
    )


@pytest.mark.asyncio
async def test_prefetched_sad_not_twice(aiohttp_client):
    client, auth_man, csc_dummy = await _set_up_dummy_client(
        aiohttp_client, require_hash_pinning=False
    )

    # prefetch SAD that is not bound to any hashes
    async with client.post(
        '/csc/v1/credentials/authorize',
        json=auth_man.format_csc_auth_request(),
        raise_for_status=True,
    ) as resp:
        sad = (await resp.json())['SAD']
    auth_man = csc_signer.PrefetchedSADAuthorizationManager(
        csc_session_info=auth_man.csc_session_info,
        credential_info=auth_man.credential_info,
        csc_auth_info=csc_signer.CSCAuthorizationInfo(sad=sad),
    )

    signer = csc_signer.CSCSigner(
        session=client,
        auth_manager=auth_man,
        batch_autocommit=True,
        batch_size=1,
    )

    result = await signer.async_sign_raw(b'foobar', digest_algorithm='sha256')
    signer_cert = TESTING_CA.get_cert(CertLabel('signer1'))
    validate_raw(
        result,
        b'foobar',
        signer_cert,
        signature_algorithm=algos.SignedDigestAlgorithm(
            {'algorithm': 'sha256_rsa'}
        ),
        md_algorithm='sha256',
    )

    # but a second attempt should fail
    with pytest.raises(SigningError, match='No signing results'):
        await signer.async_sign_raw(b'foobar', digest_algorithm='sha256')


# The API docs say that the placeholder will be 512 bytes, so we record
# that in a test here


@pytest.mark.asyncio
async def test_csc_placeholder_sig_size():
    csc_session_info = csc_signer.CSCServiceSessionInfo(
        'https://example.com', 'foobar'
    )
    auth_man = csc_signer.PrefetchedSADAuthorizationManager(
        csc_session_info=csc_session_info,
        credential_info=csc_signer.CSCCredentialInfo(
            signing_cert=TESTING_CA.get_cert(CertLabel('signer1')),
            chain=[],
            supported_mechanisms=frozenset({'is_nonsense'}),
            max_batch_size=10,
            hash_pinning_required=False,
            response_data={},
        ),
        csc_auth_info=csc_signer.CSCAuthorizationInfo(sad=''),
    )
    # noinspection PyTypeChecker
    signer = csc_signer.CSCSigner(None, auth_manager=auth_man)
    await signer.async_sign_raw(b'foobarbazquux', 'sha256', dry_run=True)
