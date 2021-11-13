import asyncio
from typing import List

import aiohttp

from pyhanko.sign.general import SigningError
from pyhanko.sign.signers.csc_signer import (
    CSCAuthorizationInfo,
    CSCAuthorizationManager,
    CSCServiceSessionInfo,
    CSCSigner,
    fetch_certs_in_csc_credential,
)


class CSCDummyClientAuthManager(CSCAuthorizationManager):
    def __init__(self, session, session_info, credential_info, waste_time=0):
        self.session = session
        super().__init__(
            csc_session_info=session_info,
            credential_info=credential_info
        )
        self.authorizations_requested = 0
        self.waste_time = waste_time

    async def authorize_signature(self,
                                  hash_b64s: List[str]) -> CSCAuthorizationInfo:
        self.authorizations_requested += 1
        session_info = self.csc_session_info
        req_data = self.format_csc_auth_request(hash_b64s=hash_b64s)
        session = self.session

        url = session_info.endpoint_url("credentials/authorize")
        async with session.post(url, headers=self.auth_headers,
                                json=req_data, raise_for_status=True,
                                timeout=30) as response:
            try:
                response_data = await response.json()
            except aiohttp.ClientError as e:
                raise SigningError("Credential auth request failed") from e

        if self.waste_time:
            await asyncio.sleep(self.waste_time)
        return self.parse_csc_auth_response(response_data)


class CSCDummy:
    def __init__(self, endpoint_url, credential_id, timeout: int,
                 waste_time=0, **signer_kwargs):
        self.timeout = timeout
        self.svc_info = CSCServiceSessionInfo(
            service_url=endpoint_url,
            credential_id=credential_id,
            oauth_token='deadbeef',
            api_ver='v1'
        )
        self.waste_time = waste_time
        self.signer_kwargs = signer_kwargs
        self.session = None

    async def __aenter__(self):
        svc_info = self.svc_info
        self.session = session = aiohttp.ClientSession()
        creds = await fetch_certs_in_csc_credential(
            session=session, csc_session_info=svc_info
        )
        auth_manager = CSCDummyClientAuthManager(
            session, svc_info, credential_info=creds,
            waste_time=self.waste_time
        )
        signer = CSCSigner(
            session, auth_manager=auth_manager,
            sign_timeout=self.timeout, **self.signer_kwargs
        )
        return signer

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session is not None:
            await self.session.close()
