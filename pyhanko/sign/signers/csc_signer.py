import abc
import asyncio
import base64
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional

from asn1crypto import algos, x509
from cryptography.hazmat.primitives import hashes
from dateutil.tz import tzlocal
from pyhanko_certvalidator.registry import (
    CertificateStore,
    SimpleCertificateStore,
)

from pyhanko.sign import Signer
from pyhanko.sign.general import SigningError, get_pyca_cryptography_hash

try:
    import aiohttp
except ImportError:
    raise ImportError("Install pyHanko with [async_http]")

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CSCServiceSessionInfo:
    service_url: str
    credential_id: str
    oauth_token: str
    api_ver: str = 'v1'

    def endpoint_url(self, endpoint_name):
        return f"{self.service_url}/csc/{self.api_ver}/{endpoint_name}"

    @property
    def auth_headers(self):
        return {'Authorization': f'Bearer {self.oauth_token}'}


@dataclass(frozen=True)
class CSCCredentialInfo:
    signing_cert: x509.Certificate
    chain: List[x509.Certificate]
    supported_mechanisms: frozenset[str]
    max_batch_size: int
    hash_pinning_required: bool

    def as_cert_store(self) -> CertificateStore:
        scs = SimpleCertificateStore()
        scs.register(self.signing_cert)
        scs.register_multiple(self.chain)
        return scs


async def fetch_certs_in_csc_credential(session: aiohttp.ClientSession,
                                        csc_session_info: CSCServiceSessionInfo,
                                        timeout: int = 30) -> CSCCredentialInfo:
    url = csc_session_info.endpoint_url("credentials/info")
    req_data = {
        "credentialID": csc_session_info.credential_id,
        "certificates": "chain",
        "certInfo": True
    }

    async with session.post(url=url, headers=csc_session_info.auth_headers,
                            json=req_data, raise_for_status=True,
                            timeout=timeout) as response:

        try:
            response_data = await response.json()
        except aiohttp.ClientError as e:
            raise SigningError("Credential info request failed") from e
    return _process_certificate_info_response(response_data)


def _process_certificate_info_response(response_data) -> CSCCredentialInfo:

    try:
        b64_certs = response_data['cert']['certificates']
    except KeyError as e:
        raise SigningError(
            "Could not retrieve certificates from response"
        ) from e
    try:
        certs = [
            x509.Certificate.load(base64.b64decode(cert))
            for cert in b64_certs
        ]
    except ValueError as e:
        raise SigningError(
            "Could not decode certificates in response"
        ) from e
    try:
        algo_oids = response_data["key"]["algo"]
        supported_algos = frozenset(
            algos.SignedDigestAlgorithmId(oid).native for oid in algo_oids
        )
    except (KeyError, ValueError) as e:
        raise SigningError(
            "Could not retrieve supported signing mechanisms from response"
        ) from e

    try:
        max_batch_size = int(response_data['multisign'])
    except (KeyError, ValueError) as e:
        raise SigningError(
            "Could not retrieve max batch size from response"
        ) from e

    scal_value = int(response_data.get("SCAL", 1))
    if scal_value not in (1, 2):
        logger.warning(f"Unexpected SCAL value: {scal_value}; defaulting to 1")
        scal_value = 1
    hash_pinning_required = scal_value == 2

    return CSCCredentialInfo(
        signing_cert=certs[0], chain=certs[1:],
        supported_mechanisms=supported_algos,
        max_batch_size=max_batch_size,
        hash_pinning_required=hash_pinning_required
    )


def base64_digest(data: bytes, digest_algorithm: str):

    hash_spec = get_pyca_cryptography_hash(digest_algorithm)
    md = hashes.Hash(hash_spec)
    md.update(data)
    return base64.b64encode(md.finalize()).decode('ascii')


@dataclass(frozen=True)
class CSCAuthorizationInfo:
    sad: str
    expires_at: Optional[datetime] = None


class CSCAuthorizationManager(abc.ABC):

    def __init__(self,
                 csc_session_info: CSCServiceSessionInfo,
                 credential_info: CSCCredentialInfo):
        self.csc_session_info = csc_session_info
        self.credential_info = credential_info

    async def authorize_signature(self, hash_b64s: List[str]) \
            -> CSCAuthorizationInfo:
        """
        Request a SAD from the signing service, either freshly or to extend
        the current transaction.

        Depending on the lifecycle of this object, pre-fetched SAD values
        may be used. All authorization transaction management is left to
        implementing subclasses.

        :param hash_b64s:
            Base64-encoded hash values about to be signed.
        :return:
            Authorization data.
        """
        raise NotImplementedError

    def format_csc_auth_request(self, num_signatures: int = 1,
                                pin: Optional[str] = None,
                                otp: Optional[str] = None,
                                hash_b64s: Optional[List[str]] = None,
                                description: Optional[str] = None,
                                client_data: Optional[str] = None) -> dict:
        result = {'credentialID': self.csc_session_info.credential_id}

        if hash_b64s is not None:
            # make num_signatures congruent with the number of hashes passed in
            # (this is a SHOULD in the spec, but we enforce it here)
            num_signatures = len(hash_b64s)
            result['hash'] = hash_b64s

        result['numSignatures'] = num_signatures

        if pin is not None:
            result['PIN'] = pin
        if otp is not None:
            result['OTP'] = otp
        if description is not None:
            result['description'] = description
        if client_data is not None:
            result['client_data'] = client_data

        return result

    @staticmethod
    def parse_csc_auth_response(response_data: dict) -> CSCAuthorizationInfo:

        try:
            sad = response_data["SAD"]
        except KeyError:
            raise SigningError(
                "Could not extract SAD value from auth response"
            )

        try:
            lifetime_seconds = int(response_data['expiresIn'])
            now = datetime.now(tz=tzlocal.get_localzone())
            expires_at = now + timedelta(seconds=lifetime_seconds)
        except KeyError:
            expires_at = None
        except ValueError as e:
            raise SigningError(
                "Could not process expiresIn value in auth response"
            ) from e
        return CSCAuthorizationInfo(sad=sad, expires_at=expires_at)

    @property
    def auth_headers(self):
        return self.csc_session_info.auth_headers


class PrefetchedSADAuthorizationManager(CSCAuthorizationManager):

    def __init__(self, csc_session_info: CSCServiceSessionInfo,
                 credential_info: CSCCredentialInfo,
                 csc_auth_info: CSCAuthorizationInfo):
        super().__init__(csc_session_info, credential_info)
        self.csc_auth_info = csc_auth_info
        self._used = False

    async def authorize_signature(self,
                                  hash_b64s: List[str]) -> CSCAuthorizationInfo:
        if self._used:
            raise SigningError("Prefetched SAD token is stale")
        self._used = True
        return self.csc_auth_info


@dataclass
class _CSCBatchInfo:
    notifier: asyncio.Event
    md_algorithm: str
    b64_hashes: List[str] = field(default_factory=list)
    initiated: bool = False
    results: List[bytes] = None

    def add(self, b64_hash: str) -> int:
        ix = len(self.b64_hashes)
        self.b64_hashes.append(b64_hash)
        return ix


class CSCSigner(Signer):

    def __init__(self,
                 session: aiohttp.ClientSession,
                 auth_manager: CSCAuthorizationManager,
                 sign_timeout: int,
                 prefer_pss: bool = False, embed_roots: bool = True,
                 client_data: Optional[str] = None,
                 batch_autocommit: bool = True,
                 batch_size: Optional[int] = None,
                 est_raw_signature_size=512):

        credential_info = auth_manager.credential_info
        self.auth_manager = auth_manager
        self.signing_cert = credential_info.signing_cert
        self.cert_registry = credential_info.as_cert_store()
        self.session = session
        self.est_raw_signature_size = est_raw_signature_size
        self.sign_timeout = sign_timeout
        self.client_data = client_data
        self.batch_autocommit = batch_autocommit
        self._current_batch: Optional[_CSCBatchInfo] = None
        if not batch_size:
            batch_size = credential_info.max_batch_size
        self.batch_size = batch_size
        super().__init__(prefer_pss=prefer_pss, embed_roots=embed_roots)

    def get_signature_mechanism(self, digest_algorithm):
        if self.signature_mechanism is not None:
            return self.signature_mechanism
        result = super().get_signature_mechanism(digest_algorithm)
        result_algo = result['algorithm']
        supported = self.auth_manager.credential_info.supported_mechanisms
        if result_algo.native not in supported:
            raise SigningError(
                f"Signature mechanism {result_algo.native} is not supported, "
                f"must be one of {', '.join(alg for alg in supported)}."
            )
        return result

    async def format_csc_signing_req(self, tbs_hashes: List[str],
                                     digest_algorithm: str):

        # Note: with asyncio events, it's possible to perform batch signing
        # as well (out of scope for now)
        mechanism = self.get_signature_mechanism(digest_algorithm)
        session_info = self.auth_manager.csc_session_info
        # SAD can be bound to specific hashes, but the authorization
        # process typically takes more wall clock time (esp. when
        # authorization requires a human user to perform an action).
        # Putting get_activation_data in a separate coroutine
        # allows API users to choose whether they want to provide
        # the credentials at init time, or just-in-time tied to specific
        # hashes.
        # The latter might not scale as easily within this architecture;
        # if you want both optimal security _and_ optimal performance,
        # you'll have to use this signer in the interrupted signing workflow.
        auth_info: CSCAuthorizationInfo \
            = await self.auth_manager.authorize_signature(tbs_hashes)

        req_data = {
            'credentialID': session_info.credential_id,
            'SAD': auth_info.sad,
            'hashAlgo': algos.DigestAlgorithmId(digest_algorithm).dotted,
            'signAlgo': mechanism['algorithm'].dotted,
            'hash': tbs_hashes
        }
        if mechanism['parameters'].native is not None:
            params_der = mechanism['parameters'].dump()
            req_data['signAlgoParams'] = \
                base64.b64encode(params_der).decode('ascii')
        if self.client_data is not None:
            req_data['clientData'] = self.client_data

        return req_data

    async def async_sign_raw(self, data: bytes, digest_algorithm: str,
                             dry_run=False) -> bytes:
        if dry_run:
            return bytes(self.est_raw_signature_size)

        tbs_hash = base64_digest(data, digest_algorithm)
        if self._current_batch is None:
            self._current_batch = batch = _CSCBatchInfo(
                notifier=asyncio.Event(),
                md_algorithm=digest_algorithm,
            )
        else:
            batch = self._current_batch
            if batch.md_algorithm != digest_algorithm:
                raise SigningError(
                    f"All signatures in the same batch must use the same digest"
                    f"function; encountered both {batch.md_algorithm} "
                    f"and {digest_algorithm}."
                )
        ix = batch.add(tbs_hash)
        # autocommit if the batch is full
        if self.batch_autocommit and ix == self.batch_size - 1:
            try:
                await self.commit()
            except SigningError as e:
                # log and move on, we'll throw a regular exception later
                logger.error("Failed to commit signatures", exc_info=e)

        # Sleep until a commit goes through
        await batch.notifier.wait()
        if not batch.results:
            raise SigningError("No signing results available")
        return batch.results[ix]

    async def commit(self):
        batch = self._current_batch
        if batch is None:
            raise SigningError("There is no batch to sign")
        if batch.results is not None:
            return
        elif batch.initiated:
            # just wait for the commit to finish together with
            # all the signers in the queue
            await batch.notifier.wait()
            if not batch.results:
                raise SigningError("Commit failed")
        else:
            batch.initiated = True
            try:
                await self._do_commit(batch)
            finally:
                self._current_batch = None

    async def _do_commit(self, batch: _CSCBatchInfo):
        req_data = await self.format_csc_signing_req(
            batch.b64_hashes, batch.md_algorithm
        )
        session_info = self.auth_manager.csc_session_info
        url = session_info.endpoint_url("signatures/signHash")
        session = self.session
        try:
            async with session.post(url=url,
                                    headers=self.auth_manager.auth_headers,
                                    json=req_data, raise_for_status=True,
                                    timeout=self.sign_timeout) as response:
                response_data = await response.json()
            sig_b64s = response_data['signatures']
            actual_len = len(sig_b64s)
            expected_len = len(batch.b64_hashes)
            if actual_len != expected_len:
                raise SigningError(
                    f"Expected {expected_len} signatures, got {actual_len}"
                )
            signatures = [base64.b64decode(sig) for sig in sig_b64s]
            batch.results = signatures
        except (ValueError, KeyError) as e:
            raise SigningError(
                "Expected response with b64-encoded signature values"
            ) from e
        except aiohttp.ClientError as e:
            raise SigningError("Signature request failed") from e
        finally:
            batch.notifier.set()
