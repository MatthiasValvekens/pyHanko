import abc
import enum
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Iterable, Union

from asn1crypto import ocsp, crl, core

from pyhanko_certvalidator._types import type_name
from pyhanko_certvalidator.util import pretty_message
from pyhanko_certvalidator.policy_decl import CertRevTrustPolicy, \
    FreshnessReqType


@dataclass(frozen=True)
class ValidationTimingInfo:
    validation_time: datetime
    use_poe_time: datetime
    time_tolerance: timedelta
    point_in_time_validation: bool


class POEManager:

    def __init__(self, current_dt_override: Optional[datetime] = None):
        self._poes = {}
        self._current_dt_override = current_dt_override

    def register(self, data: Union[bytes, core.Asn1Value],
                 dt: Optional[datetime] = None) -> datetime:
        if isinstance(data, core.Asn1Value):
            data = data.dump()
        digest = hashlib.sha256(data).digest()
        return self.register_by_digest(digest, dt)

    def register_by_digest(self, digest: bytes, dt: Optional[datetime] = None) \
            -> datetime:
        dt = dt or self._current_dt_override or datetime.now(timezone.utc)
        try:
            cur_poe = self._poes[digest]
            if cur_poe <= dt:
                return cur_poe
        except KeyError:
            pass
        self._poes[digest] = dt
        return dt

    def __iter__(self):
        return iter(self._poes.items())

    def __getitem__(self, item: Union[bytes, core.Asn1Value]):
        return self.register(item, dt=None)

    def __ior__(self, other):
        if not isinstance(other, POEManager):
            raise TypeError
        for digest, dt in iter(other):
            self.register_by_digest(digest, dt)


class RevinfoUsabilityRating(enum.Enum):
    OK = enum.auto()
    STALE = enum.auto()
    TOO_NEW = enum.auto()
    UNCLEAR = enum.auto()

    @property
    def usable(self) -> bool:
        return self == RevinfoUsabilityRating.OK


class IssuedItemContainer(abc.ABC):
    @property
    def issuance_date(self) -> Optional[datetime]:
        raise NotImplementedError


class RevinfoContainer(IssuedItemContainer, abc.ABC):

    def usable_at(self, policy: CertRevTrustPolicy,
                  timing_info: ValidationTimingInfo) -> RevinfoUsabilityRating:
        raise NotImplementedError


def sort_freshest_first(lst: Iterable[RevinfoContainer]):
    def _key(container: RevinfoContainer):
        dt = container.issuance_date
        # if dt is None ---> (0, None)
        # else ---> (1, dt)
        # This ensures that None is never compared to anything (which would
        #  cause a TypeError), and that (0, None) gets sorted before everything
        #  else. Since we sort reversed, the "unknown issuance date" ones
        #  are dumped at the end of the list.
        return dt is not None, dt
    return sorted(lst, key=_key, reverse=True)


def _freshness_delta(policy, this_update, next_update, time_tolerance):

    freshness_delta = policy.freshness
    if freshness_delta is None:
        if next_update is not None and next_update >= this_update:
            freshness_delta = next_update - this_update
    if freshness_delta is not None:
        freshness_delta = abs(freshness_delta) + time_tolerance
    return freshness_delta


def _judge_revinfo(this_update: Optional[datetime],
                   next_update: Optional[datetime],
                   policy: CertRevTrustPolicy,
                   timing_info: ValidationTimingInfo) \
        -> RevinfoUsabilityRating:

    if this_update is None:
        return RevinfoUsabilityRating.UNCLEAR

    # Revinfo issued after the validation time doesn't make any sense
    # to consider, except in the case of the (legacy) default policy
    # with retroactive_revinfo active.
    # AdES-derived policies are supposed to use proper POE handling in lieu
    # of this alternative system.
    #  TODO revisit this when we actually implement AdES point-in-time
    #   validation. Maybe this needs to be dealt with at a higher level, to
    #   accept future revinfo as evidence of non-revocation or somesuch
    if timing_info.validation_time < this_update:
        if not policy.retroactive_revinfo or \
                policy.freshness_req_type != FreshnessReqType.DEFAULT:
            return RevinfoUsabilityRating.TOO_NEW

    validation_time = timing_info.validation_time
    time_tolerance = timing_info.time_tolerance
    # see 5.2.5.4 in ETSI EN 319 102-1
    if policy.freshness_req_type == FreshnessReqType.TIME_AFTER_SIGNATURE:
        # check whether the revinfo was generated sufficiently long _after_
        # the (presumptive) signature time
        freshness_delta = _freshness_delta(
            policy, this_update, next_update, time_tolerance
        )
        if freshness_delta is None:
            return RevinfoUsabilityRating.UNCLEAR
        signature_poe_time = timing_info.use_poe_time
        if this_update - signature_poe_time < freshness_delta:
            return RevinfoUsabilityRating.STALE
    elif policy.freshness_req_type \
            == FreshnessReqType.MAX_DIFF_REVOCATION_VALIDATION:
        # check whether the difference between thisUpdate
        # and the validation time is small enough

        # add time_tolerance to allow for additional time drift
        freshness_delta = _freshness_delta(
            policy, this_update, next_update, time_tolerance
        )
        if freshness_delta is None:
            return RevinfoUsabilityRating.UNCLEAR

        # See ETSI EN 319 102-1, § 5.2.5.4, item 2)
        #  in particular, "too recent" doesn't seem to apply;
        #  the result is pass/fail
        if this_update < validation_time - freshness_delta:
            return RevinfoUsabilityRating.STALE
    elif policy.freshness_req_type == FreshnessReqType.DEFAULT:
        # check whether the validation time falls within the
        # thisUpdate-nextUpdate window (non-AdES!!)
        if next_update is None:
            return RevinfoUsabilityRating.UNCLEAR

        retroactive = policy.retroactive_revinfo

        if not retroactive and validation_time < this_update - time_tolerance:
            return RevinfoUsabilityRating.TOO_NEW
        if validation_time > next_update + time_tolerance:
            return RevinfoUsabilityRating.STALE
    else:  # pragma: nocover
        raise NotImplementedError
    return RevinfoUsabilityRating.OK


def _extract_basic_ocsp_response(ocsp_response) \
        -> Optional[ocsp.BasicOCSPResponse]:

    # Make sure that we get a valid response back from the OCSP responder
    status = ocsp_response['response_status'].native
    if status != 'successful':
        return None

    response_bytes = ocsp_response['response_bytes']
    if response_bytes['response_type'].native != 'basic_ocsp_response':
        return None

    return response_bytes['response'].parsed


@dataclass(frozen=True)
class OCSPContainer(RevinfoContainer):
    ocsp_response_data: ocsp.OCSPResponse
    index: int = 0

    @classmethod
    def load_multi(cls, ocsp_response: ocsp.OCSPResponse) \
            -> List['OCSPContainer']:
        basic_ocsp_response = _extract_basic_ocsp_response(ocsp_response)
        if basic_ocsp_response is None:
            return []
        tbs_response = basic_ocsp_response['tbs_response_data']

        return [
            OCSPContainer(ocsp_response_data=ocsp_response, index=ix)
            for ix in range(len(tbs_response['responses']))
        ]

    @property
    def issuance_date(self) -> Optional[datetime]:
        cert_response = self.extract_single_response()
        if cert_response is None:
            return None

        return cert_response['this_update'].native

    def usable_at(self, policy: CertRevTrustPolicy,
                  timing_info: ValidationTimingInfo) -> RevinfoUsabilityRating:

        cert_response = self.extract_single_response()
        if cert_response is None:
            return RevinfoUsabilityRating.UNCLEAR

        this_update = cert_response['this_update'].native
        next_update = cert_response['next_update'].native
        return _judge_revinfo(
            this_update, next_update,
            policy=policy, timing_info=timing_info,
        )

    def extract_basic_ocsp_response(self) -> Optional[ocsp.BasicOCSPResponse]:
        return _extract_basic_ocsp_response(self.ocsp_response_data)

    def extract_single_response(self) -> Optional[ocsp.SingleResponse]:
        basic_ocsp_response = self.extract_basic_ocsp_response()
        if basic_ocsp_response is None:
            return None
        tbs_response = basic_ocsp_response['tbs_response_data']

        if len(tbs_response['responses']) <= self.index:
            return None
        return tbs_response['responses'][self.index]


@dataclass(frozen=True)
class CRLContainer(RevinfoContainer):
    crl_data: crl.CertificateList

    def usable_at(self, policy: CertRevTrustPolicy,
                  timing_info: ValidationTimingInfo) -> RevinfoUsabilityRating:
        tbs_cert_list = self.crl_data['tbs_cert_list']
        this_update = tbs_cert_list['this_update'].native
        next_update = tbs_cert_list['next_update'].native
        return _judge_revinfo(
            this_update, next_update,  policy=policy,
            timing_info=timing_info
        )

    @property
    def issuance_date(self) -> Optional[datetime]:
        tbs_cert_list = self.crl_data['tbs_cert_list']
        return tbs_cert_list['this_update'].native


LegacyCompatCRL = Union[bytes, crl.CertificateList, CRLContainer]
LegacyCompatOCSP = Union[bytes, ocsp.OCSPResponse, OCSPContainer]


def process_legacy_crl_input(crls: Iterable[LegacyCompatCRL]) \
        -> List[CRLContainer]:
    new_crls = []
    for crl_ in crls:
        if isinstance(crl_, bytes):
            crl_ = crl.CertificateList.load(crl_)
        if isinstance(crl_, crl.CertificateList):
            crl_ = CRLContainer(crl_)
        if isinstance(crl_, CRLContainer):
            new_crls.append(crl_)
        else:
            # TODO update error messages
            raise TypeError(pretty_message(
                '''
                crls must be a list of byte strings or
                asn1crypto.crl.CertificateList objects, not %s
                ''',
                type_name(crl_)
            ))
    return new_crls


def process_legacy_ocsp_input(ocsps: Iterable[LegacyCompatOCSP]) \
        -> List[OCSPContainer]:
    new_ocsps = []
    for ocsp_ in ocsps:
        if isinstance(ocsp_, bytes):
            ocsp_ = ocsp.OCSPResponse.load(ocsp_)
        if isinstance(ocsp_, ocsp.OCSPResponse):
            extr = OCSPContainer.load_multi(ocsp_)
            new_ocsps.extend(extr)
        elif isinstance(ocsp_, OCSPContainer):
            new_ocsps.append(ocsp_)
        else:
            # TODO update error messages
            raise TypeError(pretty_message(
                '''
                ocsps must be a list of byte strings or
                asn1crypto.ocsp.OCSPResponse objects, not %s
                ''',
                type_name(ocsp_)
            ))
    return new_ocsps
