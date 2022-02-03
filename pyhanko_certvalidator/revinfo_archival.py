import enum
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, List, Iterable

from asn1crypto import ocsp, crl

from pyhanko_certvalidator.policy_decl import CertRevTrustPolicy, \
    FreshnessReqType


@dataclass(frozen=True)
class ValidationTimingInfo:
    validation_time: datetime
    use_poe_time: datetime
    time_tolerance: timedelta
    point_in_time_validation: bool


class RevinfoFreshnessPOEType(enum.Enum):
    UNKNOWN = enum.auto()
    TIMESTAMPED = enum.auto()
    FRESHLY_FETCHED = enum.auto()


@dataclass(frozen=True)
class RevinfoFreshnessPOE:
    poe_type: RevinfoFreshnessPOEType
    archive_timestamp: Optional[datetime] = None

    @classmethod
    def unknown(cls):
        return RevinfoFreshnessPOE(RevinfoFreshnessPOEType.UNKNOWN)

    @classmethod
    def fresh(cls):
        return RevinfoFreshnessPOE(RevinfoFreshnessPOEType.FRESHLY_FETCHED)


class RevinfoUsabilityRating(enum.Enum):
    OK = enum.auto()
    STALE = enum.auto()
    TOO_NEW = enum.auto()
    UNCLEAR = enum.auto()

    @property
    def usable(self) -> bool:
        return self == RevinfoUsabilityRating.OK


class WithPOE:

    def retrieve_poe(self) -> RevinfoFreshnessPOE:
        raise NotImplementedError

    def usable_at(self, validation_time: datetime,
                  policy: CertRevTrustPolicy,
                  timing_info: ValidationTimingInfo) -> RevinfoUsabilityRating:
        raise NotImplementedError

    @property
    def issuance_date(self) -> Optional[datetime]:
        raise NotImplementedError


def sort_freshest_first(lst: Iterable[WithPOE]):
    def _key(with_poe: WithPOE):
        dt = with_poe.issuance_date
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
class OCSPWithPOE(WithPOE):
    poe: RevinfoFreshnessPOE
    ocsp_response_data: ocsp.OCSPResponse
    index: int = 0

    @classmethod
    def load_multi(cls, poe: RevinfoFreshnessPOE,
                   ocsp_response: ocsp.OCSPResponse) -> List['OCSPWithPOE']:
        basic_ocsp_response = _extract_basic_ocsp_response(ocsp_response)
        if basic_ocsp_response is None:
            return []
        tbs_response = basic_ocsp_response['tbs_response_data']

        return [
            OCSPWithPOE(poe=poe, ocsp_response_data=ocsp_response, index=ix)
            for ix in range(len(tbs_response['responses']))
        ]

    def retrieve_poe(self) -> RevinfoFreshnessPOE:
        return self.poe

    @property
    def issuance_date(self) -> Optional[datetime]:
        cert_response = self.extract_single_response()
        if cert_response is None:
            return None

        return cert_response['this_update'].native

    def usable_at(self, validation_time: datetime,
                  policy: CertRevTrustPolicy,
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
class CRLWithPOE(WithPOE):
    poe: RevinfoFreshnessPOE
    crl_data: crl.CertificateList

    def retrieve_poe(self) -> RevinfoFreshnessPOE:
        return self.poe

    def usable_at(self, validation_time: datetime,
                  policy: CertRevTrustPolicy,
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
