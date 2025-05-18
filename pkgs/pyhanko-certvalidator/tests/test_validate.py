# coding: utf-8

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, List, Optional, Type

import pytest
from asn1crypto import crl, ocsp, x509
from asn1crypto.util import timezone
from freezegun import freeze_time

from pyhanko_certvalidator import PKIXValidationParams
from pyhanko_certvalidator.authority import Authority, CertTrustAnchor
from pyhanko_certvalidator.context import ValidationContext
from pyhanko_certvalidator.errors import (
    CertificateFetchError,
    CRLFetchError,
    InsufficientRevinfoError,
    OCSPFetchError,
    OCSPValidationError,
    PathValidationError,
    RevokedError,
    StaleRevinfoError,
)
from pyhanko_certvalidator.fetchers import (
    CertificateFetcher,
    CRLFetcher,
    FetcherBackend,
    Fetchers,
    OCSPFetcher,
    aiohttp_fetchers,
    requests_fetchers,
)
from pyhanko_certvalidator.ltv.poe import POEManager
from pyhanko_certvalidator.path import QualifiedPolicy, ValidationPath
from pyhanko_certvalidator.policy_decl import (
    CertRevTrustPolicy,
    DisallowWeakAlgorithmsPolicy,
    NonRevokedStatusAssertion,
    RevocationCheckingPolicy,
    RevocationCheckingRule,
)
from pyhanko_certvalidator.registry import (
    CertificateRegistry,
    PathBuilder,
    SimpleTrustManager,
)
from pyhanko_certvalidator.revinfo.manager import RevinfoManager
from pyhanko_certvalidator.validate import async_validate_path, validate_path

from .common import (
    FIXTURES_DIR,
    load_cert_object,
    load_crl,
    load_nist_cert,
    load_nist_crl,
    load_openssl_ors,
)
from .constants import TEST_REQUEST_TIMEOUT


class MockFetcher:
    def __init__(self, *args, **kwargs):
        self.calls = 0
        super().__init__(*args, **kwargs)


class MockOCSPFetcher(OCSPFetcher, MockFetcher):
    def fetched_responses(self) -> Iterable[ocsp.OCSPResponse]:
        return ()

    def fetched_responses_for_cert(
        self, cert: x509.Certificate
    ) -> Iterable[ocsp.OCSPResponse]:
        self.calls += 1
        return ()

    async def fetch(self, cert: x509.Certificate, authority: Authority):
        self.calls += 1
        raise OCSPFetchError("No connection")


class MockOCSPFetcherWithValidationError(MockOCSPFetcher, MockFetcher):
    async def fetch(self, cert: x509.Certificate, authority: Authority):
        self.calls += 1
        raise OCSPValidationError("Something went wrong")


class MockCRLFetcher(CRLFetcher, MockFetcher):
    def fetched_crls_for_cert(
        self, cert: x509.Certificate
    ) -> Iterable[crl.CertificateList]:
        self.calls += 1
        return ()

    def fetched_crls(self) -> Iterable[crl.CertificateList]:
        return ()

    async def fetch(self, cert: x509.Certificate, *, use_deltas=None):
        self.calls += 1
        raise CRLFetchError("No connection")


class MockCertFetcher(CertificateFetcher, MockFetcher):
    def fetched_certs(self) -> Iterable[x509.Certificate]:
        return ()

    def fetch_cert_issuers(self, cert):
        self.calls += 1
        return self

    def fetch_crl_issuers(self, certificate_list):
        self.calls += 1
        return self

    def __aiter__(self):
        raise CertificateFetchError("No connection")


class MockFetcherBackend(FetcherBackend):
    def get_fetchers(self) -> Fetchers:
        return Fetchers(
            ocsp_fetcher=MockOCSPFetcher(),
            crl_fetcher=MockCRLFetcher(),
            cert_fetcher=MockCertFetcher(),
        )


class MockFetcherBackendWithValidationError(FetcherBackend):
    def get_fetchers(self) -> Fetchers:
        return Fetchers(
            ocsp_fetcher=MockOCSPFetcherWithValidationError(),
            crl_fetcher=MockCRLFetcher(),
            cert_fetcher=MockCertFetcher(),
        )


ERR_CLASSES = {
    cls.__name__: cls
    for cls in (
        PathValidationError,
        RevokedError,
        InsufficientRevinfoError,
        StaleRevinfoError,
    )
}


@dataclass(frozen=True)
class PKITSTestCaseErrorResult:
    err_class: Type[Exception]
    msg_regex: str


def test_revocation_mode_soft():
    cert = load_cert_object(
        'digicert-ecc-p384-root-g5-revoked-chain-demos-digicert-com.crt'
    )
    ca_certs = [load_cert_object('digicert-root-g5.crt')]
    other_certs = [
        load_cert_object('digicert-g5-ecc-sha384-2021-ca1.crt'),
    ]

    context = ValidationContext(
        trust_roots=ca_certs,
        other_certs=other_certs,
        moment=datetime(2023, 1, 10, tzinfo=timezone.utc),
        allow_fetching=True,
        weak_hash_algos={'md2', 'md5'},
        fetcher_backend=MockFetcherBackend(),
    )
    paths = context.path_builder.build_paths(cert)
    assert 1 == len(paths)
    path = paths[0]
    assert 3 == len(path)

    validate_path(context, path)


def test_revocation_mode_soft_fail():
    cert = load_cert_object(
        'digicert-ecc-p384-root-g5-revoked-chain-demos-digicert-com.crt'
    )
    ca_certs = [load_cert_object('digicert-root-g5.crt')]
    other_certs = [
        load_cert_object('digicert-g5-ecc-sha384-2021-ca1.crt'),
    ]

    context = ValidationContext(
        trust_roots=ca_certs,
        other_certs=other_certs,
        moment=datetime(2023, 1, 10, tzinfo=timezone.utc),
        allow_fetching=True,
        weak_hash_algos={'md2', 'md5'},
        fetcher_backend=MockFetcherBackendWithValidationError(),
    )
    paths = context.path_builder.build_paths(cert)
    path = paths[0]

    with pytest.raises(InsufficientRevinfoError, match="Something went wrong"):
        validate_path(context, path)


@pytest.mark.skip("annoying to maintain; replace with certomancer test")
def test_revocation_mode_hard():
    cert = load_cert_object(
        'digicert-ecc-p384-root-g5-revoked-chain-demos-digicert-com.crt'
    )
    ca_certs = [load_cert_object('digicert-root-g5.crt')]
    other_certs = [
        load_cert_object('digicert-g5-ecc-sha384-2021-ca1.crt'),
    ]

    context = ValidationContext(
        trust_roots=ca_certs,
        other_certs=other_certs,
        allow_fetching=True,
        revocation_mode='hard-fail',
        weak_hash_algos={'md2', 'md5'},
        fetcher_backend=requests_fetchers.RequestsFetcherBackend(
            per_request_timeout=TEST_REQUEST_TIMEOUT
        ),
    )
    paths = context.path_builder.build_paths(cert)
    assert 1 == len(paths)
    path = paths[0]
    assert 3 == len(path)

    expected = (
        '(CRL|OCSP response) indicates the end-entity certificate was '
        'revoked at \\d\\d:\\d\\d:\\d\\d on \\d\\d\\d\\d-\\d\\d-\\d\\d'
        ', due to an unspecified reason'
    )
    with pytest.raises(RevokedError, match=expected):
        validate_path(context, path)


@pytest.mark.skip("annoying to maintain; replace with certomancer test")
@pytest.mark.asyncio
async def test_revocation_mode_hard_async():
    cert = load_cert_object(
        'digicert-ecc-p384-root-g5-revoked-chain-demos-digicert-com.crt'
    )
    ca_certs = [load_cert_object('digicert-root-g5.crt')]
    other_certs = [
        load_cert_object('digicert-g5-ecc-sha384-2021-ca1.crt'),
    ]
    fb = aiohttp_fetchers.AIOHttpFetcherBackend(
        per_request_timeout=TEST_REQUEST_TIMEOUT
    )
    async with fb as fetchers:
        context = ValidationContext(
            trust_roots=ca_certs,
            other_certs=other_certs,
            allow_fetching=True,
            revocation_mode='hard-fail',
            weak_hash_algos={'md2', 'md5'},
            fetchers=fetchers,
        )
        paths = await context.path_builder.async_build_paths(cert)
        assert 1 == len(paths)
        path = paths[0]
        assert 3 == len(path)

        expected = (
            '(CRL|OCSP response) indicates the end-entity certificate was '
            'revoked at \\d\\d:\\d\\d:\\d\\d on \\d\\d\\d\\d-\\d\\d-\\d\\d'
            ', due to an unspecified reason'
        )
        with pytest.raises(RevokedError, match=expected):
            await async_validate_path(context, path)


@pytest.mark.skip("annoying to maintain; replace with certomancer test")
@pytest.mark.asyncio
async def test_revocation_mode_hard_aiohttp_autofetch():
    cert = load_cert_object(
        'digicert-ecc-p384-root-g5-revoked-chain-demos-digicert-com.crt'
    )
    ca_certs = [load_cert_object('digicert-root-g5.crt')]

    fb = aiohttp_fetchers.AIOHttpFetcherBackend(
        per_request_timeout=TEST_REQUEST_TIMEOUT
    )
    async with fb as fetchers:
        context = ValidationContext(
            trust_roots=ca_certs,
            allow_fetching=True,
            revocation_mode='hard-fail',
            weak_hash_algos={'md2', 'md5'},
            fetchers=fetchers,
        )
        paths = await context.path_builder.async_build_paths(cert)
        assert 1 == len(paths)
        path = paths[0]
        assert 3 == len(path)

        expected = (
            '(CRL|OCSP response) indicates the end-entity certificate was '
            'revoked at \\d\\d:\\d\\d:\\d\\d on \\d\\d\\d\\d-\\d\\d-\\d\\d'
            ', due to an unspecified reason'
        )
        with pytest.raises(RevokedError, match=expected):
            await async_validate_path(context, path)


@pytest.mark.skip("annoying to maintain; replace with certomancer test")
@pytest.mark.asyncio
async def test_revocation_mode_hard_requests_autofetch():
    cert = load_cert_object(
        'digicert-ecc-p384-root-g5-revoked-chain-demos-digicert-com.crt'
    )
    ca_certs = [load_cert_object('digicert-root-g5.crt')]

    fb = requests_fetchers.RequestsFetcherBackend(
        per_request_timeout=TEST_REQUEST_TIMEOUT
    )
    async with fb as fetchers:
        context = ValidationContext(
            trust_roots=ca_certs,
            allow_fetching=True,
            revocation_mode='hard-fail',
            weak_hash_algos={'md2', 'md5'},
            fetchers=fetchers,
        )
        paths = await context.path_builder.async_build_paths(cert)
        assert 1 == len(paths)
        path = paths[0]
        assert 3 == len(path)

        expected = (
            '(CRL|OCSP response) indicates the end-entity certificate was '
            'revoked at \\d\\d:\\d\\d:\\d\\d on \\d\\d\\d\\d-\\d\\d-\\d\\d'
            ', due to an unspecified reason'
        )
        with pytest.raises(RevokedError, match=expected):
            await async_validate_path(context, path)


def test_rsassa_pss():
    cert = load_cert_object('testing-ca-pss', 'signer1.cert.pem')
    ca_certs = [load_cert_object('testing-ca-pss', 'root.cert.pem')]
    other_certs = [load_cert_object('testing-ca-pss', 'interm.cert.pem')]
    moment = datetime(2021, 5, 3, tzinfo=timezone.utc)
    context = ValidationContext(
        trust_roots=ca_certs,
        other_certs=other_certs,
        allow_fetching=False,
        moment=moment,
        revocation_mode='soft-fail',
        weak_hash_algos={'md2', 'md5'},
    )
    paths = context.path_builder.build_paths(cert)
    assert 1 == len(paths)
    path = paths[0]
    assert 3 == len(path)
    validate_path(context, path)


def test_rsassa_pss_exclusive():
    cert = load_cert_object('testing-ca-pss-exclusive', 'signer1.cert.pem')
    ca_certs = [load_cert_object('testing-ca-pss-exclusive', 'root.cert.pem')]
    other_certs = [
        load_cert_object('testing-ca-pss-exclusive', 'interm.cert.pem')
    ]
    moment = datetime(2021, 5, 3, tzinfo=timezone.utc)
    context = ValidationContext(
        trust_roots=ca_certs,
        other_certs=other_certs,
        allow_fetching=False,
        moment=moment,
        revocation_mode='soft-fail',
        weak_hash_algos={'md2', 'md5'},
    )
    paths = context.path_builder.build_paths(cert)
    assert 1 == len(paths)
    path = paths[0]
    assert 3 == len(path)
    validate_path(context, path)


def test_ed25519():
    cert = load_cert_object('testing-ca-ed25519', 'signer.cert.pem')
    ca_certs = [load_cert_object('testing-ca-ed25519', 'root.cert.pem')]
    other_certs = [load_cert_object('testing-ca-ed25519', 'interm.cert.pem')]
    context = ValidationContext(
        trust_roots=ca_certs,
        other_certs=other_certs,
        allow_fetching=False,
        revocation_mode='soft-fail',
        weak_hash_algos={'md2', 'md5'},
        moment=datetime(2020, 11, 1, tzinfo=timezone.utc),
    )
    paths = context.path_builder.build_paths(cert)
    assert 1 == len(paths)
    path = paths[0]
    assert 3 == len(path)
    validate_path(context, path)


def test_ed448():
    cert = load_cert_object('testing-ca-ed448', 'signer.cert.pem')
    ca_certs = [load_cert_object('testing-ca-ed448', 'root.cert.pem')]
    other_certs = [load_cert_object('testing-ca-ed448', 'interm.cert.pem')]
    context = ValidationContext(
        trust_roots=ca_certs,
        other_certs=other_certs,
        allow_fetching=False,
        revocation_mode='soft-fail',
        weak_hash_algos={'md2', 'md5'},
        moment=datetime(2020, 11, 1, tzinfo=timezone.utc),
    )
    paths = context.path_builder.build_paths(cert)
    assert 1 == len(paths)
    path = paths[0]
    assert 3 == len(path)
    validate_path(context, path)


def test_assert_no_revinfo_needed_by_fiat():
    cert = load_cert_object('testing-ca-pss', 'signer1.cert.pem')
    ca_certs = [load_cert_object('testing-ca-pss', 'root.cert.pem')]
    other_certs = [load_cert_object('testing-ca-pss', 'interm.cert.pem')]
    moment = datetime(2021, 5, 3, tzinfo=timezone.utc)
    assertion = NonRevokedStatusAssertion(cert.sha256, moment)
    revinfo_manager = RevinfoManager(
        certificate_registry=CertificateRegistry.build(),
        poe_manager=POEManager(),
        crls=(),
        ocsps=(),
        assertions=(assertion,),
    )
    context = ValidationContext(
        trust_roots=ca_certs,
        other_certs=other_certs,
        allow_fetching=False,
        moment=moment,
        revocation_mode='require',  # turn on strict revinfovalidation
        revinfo_manager=revinfo_manager,
    )
    paths = context.path_builder.build_paths(cert)
    assert 1 == len(paths)
    path = paths[0]
    assert 3 == len(path)
    validate_path(context, path)


def test_multitasking_ocsp():
    # regression test for case where the same responder ID (name + key ID)
    # is used in OCSP responses for different issuers in the same chain of
    # trust

    ors_dir = os.path.join(FIXTURES_DIR, 'multitasking-ocsp')
    with open(os.path.join(ors_dir, 'ocsp-resp-alice.der'), 'rb') as ocspin:
        ocsp_resp_alice = ocsp.OCSPResponse.load(ocspin.read())
    with open(os.path.join(ors_dir, 'ocsp-resp-interm.der'), 'rb') as ocspin:
        ocsp_resp_interm = ocsp.OCSPResponse.load(ocspin.read())
    vc = ValidationContext(
        trust_roots=[
            load_cert_object('multitasking-ocsp', 'root.cert.pem'),
        ],
        other_certs=[load_cert_object('multitasking-ocsp', 'interm.cert.pem')],
        revocation_mode='hard-fail',
        allow_fetching=False,
        ocsps=[ocsp_resp_interm, ocsp_resp_alice],
        moment=datetime(2021, 8, 19, 12, 20, 44, tzinfo=timezone.utc),
    )

    cert = load_cert_object('multitasking-ocsp', 'alice.cert.pem')
    paths = vc.path_builder.build_paths(cert)
    assert 1 == len(paths)
    path = paths[0]
    assert 3 == len(path)
    validate_path(vc, path)


@dataclass(frozen=True)
class OCSPTestCase:
    name: str
    roots: List[x509.Certificate]
    cert: x509.Certificate
    ocsps: List[ocsp.OCSPResponse]
    path_len: int
    moment: datetime
    other_certs: List[x509.Certificate] = field(default_factory=list)
    expected_error: Optional[PKITSTestCaseErrorResult] = None

    @classmethod
    def from_json(cls, obj: dict):
        roots = [load_cert_object('openssl-ocsp', obj['root'])]
        kwargs = dict(
            name=obj['name'],
            cert=load_cert_object('openssl-ocsp', obj['cert']),
            path_len=int(obj['path_len']),
            moment=datetime.fromisoformat(obj['moment']),
            roots=roots,
        )
        kwargs['ocsps'] = [
            load_openssl_ors(filename) for filename in obj['ocsps']
        ]
        if 'other_certs' in obj:
            kwargs['other_certs'] = [
                load_cert_object('openssl-ocsp', filename)
                for filename in obj['other_certs']
            ]
        if 'error' in obj:
            kwargs['expected_error'] = PKITSTestCaseErrorResult(
                ERR_CLASSES[obj['error']['class']], obj['error']['msg_regex']
            )

        return OCSPTestCase(**kwargs)


def read_openssl_ocsp_test_params():
    data_path = os.path.join(FIXTURES_DIR, 'openssl-ocsp', 'openssl-ocsp.json')
    with open(data_path, 'r') as inf:
        cases = json.load(inf)
    return [OCSPTestCase.from_json(obj) for obj in cases]


@pytest.mark.parametrize(
    "test_case", read_openssl_ocsp_test_params(), ids=lambda case: case.name
)
def test_openssl_ocsp(test_case: OCSPTestCase):
    context = ValidationContext(
        trust_roots=test_case.roots,
        other_certs=test_case.other_certs,
        moment=test_case.moment,
        ocsps=test_case.ocsps,
        weak_hash_algos={'md2', 'md5'},
    )
    paths = context.path_builder.build_paths(test_case.cert)
    assert 1 == len(paths)
    path = paths[0]
    assert test_case.path_len == len(path)

    err = test_case.expected_error
    if err:
        with pytest.raises(err.err_class, match=err.msg_regex):
            validate_path(context, path)
    else:
        validate_path(context, path)


def parse_pkix_params(obj: dict):
    kwargs = {}
    if 'user_initial_policy_set' in obj:
        kwargs['user_initial_policy_set'] = frozenset(
            obj['user_initial_policy_set']
        )
    kwargs['initial_policy_mapping_inhibit'] = bool(
        obj.get('initial_policy_mapping_inhibit', False)
    )
    kwargs['initial_explicit_policy'] = bool(
        obj.get('initial_explicit_policy', False)
    )
    kwargs['initial_any_policy_inhibit'] = bool(
        obj.get('initial_any_policy_inhibit', False)
    )
    return PKIXValidationParams(**kwargs)


@dataclass(frozen=True)
class CannedTestInfo:
    test_id: int
    test_name: str

    def __str__(self):
        return f"{self.test_id} ({self.test_name})"


@dataclass(frozen=True)
class PKITSTestCase:
    test_info: CannedTestInfo
    cert: x509.Certificate
    roots: List[x509.Certificate]
    crls: List[crl.CertificateList]
    path_len: int
    path: Optional[ValidationPath] = None
    check_revocation: bool = True
    other_certs: List[x509.Certificate] = field(default_factory=list)
    expected_error: Optional[PKITSTestCaseErrorResult] = None
    pkix_params: Optional[PKIXValidationParams] = None

    @classmethod
    def from_json(cls, obj: dict):
        root = load_nist_cert('TrustAnchorRootCertificate.crt')
        crls = [load_nist_crl('TrustAnchorRootCRL.crl')]
        if 'crls' in obj:
            crls.extend(load_nist_crl(crl_path) for crl_path in obj['crls'])
        cert = load_nist_cert(obj['cert'])
        kwargs = dict(
            test_info=CannedTestInfo(
                test_id=int(obj['id']),
                test_name=obj['name'],
            ),
            cert=cert,
            path_len=int(obj['path_len']),
            check_revocation=bool(obj.get('revocation', True)),
            roots=[root],
            crls=crls,
        )

        kwargs['crls'] = crls
        if 'other_certs' in obj:
            kwargs['other_certs'] = [
                load_nist_cert(cert_path) for cert_path in obj['other_certs']
            ]
        if 'path_intermediates' in obj:
            # -> prebuild the path as indicated in the test spec
            kwargs['path'] = ValidationPath(
                trust_anchor=CertTrustAnchor(root),
                interm=(
                    load_nist_cert(cert_path)
                    for cert_path in obj['path_intermediates']
                ),
                leaf=cert,
            )
        if 'params' in obj:
            kwargs['pkix_params'] = parse_pkix_params(obj['params'])
        if 'error' in obj:
            kwargs['expected_error'] = PKITSTestCaseErrorResult(
                ERR_CLASSES[obj['error']['class']], obj['error']['msg_regex']
            )

        return PKITSTestCase(**kwargs)


def read_pkits_test_params():
    data_path = os.path.join(FIXTURES_DIR, 'nist_pkits', 'pkits.json')
    with open(data_path, 'r') as inf:
        cases = json.load(inf)
    return [PKITSTestCase.from_json(obj) for obj in cases]


@freeze_time('2022-05-01')
@pytest.mark.parametrize(
    'test_case', read_pkits_test_params(), ids=lambda case: str(case.test_info)
)
def test_nist_pkits(test_case: PKITSTestCase):
    revocation_mode = "require" if test_case.check_revocation else "hard-fail"

    context = ValidationContext(
        trust_roots=test_case.roots,
        other_certs=test_case.other_certs,
        crls=test_case.crls,
        revocation_mode=revocation_mode,
        # adjust default algo policy to pass NIST tests
        algorithm_usage_policy=DisallowWeakAlgorithmsPolicy(
            weak_hash_algos={'md2', 'md5'}, dsa_key_size_threshold=1024
        ),
    )

    if test_case.path is None:
        paths = context.path_builder.build_paths(test_case.cert)
        assert 1 == len(paths)
        path: ValidationPath = paths[0]
    else:
        path = test_case.path

    assert test_case.path_len == len(path)

    err = test_case.expected_error
    params = test_case.pkix_params
    if err is not None:
        with pytest.raises(err.err_class, match=err.msg_regex):
            validate_path(context, path, parameters=params)
    else:
        validate_path(context, path, parameters=params)

        # sanity check
        if params is not None and params.user_initial_policy_set != {
            'any_policy'
        }:
            qps = path.qualified_policies()
            if qps is not None:
                for pol in qps:
                    assert (
                        pol.user_domain_policy_id
                        in params.user_initial_policy_set
                    )


def nist_revocation_tests():
    specs = read_pkits_test_params()
    return [spec for spec in specs if spec.check_revocation]


class ReturnPredeterminedCRLs(CRLFetcher):
    def __init__(self, crls):
        self.crls = crls

    def fetched_crls_for_cert(
        self, cert: x509.Certificate
    ) -> Iterable[crl.CertificateList]:
        raise KeyError()

    def fetched_crls(self) -> Iterable[crl.CertificateList]:
        return ()

    async def fetch(self, cert: x509.Certificate, *, use_deltas=None):
        return self.crls


@freeze_time('2022-05-01')
@pytest.mark.parametrize(
    'test_case', nist_revocation_tests(), ids=lambda case: str(case.test_info)
)
def test_nist_pkits_with_simulated_crl_downloads(test_case: PKITSTestCase):

    fetchers = Fetchers(
        ocsp_fetcher=MockOCSPFetcher(),
        crl_fetcher=ReturnPredeterminedCRLs(test_case.crls),
        cert_fetcher=MockCertFetcher(),
    )

    # TODO rework failure messages and realign fixtures
    #  so we can do message validations here.
    #  Also consider having multiple variant runs with
    #  slightly different revo policies
    policy = RevocationCheckingPolicy(
        RevocationCheckingRule.CRL_REQUIRED,
        RevocationCheckingRule.CRL_REQUIRED,
    )
    context = ValidationContext(
        trust_roots=test_case.roots,
        other_certs=test_case.other_certs,
        allow_fetching=True,
        fetchers=fetchers,
        revinfo_policy=CertRevTrustPolicy(
            revocation_checking_policy=policy,
        ),
        # adjust default algo policy to pass NIST tests
        algorithm_usage_policy=DisallowWeakAlgorithmsPolicy(
            weak_hash_algos={'md2', 'md5'}, dsa_key_size_threshold=1024
        ),
    )

    if test_case.path is None:
        paths = context.path_builder.build_paths(test_case.cert)
        assert 1 == len(paths)
        path: ValidationPath = paths[0]
    else:
        path = test_case.path

    err = test_case.expected_error
    params = test_case.pkix_params
    if err is not None:
        with pytest.raises(err.err_class):
            validate_path(context, path, parameters=params)
    else:
        validate_path(context, path, parameters=params)


@dataclass(frozen=True)
class PKITSUserNoticeTestCase:
    test_info: CannedTestInfo
    cert: x509.Certificate
    roots: List[x509.Certificate]
    crls: List[crl.CertificateList]
    notice: str
    other_certs: List[x509.Certificate] = field(default_factory=list)
    pkix_params: Optional[PKIXValidationParams] = None

    @classmethod
    def from_json(cls, obj: dict):
        roots = [load_nist_cert('TrustAnchorRootCertificate.crt')]
        crls = [load_nist_crl('TrustAnchorRootCRL.crl')]
        if 'crls' in obj:
            crls.extend(load_nist_crl(crl_path) for crl_path in obj['crls'])
        kwargs = dict(
            test_info=CannedTestInfo(
                test_id=int(obj['id']),
                test_name=obj['name'],
            ),
            cert=load_nist_cert(obj['cert']),
            roots=roots,
            crls=crls,
            notice=obj['notice'],
        )

        kwargs['crls'] = crls
        if 'other_certs' in obj:
            kwargs['other_certs'] = [
                load_nist_cert(cert_path) for cert_path in obj['other_certs']
            ]
        if 'params' in obj:
            kwargs['pkix_params'] = parse_pkix_params(obj['params'])

        return PKITSUserNoticeTestCase(**kwargs)


def read_pkits_user_notice_test_params():
    data_path = os.path.join(
        FIXTURES_DIR, 'nist_pkits', 'pkits-user-notice.json'
    )
    with open(data_path, 'r') as inf:
        cases = json.load(inf)
    return [PKITSUserNoticeTestCase.from_json(obj) for obj in cases]


@freeze_time('2022-05-01')
@pytest.mark.parametrize(
    'test_case',
    read_pkits_user_notice_test_params(),
    ids=lambda case: str(case.test_info),
)
def test_nist_pkits_user_notice(test_case: PKITSUserNoticeTestCase):
    context = ValidationContext(
        trust_roots=test_case.roots,
        other_certs=test_case.other_certs,
        crls=test_case.crls,
        revocation_mode="require",
        weak_hash_algos={'md2', 'md5'},
    )

    paths = context.path_builder.build_paths(test_case.cert)
    assert 1 == len(paths)
    path: ValidationPath = paths[0]
    validate_path(context, path, parameters=test_case.pkix_params)

    qps = path.qualified_policies()
    assert 1 == len(qps)

    qp: QualifiedPolicy
    (qp,) = qps
    assert 1 == len(qp.qualifiers)
    (qual_obj,) = qp.qualifiers
    assert qual_obj['policy_qualifier_id'].native == 'user_notice'
    assert qual_obj['qualifier']['explicit_text'].native == test_case.notice


@freeze_time('2022-05-01')
def test_408020_cps_pointer_qualifier_test20():
    cert = load_nist_cert('CPSPointerQualifierTest20EE.crt')
    ca_certs = [load_nist_cert('TrustAnchorRootCertificate.crt')]
    other_certs = [load_nist_cert('GoodCACert.crt')]
    crls = [
        load_nist_crl('GoodCACRL.crl'),
        load_nist_crl('TrustAnchorRootCRL.crl'),
    ]

    context = ValidationContext(
        trust_roots=ca_certs,
        other_certs=other_certs,
        crls=crls,
        revocation_mode="require",
        weak_hash_algos={'md2', 'md5'},
    )

    paths = context.path_builder.build_paths(cert)
    assert 1 == len(paths)
    path: ValidationPath = paths[0]
    validate_path(context, path)

    qps = path.qualified_policies()
    assert 1 == len(qps)

    qp: QualifiedPolicy
    (qp,) = qps
    assert 1 == len(qp.qualifiers)
    (qual_obj,) = qp.qualifiers
    assert (
        qual_obj['policy_qualifier_id'].native
        == 'certification_practice_statement'
    )
    assert qual_obj['qualifier'].native == (
        'http://csrc.nist.gov/groups/ST/crypto_apps_infra/csor/'
        'pki_registration.html#PKITest'
    )


class MockRequestsCertificateFetcher(
    requests_fetchers.RequestsCertificateFetcher
):
    def __init__(self, *args, order, **kwargs):
        super().__init__(*args, **kwargs)
        self.order = order

    async def fetch_certs(self, *args, **kwargs) -> Iterable[x509.Certificate]:
        root_ca = load_cert_object('testing-aia', 'brazilian_root_ca_v5')
        middle_ca = load_cert_object('testing-aia', 'ca_brazilian_fro_v4')
        end_ca = load_cert_object('testing-aia', 'ca_serprorfbv5')
        certs = {'root': root_ca, 'middle': middle_ca, 'end': end_ca}

        return [
            certs[self.order[0]],
            certs[self.order[1]],
            certs[self.order[2]],
        ]


@pytest.mark.parametrize(
    'cert_order',
    [
        ('root', 'middle', 'end'),
        ('root', 'end', 'middle'),
        ('middle', 'root', 'end'),
        ('middle', 'end', 'root'),
        ('root', 'end', 'middle'),
        ('root', 'middle', 'end'),
    ],
)
@pytest.mark.asyncio
async def test_building_trust_path_with_pkcs7_in_different_orders(cert_order):
    trust_path = [
        'Autoridade Certificadora Raiz Brasileira v5',
        'AC Secretaria da Receita Federal do Brasil v4',
        'Autoridade Certificadora SERPRORFBv5',
    ]

    serpro_root = load_cert_object('testing-aia', 'brazilian_root_ca_v5')

    trust_manager = SimpleTrustManager.build(
        extra_trust_roots=[serpro_root],
    )
    cert = load_cert_object('testing-aia', 'repositorio.serpro.gov.br')
    registry = CertificateRegistry.build(
        certs=(cert,),
        cert_fetcher=MockRequestsCertificateFetcher(order=cert_order),
    )
    builder = PathBuilder(trust_manager=trust_manager, registry=registry)
    paths = await builder.async_build_paths(end_entity_cert=cert)

    paths_common_name = [
        [
            authority.name.native['common_name']
            for authority in path.iter_authorities()
        ]
        for path in paths
    ]

    assert trust_path in paths_common_name


@freeze_time('2020-11-29')
def test_do_not_fetch_crl_if_cache_sufficient():
    cert = load_cert_object('ades', 'time-slide', 'certs', 'alice.crt')
    ca_certs = [load_cert_object('ades', 'time-slide', 'certs', 'root.crt')]
    other_certs = [
        load_cert_object('ades', 'time-slide', 'certs', 'interm.crt')
    ]
    crls = [
        load_crl('ades', 'time-slide', 'interm-2020-10-01.crl'),
        load_crl('ades', 'time-slide', 'root-2020-10-01.crl'),
    ]
    moment = datetime(2020, 10, 2, tzinfo=timezone.utc)
    fetchers = MockFetcherBackend().get_fetchers()

    crl_fetcher = MockCRLFetcher()
    fetchers = Fetchers(
        ocsp_fetcher=MockOCSPFetcher(),
        crl_fetcher=crl_fetcher,
        cert_fetcher=MockCertFetcher(),
    )
    context = ValidationContext(
        trust_roots=ca_certs,
        other_certs=other_certs,
        crls=crls,
        allow_fetching=True,
        fetchers=fetchers,
        moment=moment,
        revocation_mode='require',
    )

    assert crl_fetcher.calls == 0

    paths = context.path_builder.build_paths(cert)
    assert 1 == len(paths)
    path = paths[0]
    assert 3 == len(path)
    validate_path(context, path)


@freeze_time('2022-05-01')
def test_41503_invalid_deltacrl_test3_combine_cache_with_fetched():
    cert = load_nist_cert('InvaliddeltaCRLTest4EE.crt')
    ca_certs = [load_nist_cert('TrustAnchorRootCertificate.crt')]
    other_certs = [load_nist_cert('deltaCRLCA1Cert.crt')]
    crls = [
        load_nist_crl('deltaCRLCA1CRL.crl'),
        load_nist_crl('TrustAnchorRootCRL.crl'),
        # the delta CRL will only be returned later
    ]

    class DeltaCRLFetcher(CRLFetcher, MockFetcher):
        def fetched_crls_for_cert(
            self, cert: x509.Certificate
        ) -> Iterable[crl.CertificateList]:
            raise KeyError()

        def fetched_crls(self) -> Iterable[crl.CertificateList]:
            return ()

        async def fetch(self, cert: x509.Certificate, *, use_deltas=None):
            self.calls += 1
            return [load_nist_crl('deltaCRLCA1deltaCRL.crl')]

    fetchers = Fetchers(
        ocsp_fetcher=MockOCSPFetcher(),
        crl_fetcher=DeltaCRLFetcher(),
        cert_fetcher=MockCertFetcher(),
    )
    context = ValidationContext(
        trust_roots=ca_certs,
        other_certs=other_certs,
        crls=crls,
        allow_fetching=True,
        fetchers=fetchers,
        revocation_mode="require",
        weak_hash_algos={'md2', 'md5'},
    )

    paths = context.path_builder.build_paths(cert)
    assert 1 == len(paths)
    path: ValidationPath = paths[0]
    with pytest.raises(RevokedError, match=".*revoked at 08:30:00.*"):
        validate_path(context, path)


@freeze_time('2022-05-01')
def test_fail_validation_if_required_delta_crl_not_available():
    cert = load_nist_cert('InvaliddeltaCRLTest4EE.crt')
    ca_certs = [load_nist_cert('TrustAnchorRootCertificate.crt')]
    other_certs = [load_nist_cert('deltaCRLCA1Cert.crt')]
    crls = [
        load_nist_crl('deltaCRLCA1CRL.crl'),
        load_nist_crl('TrustAnchorRootCRL.crl'),
    ]

    context = ValidationContext(
        trust_roots=ca_certs,
        other_certs=other_certs,
        crls=crls,
        allow_fetching=False,
        revocation_mode="require",
        weak_hash_algos={'md2', 'md5'},
    )

    paths = context.path_builder.build_paths(cert)
    assert 1 == len(paths)
    path: ValidationPath = paths[0]
    with pytest.raises(InsufficientRevinfoError, match=".*Delta CRL.*"):
        validate_path(context, path)


def test_context_retrieve_all_crls():

    cert = load_nist_cert('InvaliddeltaCRLTest4EE.crt')
    ca_certs = [load_nist_cert('TrustAnchorRootCertificate.crt')]
    other_certs = [load_nist_cert('deltaCRLCA1Cert.crt')]
    crl1 = load_nist_crl('deltaCRLCA1CRL.crl')
    crl2 = load_nist_crl('TrustAnchorRootCRL.crl')
    crl3 = load_nist_crl('deltaCRLCA1deltaCRL.crl')
    crls = [crl1, crl2]

    context = ValidationContext(
        trust_roots=ca_certs,
        other_certs=other_certs,
        crls=crls,
        allow_fetching=True,
        fetchers=Fetchers(
            ocsp_fetcher=MockOCSPFetcher(),
            crl_fetcher=ReturnPredeterminedCRLs([crl3]),
            cert_fetcher=MockCertFetcher(),
        ),
        revocation_mode="require",
        weak_hash_algos={'md2', 'md5'},
    )

    with pytest.warns(DeprecationWarning):
        retrieved_crls = context.retrieve_crls(cert)
    assert {c.dump() for c in retrieved_crls} == {
        crl1.dump(),
        crl2.dump(),
        crl3.dump(),
    }
