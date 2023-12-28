import dataclasses
from datetime import datetime, timezone
from pathlib import Path

import pytest
from certomancer.registry import ArchLabel
from freezegun import freeze_time
from pyhanko_certvalidator import CertificateValidator, ValidationContext
from pyhanko_certvalidator.authority import AuthorityWithCert, NamedKeyAuthority
from pyhanko_certvalidator.policy_decl import (
    CertRevTrustPolicy,
    RevocationCheckingPolicy,
    RevocationCheckingRule,
)
from signing_commons import ECC_INTERM_CERT, FROM_CA, INTERM_CERT
from xsdata.formats.dataclass.parsers import XmlParser
from xsdata.formats.dataclass.parsers.config import ParserConfig

from pyhanko.generated.etsi import ts_119612
from pyhanko.sign.validation.qualified import assess, eutl_parse, q_status, tsp
from pyhanko.sign.validation.qualified.eutl_parse import (
    CA_QC_URI,
    STATUS_GRANTED,
)
from pyhanko.sign.validation.settings import KeyUsageConstraints

from .samples import CERTOMANCER

TESTING_CA_QUALIFIED = CERTOMANCER.get_pki_arch(
    ArchLabel('testing-ca-qualified')
)


def _read_cas_from_file(path: Path):
    with path.open('r', encoding='utf8') as inf:
        tl_str = inf.read()
        return list(eutl_parse.read_qualified_certificate_authorities(tl_str))


def _raw_tlservice_parse(xml: str) -> ts_119612.TSPService:
    parser = XmlParser(
        config=ParserConfig(
            load_dtd=False,
            process_xinclude=False,
            fail_on_unknown_properties=False,
            fail_on_unknown_attributes=False,
        ),
    )
    return parser.from_string(xml, clazz=ts_119612.TSPService)


TEST_DATA_DIR = Path('pyhanko_tests') / 'data' / 'tl'
TEST_REAL_TL = TEST_DATA_DIR / 'tsl-be.xml'


def test_parse_cas_from_real_tl_smoke_test():
    cas_read = _read_cas_from_file(TEST_REAL_TL)
    current_cas = [ca for ca in cas_read if not ca.base_info.valid_until]
    assert len(current_cas) == 52
    assert len(cas_read) == 73


ETSI_NS = 'http://uri.etsi.org'
NAMESPACES = ' '.join(
    [
        f'xmlns="{ETSI_NS}/02231/v2#"',
        f'xmlns:xades="{ETSI_NS}/01903/v1.3.2#"',
        f'xmlns:q="{ETSI_NS}/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#"',
        f'xmlns:extra="http://uri.etsi.org/02231/v2/additionaltypes#"',
    ]
)


def test_parse_ca_with_unsupported_critical_qualifier():
    xml = f"""
    <TSPService {NAMESPACES}>
        <ServiceInformation>
            <ServiceName>
                <Name xml:lang="en">Test</Name>
            </ServiceName>
            <ServiceTypeIdentifier>
                http://uri.etsi.org/TrstSvc/Svctype/CA/QC
            </ServiceTypeIdentifier>
            <ServiceDigitalIdentity/>
            <StatusStartingTime>
                2020-11-01T00:00:00Z
            </StatusStartingTime>
            <ServiceInformationExtensions>
                <Extension Critical="true">
                    <blah/>
                </Extension>
            </ServiceInformationExtensions>
        </ServiceInformation>
    </TSPService>
    """

    parse_result = _raw_tlservice_parse(xml)
    with pytest.raises(
        eutl_parse.TSPServiceParsingError,
        match="critical",
    ):
        eutl_parse._interpret_service_info_for_ca(parse_result)


def test_parse_ca_with_unsupported_noncritical_extension():
    xml = f"""
    <TSPService {NAMESPACES}>
        <ServiceInformation>
            <ServiceName>
                <Name xml:lang="en">Test</Name>
            </ServiceName>
            <ServiceTypeIdentifier>
                http://uri.etsi.org/TrstSvc/Svctype/CA/QC
            </ServiceTypeIdentifier>
            <ServiceDigitalIdentity/>
            <StatusStartingTime>
                2020-11-01T00:00:00Z
            </StatusStartingTime>
            <ServiceInformationExtensions>
                <Extension Critical="false">
                    <blah/>
                </Extension>
            </ServiceInformationExtensions>
        </ServiceInformation>
    </TSPService>
    """

    parse_result = _raw_tlservice_parse(xml)
    assert eutl_parse._interpret_service_info_for_ca(parse_result) is not None


def test_parse_ca_with_extensions():
    qual_xml = """
    <q:Qualifiers>
        <q:Qualifier
        uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithSSCD"/>
    </q:Qualifiers>
    <q:CriteriaList assert="all">
        <q:KeyUsage>
            <q:KeyUsageBit name="nonRepudiation">true</q:KeyUsageBit>
        </q:KeyUsage>
        <q:PolicySet>
            <q:PolicyIdentifier>
                <xades:Identifier>2.999</xades:Identifier>
            </q:PolicyIdentifier>
        </q:PolicySet>
        <q:otherCriteriaList>
            <extra:CertSubjectDNAttribute>
                <extra:AttributeOID>
                    <xades:Identifier>2.999</xades:Identifier>
                </extra:AttributeOID>
            </extra:CertSubjectDNAttribute>
            <extra:ExtendedKeyUsage>
                <extra:KeyPurposeId>
                    <xades:Identifier>2.999</xades:Identifier>
                </extra:KeyPurposeId>
            </extra:ExtendedKeyUsage>
        </q:otherCriteriaList>
    </q:CriteriaList>
    """
    xml = f"""
    <TSPService {NAMESPACES}>
        <ServiceInformation>
            <ServiceName>
                <Name xml:lang="en">Test</Name>
            </ServiceName>
            <ServiceTypeIdentifier>
                http://uri.etsi.org/TrstSvc/Svctype/CA/QC
            </ServiceTypeIdentifier>
            <ServiceDigitalIdentity/>
            <StatusStartingTime>
                2020-11-01T00:00:00Z
            </StatusStartingTime>
            <ServiceInformationExtensions>
                <Extension Critical="false">
                    <q:Qualifications>
                        <q:QualificationElement>
                            {qual_xml}
                        </q:QualificationElement>
                    </q:Qualifications>
                </Extension>
                <Extension Critical="false">
                    <ExpiredCertsRevocationInfo>
                        2016-06-30T21:00:00Z
                    </ExpiredCertsRevocationInfo>
                </Extension>
            </ServiceInformationExtensions>
        </ServiceInformation>
    </TSPService>
    """

    parse_result = _raw_tlservice_parse(xml)
    result = eutl_parse._interpret_service_info_for_ca(parse_result)
    assert result.expired_certs_revocation_info == datetime(
        2016, 6, 30, 21, 0, 0, tzinfo=timezone.utc
    )
    qualification = list(result.qualifications)[0]
    assert qualification.qualifiers == frozenset([tsp.Qualifier.WITH_SSCD])
    criteria = qualification.criteria_list.criteria
    assert tsp.PolicySetCriterion(frozenset(['2.999'])) in criteria
    assert (
        tsp.KeyUsageCriterion(
            KeyUsageConstraints(
                key_usage=frozenset(['non_repudiation']),
                key_usage_forbidden=frozenset(),
            )
        )
        in criteria
    )
    assert (
        tsp.KeyUsageCriterion(
            KeyUsageConstraints(extd_key_usage=frozenset(['2.999']))
        )
        in criteria
    )
    assert (
        tsp.CertSubjectDNCriterion(required_rdn_part_oids=frozenset(['2.999']))
        in criteria
    )


@pytest.mark.parametrize(
    'qualifiers',
    [
        '',
        '<q:Qualifiers/>',
        '<q:Qualifiers><q:Qualifier uri="urn:blah"/></q:Qualifiers>',
    ],
)
def test_parse_omit_empty_or_unknown_quals(qualifiers):
    qual_xml = f"""
    {qualifiers}
    <q:CriteriaList assert="all">
        <q:KeyUsage>
            <q:KeyUsageBit name="nonRepudiation">true</q:KeyUsageBit>
        </q:KeyUsage>
        <q:PolicySet>
            <q:PolicyIdentifier>
                <xades:Identifier>2.999</xades:Identifier>
            </q:PolicyIdentifier>
        </q:PolicySet>
    </q:CriteriaList>
    """
    xml = f"""
    <TSPService {NAMESPACES}>
        <ServiceInformation>
            <ServiceName>
                <Name xml:lang="en">Test</Name>
            </ServiceName>
            <ServiceTypeIdentifier>
                http://uri.etsi.org/TrstSvc/Svctype/CA/QC
            </ServiceTypeIdentifier>
            <ServiceDigitalIdentity/>
            <StatusStartingTime>
                2020-11-01T00:00:00Z
            </StatusStartingTime>
            <ServiceInformationExtensions>
                <Extension Critical="false">
                    <q:Qualifications>
                        <q:QualificationElement>
                            {qual_xml}
                        </q:QualificationElement>
                    </q:Qualifications>
                </Extension>
            </ServiceInformationExtensions>
        </ServiceInformation>
    </TSPService>
    """

    parse_result = _raw_tlservice_parse(xml)
    result = eutl_parse._interpret_service_info_for_ca(parse_result)
    assert len(result.qualifications) == 0


@pytest.mark.parametrize(
    'names',
    [
        '<Name xml:lang="en">Test</Name>',
        '<Name xml:lang="nl">Test</Name>',
        '<Name xml:lang="en">Test</Name><Name xml:lang="nl">Fout</Name>',
        '<Name xml:lang="nl">Fout</Name><Name xml:lang="en">Test</Name>',
        '<Name xml:lang="nl">Test</Name><Name xml:lang="zz">Zzz</Name>',
    ],
)
def test_parse_service_name(names):
    xml = f"""
    <TSPService {NAMESPACES}>
        <ServiceInformation>
            <ServiceName>{names}</ServiceName>
            <ServiceTypeIdentifier>
                http://uri.etsi.org/TrstSvc/Svctype/CA/QC
            </ServiceTypeIdentifier>
            <ServiceDigitalIdentity/>
            <StatusStartingTime>
                2020-11-01T00:00:00Z
            </StatusStartingTime>
        </ServiceInformation>
    </TSPService>
    """

    parse_result = _raw_tlservice_parse(xml)
    result = eutl_parse._interpret_service_info_for_ca(parse_result)
    assert result.base_info.service_name == 'Test'


@pytest.mark.parametrize(
    'date_string',
    [
        '2020-11-01T00:00:00Z',
        '2020-11-01T01:00:00+01:00',
    ],
)
def test_parse_service_validity_dates(date_string):
    xml = f"""
    <TSPService {NAMESPACES}>
        <ServiceInformation>
            <ServiceName><Name xml:lang="en">Test</Name></ServiceName>
            <ServiceTypeIdentifier>
                http://uri.etsi.org/TrstSvc/Svctype/CA/QC
            </ServiceTypeIdentifier>
            <ServiceDigitalIdentity/>
            <StatusStartingTime>
                {date_string}
            </StatusStartingTime>
        </ServiceInformation>
    </TSPService>
    """

    parse_result = _raw_tlservice_parse(xml)
    result = eutl_parse._interpret_service_info_for_ca(parse_result)
    assert result.base_info.valid_from == datetime(
        2020, 11, 1, tzinfo=timezone.utc
    )


def test_reject_service_without_status_starting_time():
    xml = f"""
    <TSPService {NAMESPACES}>
        <ServiceInformation>
            <ServiceName><Name xml:lang="en">Test</Name></ServiceName>
            <ServiceTypeIdentifier>
                http://uri.etsi.org/TrstSvc/Svctype/CA/QC
            </ServiceTypeIdentifier>
            <ServiceDigitalIdentity/>
        </ServiceInformation>
    </TSPService>
    """

    parse_result = _raw_tlservice_parse(xml)
    with pytest.raises(
        eutl_parse.TSPServiceParsingError, match='validity start'
    ):
        eutl_parse._interpret_service_info_for_ca(parse_result)


@pytest.mark.parametrize(
    'criteria_xml',
    [
        ' ',
        '<q:CriteriaList assert="all"/>',
        (
            '<q:CriteriaList assert="all">'
            '<q:otherCriteriaList><blah/></q:otherCriteriaList>'
            '</q:CriteriaList>'
        ),
        (
            '<q:CriteriaList assert="all">'
            '<q:KeyUsage>'
            '<q:KeyUsageBit name="nonRepudiation">true</q:KeyUsageBit>'
            '</q:KeyUsage>'
            '<q:otherCriteriaList><blah/></q:otherCriteriaList>'
            '</q:CriteriaList>'
        ),
    ],
)
def test_criteria_parsing_failure(criteria_xml):
    qual_xml = """
    <q:Qualifiers>
        <q:Qualifier
        uri="http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithSSCD"/>
    </q:Qualifiers>
    """
    xml = f"""
    <TSPService {NAMESPACES}>
        <ServiceInformation>
            <ServiceName>
                <Name xml:lang="en">Test</Name>
            </ServiceName>
            <ServiceTypeIdentifier>
                http://uri.etsi.org/TrstSvc/Svctype/CA/QC
            </ServiceTypeIdentifier>
            <ServiceDigitalIdentity/>
            <StatusStartingTime>
                2020-11-01T00:00:00Z
            </StatusStartingTime>
            <ServiceInformationExtensions>
                <Extension Critical="false">
                    <q:Qualifications>
                        <q:QualificationElement>
                            {qual_xml}
                            {criteria_xml}
                        </q:QualificationElement>
                    </q:Qualifications>
                </Extension>
            </ServiceInformationExtensions>
        </ServiceInformation>
    </TSPService>
    """

    parse_result = _raw_tlservice_parse(xml)
    with pytest.raises(tsp.TSPServiceParsingError):
        eutl_parse._interpret_service_info_for_ca(parse_result)


def test_parse_service_no_type():
    xml = f"""
    <TSPService {NAMESPACES}>
        <ServiceInformation>
            <ServiceName><Name xml:lang="en">Test</Name></ServiceName>
            <ServiceDigitalIdentity/>
            <StatusStartingTime>
                2020-11-01T00:00:00Z
            </StatusStartingTime>
        </ServiceInformation>
    </TSPService>
    """

    parse_result = _raw_tlservice_parse(xml)
    with pytest.raises(
        tsp.TSPServiceParsingError,
        match='Service type',
    ):
        eutl_parse._interpret_service_info_for_ca(parse_result)


@pytest.mark.parametrize(
    'criterion',
    [
        tsp.CriteriaList(
            tsp.CriteriaCombination.ALL,
            frozenset(),
        ),
        tsp.CriteriaList(
            tsp.CriteriaCombination.NONE,
            frozenset(),
        ),
        tsp.CriteriaList(
            tsp.CriteriaCombination.ALL,
            frozenset(
                [
                    tsp.CertSubjectDNCriterion(
                        required_rdn_part_oids=frozenset(['2.5.4.3'])
                    ),
                    tsp.CertSubjectDNCriterion(
                        required_rdn_part_oids=frozenset(['2.5.4.10'])
                    ),
                    tsp.KeyUsageCriterion(
                        KeyUsageConstraints(
                            key_usage=frozenset(['non_repudiation'])
                        )
                    ),
                ]
            ),
        ),
        tsp.CriteriaList(
            tsp.CriteriaCombination.AT_LEAST_ONE,
            frozenset(
                [
                    tsp.CertSubjectDNCriterion(
                        required_rdn_part_oids=frozenset(['2.5.4.3'])
                    ),
                    tsp.PolicySetCriterion(frozenset(['2.999'])),
                ]
            ),
        ),
        tsp.CriteriaList(
            tsp.CriteriaCombination.NONE,
            frozenset(
                [
                    tsp.KeyUsageCriterion(
                        KeyUsageConstraints(
                            key_usage=frozenset(['key_encipherment'])
                        )
                    )
                ]
            ),
        ),
    ],
)
def test_criteria_accept(criterion):
    assert criterion.matches(FROM_CA.signing_cert)


@pytest.mark.parametrize(
    'criterion',
    [
        tsp.CriteriaList(
            tsp.CriteriaCombination.ALL,
            frozenset(
                [
                    tsp.CertSubjectDNCriterion(
                        required_rdn_part_oids=frozenset(['2.5.4.3'])
                    ),
                    tsp.PolicySetCriterion(frozenset(['2.999'])),
                ]
            ),
        ),
        tsp.CriteriaList(
            tsp.CriteriaCombination.NONE,
            frozenset(
                [
                    tsp.CertSubjectDNCriterion(
                        required_rdn_part_oids=frozenset(['2.5.4.3'])
                    ),
                    tsp.PolicySetCriterion(frozenset(['2.999'])),
                ]
            ),
        ),
    ],
)
def test_criteria_reject(criterion):
    assert not criterion.matches(FROM_CA.signing_cert)


def _dummy_service_definition(
    *extra_certs,
) -> tsp.CAServiceInformation:
    return tsp.CAServiceInformation(
        tsp.BaseServiceInformation(
            '',
            'test1',
            valid_from=datetime(2020, 11, 1, tzinfo=timezone.utc),
            valid_until=None,
            provider_certs=(INTERM_CERT, *extra_certs),
            additional_info_certificate_type=frozenset(),
            other_additional_info=frozenset(),
        ),
        qualifications=frozenset(),
        expired_certs_revocation_info=None,
    )


def test_tsp_registry():
    registry = tsp.TSPRegistry()
    registry.register_ca(_dummy_service_definition())

    result = list(
        registry.applicable_service_definitions(AuthorityWithCert(INTERM_CERT))
    )
    assert len(result) == 1
    assert result[0].base_info.service_name == 'test1'


def test_tsp_registry_by_name():
    registry = tsp.TSPRegistry()
    registry.register_ca(_dummy_service_definition())

    result = list(
        registry.applicable_service_definitions(
            NamedKeyAuthority(INTERM_CERT.subject, INTERM_CERT.public_key)
        )
    )
    assert len(result) == 1
    assert result[0].base_info.service_name == 'test1'


def test_tsp_registry_alternative_cert():
    registry = tsp.TSPRegistry()
    registry.register_ca(_dummy_service_definition(ECC_INTERM_CERT))

    result = list(
        registry.applicable_service_definitions(AuthorityWithCert(INTERM_CERT))
    )

    result2 = list(
        registry.applicable_service_definitions(
            AuthorityWithCert(ECC_INTERM_CERT)
        )
    )
    assert result == result2
    assert len(result) == 1
    assert result[0].base_info.service_name == 'test1'


def test_tsp_registry_multiple_sds():
    registry = tsp.TSPRegistry()
    # multiple SDs with the same issuer
    registry.register_ca(
        tsp.CAServiceInformation(
            tsp.BaseServiceInformation(
                '',
                'test1',  # quals are too much work to mock
                valid_from=datetime(2020, 11, 1, tzinfo=timezone.utc),
                valid_until=None,
                provider_certs=(INTERM_CERT,),
                other_additional_info=frozenset(),
                additional_info_certificate_type=frozenset(),
            ),
            qualifications=frozenset(),
            expired_certs_revocation_info=None,
        )
    )

    registry.register_ca(
        tsp.CAServiceInformation(
            tsp.BaseServiceInformation(
                '',
                'test2',
                valid_from=datetime(2020, 11, 1, tzinfo=timezone.utc),
                valid_until=None,
                provider_certs=(INTERM_CERT,),
                other_additional_info=frozenset(),
                additional_info_certificate_type=frozenset(),
            ),
            qualifications=frozenset(),
            expired_certs_revocation_info=None,
        )
    )

    result = list(
        registry.applicable_service_definitions(AuthorityWithCert(INTERM_CERT))
    )
    assert len(result) == 2
    assert set(r.base_info.service_name for r in result) == {'test1', 'test2'}


@pytest.mark.parametrize(
    'cert_id,expected_prelim_status',
    [
        (
            'esig-qualified',
            q_status.QualifiedStatus(
                qualified=True,
                qc_type=tsp.QcCertType.QC_ESIGN,
                qc_key_security=q_status.QcPrivateKeyManagementType.QCSD,
            ),
        ),
        (
            'eseal-qualified',
            q_status.QualifiedStatus(
                qualified=True,
                qc_type=tsp.QcCertType.QC_ESEAL,
                qc_key_security=q_status.QcPrivateKeyManagementType.QCSD,
            ),
        ),
        (
            'esig-qualified-no-qscd',
            q_status.QualifiedStatus(
                qualified=True,
                qc_type=tsp.QcCertType.QC_ESIGN,
                qc_key_security=q_status.QcPrivateKeyManagementType.UNKNOWN,
            ),
        ),
        ('not-qualified', assess.UNQUALIFIED),
        ('not-qualified-nonsense-qcsd', assess.UNQUALIFIED),
    ],
)
def test_qcstatements_processing(cert_id, expected_prelim_status):
    cert = TESTING_CA_QUALIFIED.get_cert(cert_id)
    result = assess.QualificationAssessor._process_qc_statements(cert)
    assert result == expected_prelim_status


@pytest.mark.parametrize(
    'prelim_status,applicable_qualifiers,expected_status_fields',
    [
        (
            q_status.QualifiedStatus(
                qualified=True,
                qc_type=tsp.QcCertType.QC_ESIGN,
                qc_key_security=q_status.QcPrivateKeyManagementType.QCSD,
            ),
            [tsp.Qualifier.NOT_QUALIFIED],
            {
                'qualified': False,
                'qc_key_security': q_status.QcPrivateKeyManagementType.UNKNOWN,
            },
        ),
        (
            q_status.QualifiedStatus(
                qualified=False,
                qc_type=tsp.QcCertType.QC_ESIGN,
                qc_key_security=q_status.QcPrivateKeyManagementType.QCSD,
            ),
            [tsp.Qualifier.QC_STATEMENT],
            {
                'qualified': True,
                'qc_key_security': q_status.QcPrivateKeyManagementType.QCSD,
            },
        ),
        (
            q_status.QualifiedStatus(
                qualified=False,
                qc_type=tsp.QcCertType.QC_ESIGN,
                qc_key_security=q_status.QcPrivateKeyManagementType.QCSD,
            ),
            [tsp.Qualifier.WITH_QSCD],
            {
                'qualified': False,
                'qc_key_security': q_status.QcPrivateKeyManagementType.UNKNOWN,
            },
        ),
        (
            q_status.QualifiedStatus(
                qualified=True,
                qc_type=tsp.QcCertType.QC_ESIGN,
                qc_key_security=q_status.QcPrivateKeyManagementType.UNKNOWN,
            ),
            [tsp.Qualifier.WITH_QSCD],
            {
                'qualified': True,
                'qc_key_security': q_status.QcPrivateKeyManagementType.QCSD,
            },
        ),
        (
            q_status.QualifiedStatus(
                qualified=True,
                qc_type=tsp.QcCertType.QC_ESIGN,
                qc_key_security=q_status.QcPrivateKeyManagementType.UNKNOWN,
            ),
            [tsp.Qualifier.WITH_SSCD],
            {
                'qualified': True,
                'qc_key_security': q_status.QcPrivateKeyManagementType.QCSD,
            },
        ),
        (
            q_status.QualifiedStatus(
                qualified=True,
                qc_type=tsp.QcCertType.QC_ESIGN,
                qc_key_security=q_status.QcPrivateKeyManagementType.UNKNOWN,
            ),
            [tsp.Qualifier.FOR_ESEAL],
            {
                'qualified': True,
                'qc_type': tsp.QcCertType.QC_ESEAL,
            },
        ),
        (
            q_status.QualifiedStatus(
                qualified=True,
                qc_type=tsp.QcCertType.QC_ESEAL,
                qc_key_security=q_status.QcPrivateKeyManagementType.UNKNOWN,
            ),
            [tsp.Qualifier.FOR_ESIG],
            {
                'qualified': True,
                'qc_type': tsp.QcCertType.QC_ESIGN,
            },
        ),
        (
            q_status.QualifiedStatus(
                qualified=True,
                qc_type=tsp.QcCertType.QC_ESIGN,
                qc_key_security=q_status.QcPrivateKeyManagementType.UNKNOWN,
            ),
            [tsp.Qualifier.FOR_WSA],
            {
                'qualified': True,
                'qc_type': tsp.QcCertType.QC_WEB,
            },
        ),
        (
            q_status.QualifiedStatus(
                qualified=True,
                qc_type=tsp.QcCertType.QC_ESEAL,
                qc_key_security=q_status.QcPrivateKeyManagementType.QCSD,
            ),
            [tsp.Qualifier.QSCD_MANAGED_ON_BEHALF],
            {
                'qc_key_security': (
                    q_status.QcPrivateKeyManagementType.QCSD_DELEGATED
                )
            },
        ),
        (
            q_status.QualifiedStatus(
                qualified=True,
                qc_type=tsp.QcCertType.QC_ESIGN,
                qc_key_security=q_status.QcPrivateKeyManagementType.QCSD,
            ),
            [tsp.Qualifier.NO_QSCD],
            {
                'qualified': True,
                'qc_key_security': q_status.QcPrivateKeyManagementType.UNKNOWN,
            },
        ),
        (
            q_status.QualifiedStatus(
                qualified=True,
                qc_type=tsp.QcCertType.QC_ESIGN,
                qc_key_security=q_status.QcPrivateKeyManagementType.QCSD,
            ),
            [tsp.Qualifier.NO_SSCD],
            {
                'qualified': True,
                'qc_key_security': q_status.QcPrivateKeyManagementType.UNKNOWN,
            },
        ),
        (
            q_status.QualifiedStatus(
                qualified=True,
                qc_type=tsp.QcCertType.QC_ESIGN,
                qc_key_security=q_status.QcPrivateKeyManagementType.QCSD,
            ),
            [tsp.Qualifier.QSCD_AS_IN_CERT],
            {
                'qualified': True,
                'qc_key_security': q_status.QcPrivateKeyManagementType.QCSD,
            },
        ),
    ],
)
def test_tl_override_processing(
    prelim_status, applicable_qualifiers, expected_status_fields
):
    result = assess.QualificationAssessor._final_status(
        prelim_status, frozenset(applicable_qualifiers)
    )
    result_fields = {
        key: getattr(result, key) for key in expected_status_fields
    }
    assert result_fields == expected_status_fields


DUMMY_BASE_INFO = tsp.BaseServiceInformation(
    service_type=eutl_parse.CA_QC_URI,
    service_name='Dummy',
    valid_from=datetime(2015, 11, 1, tzinfo=timezone.utc),
    valid_until=None,
    provider_certs=(TESTING_CA_QUALIFIED.get_cert('root'),),
    additional_info_certificate_type=frozenset([tsp.QcCertType.QC_ESIGN]),
    other_additional_info=frozenset(),
)

_SKIP_REVOCATION = CertRevTrustPolicy(
    RevocationCheckingPolicy(
        ee_certificate_rule=RevocationCheckingRule.NO_CHECK,
        intermediate_ca_cert_rule=RevocationCheckingRule.NO_CHECK,
    )
)

MUST_HAVE_POLICY0 = tsp.CriteriaList(
    combine_as=tsp.CriteriaCombination.ALL,
    criteria=frozenset([tsp.PolicySetCriterion(frozenset(['2.999.31337.0']))]),
)

MUST_HAVE_POLICY1 = tsp.CriteriaList(
    combine_as=tsp.CriteriaCombination.ALL,
    criteria=frozenset([tsp.PolicySetCriterion(frozenset(['2.999.31337.1']))]),
)

MUST_HAVE_NONREPUD = tsp.CriteriaList(
    combine_as=tsp.CriteriaCombination.ALL,
    criteria=frozenset(
        [
            tsp.KeyUsageCriterion(
                KeyUsageConstraints(key_usage=('non_repudiation',))
            )
        ]
    ),
)


@pytest.mark.asyncio
@freeze_time('2020-11-01')
@pytest.mark.parametrize(
    'cert_name,sd',
    [
        (
            'esig-qualified',
            tsp.CAServiceInformation(
                base_info=DUMMY_BASE_INFO,
                qualifications=frozenset(),
                expired_certs_revocation_info=None,
            ),
        ),
        (
            'esig-qualified-no-qscd',
            tsp.CAServiceInformation(
                base_info=DUMMY_BASE_INFO,
                qualifications=frozenset(
                    [
                        tsp.Qualification(
                            qualifiers=frozenset([tsp.Qualifier.WITH_QSCD]),
                            criteria_list=MUST_HAVE_POLICY0,
                        )
                    ]
                ),
                expired_certs_revocation_info=None,
            ),
        ),
        (
            'not-qualified',
            tsp.CAServiceInformation(
                base_info=DUMMY_BASE_INFO,
                qualifications=frozenset(
                    [
                        tsp.Qualification(
                            criteria_list=MUST_HAVE_POLICY0,
                            qualifiers=frozenset(
                                [
                                    tsp.Qualifier.QC_STATEMENT,
                                    tsp.Qualifier.WITH_QSCD,
                                ]
                            ),
                        )
                    ]
                ),
                expired_certs_revocation_info=None,
            ),
        ),
        (
            'not-qualified',
            tsp.CAServiceInformation(
                base_info=DUMMY_BASE_INFO,
                qualifications=frozenset(
                    [
                        tsp.Qualification(
                            criteria_list=MUST_HAVE_POLICY0,
                            qualifiers=frozenset(
                                [
                                    tsp.Qualifier.QC_STATEMENT,
                                ]
                            ),
                        ),
                        tsp.Qualification(
                            criteria_list=MUST_HAVE_NONREPUD,
                            qualifiers=frozenset(
                                [
                                    tsp.Qualifier.WITH_QSCD,
                                ]
                            ),
                        ),
                    ]
                ),
                expired_certs_revocation_info=None,
            ),
        ),
        (
            'esig-qualified',
            tsp.CAServiceInformation(
                base_info=DUMMY_BASE_INFO,
                qualifications=frozenset(
                    [
                        tsp.Qualification(
                            criteria_list=MUST_HAVE_POLICY1,
                            qualifiers=frozenset(
                                [
                                    tsp.Qualifier.NO_QSCD,
                                ]
                            ),
                        ),
                    ]
                ),
                expired_certs_revocation_info=None,
            ),
        ),
        (
            'esig-qualified',
            tsp.CAServiceInformation(
                base_info=DUMMY_BASE_INFO,
                qualifications=frozenset(
                    [
                        tsp.Qualification(
                            criteria_list=MUST_HAVE_POLICY1,
                            qualifiers=frozenset(
                                [
                                    tsp.Qualifier.NOT_QUALIFIED,
                                ]
                            ),
                        ),
                    ]
                ),
                expired_certs_revocation_info=None,
            ),
        ),
    ],
)
async def test_conclude_qualified_qcsd(cert_name, sd):
    ee_cert = TESTING_CA_QUALIFIED.get_cert(cert_name)
    vc = ValidationContext(
        trust_roots=[TESTING_CA_QUALIFIED.get_cert('root')],
        allow_fetching=False,
        revinfo_policy=_SKIP_REVOCATION,
        other_certs=[TESTING_CA_QUALIFIED.get_cert('interm-qualified')],
    )
    cv = CertificateValidator(end_entity_cert=ee_cert, validation_context=vc)
    path = await cv.async_validate_path()
    registry = tsp.TSPRegistry()
    registry.register_ca(sd)
    assessor = assess.QualificationAssessor(tsp_registry=registry)
    status = assessor.check_entity_cert_qualified(path)
    assert status.qualified
    assert status.qc_key_security == q_status.QcPrivateKeyManagementType.QCSD


@pytest.mark.asyncio
@freeze_time('2015-11-01')
@pytest.mark.parametrize(
    'cert_name,expect_qscd',
    [
        ('esig-qualified-legacy-policy', False),
        ('esig-qualified-legacy-policy-qscd', True),
    ],
)
async def test_conclude_qualified_pre_eidas(cert_name, expect_qscd):
    sd = tsp.CAServiceInformation(
        base_info=DUMMY_BASE_INFO,
        qualifications=frozenset(),
        expired_certs_revocation_info=None,
    )
    ee_cert = TESTING_CA_QUALIFIED.get_cert(cert_name)
    vc = ValidationContext(
        trust_roots=[TESTING_CA_QUALIFIED.get_cert('root')],
        allow_fetching=False,
        revinfo_policy=_SKIP_REVOCATION,
        other_certs=[TESTING_CA_QUALIFIED.get_cert('interm-qualified')],
    )
    cv = CertificateValidator(end_entity_cert=ee_cert, validation_context=vc)
    path = await cv.async_validate_path()
    registry = tsp.TSPRegistry()
    registry.register_ca(sd)
    assessor = assess.QualificationAssessor(tsp_registry=registry)
    status = assessor.check_entity_cert_qualified(path)
    assert status.qualified
    if expect_qscd:
        assert (
            status.qc_key_security
            == q_status.QcPrivateKeyManagementType.QCSD_BY_POLICY
        )
    else:
        assert (
            status.qc_key_security
            == q_status.QcPrivateKeyManagementType.UNKNOWN
        )


@pytest.mark.asyncio
@freeze_time('2020-11-01')
@pytest.mark.parametrize(
    'cert_name,sd',
    [
        (
            'not-qualified',
            tsp.CAServiceInformation(
                base_info=DUMMY_BASE_INFO,
                qualifications=frozenset(),
                expired_certs_revocation_info=None,
            ),
        ),
        (
            'esig-qualified',
            tsp.CAServiceInformation(
                base_info=DUMMY_BASE_INFO,
                qualifications=frozenset(
                    [
                        tsp.Qualification(
                            qualifiers=frozenset([tsp.Qualifier.NOT_QUALIFIED]),
                            criteria_list=MUST_HAVE_POLICY0,
                        )
                    ]
                ),
                expired_certs_revocation_info=None,
            ),
        ),
        (
            # out of scope of this service definition
            'eseal-qualified',
            tsp.CAServiceInformation(
                base_info=DUMMY_BASE_INFO,
                qualifications=frozenset(),
                expired_certs_revocation_info=None,
            ),
        ),
        (
            'esig-qualified-legacy-policy',
            tsp.CAServiceInformation(
                base_info=DUMMY_BASE_INFO,
                qualifications=frozenset(),
                expired_certs_revocation_info=None,
            ),
        ),
    ],
)
async def test_conclude_not_qualified(cert_name, sd):
    ee_cert = TESTING_CA_QUALIFIED.get_cert(cert_name)
    vc = ValidationContext(
        trust_roots=[TESTING_CA_QUALIFIED.get_cert('root')],
        allow_fetching=False,
        revinfo_policy=_SKIP_REVOCATION,
        other_certs=[TESTING_CA_QUALIFIED.get_cert('interm-qualified')],
    )
    cv = CertificateValidator(end_entity_cert=ee_cert, validation_context=vc)
    path = await cv.async_validate_path()
    registry = tsp.TSPRegistry()
    registry.register_ca(sd)
    assessor = assess.QualificationAssessor(tsp_registry=registry)
    status = assessor.check_entity_cert_qualified(path)
    assert not status.qualified


@pytest.mark.asyncio
@freeze_time('2020-11-01')
async def test_conclude_not_qualified_contradictory():
    sd1 = tsp.CAServiceInformation(
        base_info=DUMMY_BASE_INFO,
        qualifications=frozenset(),
        expired_certs_revocation_info=None,
    )
    sd2 = tsp.CAServiceInformation(
        base_info=dataclasses.replace(DUMMY_BASE_INFO, service_name='Dummy2'),
        qualifications=frozenset(
            [
                tsp.Qualification(
                    qualifiers=frozenset([tsp.Qualifier.NO_QSCD]),
                    criteria_list=MUST_HAVE_POLICY0,
                )
            ]
        ),
        expired_certs_revocation_info=None,
    )
    ee_cert = TESTING_CA_QUALIFIED.get_cert('esig-qualified')
    vc = ValidationContext(
        trust_roots=[TESTING_CA_QUALIFIED.get_cert('root')],
        allow_fetching=False,
        revinfo_policy=_SKIP_REVOCATION,
        other_certs=[TESTING_CA_QUALIFIED.get_cert('interm-qualified')],
    )
    cv = CertificateValidator(end_entity_cert=ee_cert, validation_context=vc)
    path = await cv.async_validate_path()
    registry = tsp.TSPRegistry()
    registry.register_ca(sd1)
    registry.register_ca(sd2)
    assessor = assess.QualificationAssessor(tsp_registry=registry)
    status = assessor.check_entity_cert_qualified(path)
    assert not status.qualified


@pytest.mark.asyncio
@freeze_time('2020-11-01')
async def test_conclude_qualified_convergence():
    sd1 = tsp.CAServiceInformation(
        base_info=DUMMY_BASE_INFO,
        qualifications=frozenset(),
        expired_certs_revocation_info=None,
    )
    sd2 = tsp.CAServiceInformation(
        base_info=dataclasses.replace(DUMMY_BASE_INFO, service_name='Dummy2'),
        qualifications=frozenset(),
        expired_certs_revocation_info=None,
    )
    ee_cert = TESTING_CA_QUALIFIED.get_cert('esig-qualified')
    vc = ValidationContext(
        trust_roots=[TESTING_CA_QUALIFIED.get_cert('root')],
        allow_fetching=False,
        revinfo_policy=_SKIP_REVOCATION,
        other_certs=[TESTING_CA_QUALIFIED.get_cert('interm-qualified')],
    )
    cv = CertificateValidator(end_entity_cert=ee_cert, validation_context=vc)
    path = await cv.async_validate_path()
    registry = tsp.TSPRegistry()
    registry.register_ca(sd1)
    registry.register_ca(sd2)
    assessor = assess.QualificationAssessor(tsp_registry=registry)
    status = assessor.check_entity_cert_qualified(path)
    assert status.qualified


def test_parse_service_history_intervals():
    xml = f"""
    <TSPService {NAMESPACES}>
        <ServiceInformation>
            <ServiceName><Name xml:lang="en">Test</Name></ServiceName>
            <ServiceTypeIdentifier>{CA_QC_URI}</ServiceTypeIdentifier>
            <ServiceStatus>{STATUS_GRANTED}</ServiceStatus>
            <ServiceDigitalIdentity/>
            <StatusStartingTime>
                2020-11-01T00:00:00Z
            </StatusStartingTime>
        </ServiceInformation>
        <ServiceHistory>
            <ServiceHistoryInstance>
                <ServiceName><Name xml:lang="en">Test</Name></ServiceName>
                <ServiceTypeIdentifier>{CA_QC_URI}</ServiceTypeIdentifier>
                <ServiceStatus>{STATUS_GRANTED}</ServiceStatus>
                <ServiceDigitalIdentity/>
                <StatusStartingTime>
                    2017-11-01T00:00:00Z
                </StatusStartingTime>
            </ServiceHistoryInstance>
            <ServiceHistoryInstance>
                <ServiceName><Name xml:lang="en">Test</Name></ServiceName>
                <ServiceTypeIdentifier>{CA_QC_URI}</ServiceTypeIdentifier>
                <ServiceStatus>{STATUS_GRANTED}</ServiceStatus>
                <ServiceDigitalIdentity/>
                <StatusStartingTime>
                    2019-11-01T00:00:00Z
                </StatusStartingTime>
            </ServiceHistoryInstance>
        </ServiceHistory>
    </TSPService>
    """

    parse_result = _raw_tlservice_parse(xml)
    result = eutl_parse._interpret_service_info_for_cas([parse_result])
    date1 = datetime(2017, 11, 1, tzinfo=timezone.utc)
    date2 = datetime(2019, 11, 1, tzinfo=timezone.utc)
    date3 = datetime(2020, 11, 1, tzinfo=timezone.utc)
    intervals = [
        (r.base_info.valid_from, r.base_info.valid_until) for r in result
    ]
    assert intervals == [(date3, None), (date2, date3), (date1, date2)]


def test_parse_service_history_intervals_skip_not_granted():
    xml = f"""
    <TSPService {NAMESPACES}>
        <ServiceInformation>
            <ServiceName><Name xml:lang="en">Test</Name></ServiceName>
            <ServiceTypeIdentifier>{CA_QC_URI}</ServiceTypeIdentifier>
            <ServiceStatus>{STATUS_GRANTED}</ServiceStatus>
            <ServiceDigitalIdentity/>
            <StatusStartingTime>
                2020-11-01T00:00:00Z
            </StatusStartingTime>
        </ServiceInformation>
        <ServiceHistory>
            <ServiceHistoryInstance>
                <ServiceName><Name xml:lang="en">Test</Name></ServiceName>
                <ServiceTypeIdentifier>{CA_QC_URI}</ServiceTypeIdentifier>
                <ServiceStatus>{STATUS_GRANTED}</ServiceStatus>
                <ServiceDigitalIdentity/>
                <StatusStartingTime>
                    2017-11-01T00:00:00Z
                </StatusStartingTime>
            </ServiceHistoryInstance>
            <ServiceHistoryInstance>
                <ServiceName><Name xml:lang="en">Test</Name></ServiceName>
                <ServiceTypeIdentifier>{CA_QC_URI}</ServiceTypeIdentifier>
                <ServiceStatus>urn:blah</ServiceStatus>
                <ServiceDigitalIdentity/>
                <StatusStartingTime>
                    2019-11-01T00:00:00Z
                </StatusStartingTime>
            </ServiceHistoryInstance>
        </ServiceHistory>
    </TSPService>
    """

    parse_result = _raw_tlservice_parse(xml)
    result = eutl_parse._interpret_service_info_for_cas([parse_result])
    date1 = datetime(2017, 11, 1, tzinfo=timezone.utc)
    date2 = datetime(2019, 11, 1, tzinfo=timezone.utc)
    date3 = datetime(2020, 11, 1, tzinfo=timezone.utc)
    intervals = [
        (r.base_info.valid_from, r.base_info.valid_until) for r in result
    ]
    assert intervals == [
        (date3, None),
        # gap where status is not granted
        (date1, date2),
    ]


def test_parse_service_history_intervals_skip_invalid_entries():
    xml = f"""
    <TSPService {NAMESPACES}>
        <ServiceInformation>
            <ServiceName><Name xml:lang="en">Test</Name></ServiceName>
            <ServiceTypeIdentifier>{CA_QC_URI}</ServiceTypeIdentifier>
            <ServiceStatus>{STATUS_GRANTED}</ServiceStatus>
            <ServiceDigitalIdentity/>
            <StatusStartingTime>
                2020-11-01T00:00:00Z
            </StatusStartingTime>
        </ServiceInformation>
        <ServiceHistory>
            <ServiceHistoryInstance>
                <ServiceName><Name xml:lang="en">Test</Name></ServiceName>
                <ServiceTypeIdentifier>{CA_QC_URI}</ServiceTypeIdentifier>
                <ServiceStatus>{STATUS_GRANTED}</ServiceStatus>
                <ServiceDigitalIdentity/>
                <StatusStartingTime>
                    2017-11-01T00:00:00Z
                </StatusStartingTime>
            </ServiceHistoryInstance>
            <ServiceHistoryInstance>
                <ServiceName><Name xml:lang="en">Test</Name></ServiceName>
                <ServiceStatus>{STATUS_GRANTED}</ServiceStatus>
                <StatusStartingTime>2019-11-01T00:00:00Z</StatusStartingTime>
            </ServiceHistoryInstance>
        </ServiceHistory>
    </TSPService>
    """

    parse_result = _raw_tlservice_parse(xml)
    result = eutl_parse._interpret_service_info_for_cas([parse_result])
    date2 = datetime(2020, 11, 1, tzinfo=timezone.utc)
    intervals = [
        (r.base_info.valid_from, r.base_info.valid_until) for r in result
    ]
    assert len(intervals) == 2
    assert intervals[0] == (date2, None)
    # don't assert on second interval for now; let's call
    # that one undefined behaviour
