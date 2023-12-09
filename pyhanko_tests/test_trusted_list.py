from datetime import datetime, timezone
from pathlib import Path

import pytest
from pyhanko_certvalidator.authority import AuthorityWithCert, NamedKeyAuthority
from signing_commons import ECC_INTERM_CERT, FROM_CA, FROM_ECC_CA, INTERM_CERT
from xsdata.formats.dataclass.parsers import XmlParser
from xsdata.formats.dataclass.parsers.config import ParserConfig

from pyhanko.generated.etsi import ts_119612
from pyhanko.sign.validation import KeyUsageConstraints, eutl
from pyhanko.sign.validation.eutl import CriteriaCombination


def _read_cas_from_file(path: Path):
    with path.open('r', encoding='utf8') as inf:
        tl_str = inf.read()
        return list(eutl.read_qualified_certificate_authorities(tl_str))


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
    assert len(_read_cas_from_file(TEST_REAL_TL)) == 52


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
            <ServiceInformationExtensions>
                <Extension Critical="true">
                    <blah/>
                </Extension>
            </ServiceInformationExtensions>
        </ServiceInformation>
    </TSPService>
    """

    parse_result = _raw_tlservice_parse(xml)
    with pytest.raises(eutl.TSPServiceParsingError, match="critical"):
        eutl._interpret_service_info_for_ca(parse_result)


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
            <ServiceInformationExtensions>
                <Extension Critical="false">
                    <blah/>
                </Extension>
            </ServiceInformationExtensions>
        </ServiceInformation>
    </TSPService>
    """

    parse_result = _raw_tlservice_parse(xml)
    assert eutl._interpret_service_info_for_ca(parse_result) is not None


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
    result = eutl._interpret_service_info_for_ca(parse_result)
    assert result.expired_certs_revocation_info == datetime(
        2016, 6, 30, 21, 0, 0, tzinfo=timezone.utc
    )
    qualification = list(result.qualifications)[0]
    assert qualification.qualifiers == frozenset([eutl.Qualifier.WITH_SSCD])
    criteria = qualification.criteria_list.criteria
    assert eutl.PolicySetCriterion(frozenset(['2.999'])) in criteria
    assert (
        eutl.KeyUsageCriterion(
            KeyUsageConstraints(
                key_usage=frozenset(['non_repudiation']),
                key_usage_forbidden=frozenset(),
            )
        )
        in criteria
    )
    assert (
        eutl.KeyUsageCriterion(
            KeyUsageConstraints(extd_key_usage=frozenset(['2.999']))
        )
        in criteria
    )
    assert (
        eutl.CertSubjectDNCriterion(required_rdn_part_oids=frozenset(['2.999']))
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
    result = eutl._interpret_service_info_for_ca(parse_result)
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
        </ServiceInformation>
    </TSPService>
    """

    parse_result = _raw_tlservice_parse(xml)
    result = eutl._interpret_service_info_for_ca(parse_result)
    assert result.base_info.service_name == 'Test'


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
    with pytest.raises(eutl.TSPServiceParsingError):
        eutl._interpret_service_info_for_ca(parse_result)


def test_parse_service_no_type():
    xml = f"""
    <TSPService {NAMESPACES}>
        <ServiceInformation>
            <ServiceName><Name xml:lang="en">Test</Name></ServiceName>
            <ServiceDigitalIdentity/>
        </ServiceInformation>
    </TSPService>
    """

    parse_result = _raw_tlservice_parse(xml)
    with pytest.raises(eutl.TSPServiceParsingError, match='Service type'):
        eutl._interpret_service_info_for_ca(parse_result)


@pytest.mark.parametrize(
    'criterion',
    [
        eutl.CriteriaList(CriteriaCombination.ALL, frozenset()),
        eutl.CriteriaList(CriteriaCombination.NONE, frozenset()),
        eutl.CriteriaList(
            CriteriaCombination.ALL,
            frozenset(
                [
                    eutl.CertSubjectDNCriterion(
                        required_rdn_part_oids=frozenset(['2.5.4.3'])
                    ),
                    eutl.CertSubjectDNCriterion(
                        required_rdn_part_oids=frozenset(['2.5.4.10'])
                    ),
                    eutl.KeyUsageCriterion(
                        KeyUsageConstraints(
                            key_usage=frozenset(['non_repudiation'])
                        )
                    ),
                ]
            ),
        ),
        eutl.CriteriaList(
            CriteriaCombination.AT_LEAST_ONE,
            frozenset(
                [
                    eutl.CertSubjectDNCriterion(
                        required_rdn_part_oids=frozenset(['2.5.4.3'])
                    ),
                    eutl.PolicySetCriterion(frozenset(['2.999'])),
                ]
            ),
        ),
        eutl.CriteriaList(
            CriteriaCombination.NONE,
            frozenset(
                [
                    eutl.KeyUsageCriterion(
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
        eutl.CriteriaList(
            CriteriaCombination.ALL,
            frozenset(
                [
                    eutl.CertSubjectDNCriterion(
                        required_rdn_part_oids=frozenset(['2.5.4.3'])
                    ),
                    eutl.PolicySetCriterion(frozenset(['2.999'])),
                ]
            ),
        ),
        eutl.CriteriaList(
            CriteriaCombination.NONE,
            frozenset(
                [
                    eutl.CertSubjectDNCriterion(
                        required_rdn_part_oids=frozenset(['2.5.4.3'])
                    ),
                    eutl.PolicySetCriterion(frozenset(['2.999'])),
                ]
            ),
        ),
    ],
)
def test_criteria_reject(criterion):
    assert not criterion.matches(FROM_CA.signing_cert)


def _dummy_service_definition(*extra_certs) -> eutl.CAServiceInformation:
    return eutl.CAServiceInformation(
        eutl.BaseServiceInformation(
            '',
            'test1',
            provider_certs=(INTERM_CERT, *extra_certs),
            additional_info=frozenset(),
        ),
        qualifications=frozenset(),
        expired_certs_revocation_info=None,
    )


def test_tsp_registry():
    registry = eutl.TSPRegistry()
    registry.register_ca(_dummy_service_definition())

    result = list(
        registry.applicable_service_definitions(AuthorityWithCert(INTERM_CERT))
    )
    assert len(result) == 1
    assert result[0].base_info.service_name == 'test1'


def test_tsp_registry_by_name():
    registry = eutl.TSPRegistry()
    registry.register_ca(_dummy_service_definition())

    result = list(
        registry.applicable_service_definitions(
            NamedKeyAuthority(INTERM_CERT.subject, INTERM_CERT.public_key)
        )
    )
    assert len(result) == 1
    assert result[0].base_info.service_name == 'test1'


def test_tsp_registry_alternative_cert():
    registry = eutl.TSPRegistry()
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
    registry = eutl.TSPRegistry()
    # multiple SDs with the same issuer
    registry.register_ca(
        eutl.CAServiceInformation(
            eutl.BaseServiceInformation(
                '',
                'test1',  # quals are too much work to mock
                provider_certs=(INTERM_CERT,),
                additional_info=frozenset(),
            ),
            qualifications=frozenset(),
            expired_certs_revocation_info=None,
        )
    )

    registry.register_ca(
        eutl.CAServiceInformation(
            eutl.BaseServiceInformation(
                '',
                'test2',
                provider_certs=(INTERM_CERT,),
                additional_info=frozenset(),
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
