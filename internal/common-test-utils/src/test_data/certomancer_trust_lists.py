from asn1crypto import pem
from certomancer import PKIArchitecture
from certomancer.registry import EntityLabel
from cryptography.hazmat.primitives import serialization
from lxml.etree import fromstring, tostring
from pyhanko.generated.etsi import ts_119612
from pyhanko.sign.validation.qualified import eutl_parse
from pyhanko.sign.validation.qualified.eutl_parse import STATUS_GRANTED
from pyhanko.sign.validation.qualified.tsp import CA_QC_URI, QTST_URI
from pyhanko.sign.validation.report.tools import NAMESPACES
from signxml import SignatureMethod
from signxml.xades import XAdESSigner
from test_data.samples import TESTING_CA
from test_utils.signing_commons import FROM_CA
from xsdata.formats.dataclass.serializers import XmlSerializer
from xsdata.formats.dataclass.serializers.config import SerializerConfig
from xsdata.models.datatype import XmlDateTime


def _certomancer_pki_as_service_definitions(pki_arch: PKIArchitecture):

    # register all self-issued certs as CAs
    for iss, certs in pki_arch.enumerate_certs_by_issuer():
        for cert_spec in certs:
            if iss != cert_spec.subject:
                continue
            name = f"{pki_arch.arch_label}: CA {cert_spec.label}"
            yield ts_119612.TSPService(
                ts_119612.ServiceInformation(
                    service_type_identifier=ts_119612.ServiceTypeIdentifier(
                        CA_QC_URI
                    ),
                    service_name=ts_119612.InternationalNamesType(
                        (
                            ts_119612.MultiLangNormStringType(
                                value=name,
                                lang="en",
                            ),
                        )
                    ),
                    service_digital_identity=ts_119612.ServiceDigitalIdentity(
                        (
                            ts_119612.DigitalIdentityType(
                                x509_certificate=pki_arch.get_cert(
                                    cert_spec.label
                                ).dump()
                            ),
                        )
                    ),
                    service_status=ts_119612.ServiceStatus(STATUS_GRANTED),
                    status_starting_time=XmlDateTime.from_datetime(
                        cert_spec.validity.valid_from
                    ),
                )
            )

    for tsa_info in pki_arch.service_registry.list_time_stamping_services():
        name = f"{pki_arch.arch_label}: TSA {tsa_info.label}"
        yield ts_119612.TSPService(
            ts_119612.ServiceInformation(
                service_type_identifier=ts_119612.ServiceTypeIdentifier(
                    QTST_URI
                ),
                service_name=ts_119612.InternationalNamesType(
                    (
                        ts_119612.MultiLangNormStringType(
                            value=name,
                            lang="en",
                        ),
                    )
                ),
                service_digital_identity=ts_119612.ServiceDigitalIdentity(
                    (
                        ts_119612.DigitalIdentityType(
                            x509_certificate=pki_arch.get_cert(
                                tsa_info.signing_cert
                            ).dump()
                        ),
                    )
                ),
                service_status=ts_119612.ServiceStatus(STATUS_GRANTED),
                status_starting_time=XmlDateTime.from_datetime(
                    pki_arch.get_cert_spec(
                        tsa_info.signing_cert
                    ).validity.valid_from
                ),
            )
        )


def certomancer_pki_as_trusted_list(
    pki_arch: PKIArchitecture, tlso_entity: EntityLabel
):

    xml_root = ts_119612.TrustServiceStatusList(
        scheme_information=ts_119612.SchemeInformation(),
        trust_service_provider_list=ts_119612.TrustServiceProviderList(
            trust_service_provider=tuple(
                ts_119612.TrustServiceProvider(
                    tspservices=ts_119612.TSPServices((svc,))
                )
                for svc in _certomancer_pki_as_service_definitions(pki_arch)
            )
        ),
    )
    tlso_cert_label = pki_arch.get_unique_cert_for_entity(tlso_entity)
    tlso_cert_spec = pki_arch.get_cert_spec(tlso_cert_label)
    tlso_priv_key = pki_arch.key_set.get_private_key(tlso_cert_spec.subject_key)

    priv_key = serialization.load_der_private_key(
        tlso_priv_key.dump(), password=None
    )

    config = SerializerConfig(indent="  ")
    data = XmlSerializer(config=config).render(xml_root)
    data_read_back = fromstring(data.encode('utf8'))
    signed = XAdESSigner(signature_algorithm=SignatureMethod.ECDSA_SHA256).sign(
        data_read_back,
        key=priv_key,
        cert=pem.armor(
            "CERTIFICATE", pki_arch.get_cert(tlso_cert_label).dump()
        ),
    )
    return tostring(signed).decode('utf8')
