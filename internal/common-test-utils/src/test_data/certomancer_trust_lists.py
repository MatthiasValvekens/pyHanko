from typing import List, Tuple
from urllib.parse import urlparse

from aiohttp.test_utils import TestClient
from aiohttp.typedefs import StrOrURL
from asn1crypto import pem
from certomancer import PKIArchitecture
from certomancer.registry import CertLabel, EntityLabel
from cryptography.hazmat.primitives import serialization
from lxml.etree import fromstring, tostring
from pyhanko.generated.etsi import MimeType, ts_119612
from pyhanko.sign.validation.qualified.eutl_parse import (
    ETSI_TSL_MIME_TYPE,
    STATUS_GRANTED,
)
from pyhanko.sign.validation.qualified.tsp import CA_QC_URI, QTST_URI
from signxml import SignatureMethod
from signxml.xades import XAdESSigner
from xsdata.formats.dataclass.serializers import XmlSerializer
from xsdata.formats.dataclass.serializers.config import SerializerConfig
from xsdata.models.datatype import XmlDateTime
from yarl import URL


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


def _sign_tl(
    xml_root: ts_119612.TrustServiceStatusList,
    pki_arch: PKIArchitecture,
    tlso_entity: EntityLabel,
):
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
        always_add_key_value=False,
    )
    return tostring(signed).decode('utf8')


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
    return _sign_tl(xml_root, pki_arch, tlso_entity)


def certomancer_lotl(
    pki_arch: PKIArchitecture,
    lotl_tlso_entity: EntityLabel,
    entries: List[Tuple[CertLabel, str, str]],
):
    pointers = [
        ts_119612.OtherTSLPointer(
            tsllocation=url,
            service_digital_identities=ts_119612.ServiceDigitalIdentities(
                service_digital_identity=(
                    ts_119612.ServiceDigitalIdentity(
                        (
                            ts_119612.DigitalIdentityType(
                                x509_certificate=pki_arch.get_cert(
                                    tlso_cert
                                ).dump()
                            ),
                        )
                    ),
                )
            ),
            additional_information=ts_119612.AdditionalInformation(
                other_information=(
                    ts_119612.AnyType(
                        content=(
                            ts_119612.SchemeTerritory(territory),
                            MimeType(ETSI_TSL_MIME_TYPE),
                        )
                    ),
                ),
            ),
        )
        for tlso_cert, territory, url in entries
    ]

    xml_root = ts_119612.TrustServiceStatusList(
        scheme_information=ts_119612.SchemeInformation(
            scheme_information_uri=ts_119612.SchemeInformationURI(uri=tuple()),
            pointers_to_other_tsl=ts_119612.PointersToOtherTSL(
                other_tslpointer=tuple(pointers)
            ),
        ),
    )
    return _sign_tl(xml_root, pki_arch, lotl_tlso_entity)


class PathRetainingClient(TestClient):
    def make_url(self, path: StrOrURL) -> URL:
        components = urlparse(path)
        # only remember the path part, forget about the host etc.
        # (this is so we can test with real EUTL files using aiohttp
        # testing utils)
        return super().make_url(components.path)
