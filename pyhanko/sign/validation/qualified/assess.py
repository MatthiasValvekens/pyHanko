import zoneinfo
from dataclasses import replace
from datetime import datetime
from typing import FrozenSet, List, Optional, Set, Tuple

from asn1crypto import x509
from pyhanko_certvalidator.path import ValidationPath

from pyhanko.sign.ades import qualified_asn1
from pyhanko.sign.validation.qualified.eutl_parse import logger
from pyhanko.sign.validation.qualified.q_status import (
    QcPrivateKeyManagementType,
    QualifiedStatus,
)
from pyhanko.sign.validation.qualified.tsp import (
    CAServiceInformation,
    QcCertType,
    Qualifier,
    TSPRegistry,
)

__all__ = [
    'QualificationAssessor',
]


EIDAS_START_DATE = datetime(
    2016, 7, 1, 0, 0, 0, tzinfo=zoneinfo.ZoneInfo('CET')
)

PRE_EIDAS_QCP_POLICY = '0.4.0.1456.1.1'
PRE_EIDAS_QCP_PLUS_POLICY = '0.4.0.1456.1.2'

UNQUALIFIED = QualifiedStatus(
    qualified=False,
    qc_type=QcCertType.QC_ESIGN,
    qc_key_security=QcPrivateKeyManagementType.UNKNOWN,
)


class QualificationAssessor:
    def __init__(self, tsp_registry: TSPRegistry):
        self._registry = tsp_registry

    @staticmethod
    def _process_qc_statements(cert: x509.Certificate) -> QualifiedStatus:
        qcs = qualified_asn1.get_qc_statements(cert)
        qualified = False
        key_secure = False
        qc_type = QcCertType.QC_ESIGN
        for statement in qcs:
            st_type = statement['statement_id'].native
            if st_type == 'qc_compliance':
                qualified = True
            elif st_type == 'qc_sscd':
                # management delegation is not encoded by the QcStatements
                key_secure = True
            elif st_type == 'qc_type':
                qc_types: qualified_asn1.QcCertificateType = statement[
                    'statement_info'
                ]
                if len(qc_types) != 1:
                    # In theory this is not limited to one value, we have to
                    # let the TL override in a case like this.
                    # Nonetheless there's really no good reason to do this,
                    # and some ETSI specs are more strict than others,
                    # so I'll deal with this case when it presents itself
                    raise NotImplementedError("only support exactly 1 qc_type")
                qc_type = QcCertType(qc_types[0].native)
        return QualifiedStatus(
            qualified=qualified,
            qc_type=qc_type,
            qc_key_security=(
                QcPrivateKeyManagementType.QCSD
                if key_secure and qualified
                else QcPrivateKeyManagementType.UNKNOWN
            ),
        )

    @staticmethod
    def _check_cd_applicable(
        sd: CAServiceInformation, putative_status: QualifiedStatus
    ):
        sd_declared_type = sd.base_info.additional_info_certificate_type
        if sd_declared_type and putative_status.qc_type not in sd_declared_type:
            logger.info(
                f"Found matching SDI {sd.base_info.service_name} on path; "
                f"skipping because QC type does not match"
            )
            return False
        return True

    @staticmethod
    def _apply_sd_qualifications(
        cert: x509.Certificate,
        prelim_status: QualifiedStatus,
        sd: CAServiceInformation,
    ):
        applicable_qualifiers: Set[Qualifier] = set()
        for qualification in sd.qualifications:
            if not qualification.criteria_list.matches(cert):
                continue
            applicable_qualifiers.update(qualification.qualifiers)
        return QualificationAssessor._final_status(
            prelim_status, frozenset(applicable_qualifiers)
        )

    @staticmethod
    def _final_status(
        prelim_status: QualifiedStatus,
        applicable_qualifiers: FrozenSet[Qualifier],
    ):
        # TODO explicitly check consistency / contradictory qualifiers
        # (for now we just use conservative defaults)
        is_qualified: bool
        if (
            Qualifier.NOT_QUALIFIED in applicable_qualifiers
            or Qualifier.LEGAL_PERSON in applicable_qualifiers
        ):
            is_qualified = False
        elif Qualifier.QC_STATEMENT in applicable_qualifiers:
            is_qualified = True
        else:
            is_qualified = prelim_status.qualified

        qc_type: QcCertType
        if Qualifier.FOR_WSA in applicable_qualifiers:
            qc_type = QcCertType.QC_WEB
        elif Qualifier.FOR_ESIG in applicable_qualifiers:
            qc_type = QcCertType.QC_ESIGN
        elif Qualifier.FOR_ESEAL in applicable_qualifiers:
            qc_type = QcCertType.QC_ESEAL
        else:
            qc_type = prelim_status.qc_type

        key_mgmt: QcPrivateKeyManagementType
        if not is_qualified:
            key_mgmt = QcPrivateKeyManagementType.UNKNOWN
        elif (
            Qualifier.NO_SSCD in applicable_qualifiers
            or Qualifier.NO_QSCD in applicable_qualifiers
        ):
            key_mgmt = QcPrivateKeyManagementType.UNKNOWN
        elif Qualifier.QSCD_MANAGED_ON_BEHALF in applicable_qualifiers:
            key_mgmt = QcPrivateKeyManagementType.QCSD_DELEGATED
        elif (
            Qualifier.WITH_SSCD in applicable_qualifiers
            or Qualifier.WITH_QSCD in applicable_qualifiers
        ):
            key_mgmt = QcPrivateKeyManagementType.QCSD
        else:
            key_mgmt = prelim_status.qc_key_security
        return QualifiedStatus(
            qualified=is_qualified,
            qc_type=qc_type,
            qc_key_security=key_mgmt,
        )

    def check_entity_cert_qualified(
        self, path: ValidationPath, moment: Optional[datetime] = None
    ) -> QualifiedStatus:
        cert = path.leaf
        if not isinstance(cert, x509.Certificate):
            raise NotImplementedError(
                "Only public-key certs are in scope for qualification"
            )
        prelim_status = QualificationAssessor._process_qc_statements(cert)
        path_policies = path.qualified_policies()
        reference_time = moment or datetime.now(tz=zoneinfo.ZoneInfo('CET'))
        if reference_time < EIDAS_START_DATE and path_policies:
            # check QCP / QCP+ policy
            policy_oids = {q.user_domain_policy_id for q in path_policies}
            if PRE_EIDAS_QCP_PLUS_POLICY in policy_oids:
                prelim_status = replace(
                    prelim_status,
                    qualified=True,
                    qc_key_security=(
                        QcPrivateKeyManagementType.QCSD_BY_POLICY
                        if not prelim_status.qc_key_security.is_qcsd
                        else prelim_status.qc_key_security
                    ),
                )
            elif PRE_EIDAS_QCP_POLICY in policy_oids:
                prelim_status = replace(prelim_status, qualified=True)

        statuses_found: List[Tuple[CAServiceInformation, QualifiedStatus]] = []
        for sd in self._registry.applicable_tsps_on_path(path):
            # For this subtlety, see the hanging para in the beginning of
            # section 4 in the CEF eSignature DSS validation algorithm doc
            putative_status = QualificationAssessor._apply_sd_qualifications(
                cert, prelim_status, sd
            )
            if QualificationAssessor._check_cd_applicable(sd, putative_status):
                statuses_found.append((sd, putative_status))

        uniq_statuses = set(st for _, st in statuses_found)
        if len(statuses_found) == 1:
            # happy path
            return statuses_found[0][1]
        elif len(uniq_statuses) == 1:
            # TODO gather these warnings somewhere so they can be added
            #  to the validation report
            service_info = ', '.join(
                sd.base_info.service_name for sd, _ in statuses_found
            )
            logger.warning(
                f"Qualification algorithm for {cert.subject.human_friendly} "
                f"reached a consistent conclusion, but through several "
                f"different service definitions: {service_info}"
            )
            return statuses_found[0][1]
        elif not uniq_statuses:
            return UNQUALIFIED
        else:
            service_info = ', '.join(
                sd.base_info.service_name for sd, _ in statuses_found
            )
            logger.warning(
                f"Qualification algorithm for {cert.subject.human_friendly} "
                f"reached contradictory conclusions: {uniq_statuses}. "
                f"Several service definitions were found applicable: "
                f"{service_info}. This certificate will not be considered "
                f"qualified."
            )
            return UNQUALIFIED
