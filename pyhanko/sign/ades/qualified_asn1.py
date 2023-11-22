from asn1crypto import core

from pyhanko.sign.ades.asn1_util import register_x509_extension

__all__ = [
    'QcStatements',
    'QcStatementId',
    'QcStatement',
    'MonetaryValue',
    'Iso4217CurrencyCode',
    'PKIDisclosureStatement',
    'PKIDisclosureStatements',
    'QcCertificateTypeId',
    'QcCertificateType',
    'QcCCLegislationCountryCodes',
]


# Technically, the qcStatements types aren't AdES-specific,
# but given their status within eIDAS, there's a large overlap in usage.


class QcStatementId(core.ObjectIdentifier):
    _map = {
        # ETSI EN 319 412-5
        '0.4.0.1862.1.1': 'qc_compliance',
        '0.4.0.1862.1.2': 'qc_limit_value',
        '0.4.0.1862.1.3': 'qc_retention_period',
        '0.4.0.1862.1.4': 'qc_sscd',
        '0.4.0.1862.1.5': 'qc_pki_disclosure_statements',
        '0.4.0.1862.1.6': 'qc_type',
        '0.4.0.1862.1.7': 'qc_cc_legislation',
    }


class Iso4217CurrencyCode(core.Choice):
    _alternatives = [
        ('alphabetic', core.PrintableString),
        ('numeric', core.Integer),
    ]


class MonetaryValue(core.Sequence):
    _fields = [
        ('currency', Iso4217CurrencyCode),
        ('amount', core.Integer),
        ('exponent', core.Integer),
    ]


class PKIDisclosureStatement(core.Sequence):
    _fields = [('url', core.IA5String), ('language', core.PrintableString)]


class PKIDisclosureStatements(core.SequenceOf):
    _child_spec = PKIDisclosureStatement


class QcCertificateTypeId(core.ObjectIdentifier):
    _map = {
        '0.4.0.1862.1.6.1': 'qct_esign',
        '0.4.0.1862.1.6.2': 'qct_eseal',
        '0.4.0.1862.1.6.3': 'qct_web',
    }


class QcCertificateType(core.SequenceOf):
    _child_spec = QcCertificateTypeId


class QcCCLegislationCountryCodes(core.SequenceOf):
    _child_spec = core.PrintableString


class QcStatement(core.Sequence):
    _fields = [
        ('statement_id', QcStatementId),
        ('statement_info', core.Any, {'optional': True}),
    ]
    _oid_pair = ('statement_id', 'statement_info')
    _oid_specs = {
        'qc_compliance': core.Void,
        'qc_limit_value': MonetaryValue,
        'qc_retention_period': core.Integer,
        'qc_sscd': core.Void,
        'qc_pki_disclosure_statements': PKIDisclosureStatements,
        'qc_type': QcCertificateType,
        'qc_cc_legislation': QcCCLegislationCountryCodes,
    }


class QcStatements(core.SequenceOf):
    _child_spec = QcStatement


register_x509_extension('1.3.6.1.5.5.7.1.3', 'qc_statements', QcStatements)
