import pytest
from asn1crypto.x509 import ExtKeyUsageSyntax, KeyUsage
from pyhanko.sign.validation.settings import KeyUsageConstraints

from pyhanko_certvalidator.errors import InvalidCertificateError


@pytest.mark.parametrize(
    'cfg, cert_ku',
    [
        (
            KeyUsageConstraints(key_usage={'non_repudiation'}),
            KeyUsage({'non_repudiation'}),
        ),
        (
            KeyUsageConstraints(
                key_usage={'non_repudiation', 'digital_signature'}
            ),
            KeyUsage({'non_repudiation'}),
        ),
        (
            KeyUsageConstraints(key_usage={'non_repudiation'}),
            KeyUsage({'non_repudiation', 'digital_signature'}),
        ),
        (
            KeyUsageConstraints(
                key_usage={'non_repudiation'}, match_all_key_usages=True
            ),
            KeyUsage({'non_repudiation', 'digital_signature'}),
        ),
        (KeyUsageConstraints(key_usage=set()), KeyUsage({'non_repudiation'})),
        (KeyUsageConstraints(), KeyUsage({'non_repudiation'})),
        (KeyUsageConstraints(), None),
    ],
)
def test_ku_accept(cfg: KeyUsageConstraints, cert_ku):
    cfg._validate_key_usage(cert_ku)


@pytest.mark.parametrize(
    'cfg, cert_ku',
    [
        (
            KeyUsageConstraints(key_usage={'non_repudiation'}),
            KeyUsage({'digital_signature'}),
        ),
        (
            KeyUsageConstraints(
                key_usage={'non_repudiation', 'digital_signature'},
                match_all_key_usages=True,
            ),
            KeyUsage({'digital_signature'}),
        ),
        (
            KeyUsageConstraints(
                key_usage={'non_repudiation', 'digital_signature'},
                key_usage_forbidden={'key_agreement'},
            ),
            KeyUsage({'digital_signature', 'key_agreement'}),
        ),
    ],
)
def test_ku_reject(cfg: KeyUsageConstraints, cert_ku):
    with pytest.raises(InvalidCertificateError):
        cfg._validate_key_usage(cert_ku)


@pytest.mark.parametrize(
    'cfg, cert_eku',
    [
        (
            KeyUsageConstraints(extd_key_usage={'time_stamping'}),
            ExtKeyUsageSyntax(['time_stamping']),
        ),
        (
            KeyUsageConstraints(extd_key_usage={'time_stamping'}),
            ExtKeyUsageSyntax(
                ['time_stamping', 'microsoft_time_stamp_signing']
            ),
        ),
        (
            KeyUsageConstraints(
                extd_key_usage={'time_stamping', 'microsoft_time_stamp_signing'}
            ),
            ExtKeyUsageSyntax(['time_stamping']),
        ),
        (
            KeyUsageConstraints(
                extd_key_usage={'microsoft_document_signing'},
                explicit_extd_key_usage_required=False,
            ),
            None,
        ),
        (
            # this is a common case IRL
            KeyUsageConstraints(),
            ExtKeyUsageSyntax(['client_auth']),
        ),
        (
            KeyUsageConstraints(
                extd_key_usage={'microsoft_document_signing'},
                explicit_extd_key_usage_required=False,
            ),
            # ... and this is what the CAs mis-issuing non-repudiation + auth
            # presumably intended to put out.
            ExtKeyUsageSyntax(['client_auth', 'any_extended_key_usage']),
        ),
        (
            KeyUsageConstraints(
                extd_key_usage={'microsoft_document_signing'},
                explicit_extd_key_usage_required=False,
            ),
            ExtKeyUsageSyntax(['any_extended_key_usage']),
        ),
    ],
)
def test_eku_accept(cfg: KeyUsageConstraints, cert_eku):
    cfg._validate_extd_key_usage(cert_eku)


@pytest.mark.parametrize(
    'cfg, cert_eku, err',
    [
        (
            KeyUsageConstraints(extd_key_usage={'time_stamping'}),
            None,
            "requires an extended key usage extension",
        ),
        (
            KeyUsageConstraints(extd_key_usage={'microsoft_document_signing'}),
            ExtKeyUsageSyntax(['client_auth']),
            "Relevant key purposes are microsoft document signing",
        ),
        (
            KeyUsageConstraints(
                extd_key_usage={'microsoft_document_signing'},
                explicit_extd_key_usage_required=False,
            ),
            ExtKeyUsageSyntax(['client_auth']),
            "Relevant key purposes are microsoft document signing",
        ),
        (
            KeyUsageConstraints(extd_key_usage={'microsoft_document_signing'}),
            ExtKeyUsageSyntax(['client_auth', 'any_extended_key_usage']),
            "Relevant key purposes are microsoft document signing",
        ),
        (
            KeyUsageConstraints(extd_key_usage=set()),
            ExtKeyUsageSyntax(['client_auth']),
            "There are no acceptable extended key usages",
        ),
    ],
)
def test_eku_reject(cfg: KeyUsageConstraints, cert_eku, err):
    with pytest.raises(InvalidCertificateError, match=err):
        cfg._validate_extd_key_usage(cert_eku)
