import asyncio
import getpass
from io import BytesIO
from typing import Optional

import pytest
from certomancer import PKIArchitecture
from certomancer.registry import CertLabel, KeyLabel, ServiceLabel
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.writer import BasePdfFileWriter
from pyhanko.sign import PdfSignatureMetadata, SimpleSigner, fields, sign_pdf
from pyhanko.sign.signers.pdf_cms import select_suitable_signing_md
from pyhanko.sign.timestamps import HTTPTimeStamper
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.registry import (
    SimpleCertificateStore,
    SimpleTrustManager,
)
from test_data.samples import (
    MINIMAL,
    MINIMAL_AES256,
)

from ..conftest import _const


@pytest.fixture
def signer_cert_label():
    return CertLabel('signer1')


def write_input_to_validate(
    pki_arch: PKIArchitecture,
    fname: str,
    w: Optional[BasePdfFileWriter],
    weakened: bool = False,
    wrong_key: bool = False,
    signer_cert_label: CertLabel = CertLabel('signer1'),
):
    registry = SimpleCertificateStore()
    signing_cert_spec = pki_arch.get_cert_spec(signer_cert_label)
    registry.register(
        pki_arch.get_cert(signing_cert_spec.resolve_issuer_cert(pki_arch))
    )
    registry.register(pki_arch.get_cert(CertLabel('root')))
    signer = SimpleSigner(
        signing_cert=pki_arch.get_cert(signer_cert_label),
        cert_registry=registry,
        signing_key=pki_arch.key_set.get_private_key(
            KeyLabel('signer1') if not wrong_key else KeyLabel('signer2')
        ),
    )

    if weakened:
        md = 'sha1'
    else:
        md = select_suitable_signing_md(signer.signing_cert.public_key)
    out = BytesIO()
    if w:
        sign_pdf(
            pdf_out=w,
            signature_meta=PdfSignatureMetadata(
                field_name='Sig1', md_algorithm=md
            ),
            signer=signer,
            output=out,
        )
    else:
        ci = asyncio.run(
            signer.async_sign_general_data(
                MINIMAL,
                md,
            )
        )
        out.write(ci.dump())
    with open(fname, 'wb') as outf:
        outf.write(out.getvalue())
    return fname


def write_ltv_input_to_validate(
    pki_arch: PKIArchitecture,
    signer_cert_label: CertLabel,
    tsa_label: ServiceLabel,
    fname: str = 'to-validate.pdf',
    pades_style: bool = True,
):
    registry = SimpleCertificateStore()
    signing_cert_spec = pki_arch.get_cert_spec(signer_cert_label)
    registry.register(
        pki_arch.get_cert(signing_cert_spec.resolve_issuer_cert(pki_arch))
    )
    root_cert = pki_arch.get_cert(CertLabel('root'))
    registry.register(root_cert)
    signer = SimpleSigner(
        signing_cert=pki_arch.get_cert(signer_cert_label),
        cert_registry=registry,
        signing_key=pki_arch.key_set.get_private_key(KeyLabel('signer1')),
    )
    tsa = pki_arch.service_registry.get_tsa_info(tsa_label)

    with open(fname, 'wb') as outf:
        w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
        sign_pdf(
            pdf_out=w,
            signature_meta=PdfSignatureMetadata(
                field_name='Sig1',
                validation_context=ValidationContext(
                    trust_manager=SimpleTrustManager.build(
                        trust_roots=[root_cert]
                    ),
                    allow_fetching=True,
                ),
                subfilter=fields.SigSeedSubFilter.PADES
                if pades_style
                else None,
                embed_validation_info=True,
                use_pades_lta=True,
            ),
            signer=signer,
            timestamper=HTTPTimeStamper(url=tsa.url),
            output=outf,
        )
    return fname


@pytest.fixture(params=["regular", "encrypted"])
def input_to_validate(
    pki_arch: PKIArchitecture, monkeypatch, request, signer_cert_label
):
    if request.param == "encrypted":
        w = IncrementalPdfFileWriter(BytesIO(MINIMAL_AES256))
        monkeypatch.setattr(getpass, 'getpass', value=_const('ownersecret'))
        w.encrypt(b"ownersecret")
    else:
        w = IncrementalPdfFileWriter(BytesIO(MINIMAL))

    return write_input_to_validate(
        pki_arch, 'to-validate.pdf', w, signer_cert_label=signer_cert_label
    )


@pytest.fixture(scope="function")
def ltv_input_to_validate(pki_arch: PKIArchitecture, signer_cert_label):
    return write_ltv_input_to_validate(
        pki_arch,
        signer_cert_label=signer_cert_label,
        tsa_label=ServiceLabel('tsa'),
    )
