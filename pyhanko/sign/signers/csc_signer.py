"""
This module has parts of the flow to put a signature on a pdf.
Only first and last step are pdf specific. The middle steps can be used to
sign a hash and return a valid CMS. This is the use case for Docusign.

The 2 points marked with ! are CSC calls and are considered external to this module.

- prepare_document(pdf) => digest
! get_certificates_from_CSC_server() => cert_chain
- build_attributes_to_be_signed(digest, cert_chain) => cms_attributes
! sign_with_CSC_server(cms_attributes) => signature_pkcs1
- generate_cms(digest, cert_chain, signature_pkcs1) => signed_cms_attributes
- attach_signed_CMS_to_document(pdf, signed_cms_attributes) => signed_pdf
"""
from base64 import b64decode
from io import BytesIO
from typing import Any, TypedDict

from pyhanko.sign import signers, timestamps, fields
from pyhanko.sign.general import SimpleCertificateStore
from pyhanko.sign.signers.pdf_signer import PdfTBSDocument
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko_certvalidator import ValidationContext
from asn1crypto import x509


SigSeedSubFilter = fields.SigSeedSubFilter


def as_any(_) -> Any:
    return _


class TDigest(TypedDict):
    data_digest: bytes
    digest_algorithm: str


class TPrepDocumentConfig(TypedDict, total=False):
    embed_validation_info: bool
    subfilter: SigSeedSubFilter
    validation_context: ValidationContext
    md_algorithm: str


class CscSigner(signers.ExternalSigner):
    """
    See https://cloudsignatureconsortium.org/resources/download-api-specifications/

    note: this signer will not perform any cryptographic operations,
    it's just there to handle certificates and provide size estimates
    The signature placeholder value, appropriate for a 2048-bit RSA key
    (for example's sake)
    """

    def __init__(
        self,
        csc_credentials_info_response: dict,
        tsa_url: str,
        signature_value=bytes(32),
        use_pades=False,
    ):
        """
        csc_credentials_info_response:
            List returned by CSC credentials/info endpoint with "certificates"
            request parameter set to "chain". See section 11.5 of the CSC spec.
        """
        self.use_pades = use_pades
        self.timestamper = timestamps.HTTPTimeStamper(tsa_url)
        certs_encoded = csc_credentials_info_response['cert/certificates']
        certs = [x509.Certificate.load(b64decode(cert)) for cert in certs_encoded]
        cert_registry = SimpleCertificateStore()
        cert_registry.register_multiple(set(certs))
        super().__init__(
            signing_cert=certs[0],
            cert_registry=cert_registry,
            signature_mechanism=None,
            signature_value=signature_value,
        )

    def prep_document(self, pdf: bytes, config: TPrepDocumentConfig):
        """
        This method is pdf specific.
        It returns a pdf document that is ready to have a CMS attached.
        Also it computes the pdf specific hash of the prepared document.
        """
        pdf_signer = signers.PdfSigner(
            signers.PdfSignatureMetadata(
                field_name='SigNew',
                embed_validation_info=config.get("embed_validation_info", False),
                use_pades_lta=self.use_pades,
                subfilter=config.get("subfilter", SigSeedSubFilter.ADOBE_PKCS7_DETACHED),
                validation_context=config.get("validation_context", as_any(None)),
                md_algorithm=config.get('md_algorithm', 'sha256'),
            ),
            signer=self,
            timestamper=self.timestamper,
        )
        input_buf = BytesIO(pdf)
        pdf_out = IncrementalPdfFileWriter(input_buf)
        prep_digest, tbs_document, output = pdf_signer.digest_doc_for_signing(pdf_out)

        return {
            "digest": {
                "data_digest": prep_digest.document_digest,
                "digest_algorithm": prep_digest.md_algorithm,
            },
            "pdf": {
                "prep_digest": prep_digest,
                "post_sign_instructions": tbs_document.post_sign_instructions,
                "output": output,
            },
        }

    def generate_signed_attrs(self, digest: TDigest):
        """
        Get payload to be signed. This method is not merged with "prep_document" to:
        - allow hash signing without having the document;
        - be pdf agnostic.
        """
        return self.signed_attrs(
            digest["data_digest"], digest['digest_algorithm'], use_pades=self.use_pades
        )

    def generate_cms(self, digest: TDigest, sig_value: bytes = None):
        """
        Generate cms from signed payload. The sig_value should be the PKCS1
        signature returned by CSC signatures/signHash endpoint. The CSC spec does
        not state that signatures are PKCS1 but the example response suggests that it is.
        """
        if sig_value:
            self._signature_value = sig_value
        if not any(self._signature_value):  # all bytes are zeroes
            raise Exception("Fake signature value is used.")
        signed_attrs = self.generate_signed_attrs(digest)
        sig_cms = self.sign_prescribed_attributes(
            digest["digest_algorithm"],
            signed_attrs=signed_attrs,
            timestamper=self.timestamper,
        )
        return sig_cms


def finish_signing(pdf: dict, sig_cms: bytes):
    """
    Attaches given signature to given prepared pdf.
    See prep_document method of CscSigner to understand what is expected input.
    """
    PdfTBSDocument.finish_signing(
        pdf["output"],
        prepared_digest=pdf["prep_digest"],
        signature_cms=sig_cms,
        post_sign_instr=pdf["post_sign_instructions"],
        validation_context=None,
    )
    return pdf["output"]
