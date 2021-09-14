"""
This module hopes to make ExternalSigner more user friendly.
Hiding away and providing defaults for configuration.
Also it is made to work well together with an external service that implements
the CSC specification. (version 1.0.4)

Only first and last steps are pdf specific. The middle steps can be used to
sign a hash and return a valid CMS. This is the case for integrating with DocuSign.

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
from dataclasses import dataclass

from pyhanko.sign import signers, timestamps, pdf_signer
from pyhanko.sign.general import SimpleCertificateStore, SigningError
from pyhanko.sign.signers.pdf_signer import PdfTBSDocument
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from asn1crypto import x509


@dataclass
class TDigest:
    data_digest: bytes
    digest_algorithm: str


@dataclass
class TPreparedPdf:
    prep_digest: pdf_signer.PreparedByteRangeDigest
    post_sign_instructions: pdf_signer.PostSignInstructions
    output: BytesIO


@dataclass
class TPrepDocumentResponse:
    pdf: TPreparedPdf
    digest: TDigest


class CscSigner(signers.ExternalSigner):
    """
    See https://cloudsignatureconsortium.org/resources/download-api-specifications/
    """

    def __init__(
        self,
        csc_credentials_info_response: dict,
        tsa_url: str,
        signature_value=bytes(512),
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
            # According to CSC spec the first certificate should be the signing cert.
            # Quote: "One or more Base64-encoded X.509v3 certificates from the
            # certificate chain. If the certificates parameter is “chain”, the
            # entire certificate chain SHALL be returned with the end entity 
            # certificate at the beginning of the array."
            signing_cert=certs[0],
            cert_registry=cert_registry,
            signature_mechanism=None,
            signature_value=signature_value,
        )

    def prep_document(self, pdf: bytes, signature_meta: signers.PdfSignatureMetadata):
        """
        This method is pdf specific.
        It returns a pdf document that is ready to have a CMS attached.
        Also it computes the pdf specific hash of the prepared document.
        """
        pdf_signer = signers.PdfSigner(
            signature_meta,
            signer=self,
            timestamper=self.timestamper,
        )
        input_buf = BytesIO(pdf)
        pdf_out = IncrementalPdfFileWriter(input_buf)
        prep_digest, tbs_document, output = pdf_signer.digest_doc_for_signing(pdf_out)

        return TPrepDocumentResponse(
            digest=TDigest(
                data_digest=prep_digest.document_digest,
                digest_algorithm=prep_digest.md_algorithm,
            ),
            pdf=TPreparedPdf(
                prep_digest=prep_digest,
                post_sign_instructions=tbs_document.post_sign_instructions,
                output=output,
            ),
        )

    def signed_attrs(self, digest: TDigest, **kwargs):
        """
        Get payload to be signed. This method is not merged with "prep_document" to:
        - allow hash signing without having the document;
        - be pdf agnostic.
        """
        return super().signed_attrs(digest.data_digest, digest.digest_algorithm, **kwargs)

    def generate_cms(self, digest: TDigest, sig_value: bytes = None):
        """
        Generate cms from signed payload. The sig_value should be the PKCS1
        signature returned by CSC signatures/signHash endpoint. (The CSC spec does
        not state that signatures are PKCS1 but the example response suggests that it is.)
        """
        if sig_value:
            self._signature_value = sig_value
        signed_attrs = self.signed_attrs(digest)
        sig_cms = self.sign_prescribed_attributes(
            digest.digest_algorithm,
            signed_attrs=signed_attrs,
            timestamper=self.timestamper,
        )
        return sig_cms

    @staticmethod
    def finish_signing(pdf: TPreparedPdf, sig_cms: bytes) -> BytesIO:
        """
        Attaches given signature to given prepared pdf.
        See prep_document method of CscSigner to understand what is expected input.
        """
        PdfTBSDocument.finish_signing(
            pdf.output,
            prepared_digest=pdf.prep_digest,
            signature_cms=sig_cms,
            post_sign_instr=pdf.post_sign_instructions,
            validation_context=None,
        )
        return pdf.output
