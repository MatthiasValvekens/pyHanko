Advanced examples
=================

.. |Signer| replace:: :class:`~.pyhanko.sign.signers.pdf_cms.Signer`


.. _async-aws-kms:

A custom |Signer| to use AWS KMS asynchronously
-----------------------------------------------

.. versionadded:: 0.9.0

This example demonstrates how to use ``aioboto3`` to set up a custom |Signer|
implementation that invokes the `AWS KMS <https://aws.amazon.com/kms/>`_
API to sign documents, and does so in an asynchronous manner.

The example implementation is relatively minimal, but it should be sufficient
to get an idea of what's possible.
Further information on ``aioboto3`` is available
`from the project's GitHub page <https://github.com/terrycain/aioboto3>`_.

The ideas in this snippet can be combined with other async-native components
to set up an asynchronous signing workflow.
For example, if you're looking for a way to fetch & embed revocation information
asynchronously, have a look at
:ref:`this section in the signing docs <async-resource-management>` to learn more
about ``aiohttp`` usage and resource management.


.. code-block:: python

    import asyncio

    import aioboto3

    from asn1crypto import x509, algos
    from cryptography.hazmat.primitives import hashes

    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import Signer, signers
    from pyhanko.sign.general import (
        get_pyca_cryptography_hash,
        load_cert_from_pemder,
    )
    from pyhanko_certvalidator.registry import SimpleCertificateStore


    class AsyncKMSSigner(Signer):
        def __init__(
            self,
            session: aioboto3.session,
            key_id: str,
            signing_cert: x509.Certificate,
            signature_mechanism: algos.SignedDigestAlgorithm,
            # this can be derived from the above, obviously
            signature_mechanism_aws_id: str,
            other_certs=(),
        ):
            self.session = session
            self.key_id = key_id
            self.signature_mechanism = signature_mechanism
            self.signature_mechanism_aws_id = signature_mechanism_aws_id
            cr = SimpleCertificateStore()
            cr.register_multiple(other_certs)
            super().__init__(
                signing_cert=signing_cert,
                cert_registry=cr,
            )

        async def async_sign_raw(
            self, data: bytes, digest_algorithm: str, dry_run=False
        ) -> bytes:
            if dry_run:
                return bytes(256)

            # Send hash to server instead of raw data
            hash_spec = get_pyca_cryptography_hash(
                self.signature_mechanism.hash_algo
            )
            md = hashes.Hash(hash_spec)
            md.update(data)

            async with self.session.client('kms') as kms_client:
                result = await kms_client.sign(
                    KeyId=self.key_id,
                    Message=md.finalize(),
                    MessageType='DIGEST',
                    SigningAlgorithm=self.signature_mechanism_aws_id,
                )
                signature = result['Signature']
                assert isinstance(signature, bytes)
                return signature


    async def run():
        # Load relevant certificates
        # Note: the AWS KMS does not provide certificates by itself,
        # so the details of how certificates are provisioned are beyond
        # the scope of this example.
        cert = load_cert_from_pemder('path/to/your/signing-cert.pem')
        chain = list(load_certs_from_pemder('path/to/chain.pem'))

        # AWS credentials
        kms_key_id = "KEY_ID_GOES_HERE"

        # Set up aioboto3 session with ambient credentials & region
        session = aioboto3.Session()

        # Set up our signer
        signer = AsyncKMSSigner(
            session=session,
            key_id=kms_key_id,
            signing_cert=cert,
            other_certs=chain,
            # change the signature mechanism according to your key type
            # I'm using an ECDSA key over the NIST-P384 (secp384r1) curve here.
            signature_mechanism=algos.SignedDigestAlgorithm(
                {'algorithm': 'sha384_ecdsa'}
            ),
            signature_mechanism_aws_id='ECDSA_SHA_384',
        )

        with open('input.pdf', 'rb') as inf:
            w = IncrementalPdfFileWriter(inf)
            meta = signers.PdfSignatureMetadata(field_name='AWSKMSExampleSig')
            with open('output.pdf', 'wb') as outf:
                await signers.async_sign_pdf(w, meta, signer=signer, output=outf)


    if __name__ == '__main__':
        loop = asyncio.get_event_loop()
        loop.run_until_complete(run())


.. _gcp-kms-p11:

Using Google Cloud KMS via PKCS#11
----------------------------------

.. versionadded:: 0.26.0

This example demonstrates producing a signature with Google Cloud KMS
using Google's `PKCS#11 library <https://cloud.google.com/kms/docs/reference/pkcs11-library>`_
for Cloud KMS (``libkmsp11.so``).

The advantage of this approach is that it requires virtually no
GCP-specific code; everything is handled by the PKCS#11 wrapper library.
The sample code below assumes that you configured the PKCS#11 library
to access the relevant key ring, and that the environment variable
``KMS_PKCS11_CONFIG`` points to your Cloud KMS PKCS#11 config file.
It also assumes that credentials for accessing the Cloud KMS API
are discoverable ambiently (see
`Application Default Credentials <https://cloud.google.com/docs/authentication/application-default-credentials>`_).

The name of the key in the keyring is ``my-test-key`` in the example below.


.. code-block:: python

    from asn1crypto import algos

    from pyhanko.config.pkcs11 import PKCS11SignatureConfig
    from pyhanko.keys import load_cert_from_pemder, load_certs_from_pemder
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import pkcs11, sign_pdf, PdfSignatureMetadata

    MODULE="/path/to/libkmsp11.so"


    def run_test(input_file, output_file, key_name, signer_cert_file, ca_certs_file):
        cert_obj = load_cert_from_pemder(signer_cert_file)

        config = PKCS11SignatureConfig(
            module_path=MODULE,
            slot_no=0,
            key_label=key_name,
            signing_certificate=cert_obj,
            other_certs_to_pull=None,
            other_certs = list(load_certs_from_pemder(ca_certs_file)),
        )

        with pkcs11.PKCS11SigningContext(config) as signer:
            with open(input_file, 'rb') as inf:
                w = IncrementalPdfFileWriter(inf)
                meta = PdfSignatureMetadata(field_name='Sig1')
                with open(output_file, 'wb') as outf:
                    sign_pdf(w, meta, signer, output=outf)


    run_test(
        'input.pdf',
        'output.pdf',
        'my-test-key',
        'signer.cert.pem',
        'ca-certs.cert.pem'
    )


.. warning::
    If you intend to use RSASSA-PSS with Cloud KMS keys, you will have to set
    the ``signature_mechanism`` in your ``PKCS11SignatureConfig`` to specify
    the algorithm parameters manually. The reason is that Cloud KMS doesn't
    accept pyHanko's default choice of salt length.

    For example, for RSA-2048 with SHA-256, the correct PSS parameters for Cloud KMS
    look like this:

    .. code-block:: python

            pss_params = algos.RSASSAPSSParams(
                {
                    'hash_algorithm': algos.DigestAlgorithm(
                        {'algorithm': 'sha256'}
                    ),
                    'mask_gen_algorithm': algos.MaskGenAlgorithm(
                        {
                            'algorithm': 'mgf1',
                            'parameters': algos.DigestAlgorithm(
                                {'algorithm': 'sha256'}
                            ),
                        }
                    ),
                    'salt_length': 32,
                }
            )
            signature_mechanism = algos.SignedDigestAlgorithm(
                {
                    'algorithm': 'rsassa_pss',
                    'parameters': pss_params
                }
            )

    If you choose the wrong set of parameters, the PKCS#11 library
    will throw an error.


.. _async-gcp-kms:

A custom |Signer| to use Google Cloud KMS asynchronously
--------------------------------------------------------

.. versionadded:: 0.26.0


The example below demonstrates how to use Google's GCP client library
to produce signatures using Google Cloud KMS.
While this does require some extra code, the GCP client library suite
is supported on more platforms than the PKCS#11 wrapper used in
:ref:`the preceding example <gcp-kms-p11>`, so it is somewhat more
portable.

As before, we assume that credentials for accessing the Cloud KMS API
are discoverable via
`Application Default Credentials <https://cloud.google.com/docs/authentication/application-default-credentials>`_.
Besides the ``google-cloud-kms`` package, you also need ``crcmod`` installed
to use this sample implementation.

.. code-block:: python

    @dataclass(frozen=True)
    class GCPKeyRing:
        project_id: str
        location_id: str
        key_ring_id: str


    @dataclass(frozen=True)
    class GCPKMSKey:
        key_ring: GCPKeyRing
        key_id: str
        version_id: str

        @property
        def path(self) -> str:
            return kms.KeyManagementServiceAsyncClient.crypto_key_version_path(
                self.key_ring.project_id,
                self.key_ring.location_id,
                self.key_ring.key_ring_id,
                self.key_id,
                self.version_id,
            )

    class GCPKMSSigner(Signer):

        def __init__(
            self, *, signing_cert: x509.Certificate, kms_key: GCPKMSKey, **kwargs
        ):
            self.kms_key = kms_key
            self.client = kms.KeyManagementServiceAsyncClient()
            super().__init__(signing_cert=signing_cert, **kwargs)

        async def async_sign_raw(
            self, data: bytes, digest_algorithm: str, dry_run=False
        ) -> bytes:
            if dry_run:
                return bytes(256)

            # Note: this method makes no effort to check whether the digest
            # algorithm matches the expectation of the upstream API
            md_spec = get_pyca_cryptography_hash(digest_algorithm)
            md = hashes.Hash(md_spec)
            md.update(data)
            digest = md.finalize()
            name = self.kms_key.path
            crc32c = crcmod.predefined.mkPredefinedCrcFun("crc-32c")

            request = kms.AsymmetricSignRequest(
                {
                    "name": name,
                    "digest": {digest_algorithm: digest},
                    "digest_crc32c": crc32c(digest),
                }
            )
            response = await self.client.asymmetric_sign(request=request)

            # From https://cloud.google.com/kms/docs/create-validate-signatures#kms-sign-asymmetric-python
            if (
                not response.verified_digest_crc32c
                or response.name != name
                or response.signature_crc32c != crc32c(response.signature)
            ):
                raise SigningError(
                    "The request sent to the server was corrupted in-transit."
                )

            return response.signature


    KEYRING = GCPKeyRing("my-project-id", "europe-west1", "pyhanko-test")

    def run_test(input_file, output_file, key_name, signer_cert_file, ca_certs_file):
        cert_obj = load_cert_from_pemder(signer_cert_file)

        registry = SimpleCertificateStore.from_certs(load_certs_from_pemder(ca_certs_file))
        signer = GCPKMSSigner(
            kms_key=GCPKMSKey(KEYRING, key_name, "1"),
            signing_cert=cert_obj,
            cert_registry=registry,
        )

        with open(input_file, 'rb') as inf:
            w = IncrementalPdfFileWriter(inf)
            meta = PdfSignatureMetadata(field_name='Sig1')
            with open(output_file, 'wb') as outf:
                await async_sign_pdf(w, meta, signer, output=outf)


    asyncio.run(
        run_test(
            'input.pdf',
            'output.pdf',
            'my-test-key',
            'signer.cert.pem',
            'ca-certs.cert.pem'
        )
    )


.. warning::
    The warning about RSASSA-PSS parameter choice from :ref:`the preceding example <gcp-kms-p11>`
    also applies when using the API directly. However, as the above code sample shows,
    the API doesn't allow passing through the parameter choices anywhere!
    As such, getting them wrong will result in the signing process completing without errors,
    but with a garbage signature.
