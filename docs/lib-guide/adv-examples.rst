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
    from pyhanko.sign.general import get_pyca_cryptography_hash, \
        load_cert_from_pemder
    from pyhanko_certvalidator.registry import SimpleCertificateStore


    class AsyncKMSSigner(Signer):

        def __init__(self, session: aioboto3.session, key_id: str,
                     signing_cert: x509.Certificate,
                     signature_mechanism: algos.SignedDigestAlgorithm,
                     # this can be derived from the above, obviously
                     signature_mechanism_aws_id: str,
                     other_certs=()):
            self.session = session
            self.signing_cert = signing_cert
            self.key_id = key_id
            self.signature_mechanism = signature_mechanism
            self.signature_mechanism_aws_id = signature_mechanism_aws_id
            self.cert_registry = cr = SimpleCertificateStore()
            cr.register_multiple(other_certs)
            super().__init__()

        async def async_sign_raw(self, data: bytes,
                                 digest_algorithm: str, dry_run=False) -> bytes:
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
                    SigningAlgorithm=self.signature_mechanism_aws_id
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
        aws_access_key_id = "ACCESS_KEY_GOES_HERE"
        aws_secret_access_key = "SECRET_GOES_HERE"

        # Set up aioboto3 session with provided credentials & region
        session = aioboto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            # substitute your region here
            region_name='eu-central-1'
        )

        # Set up our signer
        signer = AsyncKMSSigner(
            session=session, key_id=kms_key_id,
            signing_cert=cert, other_certs=chain,
            # change the signature mechanism according to your key type
            # I'm using an ECDSA key over the NIST-P384 (secp384r1) curve here.
            signature_mechanism=algos.SignedDigestAlgorithm(
                {'algorithm': 'sha384_ecdsa'}
            ),
            signature_mechanism_aws_id='ECDSA_SHA_384'
        )

        with open('input.pdf', 'rb') as inf:
            w = IncrementalPdfFileWriter(inf)
            meta = signers.PdfSignatureMetadata(
                field_name='AWSKMSExampleSig'
            )
            with open('output.pdf', 'wb') as outf:
                await signers.async_sign_pdf(
                    w, meta, signer=signer,output=outf
                )


    if __name__ == '__main__':
        loop = asyncio.get_event_loop()
        loop.run_until_complete(run())
