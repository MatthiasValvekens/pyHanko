import asyncio
import getpass
from datetime import datetime

import click
import tzlocal
from asn1crypto import pem

from pyhanko.cli.runtime import pyhanko_exception_manager
from pyhanko.cli.utils import logger
from pyhanko.pdf_utils import crypt
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers
from pyhanko.sign.signers.pdf_cms import PdfCMSSignedAttributes
from pyhanko.sign.timestamps import HTTPTimeStamper


def generic_sign_pdf(
    *,
    writer,
    outfile,
    signature_meta,
    signer,
    timestamper,
    style,
    new_field_spec,
    existing_fields_only,
    text_params,
):
    result = signers.PdfSigner(
        signature_meta,
        signer=signer,
        timestamper=timestamper,
        stamp_style=style,
        new_field_spec=new_field_spec,
    ).sign_pdf(
        writer,
        existing_fields_only=existing_fields_only,
        appearance_text_params=text_params,
    )

    buf = result.getbuffer()
    outfile.write(buf)
    buf.release()

    writer.prev.stream.close()
    outfile.close()


def _open_for_signing(infile_path, lenient, signer_cert=None, signer_key=None):
    infile = open(infile_path, 'rb')
    writer = IncrementalPdfFileWriter(infile, strict=not lenient)

    # TODO make this an option higher up the tree
    # TODO mention filename in prompt
    if writer.prev.encrypted:
        sh = writer.prev.security_handler
        if isinstance(sh, crypt.StandardSecurityHandler):
            pdf_pass = getpass.getpass(
                prompt='Password for encrypted file \'%s\': ' % infile_path
            )
            writer.encrypt(pdf_pass)
        elif (
            isinstance(sh, crypt.PubKeySecurityHandler)
            and signer_key is not None
        ):
            # attempt to decrypt using signer's credentials
            cred = crypt.SimpleEnvelopeKeyDecrypter(signer_cert, signer_key)
            logger.warning(
                "The file \'%s\' appears to be encrypted using public-key "
                "encryption. This is only partially supported in pyHanko's "
                "CLI. PyHanko will attempt to decrypt the document using the "
                "signer's public key, but be aware that using the same key "
                "for both signing and decryption is considered bad practice. "
                "Never use the same RSA key that you use to decrypt messages to"
                "sign hashes that you didn't compute yourself!" % infile_path
            )
            writer.encrypt_pubkey(cred)
        else:
            raise click.ClickException(
                "Input file appears to be encrypted, but appropriate "
                "credentials are not available."
            )
    return writer


def detached_sig(
    signer: signers.Signer, infile_path, outfile, timestamp_url, use_pem
):
    coro = async_detached_sig(
        signer, infile_path, outfile, timestamp_url, use_pem
    )
    return asyncio.run(coro)


async def async_detached_sig(
    signer: signers.Signer, infile_path, outfile, timestamp_url, use_pem
):
    with pyhanko_exception_manager():
        if timestamp_url is not None:
            timestamper = HTTPTimeStamper(timestamp_url)
            timestamp = None
        else:
            timestamper = None
            # in this case, embed the signing time as a signed attr
            timestamp = datetime.now(tz=tzlocal.get_localzone())

        with open(infile_path, 'rb') as inf:
            signature = await signer.async_sign_general_data(
                inf,
                signers.DEFAULT_MD,
                timestamper=timestamper,
                signed_attr_settings=PdfCMSSignedAttributes(
                    signing_time=timestamp
                ),
            )

        output_bytes = signature.dump()
        if use_pem:
            output_bytes = pem.armor('PKCS7', output_bytes)

        # outfile is managed by Click
        outfile.write(output_bytes)


def get_text_params(ctx):
    text_params = None
    stamp_url = ctx.obj.stamp_url
    if stamp_url is not None:
        text_params = {'url': stamp_url}
    return text_params
