import sys
from contextlib import contextmanager
from enum import Enum, auto

import click
import logging
import getpass

from certvalidator import ValidationContext
from pyhanko.config import (
    init_validation_context_kwargs, parse_cli_config,
    CLIConfig, LogConfig, StdLogOutput, parse_logging_config
)
from pyhanko.pdf_utils import misc
from pyhanko.pdf_utils.config_utils import ConfigurationError
from pyhanko.pdf_utils.crypt import (
    SimpleEnvelopeKeyDecrypter,
    PubKeySecurityHandler, AuthResult,
)

from pyhanko.sign import signers
from pyhanko.sign.general import SigningError
from pyhanko.sign.timestamps import HTTPTimeStamper
from pyhanko.sign import validation, beid, fields
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import copy_into_new_writer
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.validation import (
    SignatureValidationError, RevocationInfoValidationType
)
from pyhanko.stamp import QRStampStyle, text_stamp_file, qr_stamp_file
from pyhanko import __version__

__all__ = ['cli']


logger = logging.getLogger(__name__)


def logging_setup(log_configs):
    log_config: LogConfig
    for module, log_config in log_configs.items():
        cur_logger = logging.getLogger(module)
        cur_logger.setLevel(log_config.level)
        if isinstance(log_config.output, StdLogOutput):
            if StdLogOutput == StdLogOutput.STDOUT:
                handler = logging.StreamHandler(sys.stdout)
            else:
                handler = logging.StreamHandler()
        else:
            handler = logging.FileHandler(log_config.output)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        cur_logger.addHandler(handler)


@contextmanager
def pyhanko_exception_manager():
    msg = exception = None
    try:
        yield
    except click.ClickException:
        raise
    except misc.PdfReadError as e:
        exception = e
        msg = "Failed to read PDF file."
    except misc.PdfWriteError as e:
        exception = e
        msg = "Failed to write PDF file."
    except SigningError as e:
        exception = e
        msg = "Error raised while producing signed file."
    except Exception as e:
        exception = e
        msg = "Generic processing error."

    if exception is not None:
        logger.error(msg, exc_info=exception)
        raise click.ClickException(msg)


DEFAULT_CONFIG_FILE = 'pyhanko.yml'


class Ctx(Enum):
    SIG_META = auto()
    EXISTING_ONLY = auto()
    TIMESTAMP_URL = auto()
    CLI_CONFIG = auto()
    STAMP_STYLE = auto()
    STAMP_URL = auto()
    NEW_FIELD_SPEC = auto()
    PREFER_PSS = auto()


@click.group()
@click.version_option(prog_name='pyHanko', version=__version__)
@click.option('--config',
              help=(
                  'YAML file to load configuration from'
                  f'[default: {DEFAULT_CONFIG_FILE}]'
              ), required=False, type=click.File('r'))
@click.option('--verbose', help='Run in verbose mode', required=False,
              default=False, type=bool, is_flag=True)
@click.pass_context
def cli(ctx, config, verbose):
    config_text = None
    if config is None:
        try:
            with open(DEFAULT_CONFIG_FILE, 'r') as f:
                config_text = f.read()
            config = DEFAULT_CONFIG_FILE
        except FileNotFoundError:
            pass
        except IOError as e:
            raise click.ClickException(
                f"Failed to read {DEFAULT_CONFIG_FILE}: {str(e)}"
            )
    else:
        try:
            config_text = config.read()
        except IOError as e:
            raise click.ClickException(
                f"Failed to read configuration: {str(e)}",
            )

    ctx.ensure_object(dict)
    if config_text is not None:
        ctx.obj[Ctx.CLI_CONFIG] = cfg = parse_cli_config(config_text)
        log_config = cfg.log_config
    else:
        # grab the default
        log_config = parse_logging_config({})

    if verbose:
        # override the root logger's logging level, but preserve the output
        root_logger_config = log_config[None]
        log_config[None] = LogConfig(
            level=logging.DEBUG, output=root_logger_config.output
        )
    elif 'fontTools.subset' not in log_config:
        # the fontTools subsetter has a very noisy INFO log, so
        # set that one to WARNING by default
        log_config['fontTools.subset'] = LogConfig(
            level=logging.WARNING,
            # use the root logger's output settings to populate the default
            output=log_config[None].output
        )

    logging_setup(log_config)

    if verbose:
        logging.debug("Running with --verbose")
    if config_text is not None:
        logging.debug(f'Finished reading configuration from {config}.')
    else:
        logging.debug('There was no configuration to parse.')


@cli.group(help='sign PDF files', name='sign')
def signing():
    pass


readable_file = click.Path(exists=True, readable=True, dir_okay=False)


def _build_vc_kwargs(ctx, validation_context, trust,
                     trust_replace, other_certs, allow_fetching=None):
    cli_config: CLIConfig = ctx.obj.get(Ctx.CLI_CONFIG, None)
    try:
        if validation_context is not None:
            # load the desired context from config
            if cli_config is None:
                raise click.ClickException("No config file specified.")
            try:
                result = cli_config.get_validation_context(
                    validation_context, as_dict=True
                )
            except ConfigurationError as e:
                msg = (
                    "Configuration problem. Are you sure that the validation "
                    f"context '{validation_context}' is properly defined in the"
                    " configuration file?"
                )
                logger.error(msg, exc_info=e)
                raise click.ClickException(msg)
        elif trust or other_certs:
            # load a validation profile using command line kwargs
            result = init_validation_context_kwargs(
                trust, trust_replace, other_certs
            )
        elif cli_config is not None:
            # load the default settings from the CLI config
            try:
                result = cli_config.get_validation_context(as_dict=True)
            except ConfigurationError as e:
                msg = (
                    "Failed to load default validation context."
                )
                logger.error(msg, exc_info=e)
                raise click.ClickException(msg)
        else:
            result = {}

        if allow_fetching is not None:
            result['allow_fetching'] = allow_fetching

        return result
    except click.ClickException:
        raise
    except IOError as e:
        msg = "I/O problem while reading validation config"
        logger.error(msg, exc_info=e)
        raise click.ClickException(msg)
    except Exception as e:
        msg = "Generic processing problem while reading validation config"
        logger.error(msg, exc_info=e)
        raise click.ClickException(msg)


def trust_options(f):
    f = click.option(
        '--validation-context', help='use validation context from config',
        required=False, type=str
    )(f)
    f = click.option(
        '--trust', help='list trust roots (multiple allowed)',
        required=False, multiple=True, type=readable_file
    )(f)
    f = click.option(
        '--trust-replace',
        help='listed trust roots supersede OS-provided trust store',
        required=False, type=bool, is_flag=True, default=False,
        show_default=True
    )(f)
    f = click.option(
        '--other-certs', help='other certs relevant for validation',
        required=False, multiple=True, type=readable_file
    )(f)
    return f


def _select_style(ctx, style_name, url):
    try:
        cli_config: CLIConfig = ctx.obj[Ctx.CLI_CONFIG]
    except KeyError:
        if not style_name:
            return None
        raise click.ClickException(
            "Using stamp styles requires a configuration file "
            f"({DEFAULT_CONFIG_FILE} by default)."
        )
    try:
        style = cli_config.get_stamp_style(style_name)
    except ConfigurationError as e:
        msg = (
            "Configuration problem. Are you sure that the style "
            f"'{style_name}' is properly defined in the configuration file?"
        )
        logger.error(msg, exc_info=e)
        raise click.ClickException(msg)
    if url and not isinstance(style, QRStampStyle):
        raise click.ClickException(
            "The --stamp-url parameter is only meaningful for QR stamp styles."
        )
    elif not url and isinstance(style, QRStampStyle):
        raise click.ClickException(
            "QR stamp styles require the --stamp-url option."
        )

    return style


def _signature_status(ltv_profile, ltv_obsessive,
                      pretty_print, vc_kwargs,
                      executive_summary, embedded_sig):
    try:
        if ltv_profile is None:
            vc = ValidationContext(**vc_kwargs)
            status = validation.validate_pdf_signature(
                embedded_sig,
                signer_validation_context=vc
            )
        else:
            status = validation.validate_pdf_ltv_signature(
                embedded_sig, ltv_profile,
                force_revinfo=ltv_obsessive,
                validation_context_kwargs=vc_kwargs
            )
        if executive_summary and not pretty_print:
            return 'VALID' if status.bottom_line else 'INVALID'
        elif pretty_print:
            return status.pretty_print_details()
        else:
            return status.summary()
    except validation.ValidationInfoReadingError as e:
        msg = (
            'An error occurred while parsing the revocation information '
            'for this signature: ' + str(e)
        )
        logger.error(msg, exc_info=e)
        if pretty_print:
            return msg
        else:
            return 'REVINFO_FAILURE'
    except SignatureValidationError as e:
        msg = 'An error occurred while validating this signature: ' + str(e)
        logger.error(msg, exc_info=e)
        if pretty_print:
            return msg
        else:
            return 'INVALID'
    except Exception as e:
        msg = 'Generic processing error: ' + str(e)
        logger.error(msg, exc_info=e)
        if pretty_print:
            return msg
        else:
            return 'MALFORMED'


# TODO add an option to do LTV, but guess the profile
@signing.command(name='validate', help='validate signatures')
@click.argument('infile', type=click.File('rb'))
@click.option('--executive-summary',
              help='only print final judgment on signature validity',
              type=bool, is_flag=True, default=False, show_default=True)
@click.option('--pretty-print',
              help='render a prettier summary for the signatures in the file',
              type=bool, is_flag=True, default=False, show_default=True)
@trust_options
@click.option('--ltv-profile',
              help='LTV signature validation profile',
              type=click.Choice(RevocationInfoValidationType.as_tuple()),
              required=False)
@click.option('--ltv-obsessive',
              help='Fail trust validation if a certificate has no known CRL '
                   'or OCSP endpoints.',
              type=bool, is_flag=True, default=False, show_default=True)
@click.pass_context
def validate_signatures(ctx, infile, executive_summary,
                        pretty_print, validation_context, trust, trust_replace,
                        other_certs, ltv_profile, ltv_obsessive):

    if pretty_print and executive_summary:
        raise click.ClickException(
            "--pretty-print is incompatible with --executive-summary."
        )

    if ltv_profile is not None:
        ltv_profile = RevocationInfoValidationType(ltv_profile)

    vc_kwargs = _build_vc_kwargs(
        ctx, validation_context, trust, trust_replace, other_certs
    )
    with pyhanko_exception_manager():
        r = PdfFileReader(infile)
        for ix, embedded_sig in enumerate(r.embedded_signatures):
            fingerprint: str = embedded_sig.signer_cert.sha256.hex()
            status_str = _signature_status(
                ltv_profile, ltv_obsessive, pretty_print, vc_kwargs,
                executive_summary, embedded_sig
            )
            name = embedded_sig.field_name

            if pretty_print:
                header = f'Field {ix + 1}: {name}'
                line = '=' * len(header)
                print(line)
                print(header)
                print(line)
                print('\n\n' + status_str)
            else:
                print('%s:%s:%s' % (name, fingerprint, status_str))


@signing.command(name='list', help='list signature fields')
@click.argument('infile', type=click.File('rb'))
@click.option('--skip-status', help='do not print status', required=False,
              type=bool, is_flag=True, default=False, show_default=True)
def list_sigfields(infile, skip_status):

    with pyhanko_exception_manager():
        r = PdfFileReader(infile)
        field_info = fields.enumerate_sig_fields(r)
        for ix, (name, value, field_ref) in enumerate(field_info):
            if skip_status:
                print(name)
                continue
            print(f"{name}:{'EMPTY' if value is None else 'FILLED'}")


@signing.command(name='ltaupdate', help='update LTA timestamp')
@click.argument('infile', type=click.File('r+b'))
@click.option('--timestamp-url', help='URL for timestamp server',
              required=False, type=str, default=None)
@trust_options
@click.pass_context
def lta_update(ctx, infile, validation_context, trust, trust_replace,
               other_certs, timestamp_url):
    with pyhanko_exception_manager():
        vc_kwargs = _build_vc_kwargs(
            ctx, validation_context, trust, trust_replace, other_certs
        )
        timestamper = HTTPTimeStamper(timestamp_url)
        r = PdfFileReader(infile)
        signers.PdfTimeStamper(timestamper).update_archival_timestamp_chain(
            r, ValidationContext(**vc_kwargs)
        )


@signing.group(name='addsig', help='add a signature')
@click.option('--field', help='name of the signature field', required=False)
@click.option('--name', help='explicitly specify signer name', required=False)
@click.option('--reason', help='reason for signing', required=False)
@click.option('--location', help='location of signing', required=False)
@click.option('--certify', help='add certification signature', required=False, 
              default=False, is_flag=True, type=bool, show_default=True)
@click.option('--existing-only', help='never create signature fields', 
              required=False, default=False, is_flag=True, type=bool, 
              show_default=True)
@click.option('--timestamp-url', help='URL for timestamp server',
              required=False, type=str, default=None)
@click.option('--use-pades', help='sign PAdES-style [level B/B-T/B-LT]',
              required=False, default=False, is_flag=True, type=bool,
              show_default=True)
@click.option('--prefer-pss', is_flag=True, default=False, type=bool,
              help='prefer RSASSA-PSS to PKCS#1 v1.5 padding, if available')
@click.option('--with-validation-info', help='embed revocation info',
              required=False, default=False, is_flag=True, type=bool,
              show_default=True)
@click.option(
    '--style-name', help='stamp style name for signature appearance',
    required=False, type=str
)
@click.option(
    '--stamp-url', help='QR code URL to use in QR stamp style',
    required=False, type=str
)
@trust_options
@click.pass_context
def addsig(ctx, field, name, reason, location, certify, existing_only,
           timestamp_url, use_pades, with_validation_info,
           validation_context, trust_replace, trust, other_certs,
           style_name, stamp_url, prefer_pss):
    ctx.obj[Ctx.EXISTING_ONLY] = existing_only or field is None
    ctx.obj[Ctx.TIMESTAMP_URL] = timestamp_url
    ctx.obj[Ctx.PREFER_PSS] = prefer_pss

    if use_pades:
        subfilter = fields.SigSeedSubFilter.PADES
    else:
        subfilter = fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED

    if with_validation_info:
        vc_kwargs = _build_vc_kwargs(
            ctx, validation_context, trust, trust_replace, other_certs,
            allow_fetching=True
        )
        vc = ValidationContext(**vc_kwargs)
    else:
        vc = None
    field_name, new_field_spec = parse_field_location_spec(
        field, require_full_spec=False
    )
    ctx.obj[Ctx.SIG_META] = signers.PdfSignatureMetadata(
        field_name=field_name, location=location, reason=reason, name=name,
        certify=certify, subfilter=subfilter,
        embed_validation_info=with_validation_info,
        validation_context=vc
    )
    ctx.obj[Ctx.NEW_FIELD_SPEC] = new_field_spec
    ctx.obj[Ctx.STAMP_STYLE] = _select_style(ctx, style_name, stamp_url)
    ctx.obj[Ctx.STAMP_URL] = stamp_url


def _open_for_signing(infile_path, signer_cert=None, signer_key=None):
    from pyhanko.pdf_utils import crypt
    infile = open(infile_path, 'rb')
    writer = IncrementalPdfFileWriter(infile)

    # TODO make this an option higher up the tree
    # TODO mention filename in prompt
    if writer.prev.encrypted:
        sh = writer.prev.security_handler
        if isinstance(sh, crypt.StandardSecurityHandler):
            pdf_pass = getpass.getpass(
                prompt='Password for encrypted file \'%s\': ' % infile_path
            )
            writer.encrypt(pdf_pass)
        elif isinstance(sh, crypt.PubKeySecurityHandler) \
                and signer_key is not None:
            # attempt to decrypt using signer's credentials
            cred = SimpleEnvelopeKeyDecrypter(signer_cert, signer_key)
            writer.encrypt_pubkey(cred)
        else:
            raise click.ClickException(
                "Input file appears to be encrypted, but appropriate "
                "credentials are not available."
            )
    return writer


def addsig_simple_signer(signer: signers.SimpleSigner, infile_path, outfile,
                         timestamp_url, signature_meta, existing_fields_only,
                         style, stamp_url, new_field_spec):
    with pyhanko_exception_manager():
        if timestamp_url is not None:
            timestamper = HTTPTimeStamper(timestamp_url)
        else:
            timestamper = None
        writer = _open_for_signing(
            infile_path, signer_cert=signer.signing_cert,
            signer_key=signer.signing_key
        )

        text_params = None
        if stamp_url is not None:
            text_params = {'url': stamp_url}

        result = signers.PdfSigner(
            signature_meta, signer=signer, timestamper=timestamper,
            stamp_style=style, new_field_spec=new_field_spec
        ).sign_pdf(
            writer, existing_fields_only=existing_fields_only,
            appearance_text_params=text_params
        )

        buf = result.getbuffer()
        outfile.write(buf)
        buf.release()

        writer.prev.stream.close()
        outfile.close()


@addsig.command(name='pemder', help='read key material from PEM/DER files')
@click.argument('infile', type=readable_file)
@click.argument('outfile', type=click.File('wb'))
@click.option('--key', help='file containing the private key (PEM/DER)', 
              type=readable_file, required=True)
@click.option('--cert', help='file containing the signer\'s certificate '
              '(PEM/DER)', type=readable_file, required=True)
@click.option('--chain', type=readable_file, multiple=True,
              help='file(s) containing the chain of trust for the '
                   'signer\'s certificate (PEM/DER). May be '
                   'passed multiple times.')
# TODO allow reading the passphrase from a specific file descriptor
#  (for advanced scripting setups)
@click.option('--passfile', help='file containing the passphrase '
              'for the private key', required=False, type=click.File('rb'),
              show_default='stdin')
@click.pass_context
def addsig_pemder(ctx, infile, outfile, key, cert, chain, passfile):
    signature_meta = ctx.obj[Ctx.SIG_META]
    existing_fields_only = ctx.obj[Ctx.EXISTING_ONLY]
    timestamp_url = ctx.obj[Ctx.TIMESTAMP_URL]

    if passfile is None:
        passphrase = getpass.getpass(prompt='Key passphrase: ').encode('utf-8')
    else:
        passphrase = passfile.read()
        passfile.close()
    
    signer = signers.SimpleSigner.load(
        cert_file=cert, key_file=key, key_passphrase=passphrase,
        ca_chain_files=chain, prefer_pss=ctx.obj[Ctx.PREFER_PSS]
    )
    return addsig_simple_signer(
        signer, infile, outfile, timestamp_url=timestamp_url,
        signature_meta=signature_meta,
        existing_fields_only=existing_fields_only,
        style=ctx.obj[Ctx.STAMP_STYLE], stamp_url=ctx.obj[Ctx.STAMP_URL],
        new_field_spec=ctx.obj[Ctx.NEW_FIELD_SPEC]
    )


@addsig.command(name='pkcs12', help='read key material from a PKCS#12 file')
@click.argument('infile', type=readable_file)
@click.argument('outfile', type=click.File('wb'))
@click.argument('pfx', type=readable_file)
@click.option('--chain', type=readable_file, multiple=True,
              help='PEM/DER file(s) containing extra certificates to embed '
                   '(e.g. chain of trust not embedded in the PKCS#12 file)'
                   'May be passed multiple times.')
@click.option('--passfile', help='file containing the passphrase '
                                 'for the PKCS#12 file.', required=False,
              type=click.File('rb'),
              show_default='stdin')
@click.pass_context
def addsig_pkcs12(ctx, infile, outfile, pfx, chain, passfile):
    # TODO add sanity check in case the user gets the arg order wrong
    #  (now it fails with a gnarly DER decoding error, which is not very
    #  user-friendly)
    signature_meta = ctx.obj[Ctx.SIG_META]
    existing_fields_only = ctx.obj[Ctx.EXISTING_ONLY]
    timestamp_url = ctx.obj[Ctx.TIMESTAMP_URL]

    if passfile is None:
        passphrase = getpass.getpass(prompt='Export passphrase: ')\
                        .encode('utf-8')
    else:
        passphrase = passfile.read()
        passfile.close()

    signer = signers.SimpleSigner.load_pkcs12(
        pfx_file=pfx, passphrase=passphrase, ca_chain_files=chain,
        prefer_pss=ctx.obj[Ctx.PREFER_PSS]
    )
    return addsig_simple_signer(
        signer, infile, outfile, timestamp_url=timestamp_url,
        signature_meta=signature_meta,
        existing_fields_only=existing_fields_only,
        style=ctx.obj[Ctx.STAMP_STYLE], stamp_url=ctx.obj[Ctx.STAMP_URL],
        new_field_spec=ctx.obj[Ctx.NEW_FIELD_SPEC]
    )


@addsig.command(name='beid', help='use Belgian eID to sign')
@click.argument('infile', type=click.File('rb'))
@click.argument('outfile', type=click.File('wb'))
@click.option('--lib', help='path to libbeidpkcs11 library file',
              type=readable_file, required=True)
@click.option('--use-auth-cert', type=bool, show_default=True,
              default=False, required=False, is_flag=True,
              help='use Authentication cert instead')
@click.option('--slot-no', help='specify PKCS#11 slot to use', 
              required=False, type=int, default=None)
@click.pass_context
def addsig_beid(ctx, infile, outfile, lib, use_auth_cert, slot_no):
    signature_meta = ctx.obj[Ctx.SIG_META]
    existing_fields_only = ctx.obj[Ctx.EXISTING_ONLY]
    timestamp_url = ctx.obj[Ctx.TIMESTAMP_URL]
    session = beid.open_beid_session(lib, slot_no=slot_no)
    label = 'Authentication' if use_auth_cert else 'Signature'
    if timestamp_url is not None:
        timestamper = HTTPTimeStamper(timestamp_url)
    else:
        timestamper = None
    signer = beid.BEIDSigner(
        session, label
    )

    stamp_url = ctx.obj[Ctx.STAMP_URL]
    text_params = None
    if stamp_url is not None:
        text_params = {'url': stamp_url}

    with pyhanko_exception_manager():
        writer = IncrementalPdfFileWriter(infile)
        result = signers.PdfSigner(
            signature_meta, signer=signer, timestamper=timestamper,
            stamp_style=ctx.obj[Ctx.STAMP_STYLE],
            new_field_spec=ctx.obj[Ctx.NEW_FIELD_SPEC]
        ).sign_pdf(
            writer, existing_fields_only=existing_fields_only,
            appearance_text_params=text_params
        )
        buf = result.getbuffer()
        outfile.write(buf)
        buf.release()

        infile.close()
        outfile.close()


def _index_page(page):
    try:
        page_ix = int(page)
        if not page_ix:
            raise ValueError
        if page_ix > 0:
            # subtract 1 from the total, since that's what people expect
            # when referring to a page index
            return page_ix - 1
        else:
            # keep negative indexes as-is.
            return page_ix
    except ValueError:
        raise click.ClickException(
            "Sig field parameter PAGE should be a nonzero integer, "
            "not %s." % page
        )


def parse_field_location_spec(spec, require_full_spec=True):
    if spec is None:
        if require_full_spec:
            raise click.ClickException(
                "A signature field spec was not provided."
            )
        return None, None
    try:
        page, box, name = spec.split('/')
    except ValueError:
        if require_full_spec:
            raise click.ClickException(
                "Sig field spec should be of the form PAGE/X1,Y1,X2,Y2/NAME."
            )
        else:
            # interpret the entire string as a field name
            return spec, None

    page_ix = _index_page(page)

    try:
        x1, y1, x2, y2 = map(int, box.split(','))
    except ValueError:
        raise click.ClickException(
            "Sig field parameters X1,Y1,X2,Y2 should be four integers."
        )

    return name, fields.SigFieldSpec(
        sig_field_name=name, on_page=page_ix, box=(x1, y1, x2, y2)
    )


@signing.command(
    name='addfields', help='add empty signature fields to a PDF field'
)
@click.argument('infile', type=click.File('rb'))
@click.argument('outfile', type=click.File('wb'))
@click.option('--field', metavar='PAGE/X1,Y1,X2,Y2/NAME', multiple=True,
              required=True)
def add_sig_field(infile, outfile, field):
    with pyhanko_exception_manager():
        writer = IncrementalPdfFileWriter(infile)

        for s in field:
            name, spec = parse_field_location_spec(s)
            assert spec is not None
            fields.append_signature_field(writer, spec)

        writer.write(outfile)
        infile.close()
        outfile.close()


# TODO: text_params support

@cli.command(help='stamp PDF files', name='stamp')
@click.argument('infile', type=readable_file)
@click.argument('outfile', type=click.Path(writable=True, dir_okay=False))
@click.argument('x', type=int)
@click.argument('y', type=int)
@click.option(
    '--style-name', help='stamp style name for stamp appearance',
    required=False, type=str
)
@click.option(
    '--page', help='page on which the stamp should be applied',
    required=False, type=int, default=1, show_default=True
)
@click.option(
    '--stamp-url', help='QR code URL to use in QR stamp style',
    required=False, type=str
)
@click.pass_context
def stamp(ctx, infile, outfile, x, y, style_name, page, stamp_url):
    with pyhanko_exception_manager():
        stamp_style = _select_style(ctx, style_name, stamp_url)
        page_ix = _index_page(page)
        if stamp_url:
            qr_stamp_file(
                infile, outfile, stamp_style, dest_page=page_ix, x=x, y=y,
                url=stamp_url
            )
        else:
            text_stamp_file(
                infile, outfile, stamp_style, dest_page=page_ix, x=x, y=y
            )


@cli.command(help='encrypt PDF files (AES-256 only)', name='encrypt')
@click.argument('infile', type=readable_file)
@click.argument('outfile', type=click.Path(writable=True, dir_okay=False))
@click.option(
    '--password', help='password to encrypt the file with', required=False,
    type=str
)
@click.option(
    '--recipient', required=False, multiple=True,
    help='certificate(s) corresponding to entities that '
         'can decrypt the output file',
    type=click.Path(readable=True, dir_okay=False)
)
def encrypt_file(infile, outfile, password, recipient):
    if bool(password) == bool(recipient):
        raise click.ClickException(
            "Specify either a password or a list of recipients."
        )

    recipient_certs = None
    if recipient:
        recipient_certs = list(
            signers.load_certs_from_pemder(cert_files=recipient)
        )

    with pyhanko_exception_manager():
        with open(infile, 'rb') as inf:
            r = PdfFileReader(inf)
            w = copy_into_new_writer(r)

            if recipient_certs:
                w.encrypt_pubkey(recipient_certs)
            else:
                w.encrypt(owner_pass=password)

            with open(outfile, 'wb') as outf:
                w.write(outf)


@cli.group(help='decrypt PDF files (any standard PDF encryption scheme)',
           name='decrypt')
def decrypt():
    pass


decrypt_force_flag = click.option(
    '--force', help='ignore access restrictions (use at your own risk)',
    required=False, type=bool, is_flag=True, default=False
)


@decrypt.command(help='decrypt using password', name='password')
@click.argument('infile', type=readable_file)
@click.argument('outfile', type=click.Path(writable=True, dir_okay=False))
@click.option(
    '--password', help='password to decrypt the file with', required=False,
    type=str
)
@decrypt_force_flag
def decrypt_with_password(infile, outfile, password, force):
    with pyhanko_exception_manager():
        with open(infile, 'rb') as inf:
            r = PdfFileReader(inf)
            if r.security_handler is None:
                raise click.ClickException("File is not encrypted.")
            if not password:
                password = getpass.getpass(prompt='File password: ')
            auth_result = r.decrypt(password)
            if auth_result == AuthResult.USER and not force:
                raise click.ClickException(
                    "Password specified was the user password, not "
                    "the owner password. Pass --force to decrypt the "
                    "file anyway."
                )
            elif auth_result == AuthResult.FAILED:
                raise click.ClickException("Password didn't match.")
            w = copy_into_new_writer(r)
            with open(outfile, 'wb') as outf:
                w.write(outf)


@decrypt.command(help='decrypt using private key (PEM/DER)', name='pemder')
@click.argument('infile', type=readable_file)
@click.argument('outfile', type=click.Path(writable=True, dir_okay=False))
@click.option('--key', type=readable_file, required=True,
              help='file containing the recipient\'s private key (PEM/DER)')
@click.option('--cert', help='file containing the recipient\'s certificate '
                             '(PEM/DER)', type=readable_file, required=True)
@click.option('--passfile', required=False, type=click.File('rb'),
              help='file containing the passphrase for the private key',
              show_default='stdin')
@decrypt_force_flag
def decrypt_with_pemder(infile, outfile, key, cert, passfile, force):
    if passfile is None:
        passphrase = getpass.getpass(prompt='Key passphrase: ').encode('utf-8')
    else:
        passphrase = passfile.read()
        passfile.close()
    sedk = SimpleEnvelopeKeyDecrypter.load(key, cert, key_passphrase=passphrase)

    _decrypt_pubkey(sedk, infile, outfile, force)


def _decrypt_pubkey(sedk: SimpleEnvelopeKeyDecrypter, infile, outfile, force):
    with pyhanko_exception_manager():
        with open(infile, 'rb') as inf:
            r = PdfFileReader(inf)
            if r.security_handler is None:
                raise click.ClickException("File is not encrypted.")
            if not isinstance(r.security_handler, PubKeySecurityHandler):
                raise click.ClickException(
                    "File was not encrypted with a public-key security handler."
                )
            auth_result = r.decrypt_pubkey(sedk)
            if auth_result == AuthResult.USER:
                # TODO read 2nd bit of perms in CMS enveloped data
                #  is the one indicating that change of encryption is OK
                if not force:
                    raise click.ClickException(
                        "Change of encryption is typically not allowed with "
                        "user access. Pass --force to decrypt the file anyway."
                    )
            elif auth_result == AuthResult.FAILED:
                raise click.ClickException("Failed to decrypt the file.")
            w = copy_into_new_writer(r)
            with open(outfile, 'wb') as outf:
                w.write(outf)


@decrypt.command(help='decrypt using private key (PKCS#12)', name='pkcs12')
@click.argument('infile', type=readable_file)
@click.argument('outfile', type=click.Path(writable=True, dir_okay=False))
@click.argument('pfx', type=readable_file)
@click.option('--passfile', required=False, type=click.File('rb'),
              help='file containing the passphrase for the PKCS#12 file',
              show_default='stdin')
@decrypt_force_flag
def decrypt_with_pkcs12(infile, outfile, pfx, passfile, force):
    if passfile is None:
        passphrase = getpass.getpass(prompt='Key passphrase: ').encode('utf-8')
    else:
        passphrase = passfile.read()
        passfile.close()
    sedk = SimpleEnvelopeKeyDecrypter.load_pkcs12(pfx, passphrase=passphrase)

    _decrypt_pubkey(sedk, infile, outfile, force)
