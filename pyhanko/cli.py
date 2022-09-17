import asyncio
import getpass
import logging
import os
import sys
from contextlib import contextmanager
from datetime import datetime
from enum import Enum, auto

import click
import tzlocal
from asn1crypto import cms, pem
from pyhanko_certvalidator import ValidationContext

import pyhanko.sign.validation.pdf_embedded
from pyhanko import __version__
from pyhanko.config import (
    CLIConfig,
    LogConfig,
    PemDerSignatureConfig,
    PKCS11PinEntryMode,
    PKCS11SignatureConfig,
    PKCS12SignatureConfig,
    StdLogOutput,
    TokenCriteria,
    init_validation_context_kwargs,
    parse_cli_config,
    parse_logging_config,
)
from pyhanko.pdf_utils import crypt, misc
from pyhanko.pdf_utils.config_utils import ConfigurationError
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.layout import LayoutError
from pyhanko.pdf_utils.misc import isoparse
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import copy_into_new_writer
from pyhanko.sign import fields, signers, validation
from pyhanko.sign.general import SigningError, load_certs_from_pemder
from pyhanko.sign.signers import DEFAULT_SIGNER_KEY_USAGE
from pyhanko.sign.signers.pdf_cms import PdfCMSSignedAttributes
from pyhanko.sign.timestamps import HTTPTimeStamper
from pyhanko.sign.validation import RevocationInfoValidationType
from pyhanko.sign.validation.errors import SignatureValidationError
from pyhanko.stamp import QRStampStyle, qr_stamp_file, text_stamp_file

__all__ = ['cli']


logger = logging.getLogger(__name__)


try:
    import pkcs11  # lgtm [py/unused-import]
    pkcs11_available = True
except ImportError:
    pkcs11 = None
    pkcs11_available = False

P11_PIN_ENV_VAR = "PYHANKO_PKCS11_PIN"


class NoStackTraceFormatter(logging.Formatter):
    def formatException(self, ei) -> str:
        return ""


LOG_FORMAT_STRING = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'


def logging_setup(log_configs, verbose: bool):
    log_config: LogConfig
    for module, log_config in log_configs.items():
        cur_logger = logging.getLogger(module)
        cur_logger.setLevel(log_config.level)
        if isinstance(log_config.output, StdLogOutput):
            if StdLogOutput == StdLogOutput.STDOUT:
                handler = logging.StreamHandler(sys.stdout)
            else:
                handler = logging.StreamHandler()
            # when logging to the console, don't output stack traces
            # unless in verbose mode
            if verbose:
                formatter = logging.Formatter(LOG_FORMAT_STRING)
            else:
                formatter = NoStackTraceFormatter(LOG_FORMAT_STRING)
        else:
            handler = logging.FileHandler(log_config.output)
            formatter = logging.Formatter(LOG_FORMAT_STRING)
        handler.setFormatter(formatter)
        cur_logger.addHandler(handler)


@contextmanager
def pyhanko_exception_manager():
    msg = exception = None
    try:
        yield
    except click.ClickException:
        raise
    except misc.PdfStrictReadError as e:
        exception = e
        msg = (
            "Failed to read PDF file in strict mode; rerun with "
            "--no-strict-syntax to try again.\n"
            f"Error message: {e.msg}"
        )
    except misc.PdfReadError as e:
        exception = e
        msg = f"Failed to read PDF file: {e.msg}"
    except misc.PdfWriteError as e:
        exception = e
        msg = f"Failed to write PDF file: {e.msg}"
    except SigningError as e:
        exception = e
        msg = f"Error raised while producing signed file: {e.msg}"
    except LayoutError as e:
        exception = e
        msg = f"Error raised while producing signature layout: {e.msg}"
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
    DETACH_PEM = auto()
    LENIENT = auto()


def _warn_empty_passphrase():
    click.echo(
        click.style(
            "WARNING: passphrase is empty. If you intended to sign with an "
            "unencrypted private key, use --no-pass instead.",
            bold=True
        )
    )

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
    else:
        # use the root logger's output settings to populate the default
        log_output = log_config[None].output
        # Revinfo fetch logs -> filter by default
        log_config['pyhanko_certvalidator.fetchers'] = LogConfig(
            level=logging.WARNING, output=log_output
        )
        if 'fontTools.subset' not in log_config:
            # the fontTools subsetter has a very noisy INFO log, so
            # set that one to WARNING by default
            log_config['fontTools.subset'] = LogConfig(
                level=logging.WARNING, output=log_output
            )

    logging_setup(log_config, verbose)

    if verbose:
        logging.debug("Running with --verbose")
    if config_text is not None:
        logging.debug(f'Finished reading configuration from {config}.')
    else:
        logging.debug('There was no configuration to parse.')


@cli.group(help='sign PDFs and other files', name='sign')
def signing():
    pass


readable_file = click.Path(exists=True, readable=True, dir_okay=False)


def _build_vc_kwargs(ctx, validation_context, trust,
                     trust_replace, other_certs, retroactive_revinfo,
                     allow_fetching=None):
    cli_config: CLIConfig = ctx.obj.get(Ctx.CLI_CONFIG, None)
    try:
        if validation_context is not None:
            if any((trust, other_certs)):
                raise click.ClickException(
                    "--validation-context is incompatible with --trust "
                    "and --other-certs"
                )
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
                trust=trust, trust_replace=trust_replace,
                other_certs=other_certs,
                retroactive_revinfo=retroactive_revinfo
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
        else:
            result.setdefault('allow_fetching', True)

        # allow CLI --retroactive-revinfo flag to override settings
        # if necessary
        if retroactive_revinfo:
            result['retroactive_revinfo'] = True
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


def _get_key_usage_settings(ctx, validation_context):
    cli_config: CLIConfig = ctx.obj.get(Ctx.CLI_CONFIG, None)
    if cli_config is None:
        return None

    # note: validation_context can be None, this triggers fallback to the
    # default validation context specified in the configuration file
    # If we add support for specifying key usage settings as CLI arguments,
    # using the same fallbacks as _build_cli_kwargs would probably be cleaner
    return cli_config.get_signer_key_usages(name=validation_context)


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


def _prepare_vc(vc_kwargs, soft_revocation_check, force_revinfo):

    if soft_revocation_check and force_revinfo:
        raise click.ClickException(
            "--soft-revocation-check is incompatible with "
            "--force-revinfo"
        )
    if force_revinfo:
        rev_mode = 'require'
    elif soft_revocation_check:
        rev_mode = 'soft-fail'
    else:
        rev_mode = 'hard-fail'
    vc_kwargs['revocation_mode'] = rev_mode
    return vc_kwargs


def _signature_status(ltv_profile, vc_kwargs, force_revinfo, key_usage_settings,
                      embedded_sig, skip_diff=False):
    if ltv_profile is None:
        vc = ValidationContext(**vc_kwargs)
        status = pyhanko.sign.validation.validate_pdf_signature(
            embedded_sig, key_usage_settings=key_usage_settings,
            signer_validation_context=vc,
            skip_diff=skip_diff
        )
    else:
        status = validation.validate_pdf_ltv_signature(
            embedded_sig, ltv_profile,
            key_usage_settings=key_usage_settings,
            force_revinfo=force_revinfo,
            validation_context_kwargs=vc_kwargs,
            skip_diff=skip_diff
        )
    return status


def _validate_detached(infile, sig_infile, validation_context,
                       key_usage_settings):
    sig_bytes = sig_infile.read()
    try:
        if pem.detect(sig_bytes):
            _, _, sig_bytes = pem.unarmor(sig_bytes)
        content_info = cms.ContentInfo.load(sig_bytes)
        if content_info['content_type'].native != 'signed_data':
            raise click.ClickException("CMS content type is not signedData")
    except ValueError as e:
        raise click.ClickException("Could not parse CMS object") from e

    validation_coro = validation.async_validate_detached_cms(
        infile, signed_data=content_info['content'],
        signer_validation_context=validation_context,
        key_usage_settings=key_usage_settings
    )
    return asyncio.run(validation_coro)


def _signature_status_str(status_callback, pretty_print, executive_summary):
    try:
        status = status_callback()
        if executive_summary and not pretty_print:
            return 'VALID' if status.bottom_line else 'INVALID', status.bottom_line
        elif pretty_print:
            return status.pretty_print_details(), status.bottom_line
        else:
            return status.summary(), status.bottom_line
    except validation.ValidationInfoReadingError as e:
        msg = (
            'An error occurred while parsing the revocation information '
            'for this signature: ' + str(e)
        )
        logger.error(msg)
        if pretty_print:
            return msg, False
        else:
            return 'REVINFO_FAILURE', False
    except SignatureValidationError as e:
        msg = 'An error occurred while validating this signature: ' + str(e)
        logger.error(msg, exc_info=e)
        if pretty_print:
            return msg, False
        else:
            return 'INVALID', False


def _attempt_iso_dt_parse(dt_str) -> datetime:
    try:
        dt = isoparse(dt_str)
    except ValueError:
        raise click.ClickException(f"datetime {dt_str!r} could not be parsed")
    return dt


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
@click.option('--force-revinfo',
              help='Fail trust validation if a certificate has no known CRL '
                   'or OCSP endpoints.',
              type=bool, is_flag=True, default=False, show_default=True)
@click.option('--soft-revocation-check',
              help='Do not fail validation on revocation checking failures '
                   '(only applied to on-line revocation checks)',
              type=bool, is_flag=True, default=False, show_default=True)
@click.option('--no-revocation-check',
              help='Do not attempt to check revocation status '
                   '(meaningless for LTV validation)',
              type=bool, is_flag=True, default=False, show_default=True)
@click.option('--retroactive-revinfo',
              help='Treat revocation info as retroactively valid '
                   '(i.e. ignore thisUpdate timestamp)',
              type=bool, is_flag=True, default=False, show_default=True)
@click.option('--validation-time',
              help=(
                   'Override the validation time (ISO 8601 date). '
                   'The special value \'claimed\' causes the validation time '
                   'claimed by the signer to be used. Revocation checking '
                   'will be disabled. Option ignored in LTV mode.'
              ),
              type=str, required=False)
@click.option('--password', required=False, type=str,
              help='password to access the file (can also be read from stdin)')
@click.option('--no-diff-analysis', default=False, type=bool, is_flag=True,
              help='disable incremental update analysis')
@click.option(
    '--detached', type=click.File('rb'),
    help=(
        'Read signature CMS object from the indicated file; '
        'this can be used to verify signatures on non-PDF files'
    )
)
@click.option('--no-strict-syntax',
              help='Attempt to ignore syntactical problems in the input file '
                   'and enable signature validation in hybrid-reference files.'
                   '(warning: this may affect validation results in unexpected '
                   'ways.)',
              type=bool, is_flag=True, default=False, show_default=True)
@click.pass_context
def validate_signatures(ctx, infile, executive_summary,
                        pretty_print, validation_context, trust, trust_replace,
                        other_certs, ltv_profile, force_revinfo,
                        soft_revocation_check, no_revocation_check, password,
                        retroactive_revinfo, detached, no_diff_analysis,
                        validation_time, no_strict_syntax):

    no_revocation_check |= validation_time is not None

    if no_revocation_check:
        soft_revocation_check = True

    if pretty_print and executive_summary:
        raise click.ClickException(
            "--pretty-print is incompatible with --executive-summary."
        )

    if ltv_profile is not None:
        if validation_time is not None:
            raise click.ClickException(
                "--validation-time is not compatible with --ltv-profile"
            )
        ltv_profile = RevocationInfoValidationType(ltv_profile)

    vc_kwargs = _build_vc_kwargs(
        ctx, validation_context, trust, trust_replace, other_certs,
        retroactive_revinfo,
        allow_fetching=False if no_revocation_check else None
    )

    use_claimed_validation_time = False
    if validation_time == 'claimed':
        use_claimed_validation_time = True
    elif validation_time is not None:
        vc_kwargs['moment'] = _attempt_iso_dt_parse(validation_time)

    key_usage_settings = _get_key_usage_settings(ctx, validation_context)
    vc_kwargs = _prepare_vc(
        vc_kwargs, soft_revocation_check=soft_revocation_check,
        force_revinfo=force_revinfo
    )
    with pyhanko_exception_manager():
        if detached is not None:
            (status_str, signature_ok) = _signature_status_str(
                status_callback=lambda: _validate_detached(
                    infile, detached, ValidationContext(**vc_kwargs),
                    key_usage_settings
                ),
                pretty_print=pretty_print, executive_summary=executive_summary
            )
            if signature_ok:
                print(status_str)
            else:
                raise click.ClickException(status_str)
            return

        if no_strict_syntax:
            logger.info(
                "Strict PDF syntax is disabled; this could impact validation "
                "results. Use caution."
            )
            r = PdfFileReader(infile, strict=False)
        else:
            r = PdfFileReader(infile)
        sh = r.security_handler
        if isinstance(sh, crypt.StandardSecurityHandler):
            if password is None:
                password = getpass.getpass(prompt='File password: ')
            auth_result = r.decrypt(password)
            if auth_result.status == crypt.AuthStatus.FAILED:
                raise click.ClickException("Password didn't match.")
        elif sh is not None:
            raise click.ClickException(
                "The CLI supports only password-based encryption when "
                "validating (for now)"
            )

        all_signatures_ok = True
        for ix, embedded_sig in enumerate(r.embedded_regular_signatures):
            fingerprint: str = embedded_sig.signer_cert.sha256.hex()
            if use_claimed_validation_time:
                vc_kwargs['moment'] = embedded_sig.self_reported_timestamp
            (status_str, signature_ok) = _signature_status_str(
                status_callback=lambda: _signature_status(
                    ltv_profile=ltv_profile, force_revinfo=force_revinfo,
                    vc_kwargs=vc_kwargs, key_usage_settings=key_usage_settings,
                    embedded_sig=embedded_sig, skip_diff=no_diff_analysis
                ),
                pretty_print=pretty_print, executive_summary=executive_summary
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
            all_signatures_ok &= signature_ok

        if not all_signatures_ok:
            raise click.ClickException("Validation failed")


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
              required=True, type=str, default=None)
@click.option('--retroactive-revinfo',
              help='Treat revocation info as retroactively valid '
                   '(i.e. ignore thisUpdate timestamp)',
              type=bool, is_flag=True, default=False, show_default=True)
@trust_options
@click.pass_context
def lta_update(ctx, infile, validation_context, trust, trust_replace,
               other_certs, timestamp_url, retroactive_revinfo):
    with pyhanko_exception_manager():
        vc_kwargs = _build_vc_kwargs(
            ctx, validation_context, trust, trust_replace, other_certs,
            retroactive_revinfo
        )
        timestamper = HTTPTimeStamper(timestamp_url)
        r = PdfFileReader(infile)
        signers.PdfTimeStamper(timestamper).update_archival_timestamp_chain(
            r, ValidationContext(**vc_kwargs)
        )


# TODO perhaps add an option here to fix the lack of a timestamp and/or
#  warn if none is present

@signing.command(name='ltvfix',
                 help='add revocation information for a signature to the DSS')
@click.argument('infile', type=click.File('r+b'))
@click.option('--field', help='name of the signature field', required=True)
@click.option('--timestamp-url', help='URL for timestamp server',
              required=False, type=str, default=None)
@click.option('--apply-lta-timestamp',
              help='Apply a document timestamp after adding revocation info.',
              required=False, type=bool, default=False, is_flag=True,
              show_default=True)
@trust_options
@click.pass_context
def ltv_fix(ctx, infile, field, timestamp_url, apply_lta_timestamp,
            validation_context, trust_replace, trust, other_certs):
    if apply_lta_timestamp and not timestamp_url:
        raise click.ClickException(
            "Please specify a timestamp server using --timestamp-url."
        )

    vc_kwargs = _build_vc_kwargs(
        ctx, validation_context, trust, trust_replace, other_certs,
        retroactive_revinfo=False, allow_fetching=True
    )
    vc_kwargs['revocation_mode'] = 'hard-fail'
    r = PdfFileReader(infile)

    try:
        emb_sig = next(
            s for s in r.embedded_regular_signatures if s.field_name == field
        )
    except StopIteration:
        raise click.ClickException(
            f"Could not find a PDF signature labelled {field}."
        )

    output = validation.add_validation_info(
        emb_sig, ValidationContext(**vc_kwargs), in_place=True
    )

    if apply_lta_timestamp:
        timestamper = HTTPTimeStamper(timestamp_url)
        signers.PdfTimeStamper(timestamper).timestamp_pdf(
            IncrementalPdfFileWriter(output), signers.DEFAULT_MD,
            ValidationContext(**vc_kwargs), in_place=True
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
@click.option('--use-pades', help='sign PAdES-style [level B/B-T/B-LT/B-LTA]',
              required=False, default=False, is_flag=True, type=bool,
              show_default=True)
@click.option('--use-pades-lta', help='produce PAdES-B-LTA signature',
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
@click.option(
    '--detach', type=bool, is_flag=True, default=False,
    help=(
        'write only the signature CMS object to the output file; '
        'this can be used to sign non-PDF files'
    )
)
@click.option(
    '--detach-pem', help='output PEM data instead of DER when using --detach',
    type=bool, is_flag=True, default=False
)
@click.option('--retroactive-revinfo',
              help='Treat revocation info as retroactively valid '
                   '(i.e. ignore thisUpdate timestamp)',
              type=bool, is_flag=True, default=False, show_default=True)
@click.option('--no-strict-syntax',
              help='Attempt to ignore syntactical problems in the input file '
                   'and enable signature creation in hybrid-reference files.'
                   '(warning: such documents may behave in unexpected ways)',
              type=bool, is_flag=True, default=False, show_default=True)
@click.pass_context
def addsig(ctx, field, name, reason, location, certify, existing_only,
           timestamp_url, use_pades, use_pades_lta, with_validation_info,
           validation_context, trust_replace, trust, other_certs,
           style_name, stamp_url, prefer_pss, retroactive_revinfo,
           detach, detach_pem, no_strict_syntax):
    ctx.obj[Ctx.EXISTING_ONLY] = existing_only or field is None
    ctx.obj[Ctx.TIMESTAMP_URL] = timestamp_url
    ctx.obj[Ctx.PREFER_PSS] = prefer_pss

    if detach:
        ctx.obj[Ctx.DETACH_PEM] = detach_pem
        ctx.obj[Ctx.SIG_META] = None
        return  # everything else doesn't apply

    if use_pades_lta:
        use_pades = with_validation_info = True
        if not timestamp_url:
            raise click.ClickException(
                "--timestamp-url is required for --use-pades-lta"
            )
    if use_pades:
        subfilter = fields.SigSeedSubFilter.PADES
    else:
        subfilter = fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED

    key_usage = DEFAULT_SIGNER_KEY_USAGE
    if with_validation_info:
        vc_kwargs = _build_vc_kwargs(
            ctx, validation_context, trust, trust_replace, other_certs,
            retroactive_revinfo, allow_fetching=True
        )
        vc = ValidationContext(**vc_kwargs)
        key_usage_sett = _get_key_usage_settings(ctx, validation_context)
        if key_usage_sett is not None and key_usage_sett.key_usage is not None:
            key_usage = key_usage_sett.key_usage
    else:
        vc = None
    field_name, new_field_spec = parse_field_location_spec(
        field, require_full_spec=False
    )
    ctx.obj[Ctx.SIG_META] = signers.PdfSignatureMetadata(
        field_name=field_name, location=location, reason=reason, name=name,
        certify=certify, subfilter=subfilter,
        embed_validation_info=with_validation_info,
        validation_context=vc, signer_key_usage=key_usage,
        use_pades_lta=use_pades_lta
    )
    ctx.obj[Ctx.NEW_FIELD_SPEC] = new_field_spec
    ctx.obj[Ctx.STAMP_STYLE] = _select_style(ctx, style_name, stamp_url)
    ctx.obj[Ctx.STAMP_URL] = stamp_url
    ctx.obj[Ctx.LENIENT] = no_strict_syntax


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
        elif isinstance(sh, crypt.PubKeySecurityHandler) \
                and signer_key is not None:
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


def get_text_params(ctx):
    text_params = None
    stamp_url = ctx.obj[Ctx.STAMP_URL]
    if stamp_url is not None:
        text_params = {'url': stamp_url}
    return text_params


def detached_sig(signer: signers.Signer, infile_path, outfile,
                 timestamp_url, use_pem):
    coro = async_detached_sig(
        signer, infile_path, outfile, timestamp_url, use_pem
    )
    return asyncio.run(coro)


async def async_detached_sig(signer: signers.Signer, infile_path, outfile,
                             timestamp_url, use_pem):

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
                inf, signers.DEFAULT_MD, timestamper=timestamper,
                signed_attr_settings=PdfCMSSignedAttributes(
                    signing_time=timestamp
                )
            )

        output_bytes = signature.dump()
        if use_pem:
            output_bytes = pem.armor('PKCS7', output_bytes)

        # outfile is managed by Click
        outfile.write(output_bytes)


def addsig_simple_signer(signer: signers.SimpleSigner, infile_path, outfile,
                         timestamp_url, signature_meta, existing_fields_only,
                         style, text_params, new_field_spec, lenient):
    with pyhanko_exception_manager():
        if timestamp_url is not None:
            timestamper = HTTPTimeStamper(timestamp_url)
        else:
            timestamper = None
        writer = _open_for_signing(
            infile_path, signer_cert=signer.signing_cert,
            signer_key=signer.signing_key, lenient=lenient
        )

        generic_sign_pdf(
            writer=writer, outfile=outfile,
            signature_meta=signature_meta, signer=signer,
            timestamper=timestamper, style=style, new_field_spec=new_field_spec,
            existing_fields_only=existing_fields_only, text_params=text_params
        )


def generic_sign_pdf(*, writer, outfile, signature_meta, signer, timestamper,
                     style, new_field_spec, existing_fields_only, text_params):
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


def grab_certs(files):
    if files is None:
        return None
    try:
        return list(load_certs_from_pemder(files))
    except (IOError, ValueError) as e:  # pragma: nocover
        logger.error(f'Could not load certificates from {files}', exc_info=e)
        return None


@addsig.command(name='pemder', help='read key material from PEM/DER files')
@click.argument('infile', type=readable_file)
@click.argument('outfile', type=click.File('wb'))
@click.option('--key', help='file containing the private key (PEM/DER)', 
              type=readable_file, required=False)
@click.option('--cert', help='file containing the signer\'s certificate '
              '(PEM/DER)', type=readable_file, required=False)
@click.option('--chain', type=readable_file, multiple=True,
              help='file(s) containing the chain of trust for the '
                   'signer\'s certificate (PEM/DER). May be '
                   'passed multiple times.')
@click.option('--pemder-setup', type=str, required=False,
              help='name of preconfigured PEM/DER profile (overrides all '
                   'other options)')
# TODO allow reading the passphrase from a specific file descriptor
#  (for advanced scripting setups)
@click.option('--passfile', help='file containing the passphrase '
              'for the private key', required=False, type=click.File('r'),
              show_default='stdin')
@click.option('--no-pass',
              help='assume the private key file is unencrypted',
              type=bool, is_flag=True, default=False, show_default=True)
@click.pass_context
def addsig_pemder(ctx, infile, outfile, key, cert, chain, pemder_setup,
                  passfile, no_pass):
    signature_meta = ctx.obj[Ctx.SIG_META]
    existing_fields_only = ctx.obj[Ctx.EXISTING_ONLY]
    timestamp_url = ctx.obj[Ctx.TIMESTAMP_URL]

    if pemder_setup:
        cli_config: CLIConfig = ctx.obj.get(Ctx.CLI_CONFIG, None)
        if cli_config is None:
            raise click.ClickException(
                "The --pemder-setup option requires a configuration file"
            )
        try:
            pemder_config = cli_config.get_pemder_config(pemder_setup)
        except ConfigurationError as e:
            msg = f"Error while reading PEM/DER setup {pemder_setup}"
            logger.error(msg, exc_info=e)
            raise click.ClickException(msg)
    elif not (key and cert):
        raise click.ClickException(
            "Either both the --key and --cert options, or the --pemder-setup "
            "option must be provided."
        )
    else:
        pemder_config = PemDerSignatureConfig(
            key_file=key, cert_file=cert, other_certs=grab_certs(chain),
            prefer_pss=ctx.obj[Ctx.PREFER_PSS]
        )

    if pemder_config.key_passphrase is not None:
        passphrase = pemder_config.key_passphrase
    elif passfile is not None:
        passphrase = passfile.readline().strip().encode('utf-8')
        passfile.close()
    elif pemder_config.prompt_passphrase and not no_pass:
        passphrase = getpass.getpass(prompt='Key passphrase: ').encode('utf-8')
        if not passphrase:
            _warn_empty_passphrase()
    else:
        passphrase = None

    signer = pemder_config.instantiate(provided_key_passphrase=passphrase)
    if ctx.obj[Ctx.SIG_META] is None:
        detached_sig(
            signer, infile, outfile, timestamp_url=timestamp_url,
            use_pem=ctx.obj[Ctx.DETACH_PEM]
        )
    addsig_simple_signer(
        signer, infile, outfile, timestamp_url=timestamp_url,
        signature_meta=signature_meta,
        existing_fields_only=existing_fields_only,
        style=ctx.obj[Ctx.STAMP_STYLE], text_params=get_text_params(ctx),
        new_field_spec=ctx.obj[Ctx.NEW_FIELD_SPEC],
        lenient=ctx.obj.get(Ctx.LENIENT, False)
    )


@addsig.command(name='pkcs12', help='read key material from a PKCS#12 file')
@click.argument('infile', type=readable_file)
@click.argument('outfile', type=click.File('wb'))
@click.argument('pfx', type=readable_file, required=False)
@click.option('--p12-setup', type=str, required=False,
              help='name of preconfigured PKCS#12 profile (overrides all '
                   'other options)')
@click.option('--chain', type=readable_file, multiple=True,
              help='PEM/DER file(s) containing extra certificates to embed '
                   '(e.g. chain of trust not embedded in the PKCS#12 file)'
                   'May be passed multiple times.')
@click.option('--passfile', help='file containing the passphrase '
                                 'for the PKCS#12 file.', required=False,
              type=click.File('r'),
              show_default='stdin')
@click.pass_context
def addsig_pkcs12(ctx, infile, outfile, pfx, chain, passfile, p12_setup):
    # TODO add sanity check in case the user gets the arg order wrong
    #  (now it fails with a gnarly DER decoding error, which is not very
    #  user-friendly)
    signature_meta = ctx.obj[Ctx.SIG_META]
    existing_fields_only = ctx.obj[Ctx.EXISTING_ONLY]
    timestamp_url = ctx.obj[Ctx.TIMESTAMP_URL]

    if p12_setup:
        cli_config: CLIConfig = ctx.obj.get(Ctx.CLI_CONFIG, None)
        if cli_config is None:
            raise click.ClickException(
                "The --p12-setup option requires a configuration file"
            )
        try:
            pkcs12_config = cli_config.get_pkcs12_config(p12_setup)
        except ConfigurationError as e:
            msg = f"Error while reading PKCS#12 config {p12_setup}"
            logger.error(msg, exc_info=e)
            raise click.ClickException(msg)
    elif not pfx:
        raise click.ClickException(
            "Either the PFX argument or the --p12-setup option "
            "must be provided."
        )
    else:
        pkcs12_config = PKCS12SignatureConfig(
            pfx_file=pfx, other_certs=grab_certs(chain),
            prefer_pss=ctx.obj[Ctx.PREFER_PSS]
        )

    if pkcs12_config.pfx_passphrase is not None:
        passphrase = pkcs12_config.pfx_passphrase
    elif passfile is not None:
        passphrase = passfile.readline().strip().encode('utf-8')
        passfile.close()
    elif pkcs12_config.prompt_passphrase:
        passphrase = getpass.getpass(prompt='PKCS#12 passphrase: ')\
                        .encode('utf-8')
    else:
        passphrase = None

    signer = pkcs12_config.instantiate(provided_pfx_passphrase=passphrase)
    if ctx.obj[Ctx.SIG_META] is None:
        detached_sig(
            signer, infile, outfile, timestamp_url=timestamp_url,
            use_pem=ctx.obj[Ctx.DETACH_PEM]
        )
    addsig_simple_signer(
        signer, infile, outfile, timestamp_url=timestamp_url,
        signature_meta=signature_meta,
        existing_fields_only=existing_fields_only,
        style=ctx.obj[Ctx.STAMP_STYLE], text_params=get_text_params(ctx),
        new_field_spec=ctx.obj[Ctx.NEW_FIELD_SPEC],
        lenient=ctx.obj.get(Ctx.LENIENT, False)
    )


def _sign_pkcs11(ctx, signer, infile, outfile, timestamp_url):
    with pyhanko_exception_manager():
        if ctx.obj[Ctx.SIG_META] is None:
            return detached_sig(
                signer, infile, outfile, timestamp_url=timestamp_url,
                use_pem=ctx.obj[Ctx.DETACH_PEM]
            )

        if timestamp_url is not None:
            timestamper = HTTPTimeStamper(timestamp_url)
        else:
            timestamper = None

        generic_sign_pdf(
            writer=_open_for_signing(infile, ctx.obj.get(Ctx.LENIENT, False)),
            outfile=outfile,
            signature_meta=ctx.obj[Ctx.SIG_META], signer=signer,
            timestamper=timestamper, style=ctx.obj[Ctx.STAMP_STYLE],
            new_field_spec=ctx.obj[Ctx.NEW_FIELD_SPEC],
            existing_fields_only=ctx.obj[Ctx.EXISTING_ONLY],
            text_params=get_text_params(ctx)
        )


@click.argument('infile', type=readable_file)
@click.argument('outfile', type=click.File('wb'))
@click.option('--lib', help='path to PKCS#11 module',
              type=readable_file, required=False)
@click.option('--token-label', help='PKCS#11 token label', type=str,
              required=False)
@click.option('--cert-label', help='certificate label', type=str,
              required=False)
@click.option('--raw-mechanism',
              help='invoke raw PKCS#11 mechanism',
              type=bool, is_flag=True, required=False)
@click.option('--key-label', help='key label', type=str, required=False)
@click.option('--slot-no', help='specify PKCS#11 slot to use',
              required=False, type=int, default=None)
@click.option('--skip-user-pin', type=bool, show_default=True,
              default=False, required=False, is_flag=True,
              help='do not prompt for PIN (e.g. if the token has a PIN pad)')
@click.option('--p11-setup', type=str, required=False,
              help='name of preconfigured PKCS#11 profile (overrides all '
                   'other options)')
@click.pass_context
def addsig_pkcs11(ctx, infile, outfile, lib, token_label,
                  cert_label, key_label, slot_no, skip_user_pin, p11_setup,
                  raw_mechanism):
    from pyhanko.sign import pkcs11
    timestamp_url = ctx.obj[Ctx.TIMESTAMP_URL]

    if p11_setup:
        cli_config: CLIConfig = ctx.obj.get(Ctx.CLI_CONFIG, None)
        if cli_config is None:
            raise click.ClickException(
                "The --p11-setup option requires a configuration file"
            )
        try:
            pkcs11_config = cli_config.get_pkcs11_config(p11_setup)
        except ConfigurationError as e:
            msg = f"Error while reading PKCS#11 config {p11_setup}"
            logger.error(msg, exc_info=e)
            raise click.ClickException(msg)
    else:
        if not (lib and cert_label):
            raise click.ClickException(
                "The parameters --lib and --cert-label are required."
            )

        pinentry_mode = (
            PKCS11PinEntryMode.SKIP if skip_user_pin
            else PKCS11PinEntryMode.PROMPT
        )

        pkcs11_config = PKCS11SignatureConfig(
            module_path=lib, cert_label=cert_label, key_label=key_label,
            slot_no=slot_no, token_criteria=TokenCriteria(token_label),
            # for now, DEFER requires a config file
            prompt_pin=pinentry_mode,
            raw_mechanism=raw_mechanism
        )

    pin = pkcs11_config.user_pin

    # try to fetch the PIN from an env var
    if pin is None:
        pin_env = os.environ.get(P11_PIN_ENV_VAR, None)
        if pin_env:
            pin = pin_env.strip()

    if pkcs11_config.prompt_pin == PKCS11PinEntryMode.PROMPT \
            and pin is None:  # pragma: nocover
        pin = getpass.getpass(prompt='PKCS#11 user PIN: ')
    try:
        with pkcs11.PKCS11SigningContext(pkcs11_config, user_pin=pin) as signer:
            _sign_pkcs11(ctx, signer, infile, outfile, timestamp_url)
    except pkcs11.PKCS11Error as e:
        # This will catch errors that happen during PKCS#11 setup
        # TODO make sure PKCS11Signer doesn't leak PCKS11Errors in its
        #  generic signing API
        logger.error("PKCS#11 error", exc_info=e)
        raise click.ClickException(f"PKCS#11 error: [{type(e).__name__}] {e}")


@click.argument('infile', type=readable_file)
@click.argument('outfile', type=click.File('wb'))
@click.option('--lib', help='path to libbeidpkcs11 library file',
              type=readable_file, required=False)
@click.option('--use-auth-cert', type=bool, show_default=True,
              default=False, required=False, is_flag=True,
              help='use Authentication cert instead')
@click.option('--slot-no', help='specify PKCS#11 slot to use', 
              required=False, type=int, default=None)
@click.pass_context
def addsig_beid(ctx, infile, outfile, lib, use_auth_cert, slot_no):
    from pyhanko.sign import beid
    if not lib:
        cli_config: CLIConfig = ctx.obj.get(Ctx.CLI_CONFIG, None)
        if cli_config is None or cli_config.beid_module_path is None:
            raise click.ClickException(
                "The --lib option is mandatory unless beid-module-path is "
                "provided in the configuration file."
            )
        lib = cli_config.beid_module_path

    timestamp_url = ctx.obj[Ctx.TIMESTAMP_URL]

    try:
        session = beid.open_beid_session(lib, slot_no=slot_no)
    except pkcs11.PKCS11Error as e:
        logger.error("PKCS#11 error", exc_info=e)
        raise click.ClickException(f"PKCS#11 error: [{type(e).__name__}] {e}")
    with session:
        signer = beid.BEIDSigner(session, use_auth_cert=use_auth_cert)
        _sign_pkcs11(ctx, signer, infile, outfile, timestamp_url)


def _pkcs11_cmd(name, hlp, fun):
    addsig.command(name=name, help=hlp)(fun)


PKCS11_COMMANDS = [
    ('pkcs11', 'use generic PKCS#11 device to sign', addsig_pkcs11),
    ('beid', 'use Belgian eID to sign', addsig_beid)
]


def _process_pkcs11_commands():
    if pkcs11_available:
        for args in PKCS11_COMMANDS:
            _pkcs11_cmd(*args)
    else:
        def _unavailable():
            raise click.ClickException(
                "This subcommand requires python-pkcs11 to be installed."
            )
        for name, hlp, fun in PKCS11_COMMANDS:
            _pkcs11_cmd(name, hlp + ' [dependencies missing]', _unavailable)


_process_pkcs11_commands()


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
    if password and recipient:
        raise click.ClickException(
            "Specify either a password or a list of recipients."
        )
    elif not password and not recipient:
        password = getpass.getpass(prompt='Output file password: ')

    recipient_certs = None
    if recipient:
        recipient_certs = list(
            load_certs_from_pemder(cert_files=recipient)
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
            if auth_result.status == crypt.AuthStatus.USER and not force:
                raise click.ClickException(
                    "Password specified was the user password, not "
                    "the owner password. Pass --force to decrypt the "
                    "file anyway."
                )
            elif auth_result.status == crypt.AuthStatus.FAILED:
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
@click.option('--no-pass',
              help='assume the private key file is unencrypted',
              type=bool, is_flag=True, default=False, show_default=True)
@decrypt_force_flag
def decrypt_with_pemder(infile, outfile, key, cert, passfile, force, no_pass):
    if passfile is not None:
        passphrase = passfile.read()
        passfile.close()
    elif not no_pass:
        passphrase = getpass.getpass(prompt='Key passphrase: ').encode('utf-8')
        if not passphrase:
            _warn_empty_passphrase()
    else:
        passphrase = None

    sedk = crypt.SimpleEnvelopeKeyDecrypter.load(
        key, cert, key_passphrase=passphrase
    )

    _decrypt_pubkey(sedk, infile, outfile, force)


def _decrypt_pubkey(sedk: crypt.SimpleEnvelopeKeyDecrypter, infile, outfile,
                    force):
    with pyhanko_exception_manager():
        with open(infile, 'rb') as inf:
            r = PdfFileReader(inf)
            if r.security_handler is None:
                raise click.ClickException("File is not encrypted.")
            if not isinstance(r.security_handler, crypt.PubKeySecurityHandler):
                raise click.ClickException(
                    "File was not encrypted with a public-key security handler."
                )
            auth_result = r.decrypt_pubkey(sedk)
            if auth_result.status == crypt.AuthStatus.USER:
                # TODO read 2nd bit of perms in CMS enveloped data
                #  is the one indicating that change of encryption is OK
                if not force:
                    raise click.ClickException(
                        "Change of encryption is typically not allowed with "
                        "user access. Pass --force to decrypt the file anyway."
                    )
            elif auth_result.status == crypt.AuthStatus.FAILED:
                raise click.ClickException("Failed to decrypt the file.")
            w = copy_into_new_writer(r)
            with open(outfile, 'wb') as outf:
                w.write(outf)


@decrypt.command(help='decrypt using private key (PKCS#12)', name='pkcs12')
@click.argument('infile', type=readable_file)
@click.argument('outfile', type=click.Path(writable=True, dir_okay=False))
@click.argument('pfx', type=readable_file)
@click.option('--passfile', required=False, type=click.File('r'),
              help='file containing the passphrase for the PKCS#12 file',
              show_default='stdin')
@decrypt_force_flag
def decrypt_with_pkcs12(infile, outfile, pfx, passfile, force):
    if passfile is None:
        passphrase = getpass.getpass(prompt='Key passphrase: ').encode('utf-8')
    else:
        passphrase = passfile.readline().strip().encode('utf-8')
        passfile.close()
    sedk = crypt.SimpleEnvelopeKeyDecrypter.load_pkcs12(
        pfx, passphrase=passphrase
    )

    _decrypt_pubkey(sedk, infile, outfile, force)
