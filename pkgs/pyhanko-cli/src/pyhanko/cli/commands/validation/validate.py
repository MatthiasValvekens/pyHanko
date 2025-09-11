import asyncio
import getpass
import warnings
from dataclasses import replace
from datetime import datetime

import click
import pyhanko.sign
from asn1crypto import cms, pem
from pyhanko.cli._trust import (
    _get_key_usage_settings,
    build_cert_validation_policy_and_extract_extra_certs,
    build_vc_kwargs,
    trust_options,
)
from pyhanko.cli.commands.signing import signing
from pyhanko.cli.runtime import pyhanko_exception_manager
from pyhanko.cli.utils import logger
from pyhanko.keys import load_certs_from_pemder
from pyhanko.pdf_utils import crypt
from pyhanko.pdf_utils.misc import isoparse
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import validation
from pyhanko.sign.diff_analysis import DEFAULT_DIFF_POLICY
from pyhanko.sign.validation import RevocationInfoValidationType
from pyhanko.sign.validation.ades import (
    AdESLTAValidationResult,
    ades_lta_validation,
)
from pyhanko.sign.validation.errors import (
    SignatureValidationError,
    ValidationInfoReadingError,
)
from pyhanko.sign.validation.policy_decl import (
    LocalKnowledge,
    PdfSignatureValidationSpec,
    QualificationRequirements,
    SignatureValidationSpec,
)
from pyhanko.sign.validation.qualified.tsp import QTST_URI
from pyhanko.sign.validation.status import format_pretty_print_details
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.ltv.types import ValidationTimingInfo
from pyhanko_certvalidator.policy_decl import (
    NO_REVOCATION,
    REQUIRE_REVINFO,
    CertRevTrustPolicy,
    FreshnessReqType,
)

__all__ = ['validate_signatures', 'ades_validate_signatures']


def _assert_consistent_print_settings(pretty_print, executive_summary):
    if pretty_print and executive_summary:
        raise click.ClickException(
            "--pretty-print is incompatible with --executive-summary."
        )


def _pretty_print_result(name, ix, status_str):
    header = f'Field {ix + 1}: {name}'
    line = '=' * len(header)
    click.echo(line)
    click.echo(header)
    click.echo(line)
    click.echo('\n\n' + status_str)


def _print_summary_result(name, fingerprint, status_str):
    click.echo('%s:%s:%s' % (name, fingerprint, status_str))


def _signature_status(
    ltv_profile,
    vc_kwargs,
    force_revinfo,
    key_usage_settings,
    embedded_sig,
    skip_diff=False,
):
    if ltv_profile is None:
        vc = ValidationContext(**vc_kwargs)
        status = pyhanko.sign.validation.validate_pdf_signature(
            embedded_sig,
            key_usage_settings=key_usage_settings,
            signer_validation_context=vc,
            skip_diff=skip_diff,
        )
    else:
        warnings.warn(
            "LTV validation as part of the validate command is deprecated. "
            "Use pyhanko sign adesverify instead.",
            UserWarning,
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=DeprecationWarning)
            # noinspection PyDeprecation
            status = validation.validate_pdf_ltv_signature(
                embedded_sig,
                ltv_profile,
                key_usage_settings=key_usage_settings,
                force_revinfo=force_revinfo,
                validation_context_kwargs=vc_kwargs,
                skip_diff=skip_diff,
            )
    return status


def _validate_detached(
    infile, sig_infile, validation_context, key_usage_settings
):
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
        infile,
        signed_data=content_info['content'],
        signer_validation_context=validation_context,
        key_usage_settings=key_usage_settings,
    )
    return asyncio.run(validation_coro)


def _signature_status_str(status_callback, pretty_print, executive_summary):
    try:
        result = status_callback()
        if isinstance(result, AdESLTAValidationResult):
            status = result.api_status
            extra_sections = []
        else:
            status = result
            extra_sections = []
        if executive_summary and not pretty_print:
            return (
                'VALID' if status.bottom_line else 'INVALID',
                status.bottom_line,
            )
        elif pretty_print:
            pretty_printed = format_pretty_print_details(status, extra_sections)
            return pretty_printed, status.bottom_line
        else:
            return status.summary(), status.bottom_line
    except ValidationInfoReadingError as e:
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


def _open_file_for_validation(infile, no_strict_syntax, password):
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
        auth_result = None
        if password is None:
            # attempt the empty user password first--validation is a read-only
            # operation, so this is in line with expected UX in other viewers.
            empty_auth_result = r.decrypt("")
            if empty_auth_result.status == crypt.AuthStatus.FAILED:
                password = getpass.getpass(prompt='File password: ')
            else:
                auth_result = empty_auth_result
        if not auth_result:
            auth_result = r.decrypt(password)
        if auth_result.status == crypt.AuthStatus.FAILED:
            raise click.ClickException("Password didn't match.")
    elif sh is not None:
        raise click.ClickException(
            "The CLI supports only password-based encryption when "
            "validating (for now)"
        )
    return r


@trust_options
@signing.command(name='validate', help='validate signatures')
@click.argument('infile', type=click.File('rb'))
@click.option(
    '--executive-summary',
    help='only print final judgment on signature validity',
    type=bool,
    is_flag=True,
    default=False,
    show_default=True,
)
@click.option(
    '--pretty-print',
    help='render a prettier summary for the signatures in the file',
    type=bool,
    is_flag=True,
    default=False,
    show_default=True,
)
@click.option(
    '--ltv-profile',
    help='LTV signature validation profile',
    type=click.Choice(RevocationInfoValidationType.as_tuple()),
    required=False,
)
@click.option(
    '--force-revinfo',
    help='Fail trust validation if a certificate has no known CRL '
    'or OCSP endpoints.',
    type=bool,
    is_flag=True,
    default=False,
    show_default=True,
)
@click.option(
    '--soft-revocation-check',
    help='Do not fail validation on revocation checking failures '
    '(only applied to on-line revocation checks)',
    type=bool,
    is_flag=True,
    default=False,
    show_default=True,
)
@click.option(
    '--no-revocation-check',
    help='Do not attempt to check revocation status '
    '(meaningless for LTV validation)',
    type=bool,
    is_flag=True,
    default=False,
    show_default=True,
)
@click.option(
    '--retroactive-revinfo',
    help='Treat revocation info as retroactively valid '
    '(i.e. ignore thisUpdate timestamp)',
    type=bool,
    is_flag=True,
    default=False,
    show_default=True,
)
@click.option(
    '--validation-time',
    help=(
        'Override the validation time (ISO 8601 date). '
        'The special value \'claimed\' causes the validation time '
        'claimed by the signer to be used. Revocation checking '
        'will be disabled. Option ignored in LTV mode.'
    ),
    type=str,
    required=False,
)
@click.option(
    '--password',
    required=False,
    type=str,
    help='password to access the file (can also be read from stdin)',
)
@click.option(
    '--no-diff-analysis',
    default=False,
    type=bool,
    is_flag=True,
    help='disable incremental update analysis',
)
@click.option(
    '--detached',
    type=click.File('rb'),
    help=(
        'Read signature CMS object from the indicated file; '
        'this can be used to verify signatures on non-PDF files'
    ),
)
@click.option(
    '--no-strict-syntax',
    help='Attempt to ignore syntactical problems in the input file '
    'and enable signature validation in hybrid-reference files.'
    '(warning: this may affect validation results in unexpected '
    'ways.)',
    type=bool,
    is_flag=True,
    default=False,
    show_default=True,
)
@click.pass_context
def validate_signatures(
    ctx: click.Context,
    infile,
    executive_summary,
    pretty_print,
    validation_context,
    trust,
    trust_replace,
    eutl_all,
    eutl_force_redownload,
    eutl_territories,
    other_certs,
    ltv_profile,
    force_revinfo,
    soft_revocation_check,
    no_revocation_check,
    password,
    retroactive_revinfo,
    detached,
    no_diff_analysis,
    validation_time,
    no_strict_syntax,
):
    if sum((soft_revocation_check, force_revinfo, no_revocation_check)) > 1:
        raise click.ClickException(
            "--soft-revocation-check, --force-revinfo and "
            "--no-revocation-check are incompatible"
        )
    no_revocation_check |= validation_time is not None

    if no_revocation_check:
        soft_revocation_check = True

    _assert_consistent_print_settings(pretty_print, executive_summary)
    if ltv_profile is not None:
        if validation_time is not None:
            raise click.ClickException(
                "--validation-time is not compatible with --ltv-profile"
            )
        ltv_profile = RevocationInfoValidationType(ltv_profile)

    if no_revocation_check:
        rev_mode = 'none'
    else:
        if force_revinfo:
            rev_mode = 'require'
        elif soft_revocation_check:
            rev_mode = 'soft-fail'
        else:
            rev_mode = 'hard-fail'

    vc_kwargs = build_vc_kwargs(
        cli_config=ctx.obj.config,
        validation_context=validation_context,
        trust=trust,
        trust_replace=trust_replace,
        other_certs=other_certs,
        eutl_all=eutl_all,
        eutl_force_redownload=eutl_force_redownload,
        eutl_territories=eutl_territories,
        retroactive_revinfo=retroactive_revinfo,
        allow_fetching=not no_revocation_check,
        revocation_policy=rev_mode,
    )

    use_claimed_validation_time = False
    if validation_time == 'claimed':
        use_claimed_validation_time = True
    elif validation_time is not None:
        vc_kwargs['moment'] = _attempt_iso_dt_parse(validation_time)

    key_usage_settings = _get_key_usage_settings(ctx, validation_context)
    with pyhanko_exception_manager():
        if detached is not None:
            (status_str, signature_ok) = _signature_status_str(
                status_callback=lambda: _validate_detached(
                    infile,
                    detached,
                    ValidationContext(**vc_kwargs),
                    key_usage_settings,
                ),
                pretty_print=pretty_print,
                executive_summary=executive_summary,
            )
            if signature_ok:
                click.echo(status_str)
            else:
                raise click.ClickException(status_str)
            return

        r = _open_file_for_validation(infile, no_strict_syntax, password)
        all_signatures_ok = True
        for ix, embedded_sig in enumerate(r.embedded_regular_signatures):
            fingerprint: str = embedded_sig.signer_cert.sha256.hex()
            if use_claimed_validation_time:
                vc_kwargs['moment'] = embedded_sig.self_reported_timestamp
            (status_str, signature_ok) = _signature_status_str(
                status_callback=lambda: _signature_status(
                    ltv_profile=ltv_profile,
                    force_revinfo=force_revinfo,
                    vc_kwargs=vc_kwargs,
                    key_usage_settings=key_usage_settings,
                    embedded_sig=embedded_sig,
                    skip_diff=no_diff_analysis,
                ),
                pretty_print=pretty_print,
                executive_summary=executive_summary,
            )
            if pretty_print:
                _pretty_print_result(embedded_sig.field_name, ix, status_str)
            else:
                _print_summary_result(
                    embedded_sig.field_name, fingerprint, status_str
                )
            all_signatures_ok &= signature_ok

        if not all_signatures_ok:
            raise click.ClickException("Validation failed")


@trust_options
@signing.command(name='adesverify', help='validate signatures AdES-style')
@click.argument('infile', type=click.File('rb'))
@click.option(
    '--executive-summary',
    help='only print final judgment on signature validity',
    type=bool,
    is_flag=True,
    default=False,
    show_default=True,
)
@click.option(
    '--pretty-print',
    help='render a prettier summary for the signatures in the file',
    type=bool,
    is_flag=True,
    default=False,
    show_default=True,
)
@click.option(
    '--no-revocation-check',
    help='Do not attempt to check revocation status.',
    type=bool,
    is_flag=True,
    default=False,
    show_default=True,
)
@click.option(
    '--validation-time',
    help=('Override the validation time (ISO 8601 date).'),
    type=str,
    required=False,
)
@click.option(
    '--password',
    required=False,
    type=str,
    help='password to access the file (can also be read from stdin)',
)
@click.option(
    '--no-diff-analysis',
    default=False,
    type=bool,
    is_flag=True,
    help='disable incremental update analysis',
)
@click.option(
    '--require-qualified',
    default=False,
    type=bool,
    is_flag=True,
    help=(
        'require qualified signing certificates and '
        'TSAs (only meaningful with --eutl-* options)'
    ),
)
@click.option(
    '--no-strict-syntax',
    help='Attempt to ignore syntactical problems in the input file '
    'and enable signature validation in hybrid-reference files. '
    '(warning: this may affect validation results in unexpected '
    'ways.)',
    type=bool,
    is_flag=True,
    default=False,
    show_default=True,
)
@click.pass_context
def ades_validate_signatures(
    ctx: click.Context,
    infile,
    executive_summary,
    pretty_print,
    validation_context,
    trust,
    trust_replace,
    eutl_all,
    eutl_force_redownload,
    eutl_territories,
    other_certs,
    no_revocation_check,
    password,
    no_diff_analysis,
    validation_time,
    no_strict_syntax,
    require_qualified,
):
    _assert_consistent_print_settings(pretty_print, executive_summary)
    cert_policy, other_certs = (
        build_cert_validation_policy_and_extract_extra_certs(
            cli_config=ctx.obj.config,
            validation_context=validation_context,
            trust=trust,
            trust_replace=trust_replace,
            other_certs=other_certs,
            eutl_all=eutl_all,
            eutl_force_redownload=eutl_force_redownload,
            eutl_territories=eutl_territories,
            revocation_policy=None,
        )
    )

    if validation_time:
        parsed_time = _attempt_iso_dt_parse(validation_time)
        timing_info = ValidationTimingInfo(
            parsed_time, parsed_time, point_in_time_validation=True
        )
    else:
        timing_info = ValidationTimingInfo.now()

    if no_revocation_check:
        rev_policy = CertRevTrustPolicy(NO_REVOCATION)
    else:
        rev_policy = CertRevTrustPolicy(
            REQUIRE_REVINFO,
            freshness=None,
            freshness_req_type=FreshnessReqType.MAX_DIFF_REVOCATION_VALIDATION,
        )
    cert_policy = replace(cert_policy, revinfo_policy=rev_policy)
    sig_policy = SignatureValidationSpec(
        cert_validation_policy=cert_policy,
        local_knowledge=LocalKnowledge(
            known_certs=list(load_certs_from_pemder(other_certs)),
        ),
        qualification_requirements=(
            QualificationRequirements() if require_qualified else None
        ),
        ts_qualification_requirements=(
            QualificationRequirements(require_service_type=QTST_URI)
            if require_qualified
            else None
        ),
    )
    pdf_sig_policy = PdfSignatureValidationSpec(
        signature_validation_spec=sig_policy,
        diff_policy=None if no_diff_analysis else DEFAULT_DIFF_POLICY,
    )

    with pyhanko_exception_manager():
        r = _open_file_for_validation(infile, no_strict_syntax, password)
        all_signatures_ok = True
        for ix, embedded_sig in enumerate(r.embedded_regular_signatures):
            fingerprint: str = embedded_sig.signer_cert.sha256.hex()
            (status_str, signature_ok) = _signature_status_str(
                status_callback=lambda: asyncio.run(
                    ades_lta_validation(
                        embedded_sig,
                        pdf_sig_policy,
                        timing_info=timing_info,
                    )
                ),
                pretty_print=pretty_print,
                executive_summary=executive_summary,
            )
            if pretty_print:
                _pretty_print_result(embedded_sig.field_name, ix, status_str)
            else:
                _print_summary_result(
                    embedded_sig.field_name, fingerprint, status_str
                )
            all_signatures_ok &= signature_ok

        if not all_signatures_ok:
            raise click.ClickException("Validation failed")
