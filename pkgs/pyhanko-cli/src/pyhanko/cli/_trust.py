import asyncio
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Dict, Iterable, Optional, TypeVar, Union

import click
from asn1crypto import x509
from pyhanko.cli.cache import get_eutl_cache_dir
from pyhanko.cli.config import DEFAULT_TIME_TOLERANCE, CLIConfig
from pyhanko.cli.utils import logger, readable_file
from pyhanko.config import api
from pyhanko.config.errors import ConfigurationError
from pyhanko.keys import load_certs_from_pemder
from pyhanko.sign.validation.qualified.tsp import (
    CA_QC_URI,
    BaseServiceInformation,
    CAServiceInformation,
    CriteriaCombination,
    CriteriaList,
    Qualification,
    Qualifier,
    TSPTrustManager,
)
from pyhanko_certvalidator.registry import SimpleTrustManager, TrustManager

__all__ = [
    'TrustManagerSettings',
    'init_trust_manager',
    'init_validation_context_kwargs',
    'parse_trust_config',
]


DEFAULT_TL_CACHE_REFRESH_TIME = timedelta(days=15)


@dataclass(frozen=True)
class TrustManagerSettings:
    trust: Union[Iterable[str], str, None]
    trust_replace: bool
    eutl: bool
    eutl_lotl_url: Optional[str] = None
    lotl_tlso_certs: Optional[str] = None

    # TODO options to force cache refresh,
    #  limit territories to download, etc.


async def init_trust_manager(
    settings: TrustManagerSettings,
    cli_config: Optional[CLIConfig],
):
    if isinstance(settings.trust, str):
        trust = {settings.trust}
    elif settings.trust is not None:
        trust = set(settings.trust)
    else:
        trust = set()
    # add trust roots to the validation context, or replace them
    trust_certs = list(load_certs_from_pemder(trust))

    if settings.lotl_tlso_certs:
        lotl_tlso_certs = list(
            load_certs_from_pemder([settings.lotl_tlso_certs])
        )
    else:
        lotl_tlso_certs = None

    trust_manager: TrustManager

    if settings.eutl:
        # TODO check availability of imported stuff and return a nice error
        import aiohttp
        from pyhanko.sign.validation.qualified.eutl_fetch import (
            EU_LOTL_LOCATION,
            FileSystemTLCache,
            fetch_lotl,
            lotl_to_registry,
        )

        cache_dir = get_eutl_cache_dir(cli_config)
        # TODO refresh time should be customisable, also respect expiration times on TLs
        tl_cache = FileSystemTLCache(
            cache_dir, expire_after=DEFAULT_TL_CACHE_REFRESH_TIME
        )

        async with aiohttp.ClientSession() as client:
            try:
                lotl_xml = await fetch_lotl(
                    client, tl_cache, settings.eutl_lotl_url or EU_LOTL_LOCATION
                )
                registry, errors = await lotl_to_registry(
                    lotl_xml=lotl_xml,
                    client=client,
                    cache=tl_cache,
                    lotl_tlso_certs=lotl_tlso_certs,
                )
            except Exception as e:
                raise click.ClickException(
                    f"Trust list processing failed: {e}"
                ) from e
            if errors:
                err_str = "\n- ".join(str(e) for e in errors)
                logger.warning(
                    f"Errors encountered during trust list processing; "
                    f"registry may be incomplete.\n{err_str}"
                )
        cert: x509.Certificate
        for cert in trust_certs:
            # define a new CA service
            registry.register_ca(
                CAServiceInformation(
                    BaseServiceInformation(
                        service_type=CA_QC_URI,
                        service_name=cert.subject.human_friendly,
                        valid_from=cert.not_valid_before,
                        valid_until=cert.not_valid_after,
                        provider_certs=(cert,),
                        additional_info_certificate_type=frozenset(),
                        other_additional_info=frozenset(),
                    ),
                    qualifications=frozenset(
                        [
                            Qualification(
                                qualifiers=frozenset([Qualifier.NOT_QUALIFIED]),
                                criteria_list=CriteriaList(
                                    CriteriaCombination.ALL, frozenset()
                                ),
                            )
                        ]
                    ),
                    expired_certs_revocation_info=None,
                )
            )
        trust_manager = TSPTrustManager(tsp_registry=registry)
    else:
        if settings.trust_replace:
            trust_manager = SimpleTrustManager.build(trust_roots=trust_certs)
        else:
            trust_manager = SimpleTrustManager.build(
                extra_trust_roots=trust_certs
            )

    return trust_manager


def init_validation_context_kwargs(
    *,
    cli_config: Optional[CLIConfig],
    trust_manager_settings: TrustManagerSettings,
    other_certs: Union[Iterable[str], str],
    retroactive_revinfo: bool = False,
    time_tolerance: Union[timedelta, int, None] = None,
) -> Dict[str, Any]:
    if not isinstance(time_tolerance, timedelta):
        if time_tolerance is None:
            time_tolerance = DEFAULT_TIME_TOLERANCE
        elif isinstance(time_tolerance, int):
            time_tolerance = timedelta(seconds=time_tolerance)
        else:
            raise ConfigurationError(
                "time-tolerance parameter must be specified in seconds"
            )
    vc_kwargs: Dict[str, Any] = {'time_tolerance': time_tolerance}
    if retroactive_revinfo:
        vc_kwargs['retroactive_revinfo'] = True
    trust_manager = asyncio.run(
        init_trust_manager(trust_manager_settings, cli_config)
    )
    vc_kwargs['trust_manager'] = trust_manager
    if other_certs:
        if isinstance(other_certs, str):
            other_certs = (other_certs,)
        vc_kwargs['other_certs'] = list(load_certs_from_pemder(other_certs))
    return vc_kwargs


def parse_trust_config(
    trust_config,
    time_tolerance,
    retroactive_revinfo,
    cli_config: CLIConfig,
) -> dict:
    api.check_config_keys(
        'ValidationContext',
        (
            'trust',
            'trust-replace',
            'other-certs',
            'time-tolerance',
            'retroactive-revinfo',
            'signer-key-usage',
            'signer-extd-key-usage',
            'signer-key-usage-policy',
            'eutl',
            'eutl-lotl-url',
            'lotl-tlso-certs',
        ),
        trust_config,
    )
    return init_validation_context_kwargs(
        cli_config=cli_config,
        trust_manager_settings=TrustManagerSettings(
            trust=trust_config.get('trust'),
            trust_replace=trust_config.get('trust-replace', False),
            eutl=trust_config.get('eutl', False),
            eutl_lotl_url=trust_config.get('eutl-lotl-url', None),
            lotl_tlso_certs=trust_config.get('lotl-tlso-certs', None),
        ),
        other_certs=trust_config.get('other-certs'),
        time_tolerance=trust_config.get('time-tolerance', time_tolerance),
        retroactive_revinfo=trust_config.get(
            'retroactive-revinfo', retroactive_revinfo
        ),
    )


def build_vc_kwargs(
    *,
    cli_config: Optional[CLIConfig],
    validation_context: Optional[str],
    trust: Union[Iterable[str], str],
    trust_replace: bool,
    eutl: bool,
    other_certs: Union[Iterable[str], str],
    retroactive_revinfo: bool,
    allow_fetching: Optional[bool] = None,
):
    overrides = {}
    if retroactive_revinfo:
        overrides['retroactive_revinfo'] = True
    if eutl:
        overrides['eutl'] = True
    try:
        if validation_context is not None:
            if any((trust, other_certs)):
                raise click.ClickException(
                    "--validation-context is incompatible with other "
                    "trust-related settings"
                )
            # load the desired context from config
            if cli_config is None:
                raise click.ClickException("No config file specified.")
            try:
                result = cli_config.get_validation_context(
                    validation_context,
                    as_dict=True,
                    overrides=overrides,
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
            # always load a validation profile using command
            # line kwargs if the --trust or --other-certs
            # arguments are provided
            result = init_validation_context_kwargs(
                cli_config=cli_config,
                trust_manager_settings=TrustManagerSettings(
                    trust=trust,
                    trust_replace=trust_replace,
                    eutl=eutl,
                ),
                other_certs=other_certs,
                retroactive_revinfo=retroactive_revinfo,
            )
        elif cli_config is not None:
            # load the default settings from the CLI config
            try:
                result = cli_config.get_validation_context(
                    as_dict=True,
                    overrides=overrides,
                )
            except ConfigurationError as e:
                msg = "Failed to load default validation context."
                logger.error(msg, exc_info=e)
                raise click.ClickException(msg)
        else:
            # load defaults given other arguments
            result = init_validation_context_kwargs(
                cli_config=None,
                trust_manager_settings=TrustManagerSettings(
                    trust=None,
                    trust_replace=trust_replace,
                    eutl=eutl,
                ),
                other_certs=[],
                retroactive_revinfo=retroactive_revinfo,
            )

        if allow_fetching is not None:
            result['allow_fetching'] = allow_fetching
        else:
            result.setdefault('allow_fetching', True)

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


def _get_key_usage_settings(ctx: click.Context, validation_context: str):
    cli_config: Optional[CLIConfig] = ctx.obj.config
    if cli_config is None:
        return None

    # note: validation_context can be None, this triggers fallback to the
    # default validation context specified in the configuration file
    # If we add support for specifying key usage settings as CLI arguments,
    # using the same fallbacks as _build_cli_kwargs would probably be cleaner
    return cli_config.get_signer_key_usages(name=validation_context)


TRUST_OPTIONS = [
    click.Option(
        ('--validation-context',),
        help='use validation context from config',
        required=False,
        type=str,
    ),
    click.Option(
        ('--trust',),
        help='list trust roots (multiple allowed)',
        required=False,
        multiple=True,
        type=readable_file,
    ),
    click.Option(
        ('--trust-replace',),
        help='listed trust roots supersede OS-provided trust store',
        required=False,
        type=bool,
        is_flag=True,
        default=False,
        show_default=True,
    ),
    click.Option(
        ('--eutl',),
        help='source trust from EU trusted list (disregard OS trust store)',
        required=False,
        type=bool,
        is_flag=True,
        default=False,
        show_default=True,
    ),
    click.Option(
        ('--other-certs',),
        help='other certs relevant for validation',
        required=False,
        multiple=True,
        type=readable_file,
    ),
]


FC = TypeVar('FC', bound=click.Command)


def trust_options(f: FC) -> FC:
    f.params.extend(TRUST_OPTIONS)
    return f


def _prepare_vc(vc_kwargs, soft_revocation_check, force_revinfo):
    if soft_revocation_check and force_revinfo:
        raise click.ClickException(
            "--soft-revocation-check is incompatible with --force-revinfo"
        )
    if force_revinfo:
        rev_mode = 'require'
    elif soft_revocation_check:
        rev_mode = 'soft-fail'
    else:
        rev_mode = 'hard-fail'
    vc_kwargs['revocation_mode'] = rev_mode
    return vc_kwargs


def grab_certs(files):
    if not files:
        return None
    try:
        return list(load_certs_from_pemder(files))
    except (IOError, ValueError) as e:
        raise click.ClickException(
            f'Could not load certificates from {files}'
        ) from e
