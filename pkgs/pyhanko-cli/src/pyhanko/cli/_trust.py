import asyncio
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Dict, Iterable, Optional, TypeVar, Union

import click
from asn1crypto import x509
from pyhanko.cli.cache import get_eutl_cache_dir
from pyhanko.cli.config import (
    DEFAULT_TIME_TOLERANCE,
    CLIConfig,
    parse_time_tolerance,
)
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
from pyhanko_certvalidator.authority import AuthorityWithCert
from pyhanko_certvalidator.context import (
    CertValidationPolicySpec,
    ValidationDataHandlers,
)
from pyhanko_certvalidator.fetchers.requests_fetchers import (
    RequestsFetcherBackend,
)
from pyhanko_certvalidator.ltv.poe import POEManager
from pyhanko_certvalidator.ltv.types import ValidationTimingInfo
from pyhanko_certvalidator.policy_decl import (
    CertRevTrustPolicy,
    RevocationCheckingPolicy,
)
from pyhanko_certvalidator.registry import (
    CertificateRegistry,
    SimpleTrustManager,
    TrustManager,
)

__all__ = [
    'TrustManagerSettings',
    'init_trust_manager',
    'build_vc_kwargs',
]

from pyhanko_certvalidator.revinfo.manager import RevinfoManager

DEFAULT_TL_CACHE_REFRESH_TIME = timedelta(days=15)


@dataclass(frozen=True)
class TrustManagerSettings:
    trust: Union[Iterable[str], str, None]
    trust_replace: bool
    eutl: bool
    eutl_force_redownload: bool
    eutl_lotl_url: Optional[str] = None
    lotl_tlso_certs: Optional[str] = None
    territories: Union[Iterable[str], str, None] = None


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
        try:
            import aiohttp
            from pyhanko.sign.validation.qualified.eutl_fetch import (
                EU_LOTL_LOCATION,
                FileSystemTLCache,
                fetch_lotl,
                lotl_to_registry,
            )
        except ImportError as e:  # pragma: nocover
            raise click.ClickException(
                "Install pyHanko with the [async-http,etsi] optional "
                "dependency groups"
            ) from e

        cache_dir = get_eutl_cache_dir(cli_config)
        # TODO refresh time should be customisable,
        #  also respect expiration times on TLs
        tl_cache = FileSystemTLCache(
            cache_dir, expire_after=DEFAULT_TL_CACHE_REFRESH_TIME
        )

        if settings.eutl_force_redownload:
            tl_cache.reset()

        async with aiohttp.ClientSession() as client:
            if isinstance(settings.territories, str) and settings.territories:
                territories = {
                    t.strip() for t in settings.territories.split(',')
                }
            elif settings.territories is not None:
                territories = set(settings.territories)
            else:
                territories = None
            try:
                lotl_xml = await fetch_lotl(
                    client, tl_cache, settings.eutl_lotl_url or EU_LOTL_LOCATION
                )
                registry, errors = await lotl_to_registry(
                    lotl_xml=lotl_xml,
                    client=client,
                    cache=tl_cache,
                    lotl_tlso_certs=lotl_tlso_certs,
                    only_territories=territories,
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
            authority = AuthorityWithCert(cert)
            if authority in registry.known_certificate_authorities:
                continue
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


def _parse_other_certs(config_dict):
    other_certs_from_config = config_dict.get("other-certs", [])
    if isinstance(other_certs_from_config, str):
        return [other_certs_from_config]
    elif isinstance(other_certs_from_config, list):
        return other_certs_from_config
    else:
        raise ConfigurationError(
            "other-certs must be a string or a list of strings"
        )


def build_cert_validation_policy_and_extract_extra_certs(
    *,
    cli_config: Optional[CLIConfig],
    validation_context: Optional[str],
    trust: Union[Iterable[str], str],
    trust_replace: bool,
    eutl_all: bool,
    eutl_force_redownload: bool,
    eutl_territories: Optional[str],
    other_certs: Iterable[str],
    revocation_policy: Optional[str],
):
    overrides: Dict[str, Any] = {}
    if eutl_territories == '':
        raise click.ClickException(
            "argument to --eutl-territories must be non-empty"
        )
    if eutl_all and eutl_territories is not None:
        raise click.ClickException(
            "--eutl-all and --eutl-territories are mutually exclusive"
        )
    elif eutl_all:
        eutl = True
        eutl_territories = None
        overrides['eutl-territories'] = 'all'
    elif eutl_territories:
        eutl = True
        overrides['eutl-territories'] = eutl_territories
    else:
        eutl = False
    other_certs = list(other_certs)
    if eutl_force_redownload:
        overrides['eutl-force-redownload'] = True
    if revocation_policy:
        overrides['revocation-policy'] = revocation_policy
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
                vc_config_raw = cli_config.get_validation_settings_raw(
                    validation_context
                )
                vc_config_raw.update(overrides)
                cert_validation_policy = parse_trust_config_into_policy(
                    vc_config_raw,
                    cli_config=cli_config,
                )
                other_certs.extend(_parse_other_certs(vc_config_raw))
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
            cert_validation_policy = derive_cert_validation_policy(
                cli_config=cli_config,
                trust_manager_settings=TrustManagerSettings(
                    trust=trust,
                    trust_replace=trust_replace,
                    eutl=eutl,
                    territories=eutl_territories,
                    eutl_force_redownload=eutl_force_redownload,
                ),
                revinfo_policy=revocation_policy or 'require',
            )
        elif cli_config is not None:
            # load the default settings from the CLI config
            try:
                vc_config_raw = cli_config.get_validation_settings_raw(
                    validation_context
                )
                vc_config_raw.update(overrides)
                cert_validation_policy = parse_trust_config_into_policy(
                    vc_config_raw,
                    cli_config=cli_config,
                )
                other_certs.extend(_parse_other_certs(vc_config_raw))
            except ConfigurationError as e:
                msg = "Failed to load default validation context."
                logger.error(msg, exc_info=e)
                raise click.ClickException(msg)
        else:
            # load defaults given other arguments
            cert_validation_policy = derive_cert_validation_policy(
                cli_config=None,
                trust_manager_settings=TrustManagerSettings(
                    trust=None,
                    trust_replace=trust_replace,
                    eutl=eutl,
                    territories=eutl_territories,
                    eutl_force_redownload=eutl_force_redownload,
                ),
                revinfo_policy=revocation_policy or 'require',
            )

        return cert_validation_policy, other_certs
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


def derive_cert_validation_policy(
    *,
    cli_config: Optional[CLIConfig],
    trust_manager_settings: TrustManagerSettings,
    revinfo_policy: str,
    retroactive_revinfo: Optional[bool] = None,
    time_tolerance: Optional[timedelta] = None,
) -> CertValidationPolicySpec:
    if time_tolerance is None:
        if cli_config:
            time_tolerance = cli_config.time_tolerance or DEFAULT_TIME_TOLERANCE
        else:
            time_tolerance = DEFAULT_TIME_TOLERANCE
    if retroactive_revinfo is None:
        if cli_config:
            retroactive_revinfo = cli_config.retroactive_revinfo
        else:
            retroactive_revinfo = False
    trust_manager = asyncio.run(
        init_trust_manager(trust_manager_settings, cli_config)
    )
    return CertValidationPolicySpec(
        trust_manager=trust_manager,
        revinfo_policy=CertRevTrustPolicy(
            revocation_checking_policy=RevocationCheckingPolicy.from_legacy(
                revinfo_policy
            ),
            retroactive_revinfo=retroactive_revinfo,
        ),
        time_tolerance=time_tolerance,
    )


def init_handlers(
    other_certs: Union[Iterable[str], str],
    allow_fetching: bool,
):
    other_cert_objs = list(load_certs_from_pemder(other_certs))
    fetcher_backend = RequestsFetcherBackend()
    fetchers = fetcher_backend.get_fetchers() if allow_fetching else None
    cert_registry = CertificateRegistry(
        cert_fetcher=fetchers.cert_fetcher if fetchers else None,
    )
    cert_registry.register_multiple(other_cert_objs)
    poe_manager = POEManager()
    revinfo_manager = RevinfoManager(
        certificate_registry=cert_registry,
        poe_manager=poe_manager,
        crls=[],
        ocsps=[],
        fetchers=fetchers,
    )
    return ValidationDataHandlers(
        revinfo_manager=revinfo_manager,
        poe_manager=poe_manager,
        cert_registry=cert_registry,
    )


EXPECTED_CONFIG_KEYS = (
    'trust',
    'trust-replace',
    'other-certs',
    'time-tolerance',
    'retroactive-revinfo',
    'signer-key-usage',
    'signer-extd-key-usage',
    'signer-key-usage-policy',
    'eutl',
    'eutl-force-redownload',
    'eutl-lotl-url',
    'lotl-tlso-certs',
    'eutl-territories',
    'revocation-policy',
)


def parse_trust_config_into_policy(
    trust_config: dict,
    cli_config: CLIConfig,
) -> CertValidationPolicySpec:
    api.check_config_keys(
        'ValidationContext',
        EXPECTED_CONFIG_KEYS,
        trust_config,
    )
    territories: Any = trust_config.get('eutl-territories', None)
    if territories == 'all':
        territories = None
        eutl = True
    elif territories:
        eutl = True
    else:
        eutl = False
    return derive_cert_validation_policy(
        cli_config=cli_config,
        trust_manager_settings=TrustManagerSettings(
            trust=trust_config.get('trust'),
            trust_replace=trust_config.get('trust-replace', False),
            eutl=eutl,
            eutl_lotl_url=trust_config.get('eutl-lotl-url', None),
            lotl_tlso_certs=trust_config.get('lotl-tlso-certs', None),
            territories=territories,
            eutl_force_redownload=trust_config.get(
                'eutl-force-redownload', False
            ),
        ),
        time_tolerance=parse_time_tolerance(trust_config),
        revinfo_policy=trust_config.get('revocation-policy', 'require'),
        retroactive_revinfo=bool(
            trust_config.get(
                'retroactive-revinfo', cli_config.retroactive_revinfo
            )
        ),
    )


def build_vc_kwargs(
    *,
    cli_config: Optional[CLIConfig],
    validation_context: Optional[str],
    trust: Union[Iterable[str], str],
    trust_replace: bool,
    eutl_all: bool,
    eutl_force_redownload: bool,
    eutl_territories: Optional[str],
    other_certs: Union[Iterable[str], str],
    revocation_policy: Optional[str],
    retroactive_revinfo: bool,
    allow_fetching: bool,
):
    policy, other_certs = build_cert_validation_policy_and_extract_extra_certs(
        cli_config=cli_config,
        validation_context=validation_context,
        trust=trust,
        trust_replace=trust_replace,
        eutl_all=eutl_all,
        eutl_force_redownload=eutl_force_redownload,
        eutl_territories=eutl_territories,
        other_certs=other_certs,
        revocation_policy=revocation_policy,
    )
    handlers = init_handlers(
        other_certs=other_certs,
        allow_fetching=allow_fetching,
    )
    vc_kwargs = policy.build_validation_context_kwargs(
        ValidationTimingInfo.now(), handlers
    )
    if retroactive_revinfo:
        vc_kwargs['retroactive_revinfo'] = retroactive_revinfo
    return vc_kwargs


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
        ('--eutl-all',),
        help=(
            'source trust from the complete EU trusted list programme, '
            'covering all regions (note: this involves downloading all '
            'trusted lists for all territories, which can take '
            'considerable time)'
        ),
        required=False,
        type=bool,
        is_flag=True,
        default=False,
        show_default=True,
    ),
    click.Option(
        ('--eutl-force-redownload',),
        help='force re-downloading of the EUTL files by clearing the cache',
        required=False,
        type=bool,
        is_flag=True,
        default=False,
        show_default=True,
    ),
    click.Option(
        ('--eutl-territories',),
        help=(
            'source trust from the EU trusted list programme, '
            'including only the regions specified in a '
            'comma-separated list of 2-letter ISO 3166 country codes, '
            'trust lists maintained by other territories will be disregarded.'
        ),
        required=False,
        type=str,
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


def grab_certs(files):
    if not files:
        return None
    try:
        return list(load_certs_from_pemder(files))
    except (IOError, ValueError) as e:
        raise click.ClickException(
            f'Could not load certificates from {files}'
        ) from e
