import asyncio
import logging
from typing import Dict, List, Optional, Set

import aiohttp
from aiohttp import ClientTimeout
from asn1crypto import x509
from pyhanko.sign.validation.qualified import eutl_parse
from pyhanko.sign.validation.qualified.eutl_parse import LOTL_RULE
from pyhanko.sign.validation.qualified.tsp import (
    TSPRegistry,
    TSPServiceParsingError,
)

logger = logging.getLogger(__name__)

EU_LOTL_LOCATION = 'https://ec.europa.eu/tools/lotl/eu-lotl.xml'


class TLCache:
    def __init__(self: 'TLCache'):
        self._cache: Dict[str, str] = {}

    def __getitem__(self, key: str) -> str:
        return self._cache[key]

    def __setitem__(self, key: str, value: str) -> None:
        self._cache[key] = value


FETCH_TRIES = 4
FETCH_BASE_DELAY_SECONDS = 2
FETCH_TIMEOUT_SECONDS = 30


async def _fetch(
    cache: Optional[TLCache], uri: str, client: aiohttp.ClientSession
):
    async def _get() -> str:
        delay_s = FETCH_BASE_DELAY_SECONDS
        last_error = None
        for attempt in range(FETCH_TRIES):
            try:
                response = await client.get(
                    uri,
                    headers=(
                        ('Accept', 'text/xml'),
                        ('Accept', eutl_parse.ETSI_TSL_MIME_TYPE),
                    ),
                    raise_for_status=True,
                    timeout=ClientTimeout(total=FETCH_TIMEOUT_SECONDS),
                )
                return await response.text()
            except aiohttp.ClientError as e:
                if (
                    isinstance(e, aiohttp.ClientResponseError)
                    and e.status < 500
                ):
                    raise e
                last_error = e
                if attempt < FETCH_TRIES - 1:
                    await asyncio.sleep(delay_s)
                    delay_s *= 2
        assert last_error is not None
        raise last_error

    if cache is None:
        return await _get()
    else:
        try:
            return cache[uri]
        except KeyError:
            pass
        result = await _get()
        cache[uri] = result
        return result


async def bootstrap_lotl_signers(
    latest_lotl_xml: str,
    client: aiohttp.ClientSession,
    bootstrap_lotl_tlso_certs: Optional[List[x509.Certificate]] = None,
    cache: Optional[TLCache] = None,
) -> List[x509.Certificate]:
    pivots = eutl_parse.parse_lotl_unsafe(latest_lotl_xml).pivot_urls
    sorted_pivots = sorted(pivots)
    if bootstrap_lotl_tlso_certs:
        current_certs = bootstrap_lotl_tlso_certs
    else:
        current_certs = eutl_parse.ojeu_bootstrap_lotl_tlso_certs()

    for pivot in sorted_pivots:
        logger.info(f"Processing LOTL pivot {pivot}...")
        try:
            pivot_xml = await _fetch(cache, pivot, client)
            pivot_parse_result = eutl_parse.validate_and_parse_lotl(
                pivot_xml, current_certs
            )
        except Exception as e:
            raise TSPServiceParsingError(
                f"Failed to process pivot LOTL {pivot}: {e}"
            ) from e

        try:
            lotl_self_reference = next(
                ref
                for ref in pivot_parse_result.references
                if eutl_parse.LOTL_RULE in ref.scheme_rules
            )
        except StopIteration:
            raise TSPServiceParsingError(
                f"Failed to process pivot LOTL {pivot}: could not extract TLSO certs"
            )

        current_certs = lotl_self_reference.tlso_certs
    return current_certs


async def lotl_to_registry(
    lotl_xml: Optional[str],
    client: aiohttp.ClientSession,
    lotl_tlso_certs: Optional[List[x509.Certificate]] = None,
    cache: Optional[TLCache] = None,
    registry: Optional[TSPRegistry] = None,
    only_territories: Optional[Set[str]] = None,
):
    if lotl_xml is None:
        logger.info(f"Downloading LOTL from {EU_LOTL_LOCATION}...")
        lotl_xml = await _fetch(cache, EU_LOTL_LOCATION, client)

    lotl_result = eutl_parse.validate_and_parse_lotl(lotl_xml, lotl_tlso_certs)
    errors = lotl_result.errors
    registry = registry or TSPRegistry()
    territory_list = {x.casefold() for x in only_territories or ()}
    for ref in lotl_result.references:
        if territory_list and ref.territory.casefold() not in territory_list:
            continue
        if LOTL_RULE in ref.scheme_rules:
            continue
        logger.info(
            f"Processing trusted list for {ref.territory} "
            f"at {ref.location_uri}..."
        )
        try:
            tl_xml = await _fetch(cache, ref.location_uri, client)
        except Exception as e:
            errors.append(
                TSPServiceParsingError(
                    f"Failed to download trusted list for {ref.territory} "
                    f"at {ref.location_uri}: {e}"
                )
            )
            continue
        _, tl_errors = eutl_parse.trust_list_to_registry(
            tl_xml, ref.tlso_certs, registry
        )
        errors.extend(tl_errors)
    return registry, errors
