import asyncio
import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import aiohttp
from aiohttp import ClientTimeout
from asn1crypto import x509
from pyhanko.sign.validation.qualified import eutl_parse
from pyhanko.sign.validation.qualified.eutl_parse import LOTL_RULE
from pyhanko.sign.validation.qualified.tsp import (
    TSPRegistry,
    TSPServiceParsingError,
)

__all__ = [
    'EU_LOTL_LOCATION',
    'FileSystemTLCache',
    'InMemoryTLCache',
    'TLCache',
    'bootstrap_lotl_signers',
    'fetch_lotl',
    'lotl_to_registry',
]

logger = logging.getLogger(__name__)

EU_LOTL_LOCATION = 'https://ec.europa.eu/tools/lotl/eu-lotl.xml'
"""
Location of the EU's global list-of-the-lists (LOTL).

.. note::
    At the time of writing, this URL appears to have remained constant
    since eIDAS's inception, but in theory it is subject to change.
"""


class TLCache:
    """
    Cache for trusted lists, intended to speed up downloading lists
    from a list-of-lists.

    This is internal API.
    """

    def __getitem__(self, key: str) -> str:
        raise NotImplementedError

    def __setitem__(self, key: str, value: str) -> None:
        raise NotImplementedError


class InMemoryTLCache(TLCache):
    """
    Cache for trusted lists, intended to speed up downloading lists
    from a list-of-lists.

    The cache is keyed by download URL and does not have any eviction mechanism.
    """

    def __init__(self: 'InMemoryTLCache'):
        self._cache: Dict[str, str] = {}

    def __getitem__(self, key: str) -> str:
        return self._cache[key]

    def __setitem__(self, key: str, value: str) -> None:
        self._cache[key] = value


class FileSystemTLCache(TLCache):
    def __init__(self, cache_path: Path, expire_after: timedelta):
        self._cache: Dict[str, Tuple[datetime, str]] = {}
        self._root = cache_path
        self._expire_after = expire_after
        if not cache_path.exists():
            cache_path.mkdir(parents=True, exist_ok=True)

        index = cache_path / 'index.json'
        if index.exists():
            with index.open('r') as inf:
                index_data = json.load(inf)
                for key, entry in index_data.items():
                    exp_ts = datetime.fromtimestamp(
                        entry['exp_epoch_seconds'], tz=timezone.utc
                    )
                    self._cache[key] = (exp_ts, entry['fname'])
        logger.debug(
            f"Loaded {len(self._cache)} items from cache at {cache_path.absolute()}"
        )

    def __getitem__(self, key: str) -> str:
        exp_ts, fname = self._cache[key]
        now = datetime.now(timezone.utc)
        if now > exp_ts:
            raise KeyError
        cached_file_path = self._root / fname
        try:
            with cached_file_path.open('r') as inf:
                content = inf.read()
        except IOError as e:
            logger.warning(
                f"Failed to access cached file at {cached_file_path}: {e}",
                exc_info=e,
            )
            raise KeyError
        return content

    def __setitem__(self, key: str, value: str) -> None:
        exp_ts = datetime.now(timezone.utc) + self._expire_after
        fname = hashlib.sha256(key.encode('utf8')).hexdigest()
        index = self._root / 'index.json'
        if index.exists():
            with index.open('r') as inf:
                index_data = json.load(inf)
        else:
            index_data = {}
        index_data[key] = {
            'exp_epoch_seconds': exp_ts.timestamp(),
            'fname': fname,
        }
        with index.open('w') as outf:
            json.dump(index_data, outf)
        with (self._root / fname).open('w') as outf:
            outf.write(value)
        self._cache[key] = (exp_ts, fname)

    def reset(self):
        for fname in self._root.iterdir():
            fname.unlink(missing_ok=True)


FETCH_TRIES = 3
FETCH_BASE_DELAY_SECONDS = 2
FETCH_TIMEOUT_SECONDS = 30
FETCH_CONNECT_TIMEOUT_SECONDS = 2


async def _get(uri: str, client: aiohttp.ClientSession) -> str:
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
                timeout=ClientTimeout(
                    total=FETCH_TIMEOUT_SECONDS,
                    sock_read=FETCH_CONNECT_TIMEOUT_SECONDS,
                ),
            )
            return await response.text()
        except aiohttp.ClientError as e:
            if isinstance(e, aiohttp.ClientResponseError) and e.status < 500:
                raise e
            last_error = e
            if attempt < FETCH_TRIES - 1:
                await asyncio.sleep(delay_s)
                delay_s *= 2
    assert last_error is not None
    raise last_error


async def _fetch(
    cache: Optional[TLCache], uri: str, client: aiohttp.ClientSession
):
    if cache is None:
        return await _get(uri, client)
    else:
        try:
            result = cache[uri]
            logger.info(f"Retrieved {uri} from cache")
            return result
        except KeyError:
            pass
        result = await _get(uri, client)
        cache[uri] = result
        return result


async def bootstrap_lotl_signers(
    latest_lotl_xml: str,
    client: aiohttp.ClientSession,
    bootstrap_lotl_tlso_certs: Optional[List[x509.Certificate]] = None,
    cache: Optional[TLCache] = None,
) -> List[x509.Certificate]:
    """
    Perform the bootstrapping process specified in
    Article 4 of Commission Implementing Decision (EU) 2015/1505 to determine
    the certificates that can be used to verify a list-of-the-lists
    signature.

    The EC's `technical guidance <https://ec.europa.eu/tools/lotl/pivot-lotl-explanation.html>`_
    on this topic is also of interest.

    .. warning::
        PyHanko bundles the both the initial set of list-of-the-lists signing
        certificates and the last-known set of such certificates.
        In principle, you only need to use this function if there have not
        been any pyHanko releases since the last change in the list-of-the-lists
        signers, or you cannot upgrade for some reason.

        The process to fetch and process all relevant trust lists is rather
        slow, so this bootstrapping logic should be used judiciously.

    :param latest_lotl_xml:
        The XML content of the most recent list-of-the-lists.
    :param client:
        An :class:`aiohttp.ClientSession` object to use for fetching pivot
        lists-of-the-lists.
    :param bootstrap_lotl_tlso_certs:
        Initial list of certificates. This defaults to the list published
        in `OJ C 276, 16.8.2019 <https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=uriserv:OJ.C_.2019.276.01.0001.01.ENG>`_,
        which is bundled with this library.
    :param cache:
        An optional :class:`TLCache` to be used while fetching pivot
        lists-of-the-lists.
    :return:
        The list of certificates that can be used to verify the most recent
        list-of-the-lists.
    """

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


async def fetch_lotl(
    client: aiohttp.ClientSession,
    cache: Optional[TLCache] = None,
    url=EU_LOTL_LOCATION,
):
    """
    Fetch the EU list-of-the-lists (LOTL).

    :param client:
        An :class:`aiohttp.ClientSession` object to use for fetching
        trust lists.
    :param cache:
        An optional :class:`TLCache` to be used while fetching trust lists.
    :param url:
        The URL content of the list-of-the-lists. The default is
        the location specified in :const:`EU_LOTL_LOCATION`.
    :return:
    """
    logger.info(f"Downloading LOTL from {url}...")
    lotl_xml = await _fetch(cache, url, client)
    return lotl_xml


async def lotl_to_registry(
    lotl_xml: Optional[str],
    client: aiohttp.ClientSession,
    lotl_tlso_certs: Optional[List[x509.Certificate]] = None,
    cache: Optional[TLCache] = None,
    registry: Optional[TSPRegistry] = None,
    only_territories: Optional[Set[str]] = None,
) -> Tuple[TSPRegistry, List[TSPServiceParsingError]]:
    """
    Populate a :class:`.TSPRegistry` instance from a list-of-the-lists XML
    payload, validating the signatures on the trusted lists in the process.

    :param lotl_xml:
        The XML content of a list-of-the-lists. If ``None``, it will
        be downloaded from the location specified in :const:`EU_LOTL_LOCATION`.
    :param client:
        An :class:`aiohttp.ClientSession` object to use for fetching
        trust lists.
    :param lotl_tlso_certs:
        List of certificates that can be used to validate the list-of-the-lists.
        If not specified, the list-of-the-lists will be validated against the
        last known set of list-of-the-lists signer certs bundled with this
        library.

        See :func:`bootstrap_lotl_signers` and
        :func:`~.eutl_parse.validate_and_parse_lotl`.
    :param cache:
        An optional :class:`TLCache` to be used while fetching trust lists.
    :param registry:
        An optional :class:`.TSPRegistry` to be used to collect
        service definitions for trusted service providers.
        If not supplied, a registry will be instantiated.
    :param only_territories:
        Limit downloads to the territories specified (as
        two-letter ISO 3166-1 country codes).
        If ``None``, no filtering is applied.
    :return:
        A :class:`.TSPRegistry` instance populated with the
        fetched contents, in addition to any parsing errors encountered.
    """
    if lotl_xml is None:
        lotl_xml = await fetch_lotl(client, cache)

    lotl_result = eutl_parse.validate_and_parse_lotl(lotl_xml, lotl_tlso_certs)
    errors = lotl_result.errors
    registry = registry or TSPRegistry()
    if only_territories is not None:
        territory_list = {x.casefold() for x in only_territories}
    else:
        territory_list = None
    for ref in lotl_result.references:
        if (
            territory_list is not None
            and ref.territory.casefold() not in territory_list
        ):
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
        try:
            _, tl_errors = eutl_parse.trust_list_to_registry(
                tl_xml, ref.tlso_certs, registry
            )
            errors.extend(tl_errors)
        except Exception as e:
            errors.append(
                TSPServiceParsingError(
                    f"Failed to parse trusted list for {ref.territory} "
                    f"at {ref.location_uri}: {e}"
                )
            )
    return registry, errors
