import logging
from datetime import datetime
from typing import Optional

import tzlocal

from pyhanko.pdf_utils import generic, misc

from . import model

__all__ = ['update_info_dict', 'view_from_info_dict']

logger = logging.getLogger(__name__)


def _string_with_lang_to_pdf(string: misc.StringWithLanguage) \
        -> generic.TextStringObject:
    if string.lang_code is None:
        return generic.TextStringObject(string.value)
    else:
        return generic.TextStringObject(
            f"\u001b{string.lang_code}{string.country_code or ''}{string.value}"
        )


def _write_meta_string(dictionary: generic.DictionaryObject,
                       key: str, meta_str: model.MetaString) -> bool:

    if isinstance(meta_str, misc.StringWithLanguage):
        pdf_str = _string_with_lang_to_pdf(meta_str)
    elif isinstance(meta_str, str):
        pdf_str = generic.TextStringObject(meta_str)
    else:
        return False

    try:
        old_value = dictionary[key]
        mod = old_value != pdf_str
    except KeyError:
        mod = True
    dictionary[key] = pdf_str
    return mod


def _write_meta_date(dictionary: generic.DictionaryObject,
                     key: str, meta_date: Optional[datetime]) -> bool:
    if isinstance(meta_date, datetime):
        dictionary[key] = generic.pdf_date(meta_date)
        return True
    return False


def update_info_dict(meta: model.DocumentMetadata,
                     info: generic.DictionaryObject) -> bool:

    mod = False
    mod |= _write_meta_string(info, "/Title", meta.title)
    mod |= _write_meta_string(info, "/Author", meta.author)
    mod |= _write_meta_string(info, "/Subject", meta.subject)
    mod |= _write_meta_string(info, "/Creator", meta.creator)
    mod |= _write_meta_date(info, "/CreationDate", meta.created)
    mod |= _write_meta_date(
        info, "/ModDate",
        meta.last_modified or datetime.now(tz=tzlocal.get_localzone())
    )

    if meta.keywords:
        info['/Keywords'] = generic.TextStringObject(','.join(meta.keywords))
        mod = True

    producer = model.VENDOR
    try:
        producer_string = info['/Producer']
        if producer not in producer_string:
            producer_string = \
                generic.TextStringObject(f"{producer_string}; {producer}")
            mod = True
    except KeyError:
        producer_string = generic.TextStringObject(producer)
        mod = True
    # always override this
    info['/Producer'] = producer_string
    return mod


def _read_date_from_dict(info_dict: generic.DictionaryObject,
                         key: str) -> Optional[datetime]:
    try:
        date_str = info_dict[key]
    except KeyError:
        return None

    try:
        if isinstance(date_str,
                      (generic.TextStringObject, generic.ByteStringObject)):
            return generic.parse_pdf_date(date_str)
    except misc.PdfReadError:
        pass

    logger.warning(
        "Key {} in info dict has value {}, which is not a valid date string",
        key, date_str
    )
    return None


def view_from_info_dict(info_dict: generic.DictionaryObject) \
        -> model.DocumentMetadata:
    kwargs = {}
    for s_entry in ('title', 'author', 'subject', 'creator'):
        try:
            kwargs[s_entry] = str(info_dict[f"/{s_entry.title()}"])
        except KeyError:
            pass

    creation_date = _read_date_from_dict(info_dict, '/CreationDate')
    if creation_date is not None:
        kwargs['created'] = creation_date

    mod_date = _read_date_from_dict(info_dict, '/ModDate')
    if mod_date is not None:
        kwargs['last_modified'] = mod_date

    if '/Keywords' in info_dict:
        kwargs['keywords'] = str(info_dict['/Keywords']).split(',')

    return model.DocumentMetadata(**kwargs)
