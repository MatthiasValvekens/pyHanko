"""
Simplified document metadata model.
"""
import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple, Union

from pyhanko import __version__
from pyhanko.pdf_utils.misc import StringWithLanguage

__all__ = [
    'DocumentMetadata', 'VENDOR', 'MetaString',
    'NS', 'ExpandedName', 'Qualifiers', 'XmpValue',
    'XmpStructure', 'XmpArrayType', 'XmpArray'
]

VENDOR = 'pyHanko ' + __version__
"""
pyHanko version identifier in textual form
"""

MetaString = Union[StringWithLanguage, str, None]
"""
A regular string, a string with a language code, or nothing at all.
"""


@dataclass
class DocumentMetadata:
    """
    Simple representation of document metadata. All entries are optional.
    """

    title: MetaString = None
    """
    The document's title.
    """

    author: MetaString = None
    """
    The document's author.
    """

    subject: MetaString = None
    """
    The document's subject.
    """

    keywords: List[str] = field(default_factory=list)
    """
    Keywords associated with the document.
    """

    creator: MetaString = None
    """
    The software that was used to author the document.

    .. note::
        This is distinct from the producer, which is typically used to indicate
        which PDF processor(s) interacted with the file.
    """

    created: Union[str, datetime, None] = None
    """
    The time when the document was created. To set it to the current time,
    specify ``now``.
    """

    last_modified: Union[str, datetime, None] = "now"
    """
    The time when the document was last modified. Defaults to the current time
    upon serialisation if not specified.
    """

    xmp_extra: List['XmpStructure'] = field(default_factory=list)
    """
    Extra XMP metadata.
    """

    xmp_unmanaged: bool = False
    """
    Flag metadata as XMP-only. This means that the info dictionary will be
    cleared out as much as possible, and that all attributes other than
    :attr:`xmp_extra` will be ignored when updating XMP metadata.

    .. note::
        The last-modified date and producer entries
        in the info dictionary will still be updated.

    .. note::
        :class:`DocumentMetadata` represents a data model that is much more
        simple than what XMP is actually capable of. You can use this flag
        if you need more fine-grained control.
    """

    def view_over(self, base: 'DocumentMetadata'):
        return DocumentMetadata(
            title=self.title or base.title,
            author=self.author or base.author,
            subject=self.subject or base.subject,
            keywords=list(self.keywords or base.keywords),
            creator=self.creator or base.creator,
            created=self.created or base.created,
            last_modified=self.last_modified
        )


@dataclass(frozen=True)
class ExpandedName:
    ns: str
    local_name: str

    def __str__(self):
        ns = self.ns
        return f"{ns}{'' if ns.endswith('/') else '/'}{self.local_name}"

    def __repr__(self):
        return str(self)


NS = {
    'xml': 'http://www.w3.org/XML/1998/namespace',
    'rdf': 'http://www.w3.org/1999/02/22-rdf-syntax-ns#',
    'xmp': 'http://ns.adobe.com/xap/1.0/',
    'dc': 'http://purl.org/dc/elements/1.1/',
    'pdf': 'http://ns.adobe.com/pdf/1.3/',
    'x': 'adobe:ns:meta/'
}


XML_LANG = ExpandedName(ns=NS['xml'], local_name='lang')
RDF_RDF = ExpandedName(ns=NS['rdf'], local_name='RDF')
RDF_SEQ = ExpandedName(ns=NS['rdf'], local_name='Seq')
RDF_BAG = ExpandedName(ns=NS['rdf'], local_name='Bag')
RDF_ALT = ExpandedName(ns=NS['rdf'], local_name='Alt')
RDF_LI = ExpandedName(ns=NS['rdf'], local_name='li')
RDF_VALUE = ExpandedName(ns=NS['rdf'], local_name='value')
RDF_RESOURCE = ExpandedName(ns=NS['rdf'], local_name='resource')
RDF_ABOUT = ExpandedName(ns=NS['rdf'], local_name='about')
RDF_PARSE_TYPE = ExpandedName(ns=NS['rdf'], local_name='parseType')
RDF_DESCRIPTION = ExpandedName(ns=NS['rdf'], local_name='Description')
X_XMPMETA = ExpandedName(ns=NS['x'], local_name='xmpmeta')
X_XMPTK = ExpandedName(ns=NS['x'], local_name='xmptk')

DC_TITLE = ExpandedName(ns=NS['dc'], local_name='title')
DC_CREATOR = ExpandedName(ns=NS['dc'], local_name='creator')
DC_DESCRIPTION = ExpandedName(ns=NS['dc'], local_name='description')
PDF_KEYWORDS = ExpandedName(ns=NS['pdf'], local_name='keywords')
XMP_CREATORTOOL = ExpandedName(ns=NS['xmp'], local_name='CreatorTool')
PDF_PRODUCER = ExpandedName(ns=NS['pdf'], local_name='Producer')
XMP_CREATEDATE = ExpandedName(ns=NS['xmp'], local_name='CreateDate')
XMP_MODDATE = ExpandedName(ns=NS['xmp'], local_name='ModifyDate')


class Qualifiers:

    _quals: Dict[ExpandedName, 'XmpValue']
    _lang: Optional[str]

    def __init__(self, quals: Dict[ExpandedName, 'XmpValue']):
        self._quals = quals
        try:
            lang = quals[XML_LANG]
            del quals[XML_LANG]
            if not isinstance(lang.value, str):
                raise TypeError  # pragma: nocover
            self._lang = lang.value
        except KeyError:
            self._lang = None

    @classmethod
    def of(cls, *lst: Tuple[ExpandedName, 'XmpValue']) -> 'Qualifiers':
        return Qualifiers({k: v for k, v in lst})

    @classmethod
    def lang_as_qual(cls, lang: Optional[str]) -> 'Qualifiers':
        quals = Qualifiers({})
        if lang:
            quals._lang = lang
        return quals

    def __getitem__(self, item):
        return self._quals[item]

    def iter_quals(self, with_lang: bool = True) \
            -> Iterable[Tuple[ExpandedName, 'XmpValue']]:
        yield from self._quals.items()
        if with_lang and self._lang is not None:
            yield XML_LANG, XmpValue(self._lang)

    @property
    def lang(self) -> Optional[str]:
        return self._lang

    @property
    def has_non_lang_quals(self) -> bool:
        return bool(self._quals)

    def __repr__(self):
        q = dict(self._quals)
        if self._lang:
            q['lang'] = self._lang
        return f"Qualifiers({q!r})"

    def __eq__(self, other):
        return isinstance(other, Qualifiers) \
                and self._lang == other._lang \
                and self._quals == other._quals


@dataclass(frozen=True)
class XmpUri:
    value: str

    def __str__(self):
        return self.value


@dataclass
class XmpValue:
    value: Union['XmpStructure', 'XmpArray', XmpUri, str]
    qualifiers: Qualifiers = field(default_factory=Qualifiers.of)


class XmpStructure:
    # isomorphic to Qualifiers, but we keep them separate to stay
    # closer to the spec (and this one doesn't special-case anything)

    def __init__(self, fields: Dict[ExpandedName, 'XmpValue']):
        self._fields: Dict[ExpandedName, XmpValue] = fields

    @classmethod
    def of(cls, *lst: Tuple[ExpandedName, 'XmpValue']) -> 'XmpStructure':
        return cls({k: v for k, v in lst})

    def __getitem__(self, item):
        return self._fields[item]

    def __iter__(self) -> Iterable[Tuple[ExpandedName, 'XmpValue']]:
        yield from self._fields.items()

    def __repr__(self):
        return f"XmpStructure({self._fields!r})"

    def __eq__(self, other):
        return isinstance(other, XmpStructure) \
                and self._fields == other._fields


@enum.unique
class XmpArrayType(enum.Enum):
    ORDERED = 'Seq'
    UNORDERED = 'Bag'
    ALTERNATIVE = 'Alt'

    def as_rdf(self) -> ExpandedName:
        return ExpandedName(ns=NS['rdf'], local_name=str(self.value))


@dataclass
class XmpArray:
    array_type: XmpArrayType
    entries: List[XmpValue]

    @classmethod
    def ordered(cls, lst: Iterable[XmpValue]) -> 'XmpArray':
        return cls(XmpArrayType.ORDERED, list(lst))

    @classmethod
    def unordered(cls, lst: Iterable[XmpValue]) -> 'XmpArray':
        return cls(XmpArrayType.UNORDERED, list(lst))

    @classmethod
    def alternative(cls, lst: Iterable[XmpValue]) -> 'XmpArray':
        return cls(XmpArrayType.ALTERNATIVE, list(lst))

    def __eq__(self, other):
        if not isinstance(other, XmpArray) or \
                self.array_type != other.array_type:
            return False
        if self.array_type == XmpArrayType.UNORDERED:
            return all(e in self.entries for e in other.entries) and \
                    all(e in other.entries for e in self.entries)
        else:
            return self.entries == other.entries
