"""
Simplified document metadata model.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Union

from pyhanko import __version__
from pyhanko.pdf_utils.misc import StringWithLanguage

__all__ = ['DocumentMetadata', 'VENDOR', 'MetaString']

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

    created: Optional[datetime] = None
    """
    The time when the document was created.
    """

    last_modified: Optional[datetime] = None
    """
    The time when the document was last modified. Defaults to the current time
    upon serialisation if not specified.
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
