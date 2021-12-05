"""
Module defining common API types for use by rules and policies.

In principle, these aren't relevant to the high-level validation API.
"""

import logging
from dataclasses import dataclass
from typing import Iterable, Optional, Tuple, Union

from pyhanko.pdf_utils.generic import Reference
from pyhanko.pdf_utils.reader import HistoricalResolver, RawPdfPath

from .policy_api import ModificationLevel

logger = logging.getLogger(__name__)


__all__ = [
    'QualifiedWhitelistRule', 'WhitelistRule', 'ReferenceUpdate',
]


@dataclass(frozen=True)
class ReferenceUpdate:

    updated_ref: Reference
    """
    Reference that was (potentially) updated.
    """

    # TODO document
    paths_checked: Optional[Union[RawPdfPath, Iterable[RawPdfPath]]] \
        = None

    blanket_approve: bool = False

    @classmethod
    def curry_ref(cls, **kwargs):
        return lambda ref: cls(updated_ref=ref, **kwargs)


class QualifiedWhitelistRule:
    """
    Abstract base class for a whitelisting rule that outputs references together
    with the modification level at which they're cleared.

    This is intended for use by complicated whitelisting rules that need to
    differentiate between multiple levels.
    """

    def apply_qualified(self, old: HistoricalResolver, new: HistoricalResolver)\
            -> Iterable[Tuple[ModificationLevel, ReferenceUpdate]]:
        """
        Apply the rule to the changes between two revisions.

        :param old:
            The older, base revision.
        :param new:
            The newer revision to be vetted.
        """
        raise NotImplementedError


class WhitelistRule:
    """
    Abstract base class for a whitelisting rule that simply outputs
    cleared references without specifying a modification level.

    These rules are more flexible than rules of type
    :class:`.QualifiedWhitelistRule`, since the modification level can be
    specified separately (see :meth:`.WhitelistRule.as_qualified`).
    """

    def apply(self, old: HistoricalResolver, new: HistoricalResolver) \
            -> Iterable[ReferenceUpdate]:
        """
        Apply the rule to the changes between two revisions.

        :param old:
            The older, base revision.
        :param new:
            The newer revision to be vetted.
        """
        raise NotImplementedError

    def as_qualified(self, level: ModificationLevel) -> QualifiedWhitelistRule:
        """
        Construct a new :class:`QualifiedWhitelistRule` that whitelists the
        object references from this rule at the level specified.

        :param level:
            The modification level at which the output of this rule should be
            cleared.
        :return:
            A :class:`.QualifiedWhitelistRule` backed by this rule.
        """
        return _WrappingQualifiedWhitelistRule(self, level)


class _WrappingQualifiedWhitelistRule(QualifiedWhitelistRule):

    def __init__(self, rule: WhitelistRule, level: ModificationLevel):
        self.rule = rule
        self.level = level

    def apply_qualified(self, old: HistoricalResolver, new: HistoricalResolver)\
            -> Iterable[Tuple[ModificationLevel, ReferenceUpdate]]:
        for ref in self.rule.apply(old, new):
            yield self.level, ref
