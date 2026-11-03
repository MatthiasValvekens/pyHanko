"""
Internal API: bookkeeping for overridden objects that are used in more than
one way in the signed revision.

Not part of the public API, and subject to change without notice.
"""

from collections.abc import Iterable
from typing import Protocol

from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.reader import HistoricalResolver

from .policy_api import ModificationLevel
from .rules_api import ApprovalType, Context, ReferenceUpdate


class _UsageLedger(Protocol):
    """
    Tracks which usages of overridden objects have been approved so far.
    """

    def track(self, refs: Iterable[generic.Reference]) -> None:
        """
        Register the overridden references that need to be cleared together
        with the ways in which they are used in the old revision.
        """

    def ingest(
        self, level: ModificationLevel, upd: ReferenceUpdate
    ) -> ModificationLevel | None:
        """
        Process an approval.

        :return:
            The level at which the updated reference is now fully explained,
            or ``None`` if some of its usages remain unapproved.
        """

    def remaining_report(self) -> str:
        """
        Describe the usages that have not been approved yet (one line per
        reference), or return an empty string if there are none.
        """


class _PathLedger(_UsageLedger):
    """
    Ledger that enumerates every path to an overridden reference.
    """

    def __init__(self, old: HistoricalResolver):
        self._old = old
        self._table: dict[
            generic.Reference, tuple[ModificationLevel, set[Context]]
        ] = {}

    def track(self, refs: Iterable[generic.Reference]) -> None:
        old = self._old
        refs = list(refs)
        old._load_reverse_xref_cache(targets=refs)
        for ref in refs:
            usages = old._get_usages_of_ref(ref)
            if usages:
                contexts = {Context.from_absolute(old, p) for p in usages}
                self._table[ref] = (ModificationLevel.NONE, contexts)

    def ingest(
        self, level: ModificationLevel, upd: ReferenceUpdate
    ) -> ModificationLevel | None:
        ref = upd.updated_ref
        try:
            current_max_level, usages = self._table[ref]
        except KeyError:
            return level
        upd_type = upd.approval_type
        if upd_type == ApprovalType.BLANKET_APPROVE:
            # approve all usages at once
            usages = set()
        elif upd_type == ApprovalType.APPROVE_RELATIVE_CONTEXT:
            # approve all usages that match the relative context,
            # keep the rest
            usages = {
                ctx
                for ctx in usages
                if ctx.relative_view != upd.context_checked
            }
        else:
            # path-level approval: remove the path that has just been cleared
            # from the checklist
            usages.discard(upd.context_checked)
        level = max(current_max_level, level)
        self._table[ref] = level, usages
        return level if not usages else None

    def remaining_report(self) -> str:
        return '\n'.join(
            f" - {ref!r} is also used in "
            f"{', '.join(str(p) for p in paths_remaining)} in the prior "
            f"revision."
            for ref, (_, paths_remaining) in self._table.items()
            if paths_remaining
        )
