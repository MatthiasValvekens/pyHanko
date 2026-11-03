"""
Internal API: bookkeeping for overridden objects that are used in more than
one way in the signed revision.

Not part of the public API, and subject to change without notice.
"""

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol

from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.reader import HistoricalResolver, RawPdfPath

from .policy_api import ModificationLevel
from .rules_api import (
    ApprovalType,
    ReferenceUpdate,
    RelativeContext,
)
from .usage_graph import (
    MAX_REPORTED_GROUPS_PER_REF,
    SATURATION_CAP,
    GroupInfo,
    abbreviate_path,
    build_usage_graph,
    group_sort_key,
)


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


MAX_REPORTED_REFS = 20


@dataclass
class _RefUsages:
    level: ModificationLevel
    groups: dict[RelativeContext, GroupInfo]
    approved: set[RelativeContext] = field(default_factory=set)
    validated_paths: dict[RelativeContext, set[RawPdfPath]] = field(
        default_factory=dict
    )
    outstanding: int = 0

    def __post_init__(self):
        self.outstanding = len(self.groups)

    def is_satisfied(self, group: RelativeContext) -> bool:
        info = self.groups[group]
        return group in self.approved or (
            info.count < SATURATION_CAP
            and len(self.validated_paths.get(group, ())) == info.count
        )

    def approve_group(self, group: RelativeContext):
        was_satisfied = self.is_satisfied(group)
        self.approved.add(group)
        self.outstanding -= not was_satisfied

    def record_path(self, group: RelativeContext, path: RawPdfPath):
        was_satisfied = self.is_satisfied(group)
        self.validated_paths.setdefault(group, set()).add(path)
        self.outstanding -= self.is_satisfied(group) and not was_satisfied

    def approve_all(self):
        self.approved.update(self.groups)
        self.outstanding = 0


class _GraphLedger(_UsageLedger):
    """
    Ledger that works on the usage graph of the old revision.

    For every overridden reference, the usages are grouped by their last hop
    (the relative context). A group is cleared by approving its relative
    context, or by approving every path that makes up the group.
    """

    def __init__(self, old: HistoricalResolver):
        self._graph = build_usage_graph(old)
        self._tracked: dict[generic.Reference, _RefUsages] = {}

    def track(self, refs: Iterable[generic.Reference]) -> None:
        for ref in refs:
            groups = self._graph.inbound_groups(ref)
            if groups:
                self._tracked[ref] = _RefUsages(ModificationLevel.NONE, groups)

    def ingest(
        self, level: ModificationLevel, upd: ReferenceUpdate
    ) -> ModificationLevel | None:
        ref = upd.updated_ref
        try:
            usages = self._tracked[ref]
        except KeyError:
            return level
        upd_type = upd.approval_type
        if upd_type == ApprovalType.BLANKET_APPROVE:
            usages.approve_all()
        elif upd_type == ApprovalType.APPROVE_RELATIVE_CONTEXT:
            if upd.context_checked in usages.groups:
                usages.approve_group(upd.context_checked)  # type: ignore
        else:
            path = upd.context_checked.path  # type: ignore
            group = self._graph.enumerated_last_edge(path, ref)
            if group is not None:
                usages.record_path(group, path)
        usages.level = max(usages.level, level)
        return usages.level if not usages.outstanding else None

    def _describe(self, group: RelativeContext, usages: _RefUsages) -> str:
        info = usages.groups[group]
        witness = abbreviate_path(self._graph.witness(group))
        if info.count >= SATURATION_CAP:
            amount = "at least 2^32 paths"
        else:
            remaining = info.count - len(usages.validated_paths.get(group, ()))
            amount = f"{remaining} path{'' if remaining == 1 else 's'}"
        if info.cyclic:
            amount += ", via a reference cycle"
        return f"{witness} ({amount})"

    def remaining_report(self) -> str:
        incomplete = sorted(
            (
                ref
                for ref, usages in self._tracked.items()
                if usages.outstanding
            ),
            key=lambda ref: (ref.idnum, ref.generation),
        )
        lines = []
        for ref in incomplete[:MAX_REPORTED_REFS]:
            usages = self._tracked[ref]
            pending = sorted(
                (g for g in usages.groups if not usages.is_satisfied(g)),
                key=group_sort_key,
            )
            shown = [
                self._describe(group, usages)
                for group in pending[:MAX_REPORTED_GROUPS_PER_REF]
            ]
            omitted = len(pending) - len(shown)
            if omitted:
                shown.append(f"... and {omitted} more")
            lines.append(
                f" - {ref!r} is also used in {', '.join(shown)} "
                "in the prior revision."
            )
        if len(incomplete) > MAX_REPORTED_REFS:
            lines.append(
                f" - ... and {len(incomplete) - MAX_REPORTED_REFS} more "
                "objects with unapproved usages."
            )
        return '\n'.join(lines)
