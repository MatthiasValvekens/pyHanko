"""
Module defining pyHanko's standard difference policy implementation.
"""

import logging
from collections import defaultdict
from typing import Iterator, List, Optional, Union

from pyhanko.pdf_utils import misc
from pyhanko.pdf_utils.generic import PdfObject
from pyhanko.pdf_utils.reader import (
    HistoricalResolver,
    PdfFileReader,
    RawPdfPath,
)
from pyhanko.sign.fields import FieldMDPSpec, MDPPerm

from .form_rules_api import FormUpdatingRule
from .policy_api import (
    DiffPolicy,
    DiffResult,
    ModificationLevel,
    SuspiciousModification,
)
from .rules.file_structure_rules import (
    CatalogModificationRule,
    ObjectStreamRule,
    XrefStreamRule,
)
from .rules.form_field_rules import (
    DSSCompareRule,
    GenericFieldModificationRule,
    SigFieldCreationRule,
    SigFieldModificationRule,
)
from .rules.metadata_rules import DocInfoRule, MetadataUpdateRule
from .rules_api import QualifiedWhitelistRule, ReferenceUpdate

logger = logging.getLogger(__name__)


__all__ = [
    'StandardDiffPolicy',
    'DEFAULT_DIFF_POLICY', 'NO_CHANGES_DIFF_POLICY',
]


def _find_orphans(hist_rev: HistoricalResolver):
    """
    Within a revision, find new refs that can't be reached from refs in the
    older ones.
    """

    # Note: this function assumes that there is no shady behaviour with older
    #  revisions referring to as-of-yet-undefined references in future
    #  revisions.
    # TODO I might want to put a failsafe in the PdfFileReader class's
    #  dereferencing logic to prevent that.

    # This assumption makes finding orphans relatively cheap: we only need to
    # pull up the dependencies of the older objects that were overwritten
    # in this exact revision, and we only have to recurse into branches that
    # pass through new objects themselves.

    new_refs = hist_rev.explicit_refs_in_revision()

    previous = hist_rev.reader.get_historical_resolver(hist_rev.revision - 1)

    # These are newly updated refs that already existed in older revisions.
    #  We want to know which of the new refs are reachable from one of these.
    updated_old_refs = set()
    # The candidate orphans are all the others
    candidate_orphans = set()
    for ref in new_refs:
        if previous.is_ref_available(ref):
            # ref didn't exist in previous revision
            candidate_orphans.add(ref)
        else:
            updated_old_refs.add(ref)

    def _objs_to_check() -> Iterator[PdfObject]:
        # check the trailer too!
        yield hist_rev.trailer_view
        for _ref in updated_old_refs:
            # take care to return the historical value here
            yield hist_rev(_ref)

    obj_iter = _objs_to_check()
    while candidate_orphans:
        try:
            obj = next(obj_iter)
        except StopIteration:
            break
        candidate_orphans -= hist_rev.collect_dependencies(
            obj, since_revision=hist_rev.revision
        )
    return candidate_orphans


class StandardDiffPolicy(DiffPolicy):
    """
    Run a list of rules to analyse the differences between two revisions.

    :param global_rules:
        The :class:`.QualifiedWhitelistRule` objects encoding the rules to
        apply.
    :param form_rule:
        The :class:`.FormUpdatingRule` that adjudicates changes to form fields
        and their values.
    :param reject_object_freeing:
        Always fail revisions that free objects that existed prior to signing.

        .. note::
            PyHanko resolves freed references to the ``null`` object in PDF,
            and a freeing instruction in a cross-reference section is
            always registered as a change that needs to be approved, regardless
            of the value of this setting.

            It is theoretically possible for a rule to permit deleting content,
            in which case allowing objects to be freed might be reasonable.
            That said, pyHanko takes the conservative default position to reject
            all object freeing instructions as suspect.
    :param ignore_orphaned_objects:
        Some PDF writers create objects that aren't used anywhere (tsk tsk).
        Since those don't affect the "actual" document content, they can usually
        be ignored. If ``True``, newly created orphaned objects will be
        cleared at level :attr:`.ModificationLevel.LTA_UPDATES`.
        Default is ``True``.
    """

    def __init__(self, global_rules: List[QualifiedWhitelistRule],
                 form_rule: Optional[FormUpdatingRule],
                 reject_object_freeing=True, ignore_orphaned_objects=True):
        self.global_rules = global_rules
        self.form_rule = form_rule
        self.reject_object_freeing = reject_object_freeing
        self.ignore_orphaned_objects = ignore_orphaned_objects

    def apply(self, old: HistoricalResolver, new: HistoricalResolver,
              field_mdp_spec: Optional[FieldMDPSpec] = None,
              doc_mdp: Optional[MDPPerm] = None) -> DiffResult:

        if doc_mdp == MDPPerm.ANNOTATE:
            logger.warning(
                "StandardDiffPolicy was not designed to support "
                "DocMDP level 3 (MDPPerm.ANNOTATE). Unexpected validation "
                "results may occur."
            )

        if self.reject_object_freeing:
            freed = new.refs_freed_in_revision()
            if freed:
                raise SuspiciousModification(
                    f"The refs {freed} were freed in the revision provided. "
                    "The configured difference analysis policy does not allow "
                    "object freeing."
                )
        # we need to verify that there are no xrefs in the revision's xref table
        # other than the ones we can justify.
        new_xrefs = new.explicit_refs_in_revision()

        explained = defaultdict(set)

        # prepare LUT for refs that are used multiple times in the old revision
        # (this is a very expensive operation, since it reads all objects in
        #  the signed revision)
        def _init_multi_lut():
            old._load_reverse_xref_cache()
            for new_ref in new_xrefs:
                usages = old._get_usages_of_ref(new_ref)
                if usages:
                    yield new_ref, (ModificationLevel.NONE, set(usages))

        # orphaned objects are cleared at LTA update level
        if self.ignore_orphaned_objects:
            for _ref in _find_orphans(new):
                explained[ModificationLevel.LTA_UPDATES].add(_ref)

        # This table records all the overridden refs that already existed
        # in the old revision, together with the different ways they can be
        # reached from the document trailer.
        # Unlike fresh refs, these need to be cleared together with the paths
        # through which they are accessed.
        old_usages_to_clear = dict(_init_multi_lut())

        def ingest_ref(_level: ModificationLevel, _upd: ReferenceUpdate):
            ref = _upd.updated_ref
            try:
                current_max_level, usages = old_usages_to_clear[ref]
                if _upd.blanket_approve:
                    # approve all usages at once
                    usages = set()
                else:
                    # remove the paths that have just been cleared from
                    # the checklist
                    paths_checked = _upd.paths_checked or ()
                    if isinstance(paths_checked, RawPdfPath):
                        # single path
                        paths_checked = paths_checked,
                    usages.difference_update(paths_checked)
                # bump the modification level for this reference if necessary
                _level = max(current_max_level, _level)
                old_usages_to_clear[ref] = _level, usages
                if usages:
                    # not all paths/usages have been cleared, so we can't
                    # approve the reference yet
                    return
            except KeyError:
                pass
            explained[_level].add(ref)

        for rule in self.global_rules:
            for level, upd in rule.apply_qualified(old, new):
                ingest_ref(level, upd)

        changed_form_fields = set()

        if self.form_rule:
            form_changes = self.form_rule.apply(old, new)

            def is_locked(fq_name):
                return field_mdp_spec is not None \
                       and field_mdp_spec.is_locked(fq_name)

            for level, fu in form_changes:
                ingest_ref(level, fu)
                field_name = fu.field_name
                if field_name is not None and not fu.valid_when_locked:
                    if is_locked(field_name):
                        raise SuspiciousModification(
                            f"Update of {fu.updated_ref} is not allowed "
                            f"because the form field {field_name} is locked."
                        )
                    changed_form_fields.add(fu.field_name)
                if doc_mdp is not None and not fu.valid_when_certifying:
                    raise SuspiciousModification(
                        f"Update of {fu.updated_ref} is only allowed "
                        f"after an approval signature, not a certification "
                        f"signature."
                    )

        unexplained_lta = new_xrefs - explained[ModificationLevel.LTA_UPDATES]
        unexplained_formfill = \
            unexplained_lta - explained[ModificationLevel.FORM_FILLING]
        unexplained_annot = \
            unexplained_formfill - explained[ModificationLevel.ANNOTATIONS]
        if unexplained_annot:
            msg = misc.LazyJoin(
                '\n', (
                    '%s:%s...' % (
                        repr(x), repr(x.get_object())[:300]
                    ) for x in unexplained_annot
                )
            )
            logger.debug(
                "Unexplained xrefs in revision %d:\n%s",
                new.revision, msg
            )
            unexplained_overrides = [
                f" - {repr(ref)} is also used at "
                f"{', '.join(str(p) for p in paths_remaining)} in the prior "
                f"revision."
                for ref, (_, paths_remaining) in old_usages_to_clear.items()
                if paths_remaining
            ]
            err_msg = (
                f"There are unexplained xrefs in revision {new.revision}: "
                f"{', '.join(repr(x) for x in unexplained_annot)}."
            )
            if unexplained_overrides:
                unchecked_paths_msg = (
                    f"Some objects from revision {old.revision} were replaced "
                    f"in revision {new.revision} without precise "
                    "justification:\n" + '\n'.join(unexplained_overrides)
                )
                err_msg = "%s\n%s" % (err_msg, unchecked_paths_msg)
                logger.debug(unchecked_paths_msg)

            raise SuspiciousModification(err_msg)
        elif unexplained_formfill:
            level = ModificationLevel.ANNOTATIONS
        elif unexplained_lta:
            level = ModificationLevel.FORM_FILLING
        else:
            level = ModificationLevel.LTA_UPDATES

        return DiffResult(
            modification_level=level, changed_form_fields=changed_form_fields
        )

    def review_file(self, reader: PdfFileReader,
                    base_revision: Union[int, HistoricalResolver],
                    field_mdp_spec: Optional[FieldMDPSpec] = None,
                    doc_mdp: Optional[MDPPerm] = None) \
            -> Union[DiffResult, SuspiciousModification]:
        """
        Implementation of :meth:`.DiffPolicy.review_file` that reviews
        each intermediate revision between the base revision and the current one
        individually.
        """

        changed_form_fields = set()

        rev_count = reader.xrefs.total_revisions
        current_max = ModificationLevel.NONE
        if isinstance(base_revision, int):
            base_rev_resolver = reader.get_historical_resolver(
                base_revision
            )
        else:
            base_rev_resolver = base_revision
            base_revision = base_rev_resolver.revision

        # Note: there's a pragmatic reason why we iterate over all revisions
        # instead of just asking for all updated objects between the signed
        # revision and the most recent one:
        #
        # The effect of intermediate updates may not be detectable anymore in
        # the most recent version, so if we'd consolidate all checks into one,
        # we would have no way to tell whether or not the objects created
        # (and later forgotten) by these intermediate revisions actually
        # constituted legitimate changes.
        # (see the test_pades_revinfo tests for examples where this applies)
        #
        # Until we have a reference counter (which comes with its own
        # performance problems that may or may not be worse), I don't really
        # see a good way around this issue other than diffing every intermediate
        # version separately.
        for revision in range(base_revision + 1, rev_count):
            try:
                diff_result = self.apply(
                    old=base_rev_resolver,
                    new=reader.get_historical_resolver(revision),
                    field_mdp_spec=field_mdp_spec, doc_mdp=doc_mdp
                )
            except SuspiciousModification as e:
                logger.warning(
                    'Error in diff operation between revision '
                    f'{base_revision} and {revision}', exc_info=e
                )
                return e
            current_max = max(current_max, diff_result.modification_level)
            changed_form_fields |= diff_result.changed_form_fields
        return DiffResult(current_max, changed_form_fields)


DEFAULT_DIFF_POLICY = StandardDiffPolicy(
    global_rules=[
        CatalogModificationRule(),
        DocInfoRule().as_qualified(ModificationLevel.LTA_UPDATES),
        XrefStreamRule().as_qualified(ModificationLevel.LTA_UPDATES),
        ObjectStreamRule().as_qualified(ModificationLevel.LTA_UPDATES),
        DSSCompareRule().as_qualified(ModificationLevel.LTA_UPDATES),
        MetadataUpdateRule().as_qualified(ModificationLevel.LTA_UPDATES)
    ],
    form_rule=FormUpdatingRule(
        field_rules=[
            SigFieldCreationRule(), SigFieldModificationRule(),
            GenericFieldModificationRule()
        ],
    )
)
"""
Default :class:`.DiffPolicy` implementation.

This policy includes the following rules, all with the default settings.
The unqualified rules in the list all have their updates qualified at
level :class:`~.ModificationLevel.LTA_UPDATES`.

* :class:`.CatalogModificationRule`,
* :class:`.DocInfoRule`,
* :class:`.ObjectStreamRule`,
* :class:`.XrefStreamRule`,
* :class:`.DSSCompareRule`,
* :class:`.MetadataUpdateRule`.
* :class:`.FormUpdatingRule`, with the following field rules:

    * :class:`.SigFieldCreationRule`,
    * :class:`.SigFieldModificationRule`,
    * :class:`.GenericFieldModificationRule`.
"""


NO_CHANGES_DIFF_POLICY = StandardDiffPolicy(global_rules=[], form_rule=None)
"""
:class:`.DiffPolicy` implementation that does not provide any rules,
and will therefore simply reject all changes.
"""
