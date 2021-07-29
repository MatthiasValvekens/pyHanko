"""
.. versionadded:: 0.2.0

    :mod:`pyhanko.sign.diff_analysis` extracted from
    :mod:`pyhanko.sign.validation` and restructured into a more rule-based
    format.

This module defines utilities for difference analysis between revisions
of the same PDF file.
PyHanko uses this functionality to validate signatures on files
that have been modified after signing (using PDF's incremental update feature).

In pyHanko's validation model, every incremental update is disallowed by
default. For a change to be accepted, it must be cleared by at least one
whitelisting rule.
These rules can moreover *qualify* the modification level at which they accept
the change (see :class:`.ModificationLevel`).
Additionally, any rule can veto an entire revision as suspect by raising
a :class:`.SuspiciousModification` exception.
Whitelisting rules are encouraged to apply their vetoes liberally.


Whitelisting rules are bundled in :class:`.DiffPolicy` objects for use by the
validator.


Guidelines for developing rules for use with :class:`.StandardDiffPolicy`
-------------------------------------------------------------------------

.. caution::
    These APIs aren't fully stable yet, so some changes might still occur
    between now and the first major release.

In general, you should keep the following informal guidelines in mind when
putting together custom diff rules.

* All rules are either executed completely (i.e. their generators exhausted)
  or aborted.
* If the diff runner aborts a rule, this always means that the entire
  revision is rejected. In other words, for accepted revisions, all rules
  will always have run to completion.
* Whitelisting rules are allowed to informally delegate some checking to
  other rules, provided that this is documented clearly.

  .. note::
      Example: :class:`.CatalogModificationRule` ignores ``/AcroForm``,
      which is validated by another rule entirely.

* Rules should be entirely stateless.
  "Clearing" a reference by yielding it does not imply that the revision
  cannot be vetoed by that same rule further down the road (this is why
  the first point is important).

"""

import re
import logging
from collections import defaultdict
from dataclasses import dataclass
from enum import unique
from io import BytesIO
from typing import (
    Iterable, Optional, Set, Tuple, Generator, TypeVar, Dict,
    List, Callable, Union, Iterator
)

from pyhanko.pdf_utils.generic import Reference, PdfObject
from pyhanko.pdf_utils.misc import OrderedEnum
from pyhanko.pdf_utils.reader import (
    HistoricalResolver, PdfFileReader,
    RawPdfPath,
)
from pyhanko.pdf_utils import generic, misc
from pyhanko.sign.fields import FieldMDPSpec, MDPPerm

__all__ = [
    'ModificationLevel', 'SuspiciousModification',
    'QualifiedWhitelistRule', 'WhitelistRule', 'qualify', 'ReferenceUpdate',
    'DocInfoRule', 'DSSCompareRule', 'MetadataUpdateRule',
    'CatalogModificationRule', 'ObjectStreamRule', 'XrefStreamRule',
    'FormUpdatingRule', 'FormUpdate',
    'FieldMDPRule', 'FieldComparisonSpec', 'FieldComparisonContext',
    'GenericFieldModificationRule', 'SigFieldCreationRule',
    'SigFieldModificationRule', 'BaseFieldModificationRule',
    'DiffPolicy', 'StandardDiffPolicy',
    'DEFAULT_DIFF_POLICY', 'NO_CHANGES_DIFF_POLICY',
    'DiffResult'
]

logger = logging.getLogger(__name__)

# /Ff: Form field flags can always be updated
FORMFIELD_ALWAYS_MODIFIABLE = {'/Ff'}
# /AP: appearance dictionary
# /AS: current appearance state
# /V: field value
# /F: (widget) annotation flags
# /DA: default appearance
# /Q: quadding
VALUE_UPDATE_KEYS = (
    FORMFIELD_ALWAYS_MODIFIABLE | {'/AP', '/AS', '/V', '/F', '/DA', '/Q'}
)
VRI_KEY_PATTERN = re.compile('/[A-Z0-9]{40}')


@unique
class ModificationLevel(OrderedEnum):
    """
    Records the (semantic) modification level of a document.

    Compare :class:`~.pyhanko.sign.fields.MDPPerm`, which records the document
    modification policy associated with a particular signature, as opposed
    to the empirical judgment indicated by this enum.
    """

    NONE = 0
    """
    The document was not modified at all (i.e. it is byte-for-byte unchanged).
    """

    LTA_UPDATES = 1
    """
    The only updates are of the type that would be allowed as part of 
    signature long term archival (LTA) processing.
    That is to say, updates to the document security store or new document
    time stamps. For the purposes of evaluating whether a document has been
    modified in the sense defined in the PAdES and ISO 32000-2 standards,
    these updates do not count.
    Adding form fields is permissible at this level, but only if they are 
    signature fields. This is necessary for proper document timestamp support.
    """

    FORM_FILLING = 2
    """
    The only updates are extra signatures and updates to form field values or
    their appearance streams, in addition to the previous levels.
    """

    ANNOTATIONS = 3
    """
    In addition to the previous levels, manipulating annotations is also allowed 
    at this level.

    .. note::
        This level is currently unused by the default diff policy, and 
        modifications to annotations other than those permitted to fill in forms
        are treated as suspicious.
    """

    OTHER = 4
    """
    The document has been modified in ways that aren't on the validator's
    whitelist. This always invalidates the corresponding signature, irrespective
    of cryptographical integrity or ``/DocMDP`` settings.
    """


class SuspiciousModification(ValueError):
    """Error indicating a suspicious modification"""
    pass


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


R = TypeVar('R')
X = TypeVar('X')


def qualify(level: ModificationLevel,
            rule_result: Generator[X, None, R],
            transform: Callable[[X], ReferenceUpdate] = lambda x: x)\
        -> Generator[Tuple[ModificationLevel, ReferenceUpdate], None, R]:
    """
    This is a helper function for rule implementors.
    It attaches a fixed modification level to an existing reference update
    generator, respecting the original generator's return value (if relevant).

    A prototypical use would be of the following form:

    .. code-block:: python

        def some_generator_function():
            # do stuff
            for ref in some_list:
                # do stuff
                yield ref

            # do more stuff
            return summary_value

        # ...

        def some_qualified_generator_function():
            summary_value = yield from qualify(
                ModificationLevel.FORM_FILLING,
                some_generator_function()
            )

    Provided that ``some_generator_function`` yields
    :class:`~.generic.ReferenceUpdate` objects, the yield type of the resulting
    generator will be tuples of the form ``(level, ref)``.

    :param level:
        The modification level to set.
    :param rule_result:
        A generator that outputs references to be whitelisted.
    :param transform:
        Function to apply to the reference object before appending
        the modification level and yielding it.
        Defaults to the identity.
    :return:
        A converted generator that outputs references qualified at the
        modification level specified.
    """
    return misc.map_with_return(
        rule_result, lambda ref: (level, transform(ref))
    )


def _safe_whitelist(old: HistoricalResolver, old_ref, new_ref) \
        -> Generator[Reference, None, None]:
    if old_ref:
        _assert_not_stream(old_ref.get_object())

    if old_ref == new_ref:
        _assert_not_stream(new_ref.get_object())
        yield new_ref
    elif old.is_ref_available(new_ref):
        yield new_ref
    else:
        raise SuspiciousModification(
            f"Update clobbers or reuses {new_ref} in an unexpected way."
        )


class DocInfoRule(WhitelistRule):
    """
    Rule that allows the ``/Info`` dictionary in the trailer to be updated.
    """

    def apply(self, old: HistoricalResolver, new: HistoricalResolver) \
            -> Iterable[ReferenceUpdate]:
        # updates to /Info are always OK (and must be through indirect objects)
        # Removing the /Info dictionary is no big deal, since most readers
        # will fall back to older revisions regardless
        new_info = new.trailer_view.get_value_as_reference(
            '/Info', optional=True
        )
        if new_info is None:
            return
        old_info = old.trailer_view.get_value_as_reference(
            '/Info', optional=True
        )
        path = RawPdfPath('/Info')
        yield from map(
            ReferenceUpdate.curry_ref(paths_checked=path),
            _safe_whitelist(old, old_info, new_info)
        )


def _validate_dss_substructure(old: HistoricalResolver, new: HistoricalResolver,
                               new_dict, der_stream_keys, is_vri):
    for der_obj_type in der_stream_keys:
        try:
            value = new_dict.raw_get(der_obj_type)
        except KeyError:
            continue
        if not isinstance(value.get_object(), generic.ArrayObject):
            raise SuspiciousModification(
                f"Expected array at {'VRI' if is_vri else 'DSS'} "
                f"key {der_obj_type}."
            )

        yield from map(ReferenceUpdate, new.collect_dependencies(
            value, since_revision=old.revision + 1
        ))


class DSSCompareRule(WhitelistRule):
    """
    Rule that allows changes to the document security store (DSS).

    This rule will validate the structure of the DSS quite rigidly, and
    will raise :class:`.SuspiciousModification` whenever it encounters
    structural problems with the DSS.
    Similarly, modifications that remove items from the DSS also count as
    suspicious.
    """

    def apply(self, old: HistoricalResolver, new: HistoricalResolver)\
            -> Iterable[ReferenceUpdate]:
        # TODO refactor these into less ad-hoc rules

        dss_path = RawPdfPath('/Root', '/DSS')
        old_dss, new_dss = yield from misc.map_with_return(
            _compare_key_refs('/DSS', old, old.root, new.root),
            ReferenceUpdate.curry_ref(paths_checked=dss_path)
        )
        if new_dss is None:
            return

        if old_dss is None:
            old_dss = generic.DictionaryObject()
        nodict_err = "/DSS is not a dictionary"
        if not isinstance(old_dss, generic.DictionaryObject):
            raise misc.PdfReadError(nodict_err)  # pragma: nocover
        if not isinstance(new_dss, generic.DictionaryObject):
            raise SuspiciousModification(nodict_err)

        dss_der_stream_keys = {'/Certs', '/CRLs', '/OCSPs'}
        dss_expected_keys = {'/Type', '/VRI'} | dss_der_stream_keys
        dss_keys = set(new_dss.keys())

        if not (dss_keys <= dss_expected_keys):
            raise SuspiciousModification(
                f"Unexpected keys in DSS: {dss_keys - dss_expected_keys}."
            )

        yield from _validate_dss_substructure(
            old, new, new_dss, dss_der_stream_keys, is_vri=False
        )

        # check that the /VRI dictionary still contains all old keys, unchanged.
        vri_path = RawPdfPath('/Root', '/DSS', '/VRI')
        old_vri, new_vri = yield from misc.map_with_return(
            _compare_key_refs(
                '/VRI', old, old_dss, new_dss,
            ), ReferenceUpdate.curry_ref(paths_checked=vri_path)

        )

        nodict_err = "/VRI is not a dictionary"
        if new_vri is not None:
            if not isinstance(new_vri, generic.DictionaryObject):
                raise SuspiciousModification(nodict_err)
            if old_vri is None:
                old_vri = generic.DictionaryObject()
            elif not isinstance(old_vri, generic.DictionaryObject):
                raise misc.PdfReadError(nodict_err)  # pragma: nocover
            yield from DSSCompareRule._check_vri(old, new, old_vri, new_vri)

        # The case where /VRI was deleted is checked by _compare_key_refs

    @staticmethod
    def _check_vri(old, new, old_vri, new_vri):
        new_vri_hashes = set(new_vri.keys())
        for key, old_vri_value in old_vri.items():
            try:
                new_vri_dict = new_vri.raw_get(key)
            except KeyError:
                new_vri_dict = None

            if new_vri_dict != old_vri_value:
                # indirect or direct doesn't matter, they have to be the same
                raise SuspiciousModification(
                    f"VRI key {key} was modified or deleted."
                )

        # check the newly added entries
        vri_der_stream_keys = {'/Cert', '/CRL', '/OCSP'}
        vri_expected_keys = {'/Type', '/TU', '/TS'} | vri_der_stream_keys
        for key in new_vri_hashes - old_vri.keys():
            if not VRI_KEY_PATTERN.match(key):
                raise SuspiciousModification(
                    f"VRI key {key} is not formatted correctly."
                )

            new_vri_dict = new_vri.raw_get(key)
            if isinstance(new_vri_dict, generic.IndirectObject) \
                    and old.is_ref_available(new_vri_dict.reference):
                yield ReferenceUpdate(new_vri_dict.reference)
                new_vri_dict = new_vri_dict.get_object()
            _assert_not_stream(new_vri_dict)
            if not isinstance(new_vri_dict, generic.DictionaryObject):
                raise SuspiciousModification(
                    "VRI entries should be dictionaries"
                )

            new_vri_value_keys = new_vri_dict.keys()
            if not (new_vri_value_keys <= vri_expected_keys):
                raise SuspiciousModification(
                    "Unexpected keys in VRI dictionary: "
                    f"{new_vri_value_keys - vri_expected_keys}."
                )
            yield from _validate_dss_substructure(
                old, new, new_vri_dict, vri_der_stream_keys, is_vri=True
            )

            # /TS is also a DER stream
            try:
                ts_ref = new_vri_dict.get_value_as_reference(
                    '/TS', optional=True
                )
                if ts_ref is not None and old.is_ref_available(ts_ref):
                    yield ReferenceUpdate(ts_ref)
            except misc.IndirectObjectExpected:
                pass


@dataclass(frozen=True)
class FieldComparisonSpec:
    """
    Helper object that specifies a form field name together with references
    to its old and new versions.
    """

    field_type: str
    """
    The (fully qualified) form field name.
    """

    old_field_ref: Optional[generic.Reference]
    """
    A reference to the field's dictionary in the old revision, if present.
    """

    new_field_ref: Optional[generic.Reference]
    """
    A reference to the field's dictionary in the new revision, if present.
    """

    old_canonical_path: Optional[RawPdfPath]
    """
    Path from the trailer through the AcroForm structure to this field (in the
    older revision). If the field is new, set to ``None``.
    """

    @property
    def old_field(self) -> Optional[generic.DictionaryObject]:
        """
        :return:
            The field's dictionary in the old revision, if present, otherwise
            ``None``.
        """
        ref = self.old_field_ref
        if ref is None:
            return None
        field = ref.get_object()
        assert isinstance(field, generic.DictionaryObject)
        return field

    @property
    def new_field(self) -> Optional[generic.DictionaryObject]:
        """
        :return:
            The field's dictionary in the new revision, if present, otherwise
            ``None``.
        """
        ref = self.new_field_ref
        if ref is None:
            return None
        field = ref.get_object()
        assert isinstance(field, generic.DictionaryObject)
        return field

    def expected_paths(self):
        # these are the paths where we expect the form field to be referred to
        paths = self._old_annotation_paths()
        struct_path = self._find_in_structure_tree()
        if struct_path is not None:
            paths.add(struct_path)
        paths.add(self.old_canonical_path)
        return paths

    def _find_in_structure_tree(self):
        # collect paths (0 or 1) through which this field appears
        #  in the file's structure tree.

        # TODO check whether the structure element is a form control
        #  (or something role-mapped to it)
        # TODO if multiple paths exist, we should only whitelist the one
        #  that corresponds to the StructParent entry, not just the first one

        # Note: the path simplifier suppresses the extra cross-references
        # from parent pointers in the tree and from the /ParentTree index.

        old_field_ref = self.old_field_ref
        old = self.old_field_ref.get_pdf_handler()
        assert isinstance(old, HistoricalResolver)

        if '/StructTreeRoot' not in old.root:
            return

        # check if the path ends in Form.K.Obj and
        # starts with Root.StructTreeRoot.K
        for pdf_path in old._get_usages_of_ref(old_field_ref):
            # Root.StructTreeRoot.K is three, and K.Obj at the end is
            # another 2
            if '/StructTreeRoot' in pdf_path and len(pdf_path) >= 5:
                root, struct_tree_root, k1 = pdf_path.path[:3]
                k2, obj = pdf_path.path[-2:]
                if k1 == k2 == '/K' and obj == '/Obj' and root == '/Root' \
                        and struct_tree_root == '/StructTreeRoot':
                    return pdf_path

    def _old_annotation_paths(self):
        # collect path(s) through which this field is used as an annotation
        # the clean way to accomplish this would be to follow /P
        # and go from there, but /P is optional, so we have to get a little
        # creative.
        old_field_ref = self.old_field_ref
        if old_field_ref is None:
            return set()  # pragma: nocover

        old = self.old_field_ref.get_pdf_handler()
        assert isinstance(old, HistoricalResolver)

        all_paths = old._get_usages_of_ref(old_field_ref)

        def _path_ok(pdf_path: RawPdfPath):
            # check if the path looks like a path to an annotation on a page

            # .Root.Pages.Kids[0].Annots[0] is the shortest you can get,
            # so 6 nodes is the minimum
            if len(pdf_path) < 6:
                return False
            fst, snd, *rest = pdf_path.path
            if fst != '/Root' or snd != '/Pages':
                return False

            # there should be one or more elements of the form /Kids[i] now
            descended = False
            nxt, nxt_ix, *rest = rest
            while nxt == '/Kids' and isinstance(nxt_ix, int):
                descended = True
                nxt, nxt_ix, *rest = rest

            # rest should be nothing and nxt should be /Annots
            return (
                descended and not rest and nxt == '/Annots'
                and isinstance(nxt_ix, int)
            )

        return {p for p in all_paths if _path_ok(p)}


@dataclass(frozen=True)
class FieldComparisonContext:
    """
    Context for a form diffing operation.
    """

    field_specs: Dict[str, FieldComparisonSpec]
    """
    Dictionary mapping field names to :class:`.FieldComparisonSpec` objects.
    """

    old: HistoricalResolver
    """
    The older, base revision.
    """

    new: HistoricalResolver
    """
    The newer revision.
    """


@dataclass(frozen=True)
class FormUpdate(ReferenceUpdate):
    """
    Container for a reference together with (optional) metadata.

    Currently, this metadata consists of the relevant field's (fully qualified)
    name, and whether the update should be approved or not if said field
    is locked by the FieldMDP policy currently in force.
    """

    field_name: Optional[str] = None
    """
    The relevant field's fully qualified name, or ``None`` if there's either
    no obvious associated field, or if there are multiple reasonable candidates.
    """

    valid_when_locked: bool = False
    """
    Flag indicating whether the update is valid even when the field is locked.
    This is only relevant if :attr:`field_name` is not ``None``.
    """

    valid_when_certifying: bool = True
    """
    Flag indicating whether the update is valid when checking against an
    explicit DocMDP policy. Default is ``True``.
    If ``False``, the change will only be accepted if we are evaluating changes
    to a document after an approval signature.
    """


class FieldMDPRule:
    """
    Sub-rules attached to a :class:`.FormUpdatingRule`.
    """

    def apply(self, context: FieldComparisonContext) \
            -> Iterable[Tuple[ModificationLevel, FormUpdate]]:
        """
        Apply the rule to the given :class:`.FieldComparisonContext`.

        :param context:
            The context of this form revision evaluation, given as an instance
            of :class:`.FieldComparisonContext`.
        """
        raise NotImplementedError


def is_annot_visible(annot_dict):
    try:
        x1, y1, x2, y2 = annot_dict['/Rect']
        area = abs(x1 - x2) * abs(y1 - y2)
    except (TypeError, ValueError, KeyError):
        area = 0

    return bool(area)


def is_field_visible(field_dict):
    if '/Kids' not in field_dict:
        return is_annot_visible(field_dict)
    else:
        return is_annot_visible(field_dict) or any(
            is_annot_visible(kid.get_object()) for kid in field_dict['/Kids']
        )


class SigFieldCreationRule(FieldMDPRule):
    """
    This rule allows signature fields to be created at the root of the form
    hierarchy, but disallows the creation of other types of fields.
    It also disallows field deletion.

    In addition, this rule will allow newly created signature fields to
    attach themselves as widget annotations to pages.

    The creation of invisible signature fields is considered a modification
    at level :attr:`.ModificationLevel.LTA_UPDATES`, but appearance-related
    changes will be qualified with :attr:`.ModificationLevel.FORM_FILLING`.

    :param allow_new_visible_after_certify:
        Creating new visible signature fields is disallowed after
        certification signatures by default; this is stricter than Acrobat.
        Set this parameter to ``True`` to disable this check.
    :param approve_widget_bindings:
        Set to ``False`` to reject new widget annotation registrations
        associated with approved new fields.
    """

    def __init__(self, approve_widget_bindings=True,
                 allow_new_visible_after_certify=False):
        self.approve_widget_bindings = approve_widget_bindings
        self.allow_new_visible_after_certify = allow_new_visible_after_certify

    def apply(self, context: FieldComparisonContext) \
            -> Iterable[Tuple[ModificationLevel, FormUpdate]]:

        deleted = set(
            fq_name for fq_name, spec in context.field_specs.items()
            if spec.old_field_ref and not spec.new_field_ref
        )
        if deleted:
            raise SuspiciousModification(
                f"Fields {deleted} were deleted after signing."
            )

        def _collect():
            for fq_name, spec in context.field_specs.items():
                if spec.field_type != '/Sig' or spec.old_field_ref:
                    continue
                yield fq_name, spec.new_field_ref

        all_new_refs = dict(_collect())

        # The form MDP logic already vetted the /AcroForm dictionary itself
        # (including the /Fields ref), so our only responsibility is to match
        # up the names of new fields
        approved_new_fields = set(all_new_refs.keys())
        actual_new_fields = set(
            fq_name for fq_name, spec in context.field_specs.items()
            if spec.old_field_ref is None
        )

        if actual_new_fields != approved_new_fields:
            raise SuspiciousModification(
                "More form fields added than expected: expected "
                f"only {approved_new_fields}, but found new fields named "
                f"{actual_new_fields - approved_new_fields}."
            )

        # finally, deal with the signature fields themselves
        # The distinction between timestamps and signatures isn't relevant
        # yet, that's a problem for /V, which we don't bother with here.
        field_ref_reverse = {}

        for fq_name, sigfield_ref in all_new_refs.items():

            # New field, so all its dependencies are good to go
            # that said, only the field itself is cleared at LTA update level,
            # (and only if it is invisible)
            # the other deps bump the modification level up to FORM_FILL

            # Since LTA updates should arguably not trigger field locks either
            # (relevant for FieldMDP settings that use /All or /Exclude),
            # we pass valid_when_locked=True on these updates
            sigfield = sigfield_ref.get_object()
            visible = is_field_visible(sigfield)
            mod_level = (
                ModificationLevel.FORM_FILLING
                if visible else ModificationLevel.LTA_UPDATES
            )
            if context.old.is_ref_available(sigfield_ref):
                yield mod_level, FormUpdate(
                    updated_ref=sigfield_ref, field_name=fq_name,
                    valid_when_locked=not visible,
                    valid_when_certifying=(
                        not visible or self.allow_new_visible_after_certify
                    )
                )
            # checked by field listing routine already
            assert isinstance(sigfield, generic.DictionaryObject)

            def _handle_deps(pdf_dict, _key):
                try:
                    raw_value = pdf_dict.raw_get(_key)

                    deps = context.new.collect_dependencies(
                        raw_value,
                        since_revision=context.old.revision + 1
                    )
                    yield from qualify(
                        ModificationLevel.FORM_FILLING,
                        misc._as_gen(deps),
                        transform=FormUpdate.curry_ref(field_name=fq_name)
                    )
                except KeyError:
                    pass

            for _key in ('/AP', '/Lock', '/SV'):
                yield from _handle_deps(sigfield, _key)

            # if the field has widget annotations in /Kids, add them to the
            #  field_ref_reverse dictionary for annotation processing later
            try:
                kids_arr_ref = sigfield.raw_get('/Kids')
                old = context.old
                if isinstance(kids_arr_ref, generic.IndirectObject) \
                        and old.is_ref_available(kids_arr_ref.reference):
                    yield mod_level, FormUpdate(
                        updated_ref=kids_arr_ref.reference, field_name=fq_name,
                        valid_when_locked=not visible
                    )
                kid_refs = _arr_to_refs(
                    kids_arr_ref.get_object(), SuspiciousModification
                )
                # process all widgets in /Kids
                # in principle there should be only one, but we don't enforce
                # that restriction here
                # TODO make that togglable?
                for kid in kid_refs:
                    if '/T' not in kid.get_object():
                        field_ref_reverse[kid] = fq_name
                        if old.is_ref_available(kid):
                            yield mod_level, FormUpdate(
                                updated_ref=kid, field_name=fq_name,
                                valid_when_locked=not visible
                            )
                        # pull in appearance dependencies
                        yield from _handle_deps(kid.get_object(), '/AP')
            except KeyError:
                # No /Kids => assume the field is its own annotation
                field_ref_reverse[sigfield_ref] = fq_name

        # Now we process (widget) annotations: newly added signature fields may
        #  be added to the /Annots entry of any page. These are processed as LTA
        #  updates, because even invisible signature fields / timestamps might
        #  be added to /Annots (this isn't strictly necessary, but more
        #  importantly it's not forbidden).
        # Note: we don't descend into the annotation dictionaries themselves.
        #  For modifications to form field values, this is the purview
        #  of the appearance checkers.
        # TODO allow other annotation modifications, but at level ANNOTATIONS
        # if no new sigfields were added, we skip this step.
        #  Any modifications to /Annots will be flagged by the xref
        #  crawler later.

        if not self.approve_widget_bindings or not all_new_refs:
            return

        # note: this is guaranteed to be equal to its signed counterpart,
        # since we already checked the document catalog for unauthorised
        # modifications
        old_page_root = context.old.root['/Pages']
        new_page_root = context.new.root['/Pages']

        yield from qualify(
            ModificationLevel.LTA_UPDATES,
            _walk_page_tree_annots(
                old_page_root, new_page_root,
                field_ref_reverse, context.old,
                valid_when_locked=True
            )
        )


class BaseFieldModificationRule(FieldMDPRule):
    """
    Base class that implements some boilerplate to validate modifications
    to individual form fields.
    """

    def __init__(self, always_modifiable=None, value_update_keys=None):
        self.always_modifiable = (
            always_modifiable if always_modifiable is not None
            else FORMFIELD_ALWAYS_MODIFIABLE
        )
        self.value_update_keys = (
            value_update_keys if value_update_keys is not None
            else VALUE_UPDATE_KEYS
        )

    def compare_fields(self, spec: FieldComparisonSpec) -> bool:
        """
        Helper method to compare field dictionaries.

        :param spec:
            The current :class:`.FieldComparisonSpec`.
        :return:
            ``True`` if the modifications are permissible even when the field is
            locked, ``False`` otherwise.
            If keys beyond those in :attr:`value_update_keys` are changed,
            a :class:`.SuspiciousModification` is raised.
        """

        # we compare twice: the first test ignores all value_update_keys,
        # and the second (stricter) test checks if the update would still
        # be OK on a locked field.
        old_field = spec.old_field
        new_field = spec.new_field
        _compare_dicts(
            old_field, new_field, self.value_update_keys
        )
        return _compare_dicts(
            old_field, new_field, self.always_modifiable, raise_exc=False
        )

    def apply(self, context: FieldComparisonContext) \
            -> Iterable[Tuple[ModificationLevel, FormUpdate]]:

        for fq_name, spec in context.field_specs.items():
            yield from self.check_form_field(fq_name, spec, context)

    def check_form_field(self, fq_name: str, spec: FieldComparisonSpec,
                         context: FieldComparisonContext) \
            -> Iterable[Tuple[ModificationLevel, FormUpdate]]:
        """
        Investigate updates to a particular form field.
        This function is called by :meth:`apply` for every form field in
        the new revision.

        :param fq_name:
            The fully qualified name of the form field.j
        :param spec:
            The :class:`.FieldComparisonSpec` object describing the old state
            of the field in relation to the new state.
        :param context:
            The full :class:`.FieldComparisonContext` that is currently
            being evaluated.
        :return:
            An iterable yielding :class:`.FormUpdate` objects qualified
            with an appropriate :class:`.ModificationLevel`.
        """
        raise NotImplementedError


class SigFieldModificationRule(BaseFieldModificationRule):
    """
    This rule allows signature fields to be filled in, and set an appearance
    if desired. Deleting values from signature fields is disallowed, as is
    modifying signature fields that already contain a signature.

    This rule will take field locks into account if the
    :class:`.FieldComparisonContext` includes a :class:`.FieldMDPSpec`.

    For (invisible) document timestamps, this is allowed at
    :class:`.ModificationLevel.LTA_UPDATES`, but in all other cases
    the modification level will be bumped to
    :class:`.ModificationLevel.FORM_FILLING`.
    """

    def check_form_field(self, fq_name: str, spec: FieldComparisonSpec,
                         context: FieldComparisonContext) \
            -> Iterable[Tuple[ModificationLevel, FormUpdate]]:

        # deal with "freshly signed" signature fields,
        # i.e. those that are filled now, but weren't previously
        #  + newly created ones
        if spec.field_type != '/Sig' or not spec.new_field_ref:
            return

        old_field = spec.old_field
        new_field = spec.new_field

        previously_signed = old_field is not None and '/V' in old_field
        now_signed = '/V' in new_field

        if old_field:
            # operating on an existing field ---> check changes
            # (if the field we're dealing with is new, we don't need
            #  to bother, the sig field creation rule takes care of that)

            # here, we check that the form field didn't change
            # beyond the keys that we expect to change when updating,
            # and also register whether the changes made would be
            # permissible even when the field is locked.
            valid_when_locked = self.compare_fields(spec)

            field_ref_update = FormUpdate(
                updated_ref=spec.new_field_ref, field_name=fq_name,
                valid_when_locked=valid_when_locked,
                paths_checked=spec.expected_paths()
            )

            if not previously_signed and now_signed:
                yield ModificationLevel.LTA_UPDATES, field_ref_update

                # whitelist appearance updates at FORM_FILL level
                yield from qualify(
                    ModificationLevel.FORM_FILLING,
                    _allow_appearance_update(
                        old_field, new_field, context.old, context.new
                    ),
                    transform=FormUpdate.curry_ref(field_name=fq_name)
                )
            else:
                # case where the field was already signed, or is still
                # not signed in the current revision.
                # in this case, the state of the field better didn't change
                # at all!
                # ... but Acrobat apparently sometimes sets /Ff rather
                #  liberally, so we have to make some allowances
                if valid_when_locked:
                    yield ModificationLevel.LTA_UPDATES, field_ref_update
                # Skip the comparison logic on /V. In particular, if
                # the signature object in question was overridden,
                # it should trigger a suspicious modification later.
                return

        if not now_signed:
            return

        # We're now in the case where the form field did not exist or did
        # not have a value in the original revision, but does have one in
        # the revision we're auditing. If the signature is /DocTimeStamp,
        # this is a modification at level LTA_UPDATES. If it's a normal
        # signature, it requires FORM_FILLING.
        try:
            current_value_ref = new_field.get_value_as_reference('/V')
        except (misc.IndirectObjectExpected, KeyError):
            raise SuspiciousModification(
                f"Value of signature field {fq_name} should be an indirect "
                f"reference"
            )

        sig_obj = current_value_ref.get_object()
        if not isinstance(sig_obj, generic.DictionaryObject):
            raise SuspiciousModification(
                f"Value of signature field {fq_name} is not a dictionary"
            )

        visible = is_field_visible(new_field)

        # /DocTimeStamps added for LTA validation purposes shouldn't have
        # an appearance (as per the recommendation in ISO 32000-2, which we
        # enforce as a rigid rule here)
        if sig_obj.raw_get('/Type') == '/DocTimeStamp' and not visible:
            sig_whitelist = ModificationLevel.LTA_UPDATES
            valid_when_locked = True
        else:
            sig_whitelist = ModificationLevel.FORM_FILLING
            valid_when_locked = False

        # first, whitelist the actual signature object
        yield sig_whitelist, FormUpdate(
            updated_ref=current_value_ref, field_name=fq_name,
            valid_when_locked=valid_when_locked
        )

        # since apparently Acrobat didn't get the memo about not having
        # indirect references in signature objects, we have to do some
        # tweaking to whitelist /TransformParams if necessary
        try:
            # the issue is with signature reference dictionaries
            for sigref_dict in sig_obj.raw_get('/Reference'):
                try:
                    tp = sigref_dict.raw_get('/TransformParams')
                    yield (
                        sig_whitelist,
                        FormUpdate(
                            updated_ref=tp.reference, field_name=fq_name
                        )
                    )
                except (KeyError, AttributeError):
                    continue
        except KeyError:
            pass


class GenericFieldModificationRule(BaseFieldModificationRule):
    """
    This rule allows non-signature form fields to be modified at
    :class:`.ModificationLevel.FORM_FILLING`.

    This rule will take field locks into account if the
    :class:`.FieldComparisonContext` includes a :class:`.FieldMDPSpec`.
    """

    def check_form_field(self, fq_name: str, spec: FieldComparisonSpec,
                         context: FieldComparisonContext) \
            -> Iterable[Tuple[ModificationLevel, FormUpdate]]:

        if spec.field_type == '/Sig' or \
                not spec.new_field_ref or not spec.old_field_ref:
            return

        valid_when_locked = self.compare_fields(spec)

        yield (
            ModificationLevel.FORM_FILLING,
            FormUpdate(
                updated_ref=spec.new_field_ref, field_name=fq_name,
                valid_when_locked=valid_when_locked,
                paths_checked=spec.expected_paths()
            )
        )
        old_field = spec.old_field
        new_field = spec.new_field
        yield from qualify(
            ModificationLevel.FORM_FILLING,
            _allow_appearance_update(
                old_field, new_field, context.old, context.new
            ),
            transform=FormUpdate.curry_ref(field_name=fq_name)
        )
        try:
            new_value = new_field.raw_get('/V')
        except KeyError:
            # no current value => nothing else to check
            return
        try:
            old_value = old_field.raw_get('/V')
        except KeyError:
            old_value = None

        # if the value was changed, pull in newly defined objects.
        # TODO is this sufficient?
        if new_value != old_value:
            deps = context.new.collect_dependencies(
                new_value,
                since_revision=context.old.revision + 1
            )
            yield from qualify(
                ModificationLevel.FORM_FILLING,
                misc._as_gen(deps),
                transform=FormUpdate.curry_ref(field_name=fq_name)
            )


ACROFORM_EXEMPT_STRICT_COMPARISON = {
    '/Fields', '/DR', '/DA', '/Q', '/NeedAppearances'
}


class FormUpdatingRule:
    """
    Special whitelisting rule that validates changes to the form attached to
    the input document.

    This rule is special in two ways:

    * it outputs :class:`.FormUpdate` objects instead of references;
    * it delegates most of the hard work to sub-rules (instances of
      :class:`.FieldMDPRule`).

    A :class:`.DiffPolicy` can have at most one :class:`.FormUpdatingRule`,
    but there is no limit on the number of :class:`.FieldMDPRule` objects
    attached to it.

    :class:`.FormUpdate` objects contain a reference plus metadata about
    the form field it belongs to.

    :param field_rules:
        A list of :class:`.FieldMDPRule` objects to validate the individual
        form fields.
    :param ignored_acroform_keys:
        Keys in the ``/AcroForm`` dictionary that may be changed.
        Changes are potentially subject to validation by other rules.
    """

    def __init__(self, field_rules: List[FieldMDPRule],
                 ignored_acroform_keys=None):
        self.field_rules = field_rules
        self.ignored_acroform_keys = (
            ignored_acroform_keys if ignored_acroform_keys is not None
            else ACROFORM_EXEMPT_STRICT_COMPARISON
        )

    def apply(self, old: HistoricalResolver, new: HistoricalResolver)\
            -> Iterable[Tuple[ModificationLevel, FormUpdate]]:
        """
        Evaluate changes in the document's form between two revisions.

        :param old:
            The older, base revision.
        :param new:
            The newer revision to be vetted.
        """

        acroform_path = RawPdfPath('/Root', '/AcroForm')
        old_acroform, new_acroform = yield from qualify(
            ModificationLevel.LTA_UPDATES,
            _compare_key_refs(
                '/AcroForm', old, old.root, new.root
            ),
            transform=FormUpdate.curry_ref(
                field_name=None, paths_checked=acroform_path
            )
        )

        # first, compare the entries that aren't /Fields
        _compare_dicts(old_acroform, new_acroform, self.ignored_acroform_keys)
        assert isinstance(old_acroform, generic.DictionaryObject)
        assert isinstance(new_acroform, generic.DictionaryObject)

        # mark /Fields ref as OK if it's an indirect reference
        # This is fine: the _list_fields logic checks that it really contains
        # stuff that looks like form fields, and other rules are responsible
        # for vetting the creation of other form fields anyway.
        fields_path = acroform_path + '/Fields'
        old_fields, new_fields = yield from qualify(
            ModificationLevel.LTA_UPDATES,
            _compare_key_refs('/Fields', old, old_acroform, new_acroform),
            transform=FormUpdate.curry_ref(
                field_name=None, paths_checked=fields_path
            )
        )

        # we also need to deal with the default resource dict, since
        # Acrobat / Adobe Reader sometimes mess with it
        old_dr, new_dr = yield from qualify(
            ModificationLevel.FORM_FILLING,
            _compare_key_refs('/DR', old, old_acroform, new_acroform),
            transform=FormUpdate.curry_ref(
                field_name=None, paths_checked=acroform_path + '/DR'
            )
        )
        if new_dr is not None:
            dr_deps = new.collect_dependencies(
                new_dr, since_revision=old.revision + 1
            )
            yield from qualify(
                ModificationLevel.FORM_FILLING, misc._as_gen(dr_deps),
                transform=FormUpdate.curry_ref(field_name=None)
            )

        context = FieldComparisonContext(
            field_specs=dict(
                _list_fields(old_fields, new_fields, old_path=fields_path)
            ),
            old=old, new=new
        )

        for rule in self.field_rules:
            yield from rule.apply(context)


ROOT_EXEMPT_STRICT_COMPARISON = {
    '/AcroForm', '/DSS', '/Extensions', '/Metadata', '/MarkInfo', '/Version'
}


class CatalogModificationRule(QualifiedWhitelistRule):
    """
    Rule that adjudicates modifications to the document catalog.

    :param ignored_keys:
        Values in the document catalog that may change between revisions.
        The default ones are ``/AcroForm``, ``/DSS``, ``/Extensions``,
        ``/Metadata``, ``/MarkInfo`` and ``/Version``.

        Checking for ``/AcroForm``, ``/DSS`` and ``/Metadata`` is delegated to
        :class:`.FormUpdatingRule`, :class:`.DSSCompareRule` and
        :class:`.MetadataUpdateRule`, respectively.
    """

    def __init__(self, ignored_keys=None):
        self.ignored_keys = (
            ignored_keys if ignored_keys is not None
            else ROOT_EXEMPT_STRICT_COMPARISON
        )

    def apply_qualified(self, old: HistoricalResolver,
                        new: HistoricalResolver) \
            -> Iterable[Tuple[ModificationLevel, Reference]]:

        old_root = old.root
        new_root = new.root
        # first, check if the keys in the document catalog are unchanged
        _compare_dicts(old_root, new_root, self.ignored_keys)

        # As for the keys in the root dictionary that are allowed to change:
        #  - /Extensions requires no further processing since it must consist
        #    of direct objects anyway.
        #  - /MarkInfo: if it's an indirect reference (probably not) we can
        #    whitelist it if the key set makes sense. TODO do this
        #  - /DSS, /AcroForm and /Metadata are dealt with by other rules.
        yield ModificationLevel.LTA_UPDATES, ReferenceUpdate(
            new.root_ref, paths_checked=RawPdfPath('/Root'),
            # Things like /Data in a MDP policy can point to root
            # and since we checked with _compare_dicts, doing a blanket
            # approval is much easier than figuring out all the ways
            # in which /Root can be cross-referenced.
            blanket_approve=True
        )


class MetadataUpdateRule(WhitelistRule):
    """
    Rule to adjudicate updates to the XMP metadata stream.

    The content of the metadata isn't actually validated in any significant way;
    this class only checks whether the XML is well-formed.

    :param check_xml_syntax:
        Do a well-formedness check on the XML syntax. Default ``True``.
    :param always_refuse_stream_override:
        Always refuse to override the metadata stream if its object ID existed
        in a prior revision, including if the new stream overrides the old
        metadata stream and the syntax check passes. Default ``False``.

        .. note::
            In other situations, pyHanko will reject stream overrides on
            general principle, since combined with the fault-tolerance of some
            PDF readers, these can allow an attacker to manipulate parts of the
            signed content in subtle but significant ways.

            In case of the metadata stream, the risk is significantly mitigated
            thanks to the XML syntax check on both versions of the stream,
            but if you're feeling extra paranoid, you can turn the default
            behaviour back on by setting ``always_refuse_stream_override``
            to ``True``.
    """

    def __init__(self, check_xml_syntax=True,
                 always_refuse_stream_override=False):
        self.check_xml_syntax = check_xml_syntax
        self.always_refuse_stream_override = always_refuse_stream_override

    @staticmethod
    def is_well_formed_xml(metadata_ref: generic.Reference):
        """
        Checks whether the provided stream consists of well-formed XML data.
        Note that this does not perform any more advanced XML or XMP validation,
        the check is purely syntactic.

        :param metadata_ref:
            A reference to a (purported) metadata stream.
        :raises SuspiciousModification:
            if there are indications that the reference doesn't point to an XML
            stream.
        """
        metadata_stream = metadata_ref.get_object()

        if not isinstance(metadata_stream, generic.StreamObject):
            raise SuspiciousModification(
                "/Metadata should be a reference to a stream object"
            )

        from xml.sax.handler import ContentHandler
        from xml.sax import make_parser

        parser = make_parser()
        parser.setContentHandler(ContentHandler())
        try:
            parser.parse(BytesIO(metadata_stream.data))
        except Exception as e:
            raise SuspiciousModification(
                "/Metadata XML syntax could not be validated", e
            )

    def apply(self, old: HistoricalResolver, new: HistoricalResolver) \
            -> Iterable[ReferenceUpdate]:

        # /Metadata points to a stream, so we have to be careful allowing
        # object overrides!
        # we only approve the change if the metadata consists of well-formed xml
        # (note: this doesn't validate any XML schemata)

        def grab_metadata(root):
            try:
                return root.get_value_as_reference('/Metadata')
            except misc.IndirectObjectExpected:
                raise SuspiciousModification(
                    "/Metadata should be an indirect reference"
                )
            except KeyError:
                return

        new_metadata_ref = grab_metadata(new.root)
        if new_metadata_ref is None:
            return  # nothing to do

        if self.check_xml_syntax:
            MetadataUpdateRule.is_well_formed_xml(new_metadata_ref)

        old_metadata_ref = grab_metadata(old.root)

        if self.check_xml_syntax:
            MetadataUpdateRule.is_well_formed_xml(old_metadata_ref)

        same_ref_ok = (
            old_metadata_ref == new_metadata_ref
            and not self.always_refuse_stream_override
        )
        if same_ref_ok or old.is_ref_available(new_metadata_ref):
            yield ReferenceUpdate(
                new_metadata_ref,
                paths_checked=RawPdfPath('/Root', '/Metadata')
            )


class ObjectStreamRule(WhitelistRule):
    """
    Rule that allows object streams to be added.

    Note that this rule only whitelists the object streams themselves (provided
    they do not override any existing objects, obviously), not the objects
    in them.
    """

    def apply(self, old: HistoricalResolver, new: HistoricalResolver) \
            -> Iterable[Reference]:
        # object streams are OK, but overriding object streams is not.
        for objstream_ref in new.object_streams_used():
            if old.is_ref_available(objstream_ref):
                yield ReferenceUpdate(objstream_ref)


class XrefStreamRule(WhitelistRule):
    """
    Rule that allows new cross-reference streams to be defined.
    """

    def apply(self, old: HistoricalResolver, new: HistoricalResolver) \
            -> Iterable[Reference]:
        xref_start, _ = new.reader.xrefs.get_xref_container_info(new.revision)
        if isinstance(xref_start, generic.Reference) \
                and old.is_ref_available(xref_start):
            yield ReferenceUpdate(xref_start)


def _list_fields(old_fields: generic.PdfObject, new_fields: generic.PdfObject,
                 old_path: RawPdfPath, parent_name="", inherited_ft=None) \
        -> Dict[str, FieldComparisonSpec]:
    """
    Recursively construct a list of field names, together with their
    "incarnations" in either revision.
    """

    def _make_list(lst: generic.PdfObject, exc):
        if not isinstance(lst, generic.ArrayObject):
            raise exc("Field list is not an array.")
        names_seen = set()

        for ix, field_ref in enumerate(lst):
            if not isinstance(field_ref, generic.IndirectObject):
                raise exc("Fields must be indirect objects")

            field = field_ref.get_object()
            if not isinstance(field, generic.DictionaryObject):
                raise exc("Fields must be dictionary objects")

            try:
                name = field.raw_get('/T')
            except KeyError:
                continue
            if not isinstance(name, (generic.TextStringObject,
                                     generic.ByteStringObject)):
                raise exc("Names must be strings")
            if name in names_seen:
                raise exc("Duplicate field name")
            elif '.' in name:
                raise exc("Partial names must not contain periods")
            names_seen.add(name)

            fq_name = parent_name + "." + name if parent_name else name
            try:
                field_type = field.raw_get('/FT')
            except KeyError:
                field_type = inherited_ft

            try:
                kids = field["/Kids"]
            except KeyError:
                kids = generic.ArrayObject()

            if not kids and field_type is None:
                raise exc(
                    f"Field type of terminal field {fq_name} could not be "
                    f"determined"
                )
            yield fq_name, (field_type, field_ref.reference, kids, ix)

    old_fields_by_name = dict(_make_list(old_fields, misc.PdfReadError))
    new_fields_by_name = dict(_make_list(new_fields, SuspiciousModification))

    names = set()
    names.update(old_fields_by_name.keys())
    names.update(new_fields_by_name.keys())

    for field_name in names:
        try:
            old_field_type, old_field_ref, old_kids, field_index = \
                old_fields_by_name[field_name]
        except KeyError:
            old_field_type = old_field_ref = None
            old_kids = generic.ArrayObject()
            field_index = None

        try:
            new_field_type, new_field_ref, new_kids, _ = \
                new_fields_by_name[field_name]
        except KeyError:
            new_field_type = new_field_ref = None
            new_kids = generic.ArrayObject()

        if old_field_ref and new_field_ref:
            if new_field_type != old_field_type:
                raise SuspiciousModification(
                    f"Update changed field type of {field_name}"
                )
        common_ft = old_field_type or new_field_type
        if field_index is not None and old_path is not None:
            field_path = old_path + field_index
        else:
            field_path = None
        yield field_name, FieldComparisonSpec(
            field_type=common_ft,
            old_field_ref=old_field_ref, new_field_ref=new_field_ref,
            old_canonical_path=field_path
        )

        # recursively descend into /Kids if necessary
        if old_kids or new_kids:
            yield from _list_fields(
                old_kids, new_kids, parent_name=field_name, old_path=(
                    field_path + '/Kids' if field_path is not None else None
                ),
                inherited_ft=common_ft,
            )


def _allow_appearance_update(old_field, new_field, old: HistoricalResolver,
                             new: HistoricalResolver) \
        -> Generator[Reference, None, None]:

    old_ap_val, new_ap_val = yield from _compare_key_refs(
        '/AP', old, old_field, new_field
    )

    if new_ap_val is None:
        return

    if not isinstance(new_ap_val, generic.DictionaryObject):
        raise SuspiciousModification('/AP should point to a dictionary')

    # we *never* want to whitelist an update for an existing
    # stream object (too much potential for abuse), so we insist on
    # modifying the /N, /R, /D keys to point to new streams
    # TODO this could be worked around with a reference counter for
    #  streams, in which case we could allow the stream to be overridden
    #  on the condition that it isn't used anywhere else.

    for key in ('/N', '/R', '/D'):
        try:
            appearance_spec = new_ap_val.raw_get(key)
        except KeyError:
            continue
        yield from new.collect_dependencies(
            appearance_spec, since_revision=old.revision + 1
        )


def _arr_to_refs(arr_obj, exc, collector: Callable = list):
    arr_obj = arr_obj.get_object()
    if not isinstance(arr_obj, generic.ArrayObject):
        raise exc("Not an array object")

    def _convert():
        for indir in arr_obj:
            if not isinstance(indir, generic.IndirectObject):
                raise exc("Array contains direct objects")
            yield indir.reference

    return collector(_convert())


def _extract_annots_from_page(page, exc):
    if not isinstance(page, generic.DictionaryObject):
        raise exc("Page objects should be dictionaries")
    try:
        annots_value = page.raw_get('/Annots')
        annots_ref = (
            annots_value.reference
            if isinstance(annots_value, generic.IndirectObject)
            else None
        )
        annots = _arr_to_refs(
            annots_value, SuspiciousModification, collector=set
        )
        return annots, annots_ref
    except KeyError:
        raise


def _walk_page_tree_annots(old_page_root, new_page_root,
                           field_name_dict, old: HistoricalResolver,
                           valid_when_locked):
    def get_kids(page_root, exc):
        try:
            return _arr_to_refs(page_root['/Kids'], exc)
        except KeyError:
            raise exc("No /Kids in /Pages entry")

    old_kids = get_kids(old_page_root, misc.PdfReadError)
    new_kids = get_kids(new_page_root, SuspiciousModification)

    # /Kids should only contain indirect refs, so direct comparison is
    # appropriate (__eq__ ignores the attached PDF handler)
    if old_kids != new_kids:
        raise SuspiciousModification(
            "Unexpected change to page tree structure."
        )
    for new_kid_ref, old_kid_ref in zip(new_kids, old_kids):
        new_kid = new_kid_ref.get_object()
        old_kid = old_kid_ref.get_object()
        try:
            node_type = old_kid['/Type']
        except (KeyError, TypeError) as e:  # pragma: nocover
            raise misc.PdfReadError from e
        if node_type == '/Pages':
            yield from _walk_page_tree_annots(
                old_kid, new_kid, field_name_dict, old,
                valid_when_locked
            )
        elif node_type == '/Page':
            try:
                new_annots, new_annots_ref = _extract_annots_from_page(
                    new_kid, SuspiciousModification
                )
            except KeyError:
                # no annotations, continue
                continue
            try:
                old_annots, old_annots_ref = _extract_annots_from_page(
                    old_kid, misc.PdfReadError
                )
            except KeyError:
                old_annots_ref = None
                old_annots = set()

            # check if annotations were added
            if old_annots == new_annots:
                continue
            deleted_annots = old_annots - new_annots
            added_annots = new_annots - old_annots
            if deleted_annots:
                raise SuspiciousModification(
                    f"Annotations {deleted_annots} were deleted."
                )

            if not added_annots:
                # nothing to do
                continue

            # look up the names of the associated form field(s)
            # if any of the refs are not in the list
            # -> unrelated annotation -> bail
            unknown_annots = added_annots - field_name_dict.keys()
            if unknown_annots:
                raise SuspiciousModification(
                    f"The newly added annotations {unknown_annots} were not "
                    "recognised."
                )

            # there are new annotations, and they're all changes we expect
            # => cleared to edit

            # if there's only one new annotation, we can set the field name
            # on the resulting FormUpdate object, but otherwise there's
            # not much we can do.
            field_name = None
            if len(added_annots) == 1:
                field_name = field_name_dict[next(iter(added_annots))]

            # Make sure the page dictionaries are the same, so that we
            #  can safely clear them for modification across ALL paths
            #  (not necessary if both /Annots entries are indirect references,
            #   but adding even more cases is pushing things)
            _compare_dicts(old_kid, new_kid, {'/Annots'})
            # Page objects are often referenced from all sorts of places in the
            # file, and attempting to check all possible paths would probably
            # create more problems than it solves.
            yield FormUpdate(
                updated_ref=new_kid_ref, field_name=field_name,
                valid_when_locked=valid_when_locked and field_name is not None,
                blanket_approve=True
            )
            if new_annots_ref:
                # current /Annots entry is an indirect reference

                # collect paths to this page and append /Annots
                #  (recall: old_kid_ref and new_kid_ref should be the same
                #   anyhow)
                paths_to_annots = {
                    path + '/Annots'
                    for path in old._get_usages_of_ref(old_kid_ref)
                }

                # If the equality check fails,
                # either the /Annots array got reassigned to another
                # object ID, or it was moved from a direct object to an
                # indirect one, or the /Annots entry was newly created.
                # This is all fine, provided that the new  object
                # ID doesn't clobber an existing one.
                if old_annots_ref == new_annots_ref or \
                        old.is_ref_available(new_annots_ref):
                    yield FormUpdate(
                        updated_ref=new_annots_ref, field_name=field_name,
                        valid_when_locked=(
                            valid_when_locked and field_name is not None
                        ),
                        paths_checked=paths_to_annots
                    )


def _assert_not_stream(dict_obj):
    if isinstance(dict_obj, generic.StreamObject):
        raise SuspiciousModification(
            f"Unexpected stream encountered at {dict_obj.container_ref}!"
        )


def _compare_dicts(old_dict: PdfObject, new_dict: PdfObject,
                   ignored: Set[str] = frozenset(), raise_exc=True) -> bool:
    if not isinstance(old_dict, generic.DictionaryObject):
        raise misc.PdfReadError(
            "Encountered unexpected non-dictionary object in prior revision."
        )  # pragma: nocover
    if not isinstance(new_dict, generic.DictionaryObject):
        raise SuspiciousModification(
            "Dict is overridden by non-dict in new revision"
        )

    _assert_not_stream(old_dict)
    _assert_not_stream(new_dict)
    new_dict_keys = set(new_dict.keys()) - ignored
    old_dict_keys = set(old_dict.keys()) - ignored
    if new_dict_keys != old_dict_keys:
        if raise_exc:
            raise SuspiciousModification(
                f"Dict keys differ: {new_dict_keys} vs. "
                f"{old_dict_keys}."
            )
        else:
            return False

    for k in new_dict_keys:
        new_val = new_dict.raw_get(k)
        old_val = old_dict.raw_get(k)
        if new_val != old_val:
            if raise_exc:
                raise SuspiciousModification(
                    f"Values for dict key {k} differ:"
                    f"{old_val} changed to {new_val}"
                )
            else:
                return False

    return True


TwoVersions = Tuple[Optional[generic.PdfObject], Optional[generic.PdfObject]]


def _compare_key_refs(key, old: HistoricalResolver,
                      old_dict: generic.DictionaryObject,
                      new_dict: generic.DictionaryObject) \
        -> Generator[Reference, None, TwoVersions]:
    """
    Ensure that updating a key in a dictionary has no undesirable side effects.
    The following scenarios are allowed:

    1. adding a key in new_dict
    2. replacing a direct value in old_dict with a reference in new_dict
    3. the reverse (allowed by default)
    4. replacing a reference with another reference (that doesn't override
       anything else)

    The restrictions of _safe_whitelist apply to this function as well.

    Note: this routine is only safe to use if the structure of the resulting
    values is also checked. Otherwise, it can lead to reference leaks if
    one is not careful.
    """

    try:
        old_value = old_dict.raw_get(key)
        if isinstance(old_value, generic.IndirectObject):
            old_value_ref = old_value.reference
            old_value = old_value.get_object()
        else:
            old_value_ref = None
    except KeyError:
        old_value_ref = old_value = None

    try:
        new_value = new_dict.raw_get(key)
        if isinstance(new_value, generic.IndirectObject):
            new_value_ref = new_value.reference
            new_value = new_value.get_object()
        else:
            new_value_ref = None
    except KeyError:
        if old_value is not None:
            raise SuspiciousModification(
                f"Key {key} was deleted from dictionary"
            )
        return None, None  # nothing to do

    if new_value_ref is not None:
        yield from _safe_whitelist(old, old_value_ref, new_value_ref)

    return old_value, new_value


@dataclass(frozen=True)
class DiffResult:
    """
    Encodes the result of a difference analysis on two revisions.

    Returned by :meth:`.DiffPolicy.apply`.
    """

    modification_level: ModificationLevel
    """
    The strictest modification level at which all changes pass muster.
    """

    changed_form_fields: Set[str]
    """
    Set containing the names of all changed form fields.
    
    .. note::
        For the purposes of this parameter, a change is defined as any
        :class:`.FormUpdate` where :attr:`.FormUpdate.valid_when_locked`
        is ``False``.
    """


class DiffPolicy:
    """
    Analyse the differences between two revisions.
    """

    def apply(self, old: HistoricalResolver, new: HistoricalResolver,
              field_mdp_spec: Optional[FieldMDPSpec] = None,
              doc_mdp: Optional[MDPPerm] = None) -> DiffResult:
        """
        Execute the policy on a pair of revisions, with the MDP values provided.
        :class:`.SuspiciousModification` exceptions should be propagated.

        :param old:
            The older, base revision.
        :param new:
            The newer revision.
        :param field_mdp_spec:
            The field MDP spec that's currently active.
        :param doc_mdp:
            The DocMDP spec that's currently active.
        :return:
            A :class:`.DiffResult` object summarising the policy's judgment.
        """
        raise NotImplementedError

    def review_file(self, reader: PdfFileReader,
                    base_revision: Union[int, HistoricalResolver],
                    field_mdp_spec: Optional[FieldMDPSpec] = None,
                    doc_mdp: Optional[MDPPerm] = None) \
            -> Union[DiffResult, SuspiciousModification]:
        """
        Compare the current state of a file to an earlier version,
        with the MDP values provided.
        :class:`.SuspiciousModification` exceptions should be propagated.

        If there are multiple revisions between the base revision and the
        current one, the precise manner in which the review is conducted
        is left up to the implementing class. In particular,
        subclasses may choose to review each intermediate revision individually,
        or handle them all at once.

        :param reader:
            PDF reader representing the current state of the file.
        :param base_revision:
            The older, base revision. You can choose between providing it as a
            revision index, or a :class:`.HistoricalResolver` instance.
        :param field_mdp_spec:
            The field MDP spec that's currently active.
        :param doc_mdp:
            The DocMDP spec that's currently active.
        :return:
            A :class:`.DiffResult` object summarising the policy's judgment.
        """
        raise NotImplementedError


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
            for _ref in new_xrefs:
                usages = old._get_usages_of_ref(_ref)
                if usages:
                    yield _ref, (ModificationLevel.NONE, set(usages))

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

        rev_count = reader.xrefs.xref_sections
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
