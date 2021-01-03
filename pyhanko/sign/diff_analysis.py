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
"""

# TODO flesh out & comment on the contract of a whitelisting rule.
#
#  - All rules are either executed completely (i.e. their generators exhausted)
#    or aborted.
#  - If the diff runner aborts a rule, this always means that the revision
#    is rejected.
#  - Whitelisting rules are allowed to informally delegate some checking to
#    other rules, provided that this is documented clearly.
#    (example: Catalog validator ignores /AcroForm, which is validated by
#     another rule entirely)
#  - Rules should be entirely stateless.
#  - "Clearing" a reference by yielding it does not imply that the revision
#    cannot be vetoed by that same rule further down the road (this is why
#    the first point is important)


import re
import logging
from collections import defaultdict
from dataclasses import dataclass
from enum import unique
from typing import (
    Iterable, Optional, Set, Tuple, Generator, TypeVar, Dict,
    List, Callable,
)

from pyhanko.pdf_utils.generic import Reference, PdfObject
from pyhanko.pdf_utils.misc import OrderedEnum
from pyhanko.pdf_utils.reader import HistoricalResolver
from pyhanko.pdf_utils import generic, misc
from pyhanko.sign.fields import FieldMDPSpec, MDPPerm

__all__ = [
    'ModificationLevel', 'SuspiciousModification',
    'QualifiedWhitelistRule', 'WhitelistRule', 'qualify',
    'DocInfoRule', 'DSSCompareRule', 'FormUpdatingRule',
    'CatalogModificationRule', 'ObjectStreamRule',
    'FieldMDPRule', 'FieldComparisonSpec', 'FieldMDPContext',
    'DiffPolicy', 'DefaultDiffPolicy'
]

logger = logging.getLogger(__name__)

FORMFIELD_ALWAYS_MODIFIABLE = {'/Ff'}
VALUE_UPDATE_KEYS = FORMFIELD_ALWAYS_MODIFIABLE | {'/AP', '/AS', '/V'}
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
    The only updates are signature long term archival (LTA) updates.
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


class QualifiedWhitelistRule:
    """
    Abstract base class for a whitelisting rule that outputs references together
    with the modification level at which they're cleared.

    This is intended for use by complicated whitelisting rules that need to
    differentiate between multiple levels.
    """

    def apply_qualified(self, old: HistoricalResolver, new: HistoricalResolver)\
            -> Iterable[Tuple[ModificationLevel, Reference]]:
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
            -> Iterable[Reference]:
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
            -> Iterable[Tuple[ModificationLevel, Reference]]:
        for ref in self.rule.apply(old, new):
            yield self.level, ref


R = TypeVar('R')


def qualify(level: ModificationLevel,
            rule_result: Generator[Reference, None, R])\
        -> Generator[Tuple[ModificationLevel, Reference], None, R]:
    """
    This is a helper function for rule implementors.
    It attaches a fixed modification level to an existing reference generator,
    respecting the original generator's return value (if relevant).

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
    :class:`~.generic.Reference` objects, the yield type of the resulting
    generator will be tuples of the form ``(level, ref)``.

    :param level:
        The modification level to set.
    :param rule_result:
        A generator that outputs references to be whitelisted.
    :return:
        A converted generator that outputs references qualified at the
        modification level specified.
    """

    return misc.map_with_return(rule_result, lambda ref: (level, ref))


def _safe_whitelist(old: HistoricalResolver, old_ref, new_ref):
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
            -> Iterable[Reference]:
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
        yield from _safe_whitelist(old, old_info, new_info)


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
            -> Iterable[Reference]:
        # TODO refactor these into less ad-hoc rules

        old_dss, new_dss = yield from _compare_key_refs(
            '/DSS', old, old.root, new.root
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

        for der_obj_type in dss_der_stream_keys:
            try:
                value = new_dss.raw_get(der_obj_type)
            except KeyError:
                continue
            if not isinstance(value.get_object(), generic.ArrayObject):
                raise SuspiciousModification(
                    f"Expected array at DSS key {der_obj_type}"
                )

            yield from new.collect_dependencies(
                value, since_revision=old.revision + 1
            )

        # check that the /VRI dictionary still contains all old keys, unchanged.
        old_vri, new_vri = yield from _compare_key_refs(
            '/VRI', old, old_dss, new_dss,
        )
        if old_vri is None:
            old_vri = generic.DictionaryObject()

        nodict_err = "/VRI is not a dictionary"
        if not isinstance(old_vri, generic.DictionaryObject):
            raise misc.PdfReadError(nodict_err)  # pragma: nocover
        if not isinstance(new_vri, generic.DictionaryObject):
            raise SuspiciousModification(nodict_err)

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
                yield new_vri_dict.reference
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
            for der_obj_type in vri_der_stream_keys:
                try:
                    value = new_vri_dict.raw_get(der_obj_type)
                except KeyError:
                    continue
                if not isinstance(value.get_object(), generic.ArrayObject):
                    raise SuspiciousModification(
                        f"Expected array at VRI key {der_obj_type}"
                    )
                yield from new.collect_dependencies(
                    value, since_revision=old.revision + 1
                )

            # /TS is also a DER stream
            try:
                ts_ref = new_vri_dict.get_value_as_reference(
                    '/TS', optional=True
                )
                if ts_ref is not None and old.is_ref_available(ts_ref):
                    yield ts_ref
            except misc.IndirectObjectExpected:
                pass


@dataclass(frozen=True)
class FieldComparisonSpec:
    field_type: str
    old_field_ref: Optional[generic.Reference]
    new_field_ref: Optional[generic.Reference]

    @property
    def old_field(self) -> Optional[generic.DictionaryObject]:
        ref = self.old_field_ref
        if ref is None:
            return None
        field = ref.get_object()
        assert isinstance(field, generic.DictionaryObject)
        return field

    @property
    def new_field(self) -> Optional[generic.DictionaryObject]:
        ref = self.new_field_ref
        if ref is None:
            return None
        field = ref.get_object()
        assert isinstance(field, generic.DictionaryObject)
        return field


@dataclass(frozen=True)
class FieldMDPContext:
    field_specs: Dict[str, FieldComparisonSpec]
    old: HistoricalResolver
    new: HistoricalResolver
    field_mdp_spec: Optional[FieldMDPSpec] = None

    # TODO use this to work more efficiently
    doc_mdp: Optional[MDPPerm] = None


@dataclass(frozen=True)
class FormUpdate:

    updated_ref: generic.Reference
    field_name: Optional[str]


class FieldMDPRule:

    def apply(self, context: FieldMDPContext) \
            -> Iterable[Tuple[ModificationLevel, FormUpdate]]:
        raise NotImplementedError


class SigFieldCreationRule(FieldMDPRule):
    """
    This rule allows signature fields to be created at the root of the form
    hierarchy, but denies the creation of other types of fields.
    It also disallows field deletion.
    """

    def __init__(self, approve_widget_bindings=True):
        self.approve_widget_bindings = approve_widget_bindings

    def apply(self, context: FieldMDPContext) \
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
                if '.' in fq_name:
                    raise NotImplementedError(
                        "Can't deal with signature fields that aren't top level"
                    )
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
        for fq_name, sigfield_ref in all_new_refs.items():

            # new field, so all its dependencies are good to go
            # that said, only the field itself is cleared at LTA update level,
            # the other deps bump the modification level up to FORM_FILL
            yield ModificationLevel.LTA_UPDATES, FormUpdate(
                updated_ref=sigfield_ref, field_name=fq_name
            )
            sigfield = sigfield_ref.get_object()
            # checked by field listing routine already
            assert isinstance(sigfield, generic.DictionaryObject)

            for _key in ('/AP', '/Lock', '/SV'):
                try:
                    raw_value = sigfield.raw_get(_key)

                    deps = context.new.collect_dependencies(
                        raw_value,
                        since_revision=context.old.revision + 1
                    )
                    for _ref in deps:
                        yield ModificationLevel.FORM_FILLING, FormUpdate(
                            updated_ref=_ref, field_name=fq_name
                        )
                except KeyError:
                    pass

        # Next, check (widget) annotations: newly added signature fields may
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

        field_ref_reverse = {v: k for k, v in all_new_refs.items()}

        yield from qualify(
            ModificationLevel.LTA_UPDATES,
            _walk_page_tree_annots(
                old_page_root, new_page_root,
                field_ref_reverse, context.old
            )
        )


class SigFieldModificationRule(FieldMDPRule):

    def __init__(self, always_modifiable=None, value_update_keys=None):
        self.always_modifiable = (
            always_modifiable if always_modifiable is not None
            else FORMFIELD_ALWAYS_MODIFIABLE
        )
        self.value_update_keys = (
            value_update_keys if always_modifiable is not None
            else VALUE_UPDATE_KEYS
        )

    def apply(self, context: FieldMDPContext) \
            -> Iterable[Tuple[ModificationLevel, FormUpdate]]:

        # deal with "freshly signed" signature fields,
        # i.e. those that are filled now, but weren't previously
        #  + newly created ones
        for fq_name, spec in context.field_specs.items():
            if spec.field_type != '/Sig' or not spec.new_field_ref:
                continue

            old_field = spec.old_field
            new_field = spec.new_field

            previously_signed = old_field is not None and '/V' in old_field
            now_signed = '/V' in new_field

            if old_field:
                # operating on an existing field ---> check changes
                # (if the field we're dealing with is new, we don't need
                #  to bother, the sig field creation rule takes care of that)
                if not previously_signed and now_signed:
                    # here, we check that the form field didn't change
                    # beyond the keys that we expect to change when updating
                    # a signature field.
                    _compare_dicts(old_field, new_field, self.value_update_keys)
                    yield (
                        ModificationLevel.LTA_UPDATES,
                        FormUpdate(
                            updated_ref=spec.new_field_ref, field_name=fq_name
                        )
                    )

                    # whitelist appearance updates at FORM_FILL level
                    yield from map(
                        lambda ref: (
                            ModificationLevel.FORM_FILLING,
                            FormUpdate(updated_ref=ref, field_name=fq_name)
                        ), _allow_appearance_update(
                            old_field, new_field, context.old, context.new
                        )
                    )
                else:
                    # case where the field was already signed, or is still
                    # not signed in the current revision.
                    # in this case, the state of the field better didn't change
                    # at all!
                    # ... but Acrobat apparently sometimes sets /Ff rather
                    #  liberally, so let's allow that one to change
                    _compare_dicts(
                        old_field, new_field, self.always_modifiable
                    )
                    yield ModificationLevel.LTA_UPDATES, FormUpdate(
                        updated_ref=spec.new_field_ref, field_name=fq_name
                    )
                    # Skip the comparison logic on /V. In particular, if
                    # the signature object in question was overridden,
                    # it should trigger a suspicious modification later.
                    continue

            if not now_signed:
                continue

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

            try:
                x1, y1, x2, y2 = new_field['/Rect']
                area = abs(x1 - x2) * abs(y1 - y2)
            except (TypeError, ValueError, KeyError):
                area = 0

            # /DocTimeStamps added for LTA validation purposes shouldn't have
            # an appearance (as per the recommendation in ISO 32000-2, which we
            # enforce as a rigid rule here)
            if sig_obj.raw_get('/Type') == '/DocTimeStamp' and not area:
                sig_whitelist = ModificationLevel.LTA_UPDATES
            else:
                sig_whitelist = ModificationLevel.FORM_FILLING

            # first, whitelist the actual signature object
            yield sig_whitelist, FormUpdate(
                updated_ref=current_value_ref, field_name=fq_name
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


class GenericFieldModificationRule(FieldMDPRule):

    def __init__(self, always_modifiable=None, value_update_keys=None):
        self.always_modifiable = (
            always_modifiable if always_modifiable is not None
            else FORMFIELD_ALWAYS_MODIFIABLE
        )
        self.value_update_keys = (
            value_update_keys if always_modifiable is not None
            else VALUE_UPDATE_KEYS
        )

    def apply(self, context: FieldMDPContext) \
            -> Iterable[Tuple[ModificationLevel, FormUpdate]]:
        for fq_name, spec in context.field_specs.items():

            if spec.field_type == '/Sig' or not spec.new_field_ref:
                continue

            def _emit_ref(ref):
                return (
                    ModificationLevel.FORM_FILLING,
                    FormUpdate(updated_ref=ref, field_name=fq_name)
                )

            field_mdp_spec = context.field_mdp_spec
            locked = (
                field_mdp_spec is not None and field_mdp_spec.is_locked(fq_name)
            )
            old_field = spec.old_field
            new_field = spec.new_field
            if not locked:
                _compare_dicts(old_field, new_field, self.value_update_keys)
                yield _emit_ref(spec.new_field_ref)
                yield from map(
                    _emit_ref,
                    _allow_appearance_update(
                        old_field, new_field, context.old, context.new
                    )
                )
                try:
                    new_value = new_field.raw_get('/V')
                except KeyError:
                    # no current value => no thing else to check
                    continue
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
                    yield from map(_emit_ref, deps)
            else:
                _compare_dicts(
                    old_field, new_field, self.always_modifiable
                )
                yield _emit_ref(spec.new_field_ref)


class FormUpdatingRule:
    """
    Special whitelisting rule that validates changes to the form attached to
    the input document.

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
            else {'/Fields'}
        )

    def apply(self, old: HistoricalResolver, new: HistoricalResolver,
              field_mdp_spec: Optional[FieldMDPSpec] = None,
              doc_mdp: Optional[MDPPerm] = None)\
            -> Iterable[Tuple[ModificationLevel, FormUpdate]]:

        def _emit_ref(_ref):
            return (
                ModificationLevel.LTA_UPDATES,
                FormUpdate(updated_ref=_ref, field_name=None)
            )

        old_acroform, new_acroform = yield from misc.map_with_return(
            _compare_key_refs(
                '/AcroForm', old, old.root, new.root
            ),
            _emit_ref
        )

        # first, compare the entries that aren't /Fields
        _compare_dicts(old_acroform, new_acroform, self.ignored_acroform_keys)
        assert isinstance(old_acroform, generic.DictionaryObject)
        assert isinstance(new_acroform, generic.DictionaryObject)

        # mark /Fields ref as OK if it's an indirect reference
        # This is fine: the _list_fields logic checks that it really contains
        # stuff that looks like form fields, and other rules are responsible
        # for vetting the creation of other form fields anyway.
        yield from misc.map_with_return(
            _compare_key_refs('/Fields', old, old_acroform, new_acroform),
            _emit_ref
        )
        try:
            old_fields = old_acroform['/Fields']
            new_fields = new_acroform['/Fields']
        except KeyError:  # pragma: nocover
            raise misc.PdfReadError("Could not read /Fields in form")

        context = FieldMDPContext(
            field_specs=dict(_list_fields(old_fields, new_fields)),
            old=old, new=new, field_mdp_spec=field_mdp_spec,
            doc_mdp=doc_mdp
        )

        for rule in self.field_rules:
            yield from rule.apply(context)


ROOT_EXEMPT_STRICT_COMPARISON = {
    '/AcroForm', '/DSS', '/Extensions', '/Metadata', '/MarkInfo'
}


class CatalogModificationRule(QualifiedWhitelistRule):
    """
    Rule that adjudicates modifications to the document catalog.

    :param ignored_keys:
        Values in the document catalog that may change between revisions.
        The default ones are ``/AcroForm``, ``/DSS``, ``/Extensions``,
        ``/Metadata`` and ``/MarkInfo``.

        This rule also includes a basic sanity check to prevent ``/Metadata``
        from clobbering existing streams, but allows it to be redefined.
        Checking for ``/AcroForm`` and ``/DSS`` is delegated to
        :class:`.FormUpdatingRule` and :class:`.DSSCompareRule`, respectively.
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
        #  - /Metadata: is a stream ---> don't allow overrides, only new refs
        #  - /DSS and /AcroForm are dealt with by other rules.
        try:
            new_metadata_ref = new_root.get_value_as_reference('/Metadata')
            if old.is_ref_available(new_metadata_ref):
                yield ModificationLevel.LTA_UPDATES, new_metadata_ref
        except misc.IndirectObjectExpected:
            raise SuspiciousModification(
                "/Metadata should be an indirect reference"
            )
        except KeyError:
            pass

        yield ModificationLevel.LTA_UPDATES, new.root_ref


class ObjectStreamRule(WhitelistRule):

    def apply(self, old: HistoricalResolver, new: HistoricalResolver) \
            -> Iterable[Reference]:
        # object streams are OK, but overriding object streams is not.
        for objstream_ref in new.object_streams_used():
            if old.is_ref_available(objstream_ref):
                yield objstream_ref


def _list_fields(old_fields: generic.PdfObject, new_fields: generic.PdfObject,
                 parent_name="",
                 inherited_ft=None) -> Dict[str, FieldComparisonSpec]:
    """
    Recursively construct a list of field names, together with their
    "incarnations" in either revision.
    """

    def _make_list(lst: generic.PdfObject, exc):
        if not isinstance(lst, generic.ArrayObject):
            raise exc("Field list is not an array.")
        names_seen = set()

        for field_ref in lst:
            if not isinstance(field_ref, generic.IndirectObject):
                raise exc("Fields must be indirect objects")

            field = field_ref.get_object()
            if not isinstance(field, generic.DictionaryObject):
                raise exc("Fields must be dictionary objects")

            name = field.raw_get('/T')
            if name in names_seen:
                raise exc("Duplicate field name")
            elif '.' in name:
                raise exc("Partial names must not contain periods")
            names_seen.add(name)

            fq_name = parent_name + "." + name if parent_name else name
            try:
                field_type = field.raw_get('/FT')
            except KeyError:
                if inherited_ft is not None:
                    field_type = inherited_ft
                else:
                    raise exc(
                        f"Field type of {fq_name} could not be determined"
                    )

            try:
                kids = field["/Kids"]
            except KeyError:
                kids = generic.ArrayObject()
            yield fq_name, (field_type, field_ref.reference, kids)

    old_fields_by_name = dict(_make_list(old_fields, misc.PdfReadError))
    new_fields_by_name = dict(_make_list(new_fields, SuspiciousModification))

    names = set()
    names.update(old_fields_by_name.keys())
    names.update(new_fields_by_name.keys())

    for field_name in names:
        try:
            old_field_type, old_field_ref, old_kids = \
                old_fields_by_name[field_name]
        except KeyError:
            old_field_type = old_field_ref = None
            old_kids = generic.ArrayObject()

        try:
            new_field_type, new_field_ref, new_kids = \
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
        yield field_name, FieldComparisonSpec(
            field_type=common_ft,
            old_field_ref=old_field_ref, new_field_ref=new_field_ref
        )

        # recursively descend into /Kids if necessary
        if old_kids or new_kids:
            yield from _list_fields(
                old_kids, new_kids, field_name, inherited_ft=common_ft
            )


def _allow_appearance_update(old_field, new_field, old: HistoricalResolver,
                             new: HistoricalResolver) \
        -> Generator[generic.Reference, None, None]:

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
                           field_name_dict, old: HistoricalResolver):
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
                old_kid, new_kid, field_name_dict, old
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
            #  can safely clear them for modification
            #  (not necessary if both /Annots entries are indirect references,
            #   but adding even more cases is pushing things)
            _compare_dicts(old_kid, new_kid, {'/Annots'})
            yield FormUpdate(updated_ref=new_kid_ref, field_name=field_name)
            if new_annots_ref:
                # current /Annots entry is an indirect reference

                # If the equality check fails,
                # either the /Annots array got reassigned to another
                # object ID, or it was moved from a direct object to an
                # indirect one, or the /Annots entry was newly created.
                # This is all fine, provided that the new  object
                # ID doesn't clobber an existing one.
                if old_annots_ref == new_annots_ref or \
                        old.is_ref_available(new_annots_ref):
                    yield FormUpdate(updated_ref=new_annots_ref,
                                     field_name=field_name)


def _assert_not_stream(dict_obj):
    if isinstance(dict_obj, generic.StreamObject):
        raise SuspiciousModification(
            f"Unexpected stream encountered at {dict_obj.container_ref}!"
        )


def _compare_dicts(old_dict: PdfObject, new_dict: PdfObject,
                   ignored: Set[str] = frozenset()):
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
        raise SuspiciousModification(
            f"Dict keys differ: {new_dict_keys} vs. "
            f"{old_dict_keys}."
        )

    for k in new_dict_keys:
        if new_dict.raw_get(k) != old_dict.raw_get(k):
            raise SuspiciousModification(f"Values for dict key {k} differ.")


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
        return old_value, None  # nothing to do

    if new_value_ref is not None:
        yield from _safe_whitelist(old, old_value_ref, new_value_ref)

    return old_value, new_value


@dataclass(frozen=True)
class DiffResult:

    modification_level: ModificationLevel
    """
    The strictest modification level at which all changes pass muster.
    """

    changed_form_fields: Set[str]
    """
    Set containing the names of all changed form fields.
    
    .. note::
        For the purposes of this parameter, a change is defined as any update
        that is judged significant at modification level
        :attr:`.ModificationLevel.FORM_FILLING` or higher.
        
        In other words, changes at :attr:`.ModificationLevel.LTA_UPDATES`
        are ignored by design.
    """


class DiffPolicy:
    """
    Run a list of rules to analyse the differences between two revisions.

    :param global_rules:
        The :class:`.QualifiedWhitelistRule` objects encoding the rules to
        apply.
    :param form_rule:
        The :class:`.FormUpdatingRule` that adjudicates changes to form fields
        and their values.
    """

    def __init__(self, global_rules: List[QualifiedWhitelistRule],
                 form_rule: FormUpdatingRule):
        self.global_rules = global_rules
        self.form_rule = form_rule

    def apply(self, old: HistoricalResolver, new: HistoricalResolver,
              field_mdp_spec: Optional[FieldMDPSpec] = None,
              doc_mdp: Optional[MDPPerm] = None) -> DiffResult:
        """
        Execute the policy on a pair of revisions, with the MDP values provided.
        :class:`.SuspiciousModification` exceptions will be propagated.

        :param old:
            The older, base revision.
        :param new:
            The newer revision.
        :param field_mdp_spec:
            The field MDP spec that's currently active.
        :param doc_mdp:
        :return:
        """
        # we need to verify that there are no xrefs in the revision's xref table
        # other than the ones we can justify.
        new_xrefs = new.explicit_refs_in_revision()

        explained = defaultdict(set)

        for rule in self.global_rules:
            for level, ref in rule.apply_qualified(old, new):
                explained[level].add(ref)

        form_changes = self.form_rule.apply(
            old, new, field_mdp_spec, doc_mdp
        )

        changed_form_fields = set()
        for level, fu in form_changes:
            if fu.field_name is not None and \
                    level >= ModificationLevel.FORM_FILLING:
                changed_form_fields.add(fu.field_name)
            explained[level].add(fu.updated_ref)

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
            raise SuspiciousModification(
                f"There are unexplained xrefs in revision {new.revision}: "
                f"{', '.join(repr(x) for x in unexplained_annot)}."
            )
        elif unexplained_formfill:
            level = ModificationLevel.ANNOTATIONS
        elif unexplained_lta:
            level = ModificationLevel.FORM_FILLING
        else:
            level = ModificationLevel.LTA_UPDATES

        return DiffResult(
            modification_level=level, changed_form_fields=changed_form_fields
        )


class DefaultDiffPolicy(DiffPolicy):

    def __init__(self):
        super().__init__(
            global_rules=[
                CatalogModificationRule(),
                DocInfoRule().as_qualified(ModificationLevel.LTA_UPDATES),
                ObjectStreamRule().as_qualified(ModificationLevel.LTA_UPDATES),
                DSSCompareRule().as_qualified(ModificationLevel.LTA_UPDATES),
            ],
            form_rule=FormUpdatingRule(
                field_rules=[
                    SigFieldCreationRule(), SigFieldModificationRule(),
                    GenericFieldModificationRule()
                ],
            )
        )
