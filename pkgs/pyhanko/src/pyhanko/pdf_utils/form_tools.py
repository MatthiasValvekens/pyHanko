import logging
from typing import Tuple

from . import generic
from .misc import FormFillingError, PdfReadError

__all__ = [
    'get_single_field_annot',
    'enumerate_fields_in',
    'annot_width_height',
]

logger = logging.getLogger(__name__)


def get_single_field_annot(
    field: generic.DictionaryObject,
) -> generic.DictionaryObject:
    """
    Internal function to get the annotation of a field.

    :param field:
        A field dictionary.
    :return:
        The dictionary of the corresponding annotation.
    """
    try:
        (annot,) = field['/Kids']
        annot = annot.get_object()
    except (ValueError, TypeError):
        raise FormFillingError(
            "Failed to access form field's annotation. "
            "Form field must have exactly one child annotation, "
            "or it must be combined with its annotation."
        )
    except KeyError:
        annot = field
    return annot


def enumerate_fields_in(
    field_list,
    filled_status=None,
    with_name=None,
    parent_name="",
    parents=None,
    *,
    refs_seen,
    target_field_type,
):
    if not isinstance(field_list, generic.ArrayObject):
        logger.warning(
            f"Values of type {type(field_list)} are not valid as field "
            f"lists, must be array objects -- skipping."
        )
        return

    parents = parents or ()
    for field_ref in field_list:
        if not isinstance(field_ref, generic.IndirectObject):
            logger.warning(
                "Entries in field list must be indirect references -- skipping."
            )
            continue
        if field_ref.reference in refs_seen:
            raise PdfReadError("Circular reference in form tree")

        field = field_ref.get_object()
        if not isinstance(field, generic.DictionaryObject):
            logger.warning(
                "Entries in field list must be dictionary objects, not "
                f"{type(field)} -- skipping."
            )
            continue
        # /T is the field name. If not specified, we're dealing with a bare
        # widget, so skip it. (these should never occur in /Fields, but hey)
        try:
            field_name = field['/T']
        except KeyError:
            continue
        fq_name = (
            field_name
            if not parent_name
            else ("%s.%s" % (parent_name, field_name))
        )
        explicitly_requested = with_name is not None and fq_name == with_name
        child_requested = explicitly_requested or (
            with_name is not None and with_name.startswith(fq_name)
        )
        # /FT is inheritable, so go up the chain
        current_path = (field,) + parents
        for parent_field in current_path:
            try:
                field_type = parent_field['/FT']
                break
            except KeyError:
                continue
        else:
            field_type = None

        if field_type == target_field_type:
            field_value = field.get('/V')
            # "cast" to a regular string object
            filled = bool(field_value)
            status_check = filled_status is None or filled == filled_status
            name_check = with_name is None or explicitly_requested
            if status_check and name_check:
                yield fq_name, field_value, field_ref
        elif explicitly_requested:
            raise FormFillingError(
                f'Field with name {fq_name} exists but is '
                f'not a {target_field_type} field'
            )

        # if necessary, descend into the field hierarchy
        if with_name is None or (child_requested and not explicitly_requested):
            try:
                yield from enumerate_fields_in(
                    field['/Kids'],
                    parent_name=fq_name,
                    parents=current_path,
                    with_name=with_name,
                    filled_status=filled_status,
                    refs_seen=refs_seen | {field_ref.reference},
                    target_field_type=target_field_type,
                )
            except KeyError:
                continue


def annot_width_height(
    annot_dict: generic.DictionaryObject,
) -> Tuple[float, float]:
    """
    Internal function to compute the width and height of an annotation.

    :param annot_dict:
        Annotation dictionary.
    :return:
        a (width, height) tuple
    """
    try:
        x1, y1, x2, y2 = annot_dict['/Rect']
    except KeyError:
        return 0, 0
    w = abs(x1 - x2)
    h = abs(y1 - y2)
    return w, h
