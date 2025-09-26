import logging
from dataclasses import replace
from typing import Optional, Tuple

from . import generic, layout
from .content import AppearanceContent
from .generic import TextStringObject
from .misc import FormFillingError, PdfReadError
from .rw_common import PdfHandler
from .text import TextBox, TextBoxStyle
from .writer import BasePdfFileWriter

__all__ = [
    'get_single_field_annot',
    'enumerate_fields_in',
    'annot_width_height',
    'find_existing_empty_field',
    'populate_static_text_field',
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


DEFAULT_TEXT_FIELD_LAYOUT_RULE = layout.SimpleBoxLayoutRule(
    x_align=layout.AxisAlignment.ALIGN_MIN,
    y_align=layout.AxisAlignment.ALIGN_MIN,
    inner_content_scaling=layout.InnerScaling.NO_SCALING,
)


class TextFieldContent(AppearanceContent):
    def __init__(
        self,
        writer: BasePdfFileWriter,
        text_content: str,
        text_style: TextBoxStyle,
        box: Optional[layout.BoxConstraints] = None,
    ):
        self._text_content = text_content
        box_layout = (
            text_style.box_layout_rule or DEFAULT_TEXT_FIELD_LAYOUT_RULE
        )
        style = replace(
            text_style,
            box_layout_rule=box_layout,
        )
        super().__init__(writer=writer, box=box)

        self.text_box = TextBox(
            style,
            writer=self.writer,
            resources=self.resources,
            box=self.box,
        )

    def render(self) -> bytes:
        self.text_box.content = self._text_content
        rendered = self.text_box.render()
        return rendered


def find_existing_empty_field(
    handler: PdfHandler,
    field_name: str,
    field_type: str,
) -> generic.Reference:
    """
    Find an empty form field of a given type and return a reference to
    the form field dictionary.

    :param handler:
        A PDF handler representing the document to be searched.
    :param field_name:
        The name of the field to look for.
    :param field_type:
        The type of the field to look for.
    :return:
        A reference to the form field dictionary of the resulting field,
        if found.
    :raises FormFillingError:
    if the form field does not exist or is filled.
    """
    try:
        field_list = handler.root['/AcroForm']['/Fields']
    except KeyError:
        raise FormFillingError("No AcroForm present")

    candidates = enumerate_fields_in(
        field_list=field_list,
        with_name=field_name,
        filled_status=False,
        target_field_type=field_type,
        refs_seen=set(),
    )

    try:
        field_name, value, field_ref = next(candidates)
    except StopIteration:
        raise FormFillingError(
            f'No empty text field with name {field_name} found.'
        )

    return field_ref.reference


def populate_static_text_field(
    writer: BasePdfFileWriter,
    field_name: str,
    style: TextBoxStyle,
    content: str,
):
    """
    Populate an existing text field in a PDF document that is to be treated
    as read-only.

    .. warning::

        This function is intended to be used to fill out form fields
        that do not need to be edited interactively later.
        By design, it is not compatible with PDF's variable text mechanisms.

    :param writer:
        PDF document to modify.
    :param field_name:
        The name of the field to look for.
    :param style:
        The text box style to use.
    :param content:
        The content of the text field.
    """
    field_ref = find_existing_empty_field(writer, field_name, field_type='/Tx')
    field = field_ref.get_object()
    assert isinstance(field, generic.DictionaryObject)

    annot_dict = get_single_field_annot(field)

    w, h = annot_width_height(annot_dict)
    content_obj = TextFieldContent(
        writer=writer,
        text_content=content,
        text_style=style,
        box=layout.BoxConstraints(width=w, height=h),
    )
    # TODO option to use existing DR resources and DA?
    content_obj.apply_appearance(annot_dict)
    writer.update_container(annot_dict)

    field['/V'] = TextStringObject(content)

    try:
        flags = int(field['/Ff'])
    except KeyError:
        flags = 0

    field['/Ff'] = generic.NumberObject(flags | 1)
    field.pop('/DA', None)
    writer.mark_update(field_ref)
