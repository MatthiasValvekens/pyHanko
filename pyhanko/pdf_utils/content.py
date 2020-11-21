from enum import Enum
from pyhanko.pdf_utils.generic import (
    pdf_name, DictionaryObject, NameObject,
    PdfObject,
)
from pyhanko.pdf_utils.misc import BoxConstraints


class ResourceType(Enum):
    EXT_G_STATE = pdf_name('/ExtGState')
    COLOR_SPACE = pdf_name('/ColorSpace')
    PATTERN = pdf_name('/Pattern')
    SHADING = pdf_name('/Shading')
    XOBJECT = pdf_name('/XObject')
    FONT = pdf_name('/Font')
    PROPERTIES = pdf_name('/Properties')


class ResourceManagementError(ValueError):
    pass


def _res_merge_helper(dict1, dict2):
    for k, v2 in dict2.items():
        if k in dict1:
            raise ResourceManagementError(
                f"Resource with name {k} occurs in both dictionaries."
            )
        dict1[k] = v2
    return dict1


class PdfResources:
    def __init__(self):
        self.ext_g_state = DictionaryObject()
        self.color_space = DictionaryObject()
        self.pattern = DictionaryObject()
        self.shading = DictionaryObject()
        self.xobject = DictionaryObject()
        self.font = DictionaryObject()
        self.properties = DictionaryObject()

    def __getitem__(self, item: ResourceType):
        return getattr(self, item.name.lower())

    def as_pdf_object(self):
        def _gen():
            for k in ResourceType:
                val = self[k]
                if val:
                    yield k.value, val
        return DictionaryObject({k: v for k, v in _gen()})

    def __iadd__(self, other):
        for k in ResourceType:
            _res_merge_helper(self[k], other[k])
        return self


class PdfContent:

    def __init__(self, resources: PdfResources = None,
                 box: BoxConstraints = None, writer=None):
        self._resources = resources or PdfResources()
        self.box = box or BoxConstraints()
        self.writer = writer

    # TODO support a set-if-not-taken mechanism, that suggests alternative names
    #  if necessary.
    def set_resource(self, category: ResourceType, name: NameObject,
                     value: PdfObject):
        self._resources[category][name] = value

    def import_resources(self, resources: PdfResources):
        self._resources += resources

    @property
    def resources(self):
        return self._resources

    def render(self) -> bytes:
        """
        Compile the content to graphics operators.
        """
        raise NotImplementedError

    # TODO allow the bounding box to be overridden/refitted
    #  (using matrix transforms)
    def as_form_xobject(self):
        from pyhanko.pdf_utils.writer import init_xobject_dictionary
        command_stream = self.render()
        return init_xobject_dictionary(
            command_stream=command_stream, box_width=self.box.width,
            box_height=self.box.height,
            resources=self._resources.as_pdf_object()
        )

    def set_writer(self, writer):
        self.writer = writer


class RawContent(PdfContent):

    def __init__(self, data: bytes, resources: PdfResources = None,
                 box: BoxConstraints = None):
        super().__init__(resources, box)
        self.data = data

    def render(self) -> bytes:
        return self.data