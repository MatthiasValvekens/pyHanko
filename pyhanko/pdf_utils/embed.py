import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List

from . import generic, writer, misc
from .generic import pdf_name, pdf_string

__all__ = [
    'embed_file', 'EmbeddedFileObject', 'EmbeddedFileParams',
    'FileSpec', 'RelatedFileSpec',
]


@dataclass(frozen=True)
class EmbeddedFileParams:
    embed_size: bool = True
    """
    If true, record the file size of the embedded file.
    
    .. note::
        This value is computed over the file content before PDF filters
        are applied. This may have performance implications in cases where the
        file stream contents are presented in pre-encoded form.
    """

    embed_checksum: bool = True
    """
    If true, add an MD5 checksum of the file contents.

    .. note::
        This value is computed over the file content before PDF filters
        are applied. This may have performance implications in cases where the
        file stream contents are presented in pre-encoded form.
    """

    creation_date: Optional[datetime] = None
    """
    Record the creation date of the embedded file.
    """

    modification_date: Optional[datetime] = None
    """
    Record the modification date of the embedded file.
    """


class EmbeddedFileObject(generic.StreamObject):

    @classmethod
    def from_file_data(cls, pdf_writer: writer.BasePdfFileWriter,
                       data: bytes, compress=True,
                       params: EmbeddedFileParams = None,
                       mime_type: str = None) -> 'EmbeddedFileObject':
        """
        Construct an embedded file object from file data.

        This is a very thin wrapper around the constructor, with a slightly
        less intimidating API.

        .. note::
            This method will not register the embedded file into the document's
            embedded file namespace, see :func:`.embed_file`.

        :param pdf_writer:
            PDF writer to use.
        :param data:
            File contents, as a :class:`bytes` object.
        :param compress:
            Whether to compress the embedded file's contents.
        :param params:
            Optional embedded file parameters.
        :param mime_type:
            Optional MIME type string.
        :return:
            An embedded file object.
        """

        result = EmbeddedFileObject(
            pdf_writer=pdf_writer, stream_data=data,
            params=params, mime_type=mime_type
        )
        if compress:
            result.compress()

        return result

    def __init__(self, pdf_writer: writer.BasePdfFileWriter,
                 dict_data=None, stream_data=None, encoded_data=None,
                 params: EmbeddedFileParams = None, mime_type: str = None):

        super().__init__(
            dict_data=dict_data, stream_data=stream_data,
            encoded_data=encoded_data, handler=pdf_writer
        )
        self['/Type'] = generic.pdf_name('/EmbeddedFile')
        if mime_type is not None:
            # FIXME fix the name encoder to handle this situation properly
            #  (another holdover from PyPDF2)
            self['/Subtype'] = generic.pdf_name(
                '/' + mime_type.replace('/', '#2f')
            )
        self.ef_stream_ref = pdf_writer.add_object(self)
        self.params = params

    def write_to_stream(self, stream, handler=None, container_ref=None):
        # apply the parameters before serialisation

        params = self.params
        if params is not None:
            self['/Params'] = param_dict = generic.DictionaryObject()
            if params.embed_size:
                param_dict['/Size'] = generic.NumberObject(len(self.data))
            if params.embed_checksum:
                checksum = hashlib.md5(self.data).digest()
                param_dict['/CheckSum'] = generic.ByteStringObject(checksum)
            if params.creation_date is not None:
                param_dict['/CreationDate'] = generic.pdf_date(
                    params.creation_date
                )
            if params.modification_date is not None:
                param_dict['/ModDate'] = generic.pdf_date(
                    params.modification_date
                )

        super().write_to_stream(
            stream, handler=handler, container_ref=container_ref
        )


@dataclass(frozen=True)
class RelatedFileSpec:
    name: str
    """
    Name of the related file.
    
    .. note::
        The encoding requirements of this field depend on whether the related
        file is included via the ``/F`` or ``/UF`` key.
    """

    embedded_data: EmbeddedFileObject
    """
    Reference to a stream object containing the file's data, as embedded
    in the PDF file.
    """

    @classmethod
    def fmt_related_files(cls, lst: List['RelatedFileSpec']):
        def _gen():
            for rfs in lst:
                yield generic.pdf_string(rfs.name)
                yield rfs.embedded_data.ef_stream_ref
        return generic.ArrayObject(_gen())


@dataclass(frozen=True)
class FileSpec:
    # TODO encrypted payload

    # TODO collection item dictionaries

    # TODO thumbnail support

    # TODO enforce PDFDocEncoding for file_spec_string etc.

    file_spec_string: str
    """
    A path-like file specification string, or URL.
    
    .. note::
        For backwards compatibility, this string should be encodable in
        PDFDocEncoding. For names that require general Unicode support, refer
        to :class:`file_name`.
    """

    file_name: Optional[str] = None
    """
    A path-like Unicode file name.
    """

    embedded_data: Optional[EmbeddedFileObject] = None
    """
    Reference to a stream object containing the file's data, as embedded
    in the PDF file.
    """

    description: Optional[str] = None
    """
    Textual description of the file.
    """

    af_relationship: Optional[generic.NameObject] = None
    """
    Associated file relationship specifier.
    """

    f_related_files: List[RelatedFileSpec] = None
    """
    Related files with PDFDocEncoded names.
    """

    uf_related_files: List[RelatedFileSpec] = None
    """
    Related files with Unicode-encoded names.
    """

    def as_pdf_object(self) -> generic.DictionaryObject:
        result = generic.DictionaryObject({
            pdf_name('/Type'): pdf_name('/Filespec'),
            pdf_name('/F'): pdf_string(self.file_spec_string),
        })
        if self.file_name is not None:
            result['/UF'] = pdf_string(self.file_name)

        if self.embedded_data is not None:
            result['/EF'] = ef_dict = generic.DictionaryObject({
                pdf_name('/F'): self.embedded_data.ef_stream_ref,
            })
            if self.file_name is not None:
                ef_dict['/UF'] = self.embedded_data.ef_stream_ref

        if self.description is not None:
            result['/Desc'] = generic.TextStringObject(self.description)

        if self.af_relationship is not None:
            result['/AFRelationship'] = self.af_relationship

        f_related = self.f_related_files
        uf_related = self.uf_related_files
        if f_related or uf_related:
            result['/RF'] = rf = generic.DictionaryObject()
            if f_related:
                rf['/F'] = RelatedFileSpec.fmt_related_files(f_related)
            if uf_related and self.file_name is not None:
                rf['/UF'] = RelatedFileSpec.fmt_related_files(uf_related)

        return result


def embed_file(pdf_writer: writer.BasePdfFileWriter, spec: FileSpec):
    """
    Embed a file in the document-wide embedded file registry of a PDF writer.

    :param pdf_writer:
        PDF writer to house the embedded file.
    :param spec:
        File spec describing the embedded file.
    :return:
    """

    ef_stream = spec.embedded_data

    if ef_stream is None:
        raise misc.PdfWriteError(
            "File spec does not have an embedded file stream"
        )

    spec_obj = spec.as_pdf_object()

    root = pdf_writer.root
    try:
        names_dict = root['/Names']
    except KeyError:
        names_dict = generic.DictionaryObject()
        root['/Names'] = pdf_writer.add_object(names_dict)
        pdf_writer.update_root()

    try:
        ef_name_tree = names_dict['/EmbeddedFiles']
    except KeyError:
        ef_name_tree = generic.DictionaryObject()
        names_dict['/EmbeddedFiles'] = pdf_writer.add_object(ef_name_tree)
        pdf_writer.update_container(names_dict)

    # TODO support updating general name trees!
    #  (should probably be refactored into an utility method somewhere)
    if '/Kids' in ef_name_tree:
        raise NotImplementedError(
            "Only flat name trees are supported right now"
        )

    try:
        ef_name_arr = ef_name_tree['/Names']
    except KeyError:
        ef_name_arr = generic.ArrayObject()
        ef_name_tree['/Names'] = pdf_writer.add_object(ef_name_arr)
        pdf_writer.update_container(ef_name_tree)

    ef_name_arr.append(generic.pdf_string(spec.file_spec_string))
    spec_obj_ref = pdf_writer.add_object(spec_obj)
    ef_name_arr.append(spec_obj_ref)
    pdf_writer.update_container(ef_name_arr)

    if spec.af_relationship is not None:
        pdf_writer.ensure_output_version(version=(2, 0))
        # add the filespec to the /AF entry in the document catalog
        # TODO allow associations with objects other than the catalog?
        try:
            root_af_arr = root['/AF']
        except KeyError:
            root_af_arr = generic.ArrayObject()
            root['/AF'] = pdf_writer.add_object(root_af_arr)
            pdf_writer.update_root()
        root_af_arr.append(spec_obj_ref)
    else:
        pdf_writer.ensure_output_version(version=(1, 7))
