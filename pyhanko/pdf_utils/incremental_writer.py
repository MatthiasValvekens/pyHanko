"""
Utility for writing incremental updates to existing PDF files.
"""

import os
from typing import Union, Optional

from . import generic, misc
from .crypt import EnvelopeKeyDecrypter

from .reader import PdfFileReader
from .generic import pdf_name
from .content import PdfContent
from .writer import BasePdfFileWriter


__all__ = ['IncrementalPdfFileWriter']


class IncrementalPdfFileWriter(BasePdfFileWriter):
    """Class to incrementally update existing files.

    This :class:`~.writer.BasePdfFileWriter` subclass encapsulates a
    :class:`~.reader.PdfFileReader` instance in addition to exposing an
    interface to add and modify PDF objects.

    Incremental updates to a PDF file append modifications to the end of the
    file. This is critical when the original file contents are not to be
    modified directly (e.g. when it contains digital signatures).
    It has the additional advantage of providing an automatic audit trail of
    sorts.
    """

    IO_CHUNK_SIZE = 4096

    def __init__(self, input_stream):
        self.input_stream = input_stream
        self.prev = prev = PdfFileReader(input_stream)
        self.trailer = trailer = prev.trailer
        root_ref = trailer.raw_get('/Root')
        try:
            info_ref = trailer.raw_get('/Info')
        except KeyError:
            # rare, but it can happen. /Info is not a required entry
            info_ref = None
        document_id = self.__class__._handle_id(prev)
        super().__init__(
            root_ref, info_ref, document_id, obj_id_start=trailer['/Size'],
            stream_xrefs=prev.has_xref_stream
        )
        if self._info is not None:
            self.trailer['/Info'] = self._info
        self._resolves_objs_from = (self, prev)
        if self.prev.input_version < self.output_version:
            root = root_ref.get_object()
            version_str = pdf_name('/%d.%d' % self.output_version)
            root[pdf_name('/Version')] = version_str
            self.update_root()

        self.security_handler = prev.security_handler

    @classmethod
    def _handle_id(cls, prev):
        # There are a number of issues at play here
        #  - Documents *should* have a unique id, but it's not a strict
        #    requirement unless the document is encrypted.
        #  - We are updating an existing document, but the result is not the
        #    same document. Hence, we want to assign an ID to this document that
        #    is not the same as the one on the existing document.
        #  - The first part of the ID is part of the key derivation used to
        #    to encrypt documents. Since we need to encrypt the file using
        #    the same cryptographic data as the original, we cannot change
        #    this value if it is present (cf. § 7.6.3.3 in ISO 32000).
        #    Even when no encryption is involved, changing this part violates
        #    the spec (cf. § 14.4 in loc. cit.)

        # noinspection PyArgumentList
        id2 = generic.ByteStringObject(os.urandom(16))
        try:
            id1, _ = prev.trailer["/ID"]
            # is this a bug in PyPDF2?
            if isinstance(id1, generic.TextStringObject):
                # noinspection PyArgumentList
                id1 = generic.ByteStringObject(id1.original_bytes)
        except KeyError:
            # no primary ID present, so generate one
            # noinspection PyArgumentList
            id1 = generic.ByteStringObject(os.urandom(16))
        return generic.ArrayObject([id1, id2])

    def get_object(self, ido):
        try:
            return super().get_object(ido)
        except KeyError:
            return self.prev.get_object(ido)

    def mark_update(self, obj_ref: Union[generic.Reference,
                                         generic.IndirectObject]):
        ix = (obj_ref.generation, obj_ref.idnum)
        self.objects[ix] = obj_ref.get_object()

    # TODO: this new API allows me to simplify a lot of bookkeeping
    #  in the library
    def update_container(self, obj: generic.PdfObject):
        container_ref = obj.container_ref
        if container_ref is None:
            # this means that in all likelihood, the object was added by this
            # writer, and is therefore about to be written anyway.
            return
        if isinstance(container_ref, generic.TrailerReference):
            # nothing to do, the trailer is always written
            return
        elif isinstance(container_ref, generic.Reference):
            self.mark_update(container_ref)
            return
        raise TypeError  # pragma: nocover

    def update_root(self):
        self.mark_update(self._root)

    def _write_header(self, stream):
        # copy the original data to the output
        input_pos = self.input_stream.tell()
        self.input_stream.seek(0)
        misc.chunked_write(
            bytearray(self.IO_CHUNK_SIZE), self.input_stream, stream
        )
        self.input_stream.seek(input_pos)

    def set_info(self, info: Optional[Union[generic.IndirectObject,
                                      generic.DictionaryObject]]):
        info = super().set_info(info)
        if info is not None:
            # also update our trailer
            self.trailer['/Info'] = info
        else:
            del self.trailer['/Info']
        return info

    def _populate_trailer(self, trailer):
        trailer.update(self.trailer.flatten())
        super()._populate_trailer(trailer)
        trailer[pdf_name('/Prev')] = generic.NumberObject(
            self.prev.last_startxref
        )
        if self.prev.encrypted and self._encrypt is None:
            # removing encryption in an incremental update is impossible
            raise ValueError(
                'Cannot save this document unencrypted. Please call '
                'encrypt() with the password of the original file '
                'before calling write().'
            )

    def write(self, stream):

        if not self.objects:
            # just write the original and then bail
            self._write_header(stream)
            return
        super().write(stream)

    def write_updated_section(self, stream):
        """
        Only write the updated and new objects to the designated output stream.

        The new PDF file can then be put together by concatenating the original
        input with the generated output.

        :param stream:
            Output stream to write to.
        """
        self._write(stream, skip_header=True)

    def write_in_place(self):
        """
        Write the updated file contents in-place to the same stream as
        the input stream.
        This obviously requires a stream supporting both reading and writing
        operations.
        """

        stream = self.prev.stream
        stream.seek(0, os.SEEK_END)
        self.write_updated_section(stream)

    def encrypt(self, user_pwd):
        """Method to handle updates to encrypted files.

        This method handles decrypting of the original file, and makes sure
        the resulting updated file is encrypted in a compatible way.
        The standard mandates that updates to encrypted files be effected using
        the same encryption settings. In particular, incremental updates
        cannot remove file encryption.

        :param user_pwd:
            The original file's user password.

        :raises PdfReadError:
            Raised when there is a problem decrypting the file.
        """

        prev = self.prev
        result = prev.decrypt(user_pwd)

        # take care to use the same encryption algorithm as the underlying file
        self._encrypt = prev.trailer.raw_get("/Encrypt")
        return result

    def encrypt_pubkey(self, credential: EnvelopeKeyDecrypter):
        """Method to handle updates to files encrypted using public-key
        encryption.

        The same caveats as :meth:`encrypt` apply here.


        :param credential:
            The :class:`.EnvelopeKeyDecrypter` handling the recipient's
            private key.

        :raises PdfReadError:
            Raised when there is a problem decrypting the file.
        """

        prev = self.prev
        result = prev.decrypt_pubkey(credential)
        self._encrypt = prev.trailer.raw_get("/Encrypt")
        return result

    # TODO these can be simplified considerably using the new update_container
    # TODO move these to the base writer class, perhaps

    def add_stream_to_page(self, page_ix, stream_ref, resources=None,
                           prepend=False):
        """Append an indirect stream object to a page in a PDF as a content
        stream.

        :param page_ix:
            Index of the page to modify.
            The first page has index `0`.
        :param stream_ref:
            :class:`~.generic.IndirectObject` reference to the stream
            object to add.
        :param resources:
            Resource dictionary containing resources to add to the page's
            existing resource dictionary.
        :param prepend:
            Prepend the content stream to the list of content streams, as
            opposed to appending it to the end.
            This has the effect of causing the stream to be rendered
            underneath the already existing content on the page.
        :return:
            An :class:`~.generic.IndirectObject` reference to the page object
            that was modified.
        """

        page_obj_ref, res_ref = self.find_page_for_modification(page_ix)

        page_obj = page_obj_ref.get_object()

        contents_ref = page_obj.raw_get('/Contents')

        if isinstance(contents_ref, generic.IndirectObject):
            contents = contents_ref.get_object()
            if isinstance(contents, generic.ArrayObject):
                # This is the easy case. It suffices to mark
                # this array for an update, and append our stream to it.
                self.mark_update(contents_ref)
                if prepend:
                    contents.insert(0, stream_ref)
                else:
                    contents.append(stream_ref)
            elif isinstance(contents, generic.StreamObject):
                # replace the old stream with an array containing
                # a reference to the original stream, and our own stream.
                new = [stream_ref, contents_ref] \
                    if prepend else [contents_ref, stream_ref]
                contents = generic.ArrayObject(new)
                page_obj[pdf_name('/Contents')] = self.add_object(contents)
                # mark the page to be updated as well
                self.mark_update(page_obj_ref)
            else:
                raise ValueError('Unexpected type for page /Contents')
        elif isinstance(contents_ref, generic.ArrayObject):
            # make /Contents an indirect array, and append our stream
            contents = contents_ref
            if prepend:
                contents.insert(0, stream_ref)
            else:
                contents.append(stream_ref)
            page_obj[pdf_name('/Contents')] = self.add_object(contents)
            self.mark_update(page_obj_ref)
        else:
            raise ValueError('Unexpected type for page /Contents')

        if resources is None:
            return

        if isinstance(res_ref, generic.IndirectObject):
            # we can get away with only updating this reference
            orig_resource_dict = res_ref.get_object()
            assert isinstance(orig_resource_dict, generic.DictionaryObject)
            if self.merge_resources(orig_resource_dict, resources):
                self.mark_update(res_ref)
        else:
            # don't bother trying to update the resource object, just
            # clone it and add it to the current page object.
            orig_resource_dict = generic.DictionaryObject(res_ref)
            page_obj[pdf_name('/Resources')] = self.add_object(
                orig_resource_dict
            )
            self.merge_resources(orig_resource_dict, resources)

        return page_obj_ref

    def add_content_to_page(self, page_ix, pdf_content: PdfContent,
                            prepend=False):
        """
        Convenience wrapper around :meth:`add_stream_to_page` to turn a
        :class:`~.content.PdfContent` instance into a page content stream.

        :param page_ix:
            Index of the page to modify.
            The first page has index `0`.
        :param pdf_content:
            An instance of :class:`~.content.PdfContent`
        :param prepend:
            Prepend the content stream to the list of content streams, as
            opposed to appending it to the end.
            This has the effect of causing the stream to be rendered
            underneath the already existing content on the page.
        :return:
            An :class:`~.generic.IndirectObject` reference to the page object
            that was modified.
        """
        as_stream = generic.StreamObject({}, stream_data=pdf_content.render())
        return self.add_stream_to_page(
            page_ix, self.add_object(as_stream),
            resources=pdf_content.resources.as_pdf_object(), prepend=prepend
        )

    # TODO this doesn't really belong here
    def merge_resources(self, orig_dict, new_dict) -> bool:
        """
        Update an existing resource dictionary object with data from another
        one. Returns ``True`` if the original dict object was modified directly.

        The caller is responsible for avoiding name conflicts with existing
        resources.
        """

        update_needed = False
        for key, value in new_dict.items():
            try:
                orig_value_ref = orig_dict.raw_get(key)
            except KeyError:
                update_needed = True
                orig_dict[key] = value
                continue

            if isinstance(orig_value_ref, generic.IndirectObject):
                orig_value = orig_value_ref.get_object()
                self.mark_update(orig_value_ref)
            else:
                orig_value = orig_value_ref
                update_needed = True

            if isinstance(orig_value, generic.ArrayObject):
                # the /ProcSet case
                orig_value.extend(value)
            elif isinstance(orig_value, generic.DictionaryObject):
                for key_, value_ in value.items():
                    if key_ in orig_value:
                        raise ValueError(
                            'Naming conflict in resource of type %s: '
                            'key %s occurs in both.' % (key, key_)
                        )
                    orig_value[key_] = value_

        return update_needed
