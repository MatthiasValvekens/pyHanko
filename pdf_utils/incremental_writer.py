import os

from . import generic

from .reader import PdfFileReader
from .generic import pdf_name
from .writer import BasePdfFileWriter

"""
Utility class for writing incremental updates to PDF files.
Contains code from the PyPDF2 project, see LICENSE.PyPDF2
"""

__all__ = ['IncrementalPdfFileWriter']


class IncrementalPdfFileWriter(BasePdfFileWriter):

    def __init__(self, input_stream):
        self.input_stream = input_stream
        self.prev = prev = PdfFileReader(input_stream)
        trailer = prev.trailer
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
        if self.prev.input_version != self.output_version:
            root = root_ref.get_object()
            version_str = pdf_name('/%d.%d' % self.output_version)
            root[pdf_name('/Version')] = version_str
            self.update_root()

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
        if ido.pdf is not self and ido.pdf is not self.prev:
            raise ValueError("pdf must be self or prev")
        try:
            return self.objects[(ido.generation, ido.idnum)]
        except KeyError:
            return self.prev.get_object(ido)

    def mark_update(self, obj_ref: generic.IndirectObject):
        assert obj_ref.pdf is self.prev or obj_ref.pdf is self
        ix = (obj_ref.generation, obj_ref.idnum)
        self.objects[ix] = obj_ref.get_object()
        return generic.IndirectObject(obj_ref.idnum, obj_ref.generation, self)

    def update_root(self):
        return self.mark_update(self._root)

    def _write_header(self, stream):

        # copy the original data to the output
        input_pos = self.input_stream.tell()
        self.input_stream.seek(0)
        # TODO there has to be a better way to do this that doesn't involve
        #  loading the entire file into a separate buffer
        stream.write(self.input_stream.read())
        self.input_stream.seek(input_pos)

    def _populate_trailer(self, trailer):
        super()._populate_trailer(trailer)
        trailer[pdf_name('/Prev')] = generic.NumberObject(
            self.prev.last_startxref
        )
        if self.prev.encrypted:
            if self._encrypt is not None:
                trailer[pdf_name("/Encrypt")] = self._encrypt
            else:
                # removing encryption in an incremental update is impossible
                raise ValueError(
                    'Cannot save this document unencrypted. Please call '
                    'encrypt() with the user password of the original file '
                    'before calling write().'
                )

    def write(self, stream):

        if not self.objects:
            # just write the original and then bail
            self._write_header(stream)
            return
        super().write(stream)

    def encrypt(self, user_pwd):
        prev = self.prev
        # first, attempt decryption
        if prev.encrypted:
            if not prev.decrypt(user_pwd):
                raise ValueError(
                    'Failed to decrypt original with the password supplied'
                )
        else:
            raise ValueError('Original file was not encrypted.')

        # take care to use the same encryption algorithm as the underlying file
        try:
            encrypt_ref = prev.trailer.raw_get("/Encrypt")
        except KeyError:
            raise ValueError(
                'Original document does not have an encryption dictionary'
            )

        self._encrypt_key = self.prev._decryption_key
        self._encrypt = encrypt_ref

    def add_stream_to_page(self, page_ix, stream_ref, resources=None):
        """
        Append an indirect stream object to a page in a PDF.
        Returns a reference to the page object that was modified.
        """

        page_obj_ref, res_ref, page_update_boundary \
            = self.find_page_for_modification(page_ix)

        page_obj = page_obj_ref.get_object()

        # the spec says that this will always be an indirect reference
        contents_ref = page_obj.raw_get('/Contents')

        if isinstance(contents_ref, generic.IndirectObject):
            contents = contents_ref.get_object()
            if isinstance(contents, generic.ArrayObject):
                # This is the easy case. It suffices to mark
                # this array for an update, and append our stream to it.
                self.mark_update(contents_ref)
                contents.append(stream_ref)
            elif isinstance(contents, generic.DictionaryObject):
                # replace the dictionary with an array containing 
                # a reference to the original dict, and our own stream.
                contents = generic.ArrayObject([contents_ref, stream_ref])
                page_obj[pdf_name('/Contents')] = self.add_object(contents)
                # mark the page to be updated as well
                self.mark_update(page_update_boundary)
            else:
                raise ValueError('Unexpected type for page /Contents')
        elif isinstance(contents_ref, generic.ArrayObject):
            # make /Contents an indirect array, and append our stream
            contents = contents_ref
            contents.append(stream_ref)
            page_obj[pdf_name('/Contents')] = self.add_object(contents)
            self.mark_update(page_update_boundary)
        elif isinstance(contents_ref, generic.DictionaryObject):
            old_contents = contents_ref
            # create a new array with indirect references to the old contents
            # and our stream
            contents = generic.ArrayObject(
                [self.add_object(old_contents), stream_ref]
            )
            # ... then insert a reference into the page's /Contents entry
            page_obj[pdf_name('/Contents')] = self.add_object(contents) 
            self.mark_update(page_update_boundary)
        else:
            raise ValueError('Unexpected type for page /Contents')

        if resources is None:
            return

        if isinstance(res_ref, generic.IndirectObject):
            # we can get away with only updating this reference
            orig_resource_dict = res_ref.get_object()
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

    def merge_resources(self, orig_dict, new_dict) -> bool:
        """
        Update an existing resource dictionary object with data from another
        one. Returns `True` if the original dict object was modified directly.

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
