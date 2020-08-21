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

    def find_page_for_modification(self, page_ix, repair_direct_pages=True):
        """
        Retrieve the page with index page_ix from the page tree, along with
        the necessary objects to modify it.
        :param page_ix:
            The (zero-indexed) number of the page to retrieve.
        :param repair_direct_pages:
            The PDF spec mandates that /Kids be an array of indirect references.
            Passing repair_direct_pages=True fixes this problem in noncompliant
            PDFs, and also ensures that the first item returned by this method
            is always an indirect reference.
        :return:
            A triple with the page object (or a reference to it),
            (possibly inherited) resource dictionary, and a reference
            to the object that needs to be marked for an update
            if the page object is updated.
        """
        # the spec says that this will always be an indirect reference
        page_tree_root_ref = self.root.raw_get('/Pages')
        assert isinstance(page_tree_root_ref, generic.IndirectObject)
        page_tree_root = page_tree_root_ref.get_object()
        try:
            root_resources = page_tree_root['/Resources']
        except KeyError:
            root_resources = generic.DictionaryObject()

        page_count = page_tree_root['/Count']
        if not (0 <= page_ix < page_count):
            raise ValueError('Page index out of range')

        def _recurse(first_page_ix, pages_obj, last_rsrc_dict, last_indir):
            kids = pages_obj.raw_get('/Kids')
            if isinstance(kids, generic.IndirectObject):
                last_indir = kids
                kids = kids.get_object()

            try:
                last_rsrc_dict = pages_obj.raw_get('/Resources')
            except KeyError:
                pass

            cur_page_ix = first_page_ix
            for kid_index, kid_ref in enumerate(kids):
                if isinstance(kid_ref, generic.IndirectObject):
                    # should always be the case, but let's play it safe
                    recurse_last_indir = kid_ref
                    kid = kid_ref.get_object()
                else:
                    kid = kid_ref
                    if repair_direct_pages:
                        # We force the entry in /Kids to be indirect as follows.

                        # first, we register the content of the child node
                        #  as a new object.
                        kids[kid_index] = kid_ref = self.add_object(kid)
                        # then we mark the current update boundary for
                        # an update to reflect the previous update
                        self.mark_update(last_indir)
                        # further recursive branches do not need to update
                        # all the way up to last_indir, only to kid_ref, so
                        # we change the update boundary passed to the next
                        # call to _recurse()
                        recurse_last_indir = kid_ref
                    else:
                        recurse_last_indir = last_indir

                node_type = kid['/Type']
                if node_type == '/Pages':
                    # recurse into this branch if the page we need
                    # is part of it
                    desc_count = kid['/Count']
                    if cur_page_ix <= page_ix < cur_page_ix + desc_count:
                        return _recurse(
                            cur_page_ix, kid, last_rsrc_dict, recurse_last_indir
                        )
                    cur_page_ix += desc_count
                elif node_type == '/Page':
                    if cur_page_ix == page_ix:
                        try:
                            last_rsrc_dict = kid.raw_get('/Resources')
                        except KeyError:
                            pass
                        return kid_ref, last_rsrc_dict, last_indir
                    else:
                        cur_page_ix += 1
            # This means the PDF is not standards-compliant
            raise ValueError('Page not found')

        return _recurse(0, page_tree_root, root_resources, page_tree_root_ref)

    def add_stream_to_page(self, page_ix, stream_ref, resources=None):
        """
        Append an indirect stream object to a page in a PDF.
        Returns a reference to the page object that was modified.
        """

        # we pass in repair_direct_pages=True to ensure that we get
        #  a page object reference back, as opposed to a page object.
        page_obj_ref, res_ref, page_update_boundary \
            = self.find_page_for_modification(page_ix, repair_direct_pages=True)

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
