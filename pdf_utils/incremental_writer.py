import struct
import os

from io import BytesIO

from . import generic
from .misc import peek

from .reader import PdfFileReader
from hashlib import md5
from .generic import pdf_name

"""
Utility class for writing incremental updates to PDF files.
Contains code from the PyPDF2 project, see LICENSE.PyPDF2
"""

__all__ = ['IncrementalPdfFileWriter']


def _derive_key(base_key, idnum, generation):
    # Ripped out of PyPDF2
    # See § 7.6.2 in ISO 32000
    pack1 = struct.pack("<i", idnum)[:3]
    pack2 = struct.pack("<i", generation)[:2]
    key = base_key + pack1 + pack2
    md5_hash = md5(key).digest()
    return md5_hash[:min(16, len(base_key) + 5)]


# helper method to set up the xref table of an incremental update
def _contiguous_xref_chunks(position_dict):
    previous_idnum = None
    current_chunk = []

    # iterate over keys in object ID order
    key_iter = sorted(position_dict.keys(), key=lambda t: t[1])
    (_, first_idnum), key_iter = peek(key_iter)
    for ix in key_iter:
        generation, idnum = ix

        # the idnum jumped, so yield the current chunk
        # and start a new one
        if current_chunk and idnum != previous_idnum + 1:
            yield first_idnum, current_chunk
            current_chunk = []
            first_idnum = idnum

        # append the object reference to the current chunk
        # (xref table requires position and generation entries)
        current_chunk.append((position_dict[ix], generation))
        previous_idnum = idnum

    # there is always at least one chunk, so this is fine
    yield first_idnum, current_chunk


def write_xref_table(stream, position_dict):
    xref_location = stream.tell()
    stream.write(b'xref\n')
    # Insert xref table subsections in contiguous chunks.
    # This is necessarily more complicated than the implementation
    # in PyPDF2 (see ISO 32000 § 7.5.4, esp. on updates)
    subsections = _contiguous_xref_chunks(position_dict)
    # insert origin of linked list of freed objects
    # TODO support deleting objects
    stream.write(b'0 1\n0000000000 65535 f \n')
    for first_idnum, subsection in subsections:
        # subsection header: list first object ID + length of subsection
        header = '%d %d\n' % (first_idnum, len(subsection))
        stream.write(header.encode('ascii'))
        for position, generation in subsection:
            entry = "%010d %05d n \n" % (position, generation)
            stream.write(entry.encode('ascii'))

    return xref_location


class XRefStream(generic.StreamObject):

    def __init__(self, position_dict):
        super().__init__()
        self.position_dict = position_dict

        # type indicator is one byte wide
        # we use longs to indicate positions of objects (>Q)
        # two more bytes for the generation number of an uncompressed object
        widths = map(generic.NumberObject, (1, 8, 2))
        self.update({
            pdf_name('/W'): generic.ArrayObject(widths),
            pdf_name('/Type'): pdf_name('/XRef'),
        })

    def write_to_stream(self, stream, encryption_key):
        # the caller is responsible for making sure that the stream 
        # is registered in the position dictionary
        if encryption_key is not None:
            raise ValueError('XRef streams cannot be encrypted')
        
        index = [0, 1]
        subsections = _contiguous_xref_chunks(self.position_dict)
        stream_content = BytesIO()
        # write null object
        stream_content.write(b'\x00' * 9 + b'\xff\xff')
        for first_idnum, subsection in subsections:
            index += [first_idnum, len(subsection)]
            for position, generation in subsection:
                # TODO support compressing objects
                stream_content.write(b'\x01')
                stream_content.write(struct.pack('>Q', position))
                stream_content.write(struct.pack('>H', generation))
        index_entry = generic.ArrayObject(map(generic.NumberObject, index))

        self[pdf_name('/Index')] = index_entry
        self._data = stream_content.getbuffer()
        super().write_to_stream(stream, None)


resource_dict_names = map(pdf_name, [
    'ExtGState', 'ColorSpace', 'Pattern', 'Shading', 'XObject', 
    'Font', 'ProcSet', 'Properties'
])


class IncrementalPdfFileWriter:

    def __init__(self, input_stream):
        self.input_stream = input_stream
        self.prev = prev = PdfFileReader(input_stream)
        self.objects_to_update = {}
        self._lastobj_id = prev.trailer['/Size']

        # subsume root/info references
        root = prev.trailer.raw_get('/Root')
        self._root = generic.IndirectObject(root.idnum, root.generation, self)
        try:
            info = prev.trailer.raw_get('/Info')
            self._info = generic.IndirectObject(
                info.idnum, info.generation, self
            )
        except KeyError:
            # rare, but it can happen. /Info is not a required entry
            self._info = None
        self._encrypt = self._encrypt_key = None
        self._document_id = self.__class__._handle_id(prev)

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

    @property
    def root(self):
        return self._root.get_object()

    # for compatibility with PyPDF API
    def get_object(self, ido):
        if ido.pdf is not self and ido.pdf is not self.prev:
            raise ValueError("pdf must be self or prev")
        try:
            return self.objects_to_update[(ido.generation, ido.idnum)]
        except KeyError:
            return self.prev.get_object(ido)

    def mark_update(self, obj_ref: generic.IndirectObject):
        assert obj_ref.pdf is self.prev or obj_ref.pdf is self
        ix = (obj_ref.generation, obj_ref.idnum)
        self.objects_to_update[ix] = obj_ref.get_object()
        return generic.IndirectObject(obj_ref.idnum, obj_ref.generation, self)

    def update_root(self):
        return self.mark_update(self._root) 

    def add_object(self, obj):
        self._lastobj_id += 1
        self.objects_to_update[(0, self._lastobj_id)] = obj
        return generic.IndirectObject(self._lastobj_id, 0, self)

    def write(self, stream): 
        updated_object_positions = {}

        stream_xrefs = self.prev.has_xref_stream
        if stream_xrefs:
            trailer = XRefStream(updated_object_positions)
            trailer.compress()
        else:
            trailer = generic.DictionaryObject()

        # before doing anything else, we attempt to load the crypto-relevant
        # data, so that we can bail early if something's not right
        trailer[pdf_name('/ID')] = self._document_id
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

        # copy the original data to the output
        input_pos = self.input_stream.tell()
        self.input_stream.seek(0)
        # TODO there has to be a better way to do this that doesn't involve
        # loading the entire file into a separate buffer
        stream.write(self.input_stream.read())
        self.input_stream.seek(input_pos)

        if not self.objects_to_update:
            return

        for ix in sorted(self.objects_to_update.keys()):
            generation, idnum = ix
            obj = self.objects_to_update[ix]
            updated_object_positions[ix] = stream.tell()
            stream.write(('%d %d obj' % (idnum, generation)).encode('ascii'))
            if self._encrypt is not None and idnum != self._encrypt.idnum:
                key = _derive_key(self._encrypt_key, idnum, generation)
            else:
                key = None
            obj.write_to_stream(stream, key)
            stream.write(b'\nendobj\n')
        
        # prepare trailer dictionary entries
        trailer.update({
            pdf_name('/Root'): self._root,
            pdf_name('/Prev'): generic.NumberObject(self.prev.last_startxref)
        })
        if self._info is not None:
            trailer[pdf_name('/Info')] = self._info

        if stream_xrefs:
            xref_location = stream.tell()
            xrefs_id = self._lastobj_id + 1
            updated_object_positions[(0, xrefs_id)] = xref_location
            trailer[pdf_name('/Size')] = generic.NumberObject(xrefs_id + 1)
            # write XRef stream
            stream.write(('%d %d obj' % (xrefs_id, 0)).encode('ascii'))
            trailer.write_to_stream(stream, None)
            stream.write(b'\nendobj\n')
        else:
            # classical xref table
            xref_location = write_xref_table(stream, updated_object_positions)
            trailer[pdf_name('/Size')] = generic.NumberObject(
                self._lastobj_id + 1
            )
            # write trailer
            stream.write(b'trailer\n')
            trailer.write_to_stream(stream, None)

        # write xref table pointer and EOF
        xref_pointer_string = '\nstartxref\n%s\n' % xref_location
        stream.write(xref_pointer_string.encode('ascii') + b'%%EOF\n')

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

    def register_annotation(self, page_ref, annot_ref):
        page_obj = page_ref.get_object()
        try:
            annots_ref = page_obj.raw_get('/Annots')
            if isinstance(annots_ref, generic.IndirectObject):
                annots = annots_ref.get_object()
                self.mark_update(annot_ref)
            else:
                # we need to update the entire page object if the annots array
                # is a direct object
                annots = annots_ref
                self.mark_update(page_ref)
        except KeyError:
            annots = generic.ArrayObject()
            self.mark_update(page_ref)
            page_obj[pdf_name('/Annots')] = annots

        annots.append(annot_ref)


def init_xobject_dictionary(command_stream, box_width, box_height,
                            resources=None):
    resources = resources or generic.DictionaryObject()
    return generic.StreamObject({
        pdf_name('/BBox'): generic.ArrayObject(list(
            map(generic.FloatObject, (0.0, box_height, box_width, 0.0))
        )),
        pdf_name('/Resources'): resources,
        pdf_name('/Type'): pdf_name('/XObject'),
        pdf_name('/Subtype'): pdf_name('/Form')
    }, stream_data=command_stream)


class AnnotAppearances:

    def __init__(self, normal, rollover=None, down=None):
        self.normal = normal
        self.rollover = rollover
        self.down = down

    def as_pdf_object(self):
        res = generic.DictionaryObject({pdf_name('/N'): self.normal})
        if self.rollover is not None:
            res[pdf_name('/R')] = self.rollover
        if self.down is not None:
            res[pdf_name('/D')] = self.down
        return res


class SimpleAnnotAppearances(AnnotAppearances):

    def __init__(self, writer: IncrementalPdfFileWriter, w, h, normal,
                 rollover=None, down=None, resources=None):
        """
        Describe the appearance of a single-state annotation
        using three command streams operating in a common bounding box with
        a common set of resources (see Table 168 in ISO 32000).
        The command streams are specified as bytestrings of operators.

        :param writer:
            The writer to record objects to.
            This is required because all streams must be referenced indirectly.
        :param w:
            Width of the bounding box.
        :param h:
            Height of the bounding box.
        :param normal:
            The normal appearance.
        :param rollover:
            The rollover appearance (defaults to the normal appearance)
        :param down:
            The down appearance (defaults to the normal appearance)
        :param resources:
            A resource dictionary, or a reference to one.
            Since this object will be attached to the XObject dictionaries
            of all appearance stream objects, it is a good idea to pass this
            in as an indirect reference.
        """
        def as_xobject(cmds):
            xobj = init_xobject_dictionary(cmds, w, h, resources=resources)
            return writer.add_object(xobj)

        normal = as_xobject(normal)
        if rollover is not None:
            rollover = as_xobject(rollover)
        if down is not None:
            down = as_xobject(down)

        super().__init__(normal, rollover, down)
        self.w = w
        self.h = h
        self.resources = resources


def simple_grey_box_appearance(writer, w, h, lightness=0.8):
    command_stream = ' '.join([
        'q',  # save
        '%g %g %g rg' % (lightness, lightness, lightness),  # set fill colour
        # set up rectangle path
        '0 %g %g %g re' % (h, w, -h),
        'f',  # fill stroke
        'Q'  # restore graphics state
    ]).encode('ascii')
    # we'll only set normal appearance, nothing else
    return SimpleAnnotAppearances(writer, w, h, normal=command_stream)
