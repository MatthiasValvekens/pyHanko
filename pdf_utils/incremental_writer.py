import struct
from PyPDF2 import generic
from .reader import PdfFileReader
from hashlib import md5

"""
Utility class for writing incremental updates to PDF files.
Contains code from the PyPDF2 project, see LICENSE.PyPDF2
"""

__all__ = ['IncrementalPdfFileWriter']

pdf_name = generic.NameObject
pdf_string = generic.createStringObject


def _derive_key(base_key, idnum, generation):
    # Ripped out of PyPDF2
    # See § 7.6.2 in ISO 32000
    pack1 = struct.pack("<i", idnum)[:3]
    pack2 = struct.pack("<i", generation)[:2]
    key = base_key + pack1 + pack2
    md5_hash = md5(key).digest()
    return md5_hash[:min(16, len(base_key) + 5)]


def peek(itr):
    itr = iter(itr)
    first = next(itr)

    def _itr():
        yield first
        yield from itr

    return first, _itr()


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
    for first_idnum, subsection in subsections:
        # subsection header: list first object ID + length of subsection
        header = '%d %d\n' % (first_idnum, len(subsection))
        stream.write(header.encode('ascii'))
        for position, generation in subsection:
            entry = "%010d %05d n \n" % (position, generation)
            stream.write(entry.encode('ascii'))

    return xref_location


# TODO support deleting objects

class IncrementalPdfFileWriter:

    def __init__(self, input_stream):
        self.input_stream = input_stream
        self.prev = prev = PdfFileReader(input_stream)
        self.objects_to_update = {}
        # TODO This is a bit silly. Should perhaps read the spec
        # more carefully to figure out a way to deal with these things
        # properly. The write logic should already deal with object 
        # generations properly, so it's a matter of getting object
        # registration on board.
        # FIXME this is also borked in cases with xrefstream, since
        # PyPDF2 does not fully populate the trailer in this case
        self._lastobj_id = prev.trailer['/Size']

        # subsume root/info references
        root = prev.trailer.raw_get('/Root')
        self._root = generic.IndirectObject(root.idnum, root.generation, self)
        self._root_object = root.getObject()
        info = prev.trailer.raw_get('/Info')
        self._info = generic.IndirectObject(info.idnum, info.generation, self)

    # for compatibility with PyPDF API
    def getObject(self, ido):
        if ido.pdf is not self and ido.pdf is not self.prev:
            raise ValueError("pdf must be self or prev")
        try:
            return self.objects_to_update[(ido.generation, ido.idnum)]
        except KeyError:
            return self.prev.getObject(ido)

    def mark_update(self, obj_ref: generic.IndirectObject):
        assert obj_ref.pdf is self.prev or obj_ref.pdf is self
        ix = (obj_ref.generation, obj_ref.idnum)
        self.objects_to_update[ix] = obj_ref.getObject()
        return generic.IndirectObject(obj_ref.idnum, obj_ref.generation, self)

    def update_root(self):
        return self.mark_update(self._root) 

    def add_object(self, obj):
        self._lastobj_id += 1
        self.objects_to_update[(0, self._lastobj_id)] = obj
        return generic.IndirectObject(self._lastobj_id, 0, self)

    def write(self, stream):
        # first copy the original data
        input_pos = self.input_stream.tell()
        self.input_stream.seek(0)
        # TODO there has to be a better way to do this that doesn't involve
        # loading the entire file into a separate buffer
        stream.write(self.input_stream.read())
        self.input_stream.seek(input_pos)

        if not self.objects_to_update:
            return

        updated_object_positions = {}

        for ix in sorted(self.objects_to_update.keys()):
            generation, idnum = ix
            obj = self.objects_to_update[ix]
            updated_object_positions[ix] = stream.tell()
            stream.write(('%d %d obj' % (idnum, generation)).encode('ascii'))
            if hasattr(self, "_encrypt") and idnum != self._encrypt.idnum:
                key = _derive_key(self._encrypt_key, idnum, generation)
            else:
                key = None
            obj.writeToStream(stream, key)
            stream.write(b'\nendobj\n')

        # TODO what if the original PDF has an xref stream?
        xref_location = write_xref_table(stream, updated_object_positions)

        # write trailer and EOF
        trailer = generic.DictionaryObject()
        stream.write(b'trailer\n')
        trailer.update({
            pdf_name('/Size'): generic.NumberObject(self._lastobj_id + 1),
            pdf_name('/Root'): self._root,
            pdf_name('/Info'): self._info,
            pdf_name('/Prev'): generic.NumberObject(self.prev.last_startxref)
        })
        # TODO port actual encryption code
        try:
            trailer[pdf_name("/ID")] = self._ID
        except AttributeError:
            pass
        try:
            trailer[pdf_name("/Encrypt")] = self._encrypt
        except AttributeError:
            pass
        trailer.writeToStream(stream, None)
        # write xref table pointer and EOF
        xref_pointer_string = '\nstartxref\n%s\n' % xref_location
        stream.write(xref_pointer_string.encode('ascii') + b'%%EOF\n')

