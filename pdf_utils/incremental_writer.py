import struct
import os

from io import BytesIO

from PyPDF2 import generic
from PyPDF2.pdf import _alg34, _alg35

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
        widths = map(generic.NumberObject, (1,8,2))
        self.update({
            pdf_name('/W'): generic.ArrayObject(widths),
            pdf_name('/Type'): pdf_name('/XRef'),
        })

    def writeToStream(self, stream, encryption_key):
        # the caller is responsible for making sure that the stream 
        # is registered in the position dictionary
        if encryption_key is not None:
            raise ValueError('XRef streams cannot be encrypted')
        
        index = [0,1]
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
        super().writeToStream(stream, encryption_key)


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
        return self._root_object

    # for compatibility with PyPDF API
    # noinspection PyPep8Naming
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
        updated_object_positions = {}

        stream_xrefs = self.prev.has_xref_stream
        if stream_xrefs:
            trailer = XRefStream(updated_object_positions)
        else:
            trailer = generic.DictionaryObject()

        # before doing anything else, we attempt to load the crypto-relevant
        # data, so that we can bail early if something's not right
        trailer[pdf_name('/ID')] = self._document_id
        if self.prev.isEncrypted:
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
            obj.writeToStream(stream, key)
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
            trailer.writeToStream(stream, None)
            stream.write(b'\nendobj\n')
        else:
            # classical xref table
            xref_location = write_xref_table(stream, updated_object_positions)
            trailer[pdf_name('/Size')] = generic.NumberObject(
                self._lastobj_id + 1
            )
            # write trailer
            stream.write(b'trailer\n')
            trailer.writeToStream(stream, None)

        # write xref table pointer and EOF
        xref_pointer_string = '\nstartxref\n%s\n' % xref_location
        stream.write(xref_pointer_string.encode('ascii') + b'%%EOF\n')

    def encrypt(self, user_pwd):
        prev = self.prev
        # first, attempt decryption
        if prev.isEncrypted:
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
        encrypt = encrypt_ref.getObject()
        use_128bit = encrypt["/V"] == 2

        # see § 7.6.3.2 in ISO 32000
        user_access_flags = encrypt["/P"]
        owner_verif_material = encrypt["/O"]

        # TODO figure out what the first item in deriv_result is for
        if use_128bit:
            deriv_result = _alg35(
                password=user_pwd, rev=3, keylen=16,
                owner_entry=owner_verif_material,
                p_entry=user_access_flags, id1_entry=self._document_id[0],
                metadata_encrypt=False
            )
        else:
            deriv_result = _alg34(
                password=user_pwd, owner_entry=owner_verif_material,
                p_entry=user_access_flags, id1_entry=self._document_id[0]
            )

        self._encrypt_key = deriv_result[1]
        self._encrypt = encrypt_ref
