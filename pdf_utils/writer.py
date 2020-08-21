import struct
from hashlib import md5
from io import BytesIO

from pdf_utils import generic
from pdf_utils.generic import pdf_name
from pdf_utils.misc import peek


def _derive_key(base_key, idnum, generation):
    # Ripped out of PyPDF2
    # See § 7.6.2 in ISO 32000
    pack1 = struct.pack("<i", idnum)[:3]
    pack2 = struct.pack("<i", generation)[:2]
    key = base_key + pack1 + pack2
    md5_hash = md5(key).digest()
    return md5_hash[:min(16, len(base_key) + 5)]


def _contiguous_xref_chunks(position_dict):
    """
    Helper method to divide the XRef table (or stream) into contiguous chunks.
    """
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
    # in PyPDF2 (see ISO 32000 § 7.5.4, esp. on updates), since
    # we need to handle incremental updates correctly.
    subsections = _contiguous_xref_chunks(position_dict)

    def write_header(idnum, length):
        header = '%d %d\n' % (idnum, length)
        stream.write(header.encode('ascii'))

    def write_subsection(chunk):
        for position, generation in chunk:
            entry = "%010d %05d n \n" % (position, generation)
            stream.write(entry.encode('ascii'))

    first_idnum, subsection = next(subsections)
    # TODO support deleting objects
    # case distinction: in contrast with the above we have to ensure that
    # everything is written in one chunk when *not* doing incremental updates.
    # In particular, this applies to the null object
    null_obj_ref = b'0000000000 65535 f \n'
    if first_idnum == 1:
        # integrate the null object into the first subsection
        write_header(0, len(subsection) + 1)
        stream.write(null_obj_ref)
        write_subsection(subsection)
    else:
        # insert origin of linked list of freed objects, and then the first
        # subsection, as usual
        stream.write(b'0 1\n')
        stream.write(null_obj_ref)
        write_header(first_idnum, len(subsection))
        write_subsection(subsection)
    for first_idnum, subsection in subsections:
        # subsection header: list first object ID + length of subsection
        write_header(first_idnum, len(subsection))
        write_subsection(subsection)

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
                # TODO support objects in object streams
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
