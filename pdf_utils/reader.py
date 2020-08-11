from io import BytesIO

from PyPDF2.generic import *
from PyPDF2.pdf import (
    convertToInt, PdfFileReader as PdfFileReaderOrig
)
from PyPDF2.utils import readNonWhitespace


"""
Modified version of PdfFileReader from PyPDF2. See LICENSE.PyPDF2
"""

__all__ = ['PdfFileReader']


class PdfFileReader(PdfFileReaderOrig):
    last_startxref = None
    has_xref_stream = False

    def _read_xref_stream(self, stream):
        idnum, generation = self.readObjectHeader(stream)
        xrefstream = readObject(stream, self)
        assert xrefstream["/Type"] == "/XRef"
        self.cacheIndirectObject(generation, idnum, xrefstream)
        # FIXME the FlateDecode routine in PyPDF is very broken, and
        # always returns a string object, even if that doesn't make any sense.
        stream_data = BytesIO(xrefstream.getData())
        # Index pairs specify the subsections in the dictionary. If
        # none create one subsection that spans everything.
        idx_pairs = xrefstream.get("/Index", [0, xrefstream.get("/Size")])
        entry_sizes = xrefstream.get("/W")
        assert len(entry_sizes) >= 3
        if self.strict and len(entry_sizes) > 3:
            raise utils.PdfReadError("Too many entry sizes: %s" % entry_sizes)

        def get_entry(ix):
            # Reads the correct number of bytes for each entry. See the
            # discussion of the W parameter in PDF spec table 17.
            if entry_sizes[ix] > 0:
                d = stream_data.read(entry_sizes[ix])
                return convertToInt(d, entry_sizes[ix])

            # PDF Spec Table 17: A value of zero for an element in the
            # W array indicates...the default value shall be used
            if ix == 0:
                return 1  # First value defaults to 1
            else:
                return 0

        def used_before(_num, _generation):
            # We move backwards through the xrefs, don't replace any.
            return _num in self.xref.get(_generation, []) or \
                   _num in self.xref_objStm

        # Iterate through each subsection
        last_end = 0
        for start, size in self._pairs(idx_pairs):
            # The subsections must increase
            assert start >= last_end
            last_end = start + size
            for num in range(start, start + size):
                # The first entry is the type
                xref_type = get_entry(0)
                # The rest of the elements depend on the xref_type
                if xref_type == 0:
                    # linked list of free objects
                    # XXX these were assigned to something in the PyPDF source,
                    # but the value wasn't being used anywhere.
                    # TODO check the spec
                    get_entry(1)
                    get_entry(2)
                elif xref_type == 1:
                    # objects that are in use but are not compressed
                    byte_offset = get_entry(1)
                    generation = get_entry(2)
                    if generation not in self.xref:
                        self.xref[generation] = {}
                    if not used_before(num, generation):
                        self.xref[generation][num] = byte_offset
                elif xref_type == 2:
                    # compressed objects
                    objstr_num = get_entry(1)
                    obstr_idx = get_entry(2)
                    generation = 0  # PDF spec table 18, generation is 0
                    if not used_before(num, generation):
                        self.xref_objStm[num] = (objstr_num, obstr_idx)
                elif self.strict:
                    raise utils.PdfReadError("Unknown xref type: %s" %
                                             xref_type)

        trailer_keys = "/Root", "/Encrypt", "/Info", "/ID", "/Size"
        for key in trailer_keys:
            if key in xrefstream and key not in self.trailer:
                self.trailer[NameObject(key)] = xrefstream.raw_get(key)
        return xrefstream.get('/Prev')

    def _read_xref_table(self, stream):

        readNonWhitespace(stream)
        stream.seek(-1, 1)
        # check if the first time looking at the xref table
        firsttime = True
        while True:
            num = readObject(stream, self)
            if firsttime and num != 0:
                self.xrefIndex = num
                if self.strict:
                    warnings.warn(
                        "Xref table not zero-indexed. ID numbers "
                        "for objects will be corrected.",
                        utils.PdfReadWarning)
                    # if table not zero indexed, could be due to error
                    # from when PDF was created which will lead to mismatched
                    # indices later on, only warned and corrected if
                    # self.strict=True
            firsttime = False
            readNonWhitespace(stream)
            stream.seek(-1, 1)
            size = readObject(stream, self)
            readNonWhitespace(stream)
            stream.seek(-1, 1)
            cnt = 0
            while cnt < size:
                line = stream.read(20)

                # It's very clear in section 3.4.3 of the PDF spec
                # that all cross-reference table lines are a fixed
                # 20 bytes (as of PDF 1.7). However, some files have
                # 21-byte entries (or more) due to the use of \r\n
                # (CRLF) EOL's. Detect that case, and adjust the line
                # until it does not begin with a \r (CR) or \n (LF).
                while line[0] in b"\x0D\x0A":
                    stream.seek(-20 + 1, 1)
                    line = stream.read(20)

                # On the other hand, some malformed PDF files
                # use a single character EOL without a preceeding
                # space.  Detect that case, and seek the stream
                # back one character.  (0-9 means we've bled into
                # the next xref entry, t means we've bled into the
                # text "trailer"):
                if line[-1] in b"0123456789t":
                    stream.seek(-1, 1)

                offset, generation = line[:16].split(b" ")
                offset, generation = int(offset), int(generation)
                if generation not in self.xref:
                    self.xref[generation] = {}
                if num in self.xref[generation]:
                    # It really seems like we should allow the last
                    # xref table in the file to override previous
                    # ones. Since we read the file backwards, assume
                    # any existing key is already set correctly.
                    pass
                else:
                    self.xref[generation][num] = offset
                cnt += 1
                num += 1
            readNonWhitespace(stream)
            stream.seek(-1, 1)
            trailertag = stream.read(7)
            if trailertag != b"trailer":
                # more xrefs!
                stream.seek(-7, 1)
            else:
                break
        readNonWhitespace(stream)
        stream.seek(-1, 1)
        new_trailer = readObject(stream, self)
        for key, value in list(new_trailer.items()):
            if key not in self.trailer:
                self.trailer[key] = value
        return new_trailer.get('/Prev')

    def _read_xrefs(self, stream):
        # read all cross reference tables and their trailers
        self.xref = {}
        self.xref_objStm = {}
        self.trailer = DictionaryObject()
        startxref = self.last_startxref
        while startxref is not None:
            # load the xref table
            stream.seek(startxref, 0)
            x = stream.read(1)
            if x == b"x":
                # standard cross-reference table
                ref = stream.read(4)
                if ref[:3] != b"ref":
                    raise utils.PdfReadError("xref table read error")
                startxref = self._read_xref_table(stream)
            elif x.isdigit():
                # PDF 1.5+ Cross-Reference Stream
                stream.seek(-1, 1)
                startxref = self._read_xref_stream(stream)
                self.has_xref_stream = True
            else:
                # bad xref character at startxref.  Let's see if we can find
                # the xref table nearby, as we've observed this error with an
                # off-by-one before.
                stream.seek(-11, 1)
                tmp = stream.read(20)
                xref_loc = tmp.find(b"xref")
                if xref_loc != -1:
                    startxref -= (10 - xref_loc)
                    continue
                # No explicit xref table, try finding a cross-reference stream.
                stream.seek(startxref, 0)
                found = False
                for look in range(5):
                    if stream.read(1).isdigit():
                        # This is not a standard PDF, consider adding a warning
                        startxref += look
                        found = True
                        break
                if found:
                    continue
                # no xref table found at specified location
                raise utils.PdfReadError(
                    "Could not find xref table at specified location"
                )

    def read(self, stream):
        # start at the end:
        stream.seek(-1, 2)
        if not stream.tell():
            raise utils.PdfReadError('Cannot read an empty file')
        # offset of last 1024 bytes of stream
        last_1k = stream.tell() - 1024 + 1
        line = b''
        while line[:5] != b"%%EOF":
            if stream.tell() < last_1k:
                raise utils.PdfReadError("EOF marker not found")
            line = self.readNextEndLine(stream)

        # find startxref entry - the location of the xref table
        line = self.readNextEndLine(stream)
        try:
            startxref = int(line)
        except ValueError:
            # 'startxref' may be on the same line as the location
            if not line.startswith(b"startxref"):
                raise utils.PdfReadError("startxref not found")
            startxref = int(line[9:].strip())
            warnings.warn("startxref on same line as offset")
        else:
            line = self.readNextEndLine(stream)
            if line[:9] != b"startxref":
                raise utils.PdfReadError("startxref not found")

        # This needs to be recorded for incremental update purposes
        self.last_startxref = startxref
        self._read_xrefs(stream)

        # if not zero-indexed, verify that the table is correct;
        # change it if necessary
        if self.xrefIndex and not self.strict:
            loc = stream.tell()
            for gen in self.xref:
                if gen == 65535:
                    continue
                for obj_id in self.xref[gen]:
                    stream.seek(self.xref[gen][obj_id], 0)
                    try:
                        pid, pgen = self.readObjectHeader(stream)
                    except ValueError:
                        break
                    if pid == obj_id - self.xrefIndex:
                        self._zeroXref(gen)
                        break
                    # if not, then either it's just plain wrong
                    # or the non-zero-index is actually correct
            stream.seek(loc, 0)  # return to where it was
