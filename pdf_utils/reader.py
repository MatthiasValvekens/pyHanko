import struct
import os
import re
from io import BytesIO

from . import generic
from .misc import read_non_whitespace, read_until_whitespace
from . import misc
from .crypt import _alg33_1, _alg34, _alg35, derive_key, rc4_encrypt

import logging

logger = logging.getLogger(__name__)

"""
Modified version of PdfFileReader from PyPDF2. See LICENSE.PyPDF2
"""

__all__ = ['PdfFileReader']

header_regex = re.compile(b'%PDF-(\\d).(\\d)')
catalog_version_regex = re.compile(r'/(\d).(\d)')

# General remark:
# PyPDF2 parses all files backwards.
# This means that "next" and "previous" usually mean the opposite of what one
#  might expect.


def read_next_end_line(stream):
    def _build():
        while True:
            # Prevent infinite loops in malformed PDFs
            if stream.tell() == 0:
                raise misc.PdfReadError("Could not read malformed PDF file")
            x = stream.read(1)
            if stream.tell() < 2:
                raise misc.PdfReadError("EOL marker not found")
            stream.seek(-2, os.SEEK_CUR)
            if x == b'\n' or x == b'\r':
                break
            yield ord(x)
        crlf = False
        while x == b'\n' or x == b'\r':
            x = stream.read(1)
            if x == b'\n' or x == b'\r':  # account for CR+LF
                stream.seek(-1, os.SEEK_CUR)
                crlf = True
            if stream.tell() < 2:
                raise misc.PdfReadError("EOL marker not found")
            stream.seek(-2, os.SEEK_CUR)
        # if using CR+LF, go back 2 bytes, else 1
        stream.seek(2 if crlf else 1, os.SEEK_CUR)
    return bytes(reversed(tuple(_build())))


TRAILER_KEYS = "/Root", "/Encrypt", "/Info", "/ID", "/Size"


class XRefCache:

    def __init__(self):
        super().__init__()
        self.current_revision_index = 0
        self.xref_sections = 0
        self.in_obj_stream = {}
        self.standard_xrefs = {}
        # keep track of the xref section that last changed an entry
        #  (needed for some validation workflows)
        self.last_change = {}
        self.first_occurrence = {}

    def used_before(self, idnum, generation):
        # We move backwards through the xrefs, don't replace any.
        return (generation, idnum) in self.standard_xrefs or \
               idnum in self.in_obj_stream

    def put_ref(self, idnum, generation, start):
        if not self.used_before(idnum, generation):
            self.standard_xrefs[(generation, idnum)] = start
            self.last_change[idnum] = self.current_revision_index
        # we move backwards through the file, so this makes sense
        self.first_occurrence[idnum] = self.current_revision_index

    def put_obj_stream_ref(self, idnum, obj_stream_num, obj_stream_ix):
        if not self.used_before(idnum, 0):
            self.in_obj_stream[idnum] = (obj_stream_num, obj_stream_ix)
            self.last_change[idnum] = self.current_revision_index
        self.first_occurrence[idnum] = self.current_revision_index

    def __getitem__(self, ref):
        ix = (ref.generation, ref.idnum)
        if ref.generation == 0 and \
                ref.idnum in self.in_obj_stream:
            return self.in_obj_stream[ref.idnum]
        else:
            try:
                return self.standard_xrefs[ix]
            except KeyError:
                raise misc.PdfReadError("Could not find object.")

    def read_xref_table(self, stream):
        read_non_whitespace(stream)
        stream.seek(-1, os.SEEK_CUR)
        while True:
            num = generic.read_object(stream, self)
            read_non_whitespace(stream)
            stream.seek(-1, os.SEEK_CUR)
            size = generic.read_object(stream, self)
            read_non_whitespace(stream)
            stream.seek(-1, os.SEEK_CUR)
            for cnt in range(0, size):
                line = stream.read(20)

                # It's very clear in section 3.4.3 of the PDF spec
                # that all cross-reference table lines are a fixed
                # 20 bytes (as of PDF 1.7). However, some files have
                # 21-byte entries (or more) due to the use of \r\n
                # (CRLF) EOL's. Detect that case, and adjust the line
                # until it does not begin with a \r (CR) or \n (LF).
                while line[0] in b"\x0D\x0A":
                    stream.seek(-20 + 1, os.SEEK_CUR)
                    line = stream.read(20)

                # On the other hand, some malformed PDF files
                # use a single character EOL without a preceding
                # space.  Detect that case, and seek the stream
                # back one character.  (0-9 means we've bled into
                # the next xref entry, t means we've bled into the
                # text "trailer"):
                if line[-1] in b"0123456789t":
                    stream.seek(-1, os.SEEK_CUR)

                offset, generation = line[:16].split(b" ")
                self.put_ref(num, int(generation), int(offset))
                num += 1
            read_non_whitespace(stream)
            stream.seek(-1, os.SEEK_CUR)
            trailertag = stream.read(7)
            if trailertag != b"trailer":
                # more xrefs!
                stream.seek(-7, os.SEEK_CUR)
            else:
                break
        read_non_whitespace(stream)
        stream.seek(-1, os.SEEK_CUR)

        self.xref_sections += 1

    def read_xref_stream(self, xrefstream):
        stream_data = BytesIO(xrefstream.data)
        # Index pairs specify the subsections in the dictionary. If
        # none create one subsection that spans everything.
        idx_pairs = xrefstream.get("/Index", [0, xrefstream.get("/Size")])
        entry_sizes = xrefstream.get("/W")

        def get_entry(ix):
            # Reads the correct number of bytes for each entry. See the
            # discussion of the W parameter in PDF spec table 17.
            if entry_sizes[ix] > 0:
                d = stream_data.read(entry_sizes[ix])
                return convert_to_int(d, entry_sizes[ix])

            # PDF Spec Table 17: A value of zero for an element in the
            # W array indicates...the default value shall be used
            if ix == 0:
                return 1  # First value defaults to 1
            else:
                return 0

        # Iterate through each subsection
        last_end = 0
        for start, size in misc.pair_iter(idx_pairs):
            # The subsections must increase
            assert start >= last_end
            last_end = start + size
            for num in range(start, start + size):
                # The first entry is the type
                xref_type = get_entry(0)
                # The rest of the elements depend on the xref_type
                if xref_type == 1:
                    # objects that are in use but are not compressed
                    byte_offset = get_entry(1)
                    generation = get_entry(2)
                    self.put_ref(num, generation, byte_offset)
                elif xref_type == 2:
                    # compressed objects
                    objstr_num = get_entry(1)
                    objstr_idx = get_entry(2)
                    self.put_obj_stream_ref(num, objstr_num, objstr_idx)
                else:
                    # either xref_type = 0 (freed object)
                    # or it's some unknown type (=> ignore).
                    # In either case, simply advance the cursor
                    get_entry(1)
                    get_entry(2)

        self.xref_sections += 1


def read_object_header(stream, strict):
    # Should never be necessary to read out whitespace, since the
    # cross-reference table should put us in the right spot to read the
    # object header.  In reality... some files have stupid cross reference
    # tables that are off by whitespace bytes.
    extra = False
    misc.skip_over_comment(stream)
    extra |= misc.skip_over_whitespace(stream)
    stream.seek(-1, os.SEEK_CUR)
    idnum = misc.read_until_whitespace(stream)
    extra |= misc.skip_over_whitespace(stream)
    stream.seek(-1, os.SEEK_CUR)
    generation = misc.read_until_whitespace(stream)
    stream.read(3)
    read_non_whitespace(stream, seek_back=True)

    if extra and strict:
        logger.warning(
            f"Superfluous whitespace found in object header "
            f"{idnum} {generation}"
        )
    return int(idnum), int(generation)


class PdfFileReader:
    last_startxref = None
    has_xref_stream = False

    def __init__(self, stream, strict=True):
        """
        Initializes a PdfFileReader object.  This operation can take some time,
        as the PDF stream's cross-reference tables are read into memory.

        :param stream: A File object or an object that supports the standard
            read and seek methods similar to a File object. Could also be a
            string representing a path to a PDF file.
        :param bool strict: Determines whether user should be warned of all
            problems and also causes some correctable problems to be fatal.
            Defaults to ``True``.
        """
        self.strict = strict
        self.resolved_objects = {}
        self.input_version = None
        self.xrefs = XRefCache()
        self.stream = stream
        self.read()
        # override version if necessary
        try:
            # grab version info *without* triggering crypto
            root_ref = self.trailer.raw_get('/Root')
            root = self.get_object(root_ref, never_decrypt=True)
            version = root.raw_get('/Version')
            # not sure if anyone would be crazy enough to make this an indirect
            # reference, but in theory it's possible
            if isinstance(version, generic.IndirectObject):
                version = self.get_object(version, never_decrypt=True)
            m = catalog_version_regex.match(str(version))
            if m is not None:
                major = int(m.group(1))
                minor = int(m.group(2))
                self.input_version = (major, minor)
        except KeyError:
            pass

    def _get_object_from_stream(self, idnum, stmnum, idx):
        # indirect reference to object in object stream
        # read the entire object stream into memory
        stream_ref = generic.IndirectObject(stmnum, 0, self).get_object()
        # This is an xref to a stream, so its type better be a stream
        assert stream_ref['/Type'] == '/ObjStm'
        # /N is the number of indirect objects in the stream
        assert idx < stream_ref['/N']
        stream_data = BytesIO(stream_ref.data)
        first_object = stream_ref['/First']
        for i in range(stream_ref['/N']):
            read_non_whitespace(stream_data, seek_back=True)
            objnum = generic.NumberObject.read_from_stream(stream_data)
            read_non_whitespace(stream_data, seek_back=True)
            offset = generic.NumberObject.read_from_stream(stream_data)
            read_non_whitespace(stream_data, seek_back=True)
            if objnum != idnum:
                # We're only interested in one object
                continue
            if self.strict and idx != i:
                raise misc.PdfReadError("Object is in wrong index.")
            stream_data.seek(first_object + offset)
            try:
                obj = generic.read_object(stream_data, self)
            except misc.PdfStreamError as e:
                # Stream object cannot be read. Normally, a critical error, but
                # Adobe Reader doesn't complain, so continue (in strict mode?)
                logger.warning(
                    f"Invalid stream (index {i}) within object {idnum} 0: {e}"
                )

                if self.strict:
                    raise misc.PdfReadError("Can't read object stream: %s" % e)
                # Replace with null. Hopefully it's nothing important.
                obj = generic.NullObject()
            return obj

        if self.strict:
            raise misc.PdfReadError("This is a fatal error in strict mode.")
        return generic.NullObject()

    def get_encryption_params(self):
        encrypt_ref = self.trailer.raw_get('/Encrypt')
        if isinstance(encrypt_ref, generic.IndirectObject):
            return self.get_object(encrypt_ref, never_decrypt=True)
        else:
            return encrypt_ref

    def get_object(self, ref, never_decrypt=False, transparent_decrypt=True):
        """
        Read an object from the input stream.

        :param ref:
            Reference to the object.
        :param never_decrypt:
            Skip decryption step (only needed for parsing /Encrypt)
        :param transparent_decrypt:
            If True, all encrypted objects are transparently decrypted by
            default (in the sense that a user of the API in a PyPDF2 compatible
            way would only "see" decrypted objects).
            If False, this method may return a proxy object that still allows
            access to the "original".
        :return:
        """
        retval = self.cache_get_indirect_object(ref.generation, ref.idnum)
        if retval is not None:
            if transparent_decrypt and \
                    isinstance(retval, generic.DecryptedObjectProxy):
                retval = retval.decrypted
            return retval

        start = self.xrefs[ref]
        if isinstance(start, tuple):
            # object stream
            (obj_stream_num, obj_stream_ix) = start
            return self._get_object_from_stream(
                ref.idnum, obj_stream_num, obj_stream_ix
            )
        else:
            # standard indirect object
            self.stream.seek(start)
            idnum, generation = read_object_header(
                self.stream, strict=self.strict
            )
            if idnum != ref.idnum or generation != ref.generation:
                raise misc.PdfReadError(
                    f"Expected object ID ({ref.idnum} {ref.generation}) "
                    f"does not match actual ({idnum} {generation})."
                )
            retval = generic.read_object(self.stream, self)

            # override encryption is used for the /Encrypt dictionary
            if not never_decrypt and self.encrypted:
                try:
                    shared_key = self._decryption_key
                except AttributeError:
                    raise misc.PdfReadError("file has not been decrypted")
                key = derive_key(shared_key, ref.idnum, ref.generation)
                # make sure the object that lands in the cache is always
                # a proxy object
                retval = generic.proxy_encrypted_obj(retval, key)
            self.cache_indirect_object(ref.generation, ref.idnum, retval)
            if transparent_decrypt and \
                    isinstance(retval, generic.DecryptedObjectProxy):
                retval = retval.decrypted
            return retval

    def cache_get_indirect_object(self, generation, idnum):
        out = self.resolved_objects.get((generation, idnum))
        return out

    def cache_indirect_object(self, generation, idnum, obj):
        self.resolved_objects[(generation, idnum)] = obj
        return obj

    def _read_xref_stream(self):
        stream = self.stream
        idnum, generation = read_object_header(stream, strict=self.strict)
        xrefstream = generic.read_object(stream, self)
        assert xrefstream["/Type"] == "/XRef"
        self.cache_indirect_object(generation, idnum, xrefstream)
        self.xrefs.read_xref_stream(xrefstream)

        for key in TRAILER_KEYS:
            if key in xrefstream and key not in self.trailer:
                self.trailer[generic.NameObject(key)] = xrefstream.raw_get(key)
        return xrefstream.get('/Prev')

    def _read_xref_table(self):
        stream = self.stream
        self.xrefs.read_xref_table(stream)
        new_trailer = generic.read_object(stream, self)
        for key, value in list(new_trailer.items()):
            if key not in self.trailer:
                self.trailer[key] = value
        return new_trailer.get('/Prev')

    def _read_xrefs(self):
        # read all cross reference tables and their trailers
        stream = self.stream
        self.trailer = generic.DictionaryObject()
        startxref = self.last_startxref
        while startxref is not None:
            # load the xref table
            stream.seek(startxref)
            x = stream.read(1)
            if x == b"x":
                # standard cross-reference table
                ref = stream.read(4)
                if ref[:3] != b"ref":
                    raise misc.PdfReadError("xref table read error")
                startxref = self._read_xref_table()
            elif x.isdigit():
                # PDF 1.5+ Cross-Reference Stream
                stream.seek(-1, os.SEEK_CUR)
                startxref = self._read_xref_stream()
                self.has_xref_stream = True
            else:
                # bad xref character at startxref.  Let's see if we can find
                # the xref table nearby, as we've observed this error with an
                # off-by-one before.
                stream.seek(-11, os.SEEK_CUR)
                tmp = stream.read(20)
                xref_loc = tmp.find(b"xref")
                if xref_loc != -1:
                    startxref -= (10 - xref_loc)
                    continue
                # No explicit xref table, try finding a cross-reference stream.
                stream.seek(startxref)
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
                raise misc.PdfReadError(
                    "Could not find xref table at specified location"
                )

    def read(self):
        # first, read the header & PDF version number
        # (version number can be overridden in the document catalog later)
        stream = self.stream
        stream.seek(0)
        input_version = None
        try:
            header = read_until_whitespace(stream, maxchars=20)
            # match ignores trailing chars
            m = header_regex.match(header)
            if m is not None:
                major = int(m.group(1))
                minor = int(m.group(2))
                input_version = (major, minor)
        except (UnicodeDecodeError, ValueError):
            pass
        if input_version is None:
            raise ValueError('Illegal PDF header')
        self.input_version = input_version

        # start at the end:
        stream.seek(-1, os.SEEK_END)
        if not stream.tell():
            raise misc.PdfReadError('Cannot read an empty file')
        # offset of last 1024 bytes of stream
        last_1k = stream.tell() - 1024 + 1
        line = b''
        while line[:5] != b"%%EOF":
            if stream.tell() < last_1k:
                raise misc.PdfReadError("EOF marker not found")
            line = read_next_end_line(stream)

        # find startxref entry - the location of the xref table
        line = read_next_end_line(stream)
        try:
            startxref = int(line)
        except ValueError:
            # 'startxref' may be on the same line as the location
            if not line.startswith(b"startxref"):
                raise misc.PdfReadError("startxref not found")
            startxref = int(line[9:].strip())
            logger.warning("startxref on same line as offset")
        else:
            line = read_next_end_line(stream)
            if line[:9] != b"startxref":
                raise misc.PdfReadError("startxref not found")

        # This needs to be recorded for incremental update purposes
        self.last_startxref = startxref
        self._read_xrefs()

    def decrypt(self, password):
        """
        When using an encrypted / secured PDF file with the PDF Standard
        encryption handler, this function will allow the file to be decrypted.
        It checks the given password against the document's user password and
        owner password, and then stores the resulting decryption key if either
        password is correct.

        It does not matter which password was matched.  Both passwords provide
        the correct decryption key that will allow the document to be used with
        this library.

        :param bytes password: The password to match.
        :return: ``0`` if the password failed, ``1`` if the password matched the
            user password, and ``2`` if the password matched the owner password.
        :rtype: int
        :raises NotImplementedError: if document uses an unsupported encryption
            method.
        """

        return self._decrypt(password)

    def _decrypt(self, password):
        encrypt = self.get_encryption_params()
        if encrypt['/Filter'] != '/Standard':
            raise NotImplementedError(
                "only Standard PDF encryption handler is available"
            )
        if not (encrypt['/V'] in (1, 2)):
            raise NotImplementedError(
                "only algorithm code 1 and 2 are supported"
            )
        user_password, key = self._auth_user_password(password)
        if user_password:
            self._decryption_key = key
            return 1
        else:
            rev = encrypt['/R'].get_object()
            if rev == 2:
                keylen = 5
            else:
                keylen = encrypt['/Length'].get_object() // 8
            key = _alg33_1(password, rev, keylen)
            owner_token = encrypt["/O"].get_object()
            if rev == 2:
                userpass = rc4_encrypt(key, owner_token)
            else:
                val = owner_token
                for i in range(19, -1, -1):
                    new_key = bytes(b ^ i for b in key)
                    val = rc4_encrypt(new_key, val)
                userpass = val
            owner_password, key = self._auth_user_password(userpass)
            if owner_password:
                self._decryption_key = key
                return 2
        return 0

    def _auth_user_password(self, password):
        encrypt = self.get_encryption_params()
        rev = encrypt['/R'].get_object()
        owner_entry = encrypt['/O'].get_object()
        p_entry = encrypt['/P'].get_object()
        id_entry = self.trailer['/ID'].get_object()
        id1_entry = id_entry[0].get_object()
        user_token = encrypt['/U'].get_object().original_bytes
        if rev == 2:
            user_tok_supplied, key = _alg34(
                password, owner_entry, p_entry, id1_entry
            )
        elif rev >= 3:
            encrypt_meta = encrypt.get(
                "/EncryptMetadata", generic.BooleanObject(False)
            ).get_object()
            user_tok_supplied, key = _alg35(
                password, rev, encrypt["/Length"].get_object() // 8,
                owner_entry, p_entry, id1_entry, encrypt_meta)
            user_tok_supplied = user_tok_supplied[:16]
            user_token = user_token[:16]
        else:
            raise NotImplementedError
        return user_tok_supplied == user_token, key

    @property
    def encrypted(self):
        return "/Encrypt" in self.trailer


def convert_to_int(d, size):
    if size <= 8:
        padding = bytes(8 - size)
        return struct.unpack(">q", padding + d)[0]
    else:
        return sum(digit ** (size - ix - 1) for ix, digit in enumerate(d))
