from io import BytesIO

from pdf_utils import generic
from fontTools import ttLib, subset

from pdf_utils.incremental_writer import IncrementalPdfFileWriter, peek

pdf_name = generic.NameObject
pdf_string = generic.pdf_string
ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'


def generate_subset_prefix():
    import random
    return ''.join(ALPHABET[random.randint(0, 25)] for _ in range(6))


class GlyphAccumulator:

    def __init__(self, tt: ttLib.TTFont):
        self.tt = tt
        self.cmap = tt.getBestCmap()
        self.glyph_set = self.tt.getGlyphSet(preferCFF=True)
        self._glyphs = {}
        self._extracted = False
        try:
            self.units_per_em = tt['head'].unitsPerEm
        except KeyError:
            self.units_per_em = 1000

    def _encode_char(self, ch):
        try:
            (glyph_id, glyph) = self._glyphs[ch]
        except KeyError:
            try:
                glyph_name = self.cmap[ord(ch)]
                glyph = self.glyph_set[glyph_name]
                glyph_id = self.tt.getGlyphID(glyph_name)
            except KeyError:
                glyph = self.glyph_set['.notdef']
                glyph_id = self.tt.getGlyphID('.notdef')
            self._glyphs[ch] = (glyph_id, glyph)

        return glyph_id, glyph.width

    def feed_string(self, txt):
        """
        Feed a string to this glyph accumulator.

        :param txt:
            String to encode/measure.
            The glyphs used to render the string are marked for inclusion in the
            font subset associated with this glyph accumulator.
        :return:
            Returns the CID-encoded version of the string passed in, and
            an estimate of the width in em units.
            The width computation ignores kerning, but takes the width of all
            characters into account.
        """

        total_width = 0

        def _gen():
            nonlocal total_width
            for ch in txt:
                glyph_id, width = self._encode_char(ch)
                # ignore kerning
                total_width += width
                yield '%04x' % glyph_id

        hex_encoded = ''.join(_gen())
        return hex_encoded, total_width / self.units_per_em

    def extract_subset(self, options=None):
        options = options or subset.Options()
        subsetter: subset.Subsetter = subset.Subsetter(options=options)
        gids = map(lambda x: x[0], self._glyphs.values())
        subsetter.populate(gids=list(gids))
        subsetter.subset(self.tt)
        self._extracted = True

    def embed_subset(self, writer: IncrementalPdfFileWriter):
        if not self._extracted:
            self.extract_subset()
        cidfont_obj = CIDFontType0(self.tt)
        # TODO keep track of used subset prefixes in the writer!
        cff_topdict = self.tt['CFF '].cff[0]
        name = cff_topdict.rawDict['FullName']
        cff_topdict.rawDict['FullName'] = '%s+%s' % (
            generate_subset_prefix(), name
        )
        cidfont_obj.embed(writer)
        cidfont_ref = writer.add_object(cidfont_obj)
        # TODO add ToUnicode cmap? See 9.7.6 in ISO-32000
        type0 = generic.DictionaryObject({
            pdf_name('/Type'): pdf_name('/Font'),
            pdf_name('/Subtype'): pdf_name('/Type0'),
            pdf_name('/DescendantFonts'): generic.ArrayObject([cidfont_ref]),
            # take the Identity-H encoding to inherit from the /Encoding
            # entry specified in our CIDSystemInfo dict
            pdf_name('/Encoding'): pdf_name('/Identity-H'),
            pdf_name('/BaseFont'): pdf_name('/%s-Identity-H' % cidfont_obj.name)
        })
        # compute widths entry
        # (easiest to do here, since it seems we need the original CIDs)
        by_cid = iter(sorted(self._glyphs.values(), key=lambda t: t[0]))

        def _widths():
            current_chunk = []
            prev_cid = None
            (first_cid, _), itr = peek(by_cid)
            for cid, g in itr:
                if current_chunk and cid != prev_cid + 1:
                    yield generic.NumberObject(first_cid)
                    yield generic.ArrayObject(current_chunk)
                    current_chunk = []
                    first_cid = cid

                current_chunk.append(generic.NumberObject(g.width))
                prev_cid = cid

        cidfont_obj[pdf_name('/W')] = generic.ArrayObject(list(_widths()))
        return writer.add_object(type0)


class CIDFontType0(generic.DictionaryObject):
    def __init__(self, tt: ttLib.TTFont):
        self.tt = tt
        # We assume that this font set (in the CFF sense) contains
        # only one font. This is fairly safe according to the fontTools docs.
        self.cff = tt['CFF '].cff
        td = self.cff[0]
        self.name = td.rawDict['FullName']
        registry, ordering, supplement = td.ROS
        super().__init__({
            pdf_name('/Type'): pdf_name('/Font'),
            pdf_name('/Subtype'): pdf_name('/CIDFontType0'),
            pdf_name('/CIDSystemInfo'): generic.DictionaryObject({
                pdf_name('/Registry'): pdf_string(registry),
                pdf_name('/Ordering'): pdf_string(ordering),
                pdf_name('/Supplement'): generic.NumberObject(supplement)
            }),
            pdf_name('/BaseFont'): pdf_name('/' + self.name)
        })
        self._font_descriptor = None

    def embed(self, writer: IncrementalPdfFileWriter):
        self._font_descriptor = fd = FontDescriptor(self.tt)
        self[pdf_name('/FontDescriptor')] = fd_ref = writer.add_object(fd)
        font_stream_ref = fd.set_font_file3(writer)
        return fd_ref, font_stream_ref


class FontDescriptor(generic.DictionaryObject):
    """
    Lazy way to embed a font descriptor. It assumes all sorts of metadata
    to be present. If not, it'll probably fail with a gnarly error.
    """

    def __init__(self, tt: ttLib.TTFont):
        self.tt = tt
        hhea = tt['hhea']
        self.cff = tt['CFF '].cff
        postscript_name = self.cff[0].rawDict['FullName']

        # Some metrics

        weight = tt['OS/2'].usWeightClass
        stemv = int(10 + 220 * (weight - 50) / 900)

        super().__init__({
            pdf_name('/Type'): pdf_name('/FontDescriptor'),
            pdf_name('/FontName'): pdf_name('/' + postscript_name),
            pdf_name('/Ascent'): generic.NumberObject(hhea.ascent),
            pdf_name('/Descent'): generic.NumberObject(hhea.descent),
            pdf_name('/FontBBox'): generic.ArrayObject(
                list(map(generic.NumberObject, self.cff[0].FontBBox))
            ),
            # FIXME I'm setting the Serif and Symbolic flags here, but
            #  is there any way we can read/infer those from the TTF metadata?
            pdf_name('/Flags'): generic.NumberObject(0b110),
            pdf_name('/StemV'): generic.NumberObject(stemv),
            # FIXME should also grab this from the metadata
            pdf_name('/ItalicAngle'): generic.NumberObject(0),
        })

        glyph_set = tt.getGlyphSet(preferCFF=True)
        cmap = tt.getBestCmap()
        alphabet_names = [cmap[x] for x in ALPHABET if x in cmap]
        # /CapHeight is only required if the font contains latin characters
        if alphabet_names:
            try:
                cap_height = max(glyph_set[x].height for x in alphabet_names)
            except (AttributeError, TypeError, KeyError):
                # some glyphs may not have a well-defined height
                cap_height = hhea.ascent
            self[pdf_name('/CapHeight')] = generic.NumberObject(int(cap_height))

    def set_font_file3(self, writer: IncrementalPdfFileWriter):
        stream_buf = BytesIO()
        # write the CFF table to the stream
        self.cff.compile(stream_buf, self.tt)
        stream_buf.seek(0)
        font_stream = generic.StreamObject({
            # this is a Type0 CFF font program (see Table 126 in ISO 32000)
            pdf_name('/Subtype'): pdf_name('/CIDFontType0C'),
        }, stream_data=stream_buf.read())
        font_stream_ref = writer.add_object(font_stream)
        self[pdf_name('/FontFile3')] = font_stream_ref
        return font_stream_ref
