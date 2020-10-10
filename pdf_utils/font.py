import logging
from io import BytesIO

from pdf_utils import generic
from fontTools import ttLib, subset

from pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pdf_utils.misc import peek

logger = logging.getLogger(__name__)

pdf_name = generic.NameObject
pdf_string = generic.pdf_string
ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'


def generate_subset_prefix():
    import random
    return ''.join(ALPHABET[random.randint(0, 25)] for _ in range(6))


class FontEngine:

    def measure(self, txt):
        raise NotImplementedError

    def render(self, txt):
        raise NotImplementedError

    def render_and_measure(self, txt):
        return self.render(txt), self.measure(txt)

    def as_resource(self, writer):
        raise NotImplementedError


# FIXME replace with something that knows the metrics for the standard PDF fonts
class SimpleFontEngine(FontEngine):

    @staticmethod
    def default_engine():
        return SimpleFontEngine('Courier', 0.6)

    def __init__(self, name, avg_width):
        self.avg_width = avg_width
        self.name = name

    def render(self, txt):
        return f'({txt})'

    def measure(self, txt):
        return len(txt) * self.avg_width

    def as_resource(self, writer):
        # assume that self.font is the name of a PDF standard font
        # TODO enforce that
        font_dict = generic.DictionaryObject({
            pdf_name('/Type'): pdf_name('/Font'),
            pdf_name('/BaseFont'): pdf_name('/' + self.name),
            pdf_name('/Subtype'): pdf_name('/Type1'),
            pdf_name('/Encoding'): pdf_name('/WinAnsiEncoding')
        })
        return writer.add_object(font_dict)


class GlyphAccumulator(FontEngine):

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
            (cid, gid, glyph) = self._glyphs[ch]
        except KeyError:
            # NOTE: the glyph id as reported by getGlyphID is NOT what we want
            # to encode in the string. In some fonts (I've seen this in a couple
            # full CJK fonts), this happens to be the same as the CID of the
            # glyph but not always.
            # I'm not sure what the "officially sanctioned" way to do this in
            # fontTools is, but we can derive the CID from the generated name
            # of the glyph, which is of the form cidXXXXX
            # We do want to save the glyph ID to pass it to the subsetter later.
            # FIXME This obviously breaks with string-keyed fonts. How to deal
            #  with those?
            try:
                glyph_name = self.cmap[ord(ch)]
                glyph = self.glyph_set[glyph_name]
                gid = self.tt.getGlyphID(glyph_name)
                try:
                    cid = int(glyph_name[3:])
                except ValueError:
                    raise NotImplementedError(
                        f"Could not figure out CID for glyph with name "
                        f"{glyph_name}."
                    )
            except KeyError:
                glyph = self.glyph_set['.notdef']
                gid = self.tt.getGlyphID('.notdef')
                cid = 0
            self._glyphs[ch] = (cid, gid, glyph)

        return cid, glyph.width

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
                cid, width = self._encode_char(ch)
                # ignore kerning
                total_width += width
                yield '%04x' % cid

        hex_encoded = ''.join(_gen())
        return hex_encoded, total_width / self.units_per_em

    def render(self, txt):
        hex_encoded, _ = self.feed_string(txt)
        return f'<{hex_encoded}>'

    def measure(self, txt):
        return self.feed_string(txt)[1]

    def extract_subset(self, options=None):
        options = options or subset.Options()
        subsetter: subset.Subsetter = subset.Subsetter(options=options)
        gids = map(lambda x: x[1], self._glyphs.values())
        subsetter.populate(gids=list(gids))
        subsetter.subset(self.tt)
        self._extracted = True

    def embed_subset(self, writer: IncrementalPdfFileWriter, obj_stream=None):
        if not self._extracted:
            self.extract_subset()
        cidfont_obj = CIDFontType0(self.tt)
        # TODO keep track of used subset prefixes in the writer!
        cff_topdict = self.tt['CFF '].cff[0]
        name = cidfont_obj.name
        cff_topdict.rawDict['FullName'] = '%s+%s' % (
            generate_subset_prefix(), name
        )
        cidfont_obj.embed(writer, obj_stream=obj_stream)
        cidfont_ref = writer.add_object(cidfont_obj)
        to_unicode = self.format_tounicode_cmap(*cidfont_obj.ros)
        type0 = generic.DictionaryObject({
            pdf_name('/Type'): pdf_name('/Font'),
            pdf_name('/Subtype'): pdf_name('/Type0'),
            pdf_name('/DescendantFonts'): generic.ArrayObject([cidfont_ref]),
            # take the Identity-H encoding to inherit from the /Encoding
            # entry specified in our CIDSystemInfo dict
            pdf_name('/Encoding'): pdf_name('/Identity-H'),
            pdf_name('/BaseFont'):
                pdf_name('/%s-Identity-H' % cidfont_obj.name),
            pdf_name('/ToUnicode'): writer.add_object(to_unicode)
        })
        to_unicode.compress()
        # compute widths entry
        # (easiest to do here, since it seems we need the original CIDs)
        by_cid = iter(sorted(self._glyphs.values(), key=lambda t: t[0]))

        def _widths():
            current_chunk = []
            prev_cid = None
            (first_cid, _, _), itr = peek(by_cid)
            for cid, _, g in itr:
                if current_chunk and cid != prev_cid + 1:
                    yield generic.NumberObject(first_cid)
                    yield generic.ArrayObject(current_chunk)
                    current_chunk = []
                    first_cid = cid

                current_chunk.append(generic.NumberObject(g.width))
                prev_cid = cid

        cidfont_obj[pdf_name('/W')] = generic.ArrayObject(list(_widths()))
        return writer.add_object(type0, obj_stream=obj_stream)

    def as_resource(self, writer):
        return self.embed_subset(writer)

    def format_tounicode_cmap(self, registry, ordering, supplement):
        def _pairs():
            for ch, (cid, _, _) in self._glyphs.items():
                yield cid, ch
        by_cid = iter(sorted(_pairs(), key=lambda t: t[0]))
        header = (
            '/CIDInit /ProcSet findresource begin\n'
            '12 dict begin\n'
            'begincmap\n'
            '/CIDSystemInfo 3 dict dup begin\n'
            f'/Registry ({registry}) def\n'
            f'/Ordering ({ordering}) def\n'
            f'/Supplement {supplement}\n def'
            'end def\n'
            f'/CMapName {registry}-{ordering}-{supplement:03} def\n'
            '/CMapType 2 def\n'
            '1 begincodespacerange\n'
            '<0000> <FFFF>\n'
            'endcodespacerange\n'
        )
        # TODO make an effort to use ranges when appropriate, and at least
        #  group the glyphs
        body = '\n'.join(
            f'1 beginbfchar\n<{cid:04x}> <{ord(ch):04x}>\nendbfchar\n'
            for cid, ch in by_cid
        )

        footer = (
            'endcmap\n'
            'CMapName currentdict /CMap\n'
            'defineresource pop\n'
            'end\nend'
        )
        stream = generic.StreamObject(
            stream_data=(header + body + footer).encode('ascii')
        )
        return stream


class CIDFont(generic.DictionaryObject):
    def __init__(self, tt: ttLib.TTFont, ps_name, subtype, registry,
                 ordering, supplement):
        self.tt = tt
        self.name = ps_name
        self.ros = registry, ordering, supplement

        super().__init__({
            pdf_name('/Type'): pdf_name('/Font'),
            pdf_name('/Subtype'): pdf_name(subtype),
            pdf_name('/CIDSystemInfo'): generic.DictionaryObject({
                pdf_name('/Registry'): pdf_string(registry),
                pdf_name('/Ordering'): pdf_string(ordering),
                pdf_name('/Supplement'): generic.NumberObject(supplement)
            }),
            pdf_name('/BaseFont'): pdf_name('/' + ps_name)
        })
        self._font_descriptor = FontDescriptor(self)

    def embed(self, writer: IncrementalPdfFileWriter, obj_stream=None):
        fd = self._font_descriptor
        self[pdf_name('/FontDescriptor')] = fd_ref = writer.add_object(
            fd, obj_stream=obj_stream
        )
        font_stream_ref = self.set_font_file(writer)
        return fd_ref, font_stream_ref

    def set_font_file(self, writer: IncrementalPdfFileWriter):
        raise NotImplementedError

# TODO support type 2 fonts (i.e. with 'glyf' instead of 'CFF ')


class CIDFontType0(CIDFont):
    def __init__(self, tt: ttLib.TTFont):
        # We assume that this font set (in the CFF sense) contains
        # only one font. This is fairly safe according to the fontTools docs.
        self.cff = cff = tt['CFF '].cff
        td = cff[0]
        ps_name = td.rawDict['FullName'].replace(' ', '')
        try:
            registry, ordering, supplement = td.ROS
        except (AttributeError, ValueError):
            # XXX If these attributes aren't present, chances are that the
            # font won't work regardless.
            logger.warning("No ROS metadata. Is this really a CIDFont?")
            registry = "Adobe"
            ordering = "Identity"
            supplement = 0
        super().__init__(
            tt, ps_name, '/CIDFontType0', registry, ordering, supplement
        )

    def set_font_file(self, writer: IncrementalPdfFileWriter):
        stream_buf = BytesIO()
        # write the CFF table to the stream
        self.cff.compile(stream_buf, self.tt)
        stream_buf.seek(0)
        font_stream = generic.StreamObject({
            # this is a Type0 CFF font program (see Table 126 in ISO 32000)
            pdf_name('/Subtype'): pdf_name('/CIDFontType0C'),
        }, stream_data=stream_buf.read())
        font_stream.compress()
        font_stream_ref = writer.add_object(font_stream)
        self._font_descriptor[pdf_name('/FontFile3')] = font_stream_ref
        return font_stream_ref


class FontDescriptor(generic.DictionaryObject):
    """
    Lazy way to embed a font descriptor. It assumes all sorts of metadata
    to be present. If not, it'll probably fail with a gnarly error.
    """

    def __init__(self, cf: CIDFont):
        tt = cf.tt

        # Some metrics
        hhea = tt['hhea']
        head = tt['head']
        bbox = [head.xMin, head.yMin, head.xMax, head.yMax]
        os2 = tt['OS/2']
        weight = os2.usWeightClass
        stemv = int(10 + 220 * (weight - 50) / 900)
        super().__init__({
            pdf_name('/Type'): pdf_name('/FontDescriptor'),
            pdf_name('/FontName'): pdf_name('/' + cf.name),
            pdf_name('/Ascent'): generic.NumberObject(hhea.ascent),
            pdf_name('/Descent'): generic.NumberObject(hhea.descent),
            pdf_name('/FontBBox'): generic.ArrayObject(
                map(generic.NumberObject, bbox)
            ),
            # FIXME I'm setting the Serif and Symbolic flags here, but
            #  is there any way we can read/infer those from the TTF metadata?
            pdf_name('/Flags'): generic.NumberObject(0b110),
            pdf_name('/StemV'): generic.NumberObject(stemv),
            pdf_name('/ItalicAngle'): generic.FloatObject(
                tt['post'].italicAngle
            ),
            pdf_name('/CapHeight'): generic.NumberObject(os2.sCapHeight)
        })
