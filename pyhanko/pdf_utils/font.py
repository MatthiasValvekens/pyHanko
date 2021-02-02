"""Basic support for font handling & subsetting.

This module relies on `fontTools <https://pypi.org/project/fonttools/>`_ for
OTF parsing and subsetting.

.. warning ::
    If/when support is added for more advanced typographical features, the
    general :class:`FontEngine` interface might change.

"""

import logging
from dataclasses import dataclass
from io import BytesIO

from pyhanko.pdf_utils import generic
from fontTools import ttLib, subset

from pyhanko.pdf_utils.misc import peek


__all__ = [
    'FontEngine', 'SimpleFontEngine', 'GlyphAccumulator',
    'GlyphAccumulatorFactory'
]

from pyhanko.pdf_utils.writer import BasePdfFileWriter

logger = logging.getLogger(__name__)

pdf_name = generic.NameObject
pdf_string = generic.pdf_string
ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'


def generate_subset_prefix():
    import random
    return ''.join(ALPHABET[random.randint(0, 25)] for _ in range(6))


class FontEngine:
    """General interface for glyph lookups and font metrics."""

    def measure(self, txt: str) -> float:
        """Measure the length of a string in em units.

        :param txt:
            String to measure.
        :return:
            A length in em units.
        """

        raise NotImplementedError

    # FIXME this should probably return bytes
    def render(self, txt: str):
        """Render a string to a format suitable for inclusion in a content
        stream.

        :param txt:
            String to render.
        :return:
            A string.
        """
        raise NotImplementedError

    def as_resource(self) -> generic.DictionaryObject:
        """Convert a :class:`.FontEngine` to a PDF object suitable for embedding
        inside a resource dictionary.

        :return:
            A PDF dictionary.
        """
        raise NotImplementedError


# FIXME replace with something that knows the metrics for the standard PDF fonts
class SimpleFontEngine(FontEngine):
    """
    Simplistic font engine that only works with PDF standard fonts, and
    does not care about font metrics. Best used with monospaced fonts such
    as Courier.
    """

    @staticmethod
    def default_engine():
        """
        :return:
            A :class:`.FontEngine` instance representing the Courier
            standard font.
        """
        return SimpleFontEngine('Courier', 0.6)

    def __init__(self, name, avg_width):
        self.avg_width = avg_width
        self.name = name

    def render(self, txt):
        return f'({txt})'

    def measure(self, txt):
        return len(txt) * self.avg_width

    def as_resource(self):
        # assume that self.font is the name of a PDF standard font
        # TODO enforce that
        font_dict = generic.DictionaryObject({
            pdf_name('/Type'): pdf_name('/Font'),
            pdf_name('/BaseFont'): pdf_name('/' + self.name),
            pdf_name('/Subtype'): pdf_name('/Type1'),
            pdf_name('/Encoding'): pdf_name('/WinAnsiEncoding')
        })
        return font_dict


class GlyphAccumulator(FontEngine):
    """
    Utility to collect & measure glyphs from TrueType fonts.

    .. warning::
        This utility class ignores all positioning & substition information
        in the font file, other than glyph width/height.
        In particular, features such as kerning, ligatures, complex script
        support and regional substitution will not work out of the box.

    .. warning::
        This functionality was only really tested with CID-keyed fonts
        that have a CFF table. This is good enough to offer basic support
        for CJK scripts, but as I am not an OTF expert, more testing is
        necessary.

    """

    def __init__(self, tt: ttLib.TTFont):
        self.tt = tt
        self.cmap = tt.getBestCmap()
        self.glyph_set = self.tt.getGlyphSet(preferCFF=True)
        self._glyphs = {}
        self._font_ref = None
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

    def _extract_subset(self, options=None):
        options = options or subset.Options()
        subsetter: subset.Subsetter = subset.Subsetter(options=options)
        gids = map(lambda x: x[1], self._glyphs.values())
        subsetter.populate(gids=list(gids))
        subsetter.subset(self.tt)

    def embed_subset(self, writer: BasePdfFileWriter, obj_stream=None):
        """
        Embed a subset of this glyph accumulator's font into the provided PDF
        writer. Said subset will include all glyphs necessary to render the
        strings provided to the accumulator via :meth:`feed_string`.

        .. danger::
            Due to the way ``fontTools`` handles subsetting, this is a
            destructive operation. The in-memory representation of the original
            font will be overwritten by the generated subset.

        :param writer:
            A PDF writer.
        :param obj_stream:
            If provided, write all relevant objects to the provided
            `obj_stream`. If ``None`` (the default), they will simply be written
            to the file as top-level objects.
        :return:
            A reference to the embedded ``/Font`` object.
        """
        if self._font_ref is not None:
            return self._font_ref
        self._extract_subset()
        cidfont_obj = CIDFontType0(self.tt)
        # TODO keep track of used subset prefixes in the writer!
        cff_topdict = self.tt['CFF '].cff[0]
        name = cidfont_obj.name
        cff_topdict.rawDict['FullName'] = '%s+%s' % (
            generate_subset_prefix(), name
        )
        cidfont_obj.embed(writer, obj_stream=obj_stream)
        cidfont_ref = writer.add_object(cidfont_obj)
        to_unicode = self._format_tounicode_cmap(*cidfont_obj.ros)
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
            if current_chunk:
                yield generic.NumberObject(first_cid)
                yield generic.ArrayObject(current_chunk)

        cidfont_obj[pdf_name('/W')] = generic.ArrayObject(list(_widths()))
        self._font_ref = ref = writer.add_object(type0, obj_stream=obj_stream)
        return ref

    def as_resource(self):
        if self._font_ref is not None:
            return self._font_ref
        else:
            raise ValueError

    def _format_tounicode_cmap(self, registry, ordering, supplement):
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

    def embed(self, writer: BasePdfFileWriter, obj_stream=None):
        fd = self._font_descriptor
        self[pdf_name('/FontDescriptor')] = fd_ref = writer.add_object(
            fd, obj_stream=obj_stream
        )
        font_stream_ref = self.set_font_file(writer)
        return fd_ref, font_stream_ref

    def set_font_file(self, writer: BasePdfFileWriter):
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

    def set_font_file(self, writer: BasePdfFileWriter):
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


@dataclass(frozen=True)
class GlyphAccumulatorFactory:
    """
    Stateless callable helper class to instantiate :class:`.GlyphAccumulator`
    objects.
    """

    font_file: str
    """
    Path to the OTF/TTF font to load.
    """

    def __call__(self) -> GlyphAccumulator:
        return GlyphAccumulator(ttLib.TTFont(self.font_file))
