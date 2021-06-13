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
from binascii import hexlify

from pyhanko.pdf_utils import generic
from fontTools import ttLib, subset

from pyhanko.pdf_utils.misc import peek

import uharfbuzz as hb

from pyhanko.pdf_utils.writer import BasePdfFileWriter


__all__ = [
    'FontEngine', 'SimpleFontEngine', 'GlyphAccumulator',
    'GlyphAccumulatorFactory', 'ShapeResult'
]

# TODO: the holy grail would be to integrate PDF font resource management
#  and rendering with a battle-tested text layout engine like Pango.
#  Not sure how easy that is, though.


logger = logging.getLogger(__name__)

pdf_name = generic.NameObject
pdf_string = generic.pdf_string
ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'


@dataclass(frozen=True)
class ShapeResult:
    """Result of shaping a Unicode string."""
    graphics_ops: bytes
    """
    PDF graphics operators to render the glyphs.
    """

    x_advance: float
    """Total horizontal advance in em units."""

    y_advance: float
    """Total vertical advance in em units."""


def generate_subset_prefix():
    import random
    return ''.join(ALPHABET[random.randint(0, 25)] for _ in range(6))


def _format_simple_glyphline_from_buffer(buf, cid_width_callback):

    def _emit_subsegment():
        nonlocal subsgmt_cids
        current_tj_segments.append(
            f"<{''.join('%04x' % cid for cid in subsgmt_cids)}>"
        )
        subsgmt_cids = []
        if tj_adjust:
            current_tj_segments.append(str(tj_adjust))

    total_len = 0
    info: hb.GlyphInfo
    pos: hb.GlyphPosition
    subsgmt_cids = []
    tj_adjust = 0
    current_tj_segments = []

    # Horizontal text with horizontal kerning
    for info, pos in zip(buf.glyph_infos, buf.glyph_positions):
        # the TJ operator is weird like that, we have to know both
        # the glyph length and the advance reported by Harfbuzz
        current_cid, width = cid_width_callback(info.codepoint)

        # make sure the current x_offset is included in tj_adjust
        # before the current CID can be emitted
        # Note: sign convention for offsets is opposite in HarfBuzz and in
        #  PDF, hence the minus sign
        tj_adjust -= pos.x_offset
        if tj_adjust:
            # if tj_adjust is nonzero, emit a new subsegment,
            # and put in the adjustment
            _emit_subsegment()
        subsgmt_cids.append(current_cid)
        # reset tj_adjust for the next iteration
        #  (the x_offset shouldn't affect the current glyphline position,
        #  hence why we add it back)
        tj_adjust = width - pos.x_advance + pos.x_offset
        total_len += pos.x_advance

    if subsgmt_cids:
        _emit_subsegment()
    return f'[{" ".join(current_tj_segments)}] TJ'.encode('ascii'), total_len


def _format_cid_glyphline_from_buffer(buf, cid_width_callback,
                                      units_per_em, font_size,
                                      vertical):
    no_complex_positioning = not vertical and all(
        not pos.y_offset for pos in buf.glyph_positions
    )

    def _glyph_to_user(num):
        return (num / units_per_em) * font_size

    # simple case where we can do it in one TJ
    if no_complex_positioning:
        ops, total_len = \
            _format_simple_glyphline_from_buffer(buf, cid_width_callback)

        # do a Td to put the newline cursor at the end of our output,
        # for compatibility with the complex positioning layout code
        text_ops = b'%s %g 0 Td' % (
            ops, _glyph_to_user(total_len)
        )
        return text_ops, (total_len, 0)

    info: hb.GlyphInfo
    pos: hb.GlyphPosition
    commands = []

    # use manual Td's and Tj's to position glyphs
    # This routine assumes that the current Td "origin" coincides
    # with the current cursor position.
    total_x_len = 0
    total_y_len = 0
    x_pos = 0
    y_pos = 0
    for info, pos in zip(buf.glyph_infos, buf.glyph_positions):
        current_cid, _ = cid_width_callback(info.codepoint)

        x_pos += pos.x_offset
        y_pos += pos.y_offset

        # position cursor
        if x_pos or y_pos:
            # this also updates the line matrix so the next Td will be in
            # coordinates relative to this point
            commands.append(
                b'%g %g Td' % (_glyph_to_user(x_pos), _glyph_to_user(y_pos))
            )

        # emit one character
        commands.append(f'<{current_cid:04x}> Tj'.encode('ascii'))

        # note: we don't care about the width & auto-advance in PDF-land,
        # just compute everything using positioning data from HarfBuzz

        # have to compensate for x_offset / y_offset
        # since it's all relative to the origin of the current glyph
        x_pos = pos.x_advance - pos.x_offset
        y_pos = pos.y_advance - pos.y_offset

        total_x_len += pos.x_advance
        total_y_len += pos.y_advance

    # do a final Td to put the newline cursor at the end of our output
    if x_pos or y_pos:
        commands.append(
            b'%g %g Td' % (_glyph_to_user(x_pos), _glyph_to_user(y_pos))
        )

    return b' '.join(commands), (total_x_len, total_y_len)


def _gids_by_cluster(buf):
    # assumes that the first cluster is 0

    cur_cluster = 0
    cur_cluster_glyphs = []
    gi: hb.GlyphInfo
    for gi in buf.glyph_infos:
        if gi.cluster != cur_cluster:
            yield cur_cluster, gi.cluster, cur_cluster_glyphs
            cur_cluster_glyphs = []
            cur_cluster = gi.cluster
        cur_cluster_glyphs.append(gi.codepoint)

    yield cur_cluster, None, cur_cluster_glyphs


def _build_type0_font_from_cidfont(writer, cidfont_obj: 'CIDFont',
                                   widths_by_cid_iter,
                                   vertical, obj_stream=None):

    # take the Identity-* encoding to inherit from the /Encoding
    # entry specified in our CIDSystemInfo dict
    encoding = 'Identity-V' if vertical else 'Identity-H'

    cidfont_obj.embed(writer, obj_stream=obj_stream)
    cidfont_ref = writer.add_object(cidfont_obj)
    type0 = generic.DictionaryObject({
        pdf_name('/Type'): pdf_name('/Font'),
        pdf_name('/Subtype'): pdf_name('/Type0'),
        pdf_name('/DescendantFonts'): generic.ArrayObject([cidfont_ref]),
        pdf_name('/Encoding'): pdf_name('/' + encoding),
        pdf_name('/BaseFont'): pdf_name(f'/{cidfont_obj.name}-{encoding}'),
    })
    # compute widths entry

    def _widths():
        current_chunk = []
        prev_cid = None
        (first_cid, _), itr = peek(widths_by_cid_iter)
        for cid, width in itr:
            if current_chunk and cid != prev_cid + 1:
                yield generic.NumberObject(first_cid)
                yield generic.ArrayObject(current_chunk)
                current_chunk = []
                first_cid = cid

            current_chunk.append(generic.NumberObject(width))
            prev_cid = cid
        if current_chunk:
            yield generic.NumberObject(first_cid)
            yield generic.ArrayObject(current_chunk)

    cidfont_obj[pdf_name('/W')] = generic.ArrayObject(list(_widths()))
    return type0


def _breakdown_cmap(mappings):
    # group contiguous mappings in a cmap

    sorted_pairs = iter(sorted(mappings, key=lambda t: t[0]))

    # use the first item of the iterator to initialise the state
    source, target = next(sorted_pairs)
    cur_segment_start = prev = source
    cur_segment = [target]

    for source, target in sorted_pairs:
        # max segment length is 100
        if not cur_segment or source == prev + 1:
            # extend current segment
            cur_segment.append(target)
        else:
            # emit previous segment, and start a new one
            yield cur_segment_start, cur_segment
            cur_segment = [target]
            cur_segment_start = source
        prev = source

    if cur_segment:
        yield cur_segment_start, cur_segment


def _segment_cmap(mappings):
    current_heading = 'char'
    decls = []

    def _emit():
        yield f'{len(decls)} beginbf{current_heading}'
        use_bfrange = current_heading == 'range'
        for source_start, targets in decls:
            if use_bfrange:
                source_end = source_start + len(targets) - 1
                # TODO use short form for bfrange targets if they're all
                #  contiguous
                target_values = ' '.join(
                    f'<{hexlify(target).decode("ascii")}>'
                    for target in targets
                )
                yield (
                    f'<{source_start:04x}> <{source_end:04x}> [{target_values}]'
                )
            else:
                target = targets[0]
                yield (
                    f'<{source_start:04x}> <{hexlify(target).decode("ascii")}>'
                )
        yield f'endbf{current_heading}'

    for pair in _breakdown_cmap(mappings):
        current_type = 'char' if len(pair[1]) == 1 else 'range'
        if (decls and current_heading != current_type) or len(decls) >= 100:
            yield from _emit()
            decls = []
        current_heading = current_type
        decls.append(pair)

    if decls:
        yield from _emit()


class FontEngine:
    """General interface for text shaping and font metrics."""

    @property
    def uses_complex_positioning(self):
        """
        If ``True``, this font engine expects the line matrix to always be equal
        to the text matrix when exiting and entering :meth:`shape`.
        In other words, the current text position is where ``0 0 Td`` would
        move to.

        If ``False``, this method does not use any text positioning operators,
        and therefore uses the PDF standard's 'natural' positioning rules
        for text showing operators.

        The default is ``True`` unless overridden.
        """
        return True

    def shape(self, txt: str) -> ShapeResult:
        """Render a string to a format suitable for inclusion in a content
        stream and measure its total cursor advancement vector in em units.

        :param txt:
            String to shape.
        :return:
            A shaping result.
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

    @property
    def uses_complex_positioning(self):
        return False

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

    def shape(self, txt) -> ShapeResult:
        ops = f'({txt}) Tj'.encode('latin1')
        total_len = len(txt) * self.avg_width

        return ShapeResult(
            graphics_ops=ops, x_advance=total_len,
            y_advance=0
        )

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


def _check_ot_tag(tag):
    if tag is None:
        return
    if len(tag) != 4:
        raise ValueError("OpenType tags must be 4 bytes long")
    try:
        tag.encode('ascii')
    except UnicodeEncodeError as e:
        raise ValueError("OpenType tags must be ASCII-encodable") from e
    return tag


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

    :param font_handle:
        File-like object
    :param font_size:
        Font size in pt units.
        .. note::
            This is only relevant for some positioning intricacies (or hacks,
            depending on your perspective) that may not matter for your use
            case.
    :param features:
        Features to use. If ``None``, use HarfBuzz defaults.
    :param ot_script_tag:
        OpenType script tag to use. Will be guessed by HarfBuzz if not
        specified.
    :param ot_language_tag:
        OpenType language tag to use. Defaults to the default language system
        for the current script.
    :param writing_direction:
        Writing direction, one of 'ltr', 'rtl', 'ttb' or 'btt'.
        Will be guessed by HarfBuzz if not specified.
    :param bcp47_lang_code:
        BCP 47 language code. Used to mark the text's language in the PDF
        content stream, if specified.
    """

    def __init__(self, font_handle, font_size, features=None,
                 ot_language_tag=None, ot_script_tag=None,
                 writing_direction=None, bcp47_lang_code=None):
        # harfbuzz expects bytes
        font_handle.seek(0)
        font_bytes = font_handle.read()
        font_handle.seek(0)
        face = hb.Face(font_bytes)
        self.font_size = font_size
        self.hb_font = hb.Font(face)
        self.tt = tt = ttLib.TTFont(font_handle)
        try:
            cff = self.tt['CFF ']
            self.cff_charset = cff.cff[0].charset

            # CFF font programs are embedded differently
            #  (in a more Adobe-native way)
            self.is_cff_font = True
        except KeyError:
            self.cff_charset = None
            self.is_cff_font = False

        self.features = features

        try:
            self.units_per_em = tt['head'].unitsPerEm
        except KeyError:
            self.units_per_em = 1000

        self._glyphs = {}
        self._font_ref = None
        self._glyph_set = tt.getGlyphSet(preferCFF=True)

        self._cid_to_unicode = {}
        self.__reverse_cmap = None
        self.ot_language_tag = _check_ot_tag(ot_language_tag)
        self.ot_script_tag = _check_ot_tag(ot_script_tag)
        if writing_direction is not None and \
                writing_direction not in ('ltr', 'rtl', 'ttb', 'btt'):
            raise ValueError(
                "Writing direction must be one of 'ltr', 'rtl', 'ttb' or 'btt'."
            )
        self.writing_direction = writing_direction
        self.bcp47_lang_code = bcp47_lang_code

    @property
    def _reverse_cmap(self):
        if self.__reverse_cmap is None:
            self.__reverse_cmap = self.tt['cmap'].buildReversed()
        return self.__reverse_cmap

    def _get_cid_and_width(self, glyph_id):
        try:
            return self._glyphs[glyph_id]
        except KeyError:
            pass

        if self.is_cff_font:
            cid_str = self.cff_charset[glyph_id]
            current_cid = int(cid_str[3:])
            glyph = self._glyph_set.get(cid_str)
        else:
            # current_cid = glyph_id in the Type2 case
            # (for our subsetting setup)
            current_cid = glyph_id
            glyph_name = self.tt.getGlyphName(glyph_id)
            glyph = self._glyph_set.get(glyph_name)
        self._glyphs[glyph_id] = result = current_cid, glyph.width
        return result

    def marked_content_property_list(self, txt) -> generic.DictionaryObject:
        result = generic.DictionaryObject({
            pdf_name('/ActualText'): generic.TextStringObject(txt)
        })
        if self.bcp47_lang_code is not None:
            result['/Lang'] = pdf_string(self.bcp47_lang_code)
        return result

    def shape(self, txt: str) -> ShapeResult:
        buf = hb.Buffer()
        buf.add_str(txt)

        if self.ot_script_tag is not None:
            buf.set_script_from_ot_tag(self.ot_script_tag)
        if self.ot_language_tag is not None:
            buf.set_language_from_ot_tag(self.ot_language_tag)
        if self.writing_direction is not None:
            buf.direction = self.writing_direction

        # guess any remaining unset segment properties
        buf.guess_segment_properties()

        hb.shape(self.hb_font, buf, self.features)

        vertical = buf.direction in ('ttb', 'btt')
        text_ops, (total_x, total_y) = _format_cid_glyphline_from_buffer(
            buf, cid_width_callback=self._get_cid_and_width,
            units_per_em=self.units_per_em, font_size=self.font_size,
            vertical=vertical
        )

        # the original buffer's cluster values are just character indexes
        # so calculating cluster extents is not hard
        # We'll use that information to put together a ToUnicode CMap
        for cluster, next_cluster, glyph_ids in _gids_by_cluster(buf):
            # CMaps need individual CIDs, so we cannot deal with multi-glyph
            # clusters (e.g. g̈, which is g + a combining diaeresis, so two
            # unicode code points --- and often represented as two separate
            # glyphs in a font)
            # https://www.unicode.org/reports/tr29/#Grapheme_Cluster_Boundaries
            #  TODO figure out how much of a limitation that is in practice.
            #   And if so, think about other ways to handle ToUnicode
            #  TODO things like diacritic stacks can be solved by individual
            #   'cmap' table lookups, as a fallback
            if next_cluster is None:
                unicode_str = txt[cluster:]
            else:
                unicode_str = txt[cluster:next_cluster]
            if len(glyph_ids) == 1:
                gid = glyph_ids[0]
                if gid == 0:
                    continue
                cid, _ = self._get_cid_and_width(gid)
                self._cid_to_unicode[cid] = unicode_str
            else:
                # fallback for many-to-many clusters: try to look up the glyphs
                # one by one
                relevant_codepoints = frozenset(ord(x) for x in unicode_str)
                for gid in glyph_ids:
                    if gid == 0:
                        continue
                    cid, _ = self._get_cid_and_width(gid)
                    glyph_name = self.tt.getGlyphName(gid)
                    # since this is a fallback, we don't allow clobbering
                    # of existing values
                    if cid not in self._cid_to_unicode:
                        codepoints = self._reverse_cmap.get(glyph_name, ())
                        for codepoint in codepoints:
                            # only allow unicode codepoints that actually occur
                            # in the substring
                            if codepoint in relevant_codepoints:
                                self._cid_to_unicode[cid] = chr(codepoint)

        # wrap the text rendering operations in a
        marked_content_buf = BytesIO()
        marked_content_buf.write(b'/Span ')
        mc_properties = self.marked_content_property_list(txt)
        mc_properties.write_to_stream(marked_content_buf)
        marked_content_buf.write(b' BDC ')
        marked_content_buf.write(text_ops)
        marked_content_buf.write(b' EMC')

        marked_content_buf.seek(0)

        return ShapeResult(
            graphics_ops=marked_content_buf.read(),
            x_advance=total_x / self.units_per_em,
            y_advance=total_y / self.units_per_em
        )

    def _format_tounicode_cmap(self, registry, ordering, supplement):
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
        to_segment = (
            (cid, codepoints.encode('utf-16be'))
            for cid, codepoints in self._cid_to_unicode.items()
        )
        body = '\n'.join(_segment_cmap(to_segment))

        footer = (
            '\nendcmap\n'
            'CMapName currentdict /CMap\n'
            'defineresource pop\n'
            'end\nend'
        )
        stream = generic.StreamObject(
            stream_data=(header + body + footer).encode('ascii')
        )
        return stream

    def _extract_subset(self, options=None):
        options = options or subset.Options()
        if not self.is_cff_font:
            # Have to retain GIDs in the Type2 (non-CFF) case, since we don't
            # have a predefined character set available (i.e. the ROS ordering
            # param is 'Identity')
            # This ensures that the PDF operators we output will keep working
            # with the subsetted font, at the cost of a slight space overhead in
            # the output.
            # This is fine, because fonts with a number of glyphs where this
            # would matter (i.e. large CJK fonts, basically), are subsetted as
            # CFF fonts anyway (and based on a predetermined charset),
            # so this subtlety doesn't apply and the space overhead is very
            # small.
            options.retain_gids = True

        subsetter: subset.Subsetter = subset.Subsetter(options=options)
        subsetter.populate(gids=list(self._glyphs.keys()))
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
        if self.is_cff_font:
            cidfont_obj = CIDFontType0(self.tt)
        else:
            cidfont_obj = CIDFontType2(self.tt)
        # TODO keep track of used subset prefixes in the writer!

        by_cid = iter(sorted(self._glyphs.values(), key=lambda t: t[0]))
        type0 = _build_type0_font_from_cidfont(
            writer=writer, cidfont_obj=cidfont_obj,
            widths_by_cid_iter=by_cid, obj_stream=obj_stream,
            vertical=False
        )
        type0['/ToUnicode'] = writer.add_object(
            self._format_tounicode_cmap(*cidfont_obj.ros)
        )
        self._font_ref = ref = writer.add_object(type0, obj_stream=obj_stream)
        return ref

    def as_resource(self):
        if self._font_ref is not None:
            return self._font_ref
        else:
            raise ValueError


class CIDFont(generic.DictionaryObject):
    def __init__(self, tt: ttLib.TTFont, subtype, registry,
                 ordering, supplement, ps_name=None):

        self.subset_prefix = subset_prefix = generate_subset_prefix()

        if ps_name is None:
            try:
                name_table = tt['name']
                # extract PostScript name from the font's name table
                nr = next(nr for nr in name_table.names if nr.nameID == 6)
                if nr.encodingIsUnicodeCompatible():
                    ps_name = nr.string.decode('utf-16be')
            except StopIteration:
                ps_name = None

        if ps_name is None:
            raise NotImplementedError(
                "Could not read PostScript name for font"
            )

        ps_name = '%s+%s' % (subset_prefix, ps_name)

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


class CIDFontType0(CIDFont):
    def __init__(self, tt: ttLib.TTFont, ps_name=None):
        # We assume that this font set (in the CFF sense) contains
        # only one font. This is fairly safe according to the fontTools docs.
        self.cff = cff = tt['CFF '].cff
        td = cff[0]
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
            tt, '/CIDFontType0', registry, ordering, supplement,
            ps_name=ps_name
        )
        td.rawDict['FullName'] = '%s+%s' % (self.subset_prefix, self.name)

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


class CIDFontType2(CIDFont):

    def __init__(self, tt: ttLib.TTFont, ps_name=None):
        super().__init__(
            tt, '/CIDFontType0',
            registry="Adobe",
            # i.e. "no defined character set, just do whatever"
            # This makes sense because there's no native notion of character
            # sets in OTF/TTF fonts without a CFF font program.
            # (since we also put CIDToGIDMap = /Identity, this effectively means
            # that CIDs correspond to GIDs in the font)
            ordering="Identity",
            supplement=0,
            ps_name=ps_name
        )
        self['/CIDToGIDMap'] = pdf_name('/Identity')

    def set_font_file(self, writer: BasePdfFileWriter):
        stream_buf = BytesIO()
        self.tt.save(stream_buf)
        stream_buf.seek(0)

        font_stream = generic.StreamObject({
            # this is a Type2 TTF font program
            pdf_name('/Subtype'): pdf_name('/CIDFontType2'),
        }, stream_data=stream_buf.read())
        font_stream.compress()
        font_stream_ref = writer.add_object(font_stream)
        self._font_descriptor[pdf_name('/FontFile2')] = font_stream_ref
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

    def as_resource(self) -> generic.DictionaryObject:
        pass


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

    font_size: int = 10
    """
    Font size.
    """

    ot_script_tag: str = None
    """
    OpenType script tag to use. Will be guessed by HarfBuzz if not
    specified.
    """

    ot_language_tag: str = None
    """
    OpenType language tag to use. Defaults to the default language system
    for the current script.
    """

    writing_direction: str = None
    """
    Writing direction, one of 'ltr', 'rtl', 'ttb' or 'btt'.
    Will be guessed by HarfBuzz if not specified.
    """

    def __call__(self) -> GlyphAccumulator:
        fh = open(self.font_file, 'rb')
        return GlyphAccumulator(
            fh, font_size=self.font_size, ot_script_tag=self.ot_script_tag,
            ot_language_tag=self.ot_language_tag,
            writing_direction=self.writing_direction
        )
