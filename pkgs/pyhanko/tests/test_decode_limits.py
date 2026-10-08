import binascii
import zlib
from io import BytesIO

import pytest
from freezegun import freeze_time
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.decode_limits import (
    DEFAULT_PURPOSE_LIMITS,
    DecodeContext,
    DecodeLimits,
    DecodePurpose,
    DocumentDecodeBudget,
    StreamDecodeLimits,
)
from pyhanko.pdf_utils.filters import ASCIIHexDecode, FlateDecode
from pyhanko.pdf_utils.generic import pdf_name
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.metadata.xmp_xml import MetadataStream
from pyhanko.pdf_utils.misc import PdfDecodeLimitError, PdfReadError
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import PdfFileWriter
from pyhanko.pdf_utils.xref import _expected_xref_stream_size, parse_xref_stream
from pyhanko.sign import PdfTimeStamper, fields, signers
from pyhanko.sign.signers.pdf_signer import (
    DSSContentSettings,
    SigDSSPlacementPreference,
)
from pyhanko.sign.validation.dss import DocumentSecurityStore
from pyhanko_testing_commons.test_data.samples import (
    TESTING_CA,
    minimal_with_oversized_objstm,
)
from pyhanko_testing_commons.test_utils.signing_commons import (
    DUMMY_TS,
    FROM_CA,
    live_testing_vc,
)

MiB = 1024 * 1024
TRUSTED = DecodeLimits.for_trusted_input()
UNLIMITED_STREAM = StreamDecodeLimits(max_ratio=None, max_output_size=None)

EMPTY_XMP = (
    b'<x:xmpmeta xmlns:x="adobe:ns:meta/">'
    b'<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
    b'</rdf:RDF></x:xmpmeta>'
)


def make_stream(
    encoded: bytes, filters: list[str], extra: dict | None = None
) -> generic.StreamObject:
    return generic.StreamObject(
        {
            pdf_name('/Filter'): generic.ArrayObject(
                pdf_name(f) for f in filters
            ),
            **(extra or {}),
        },
        encoded_data=encoded,
    )


def write(w: PdfFileWriter) -> BytesIO:
    out = BytesIO()
    w.write(out)
    out.seek(0)
    return out


def pdf_with_streams(*streams: generic.StreamObject) -> tuple[BytesIO, list]:
    w = PdfFileWriter()
    idnums = [w.add_object(stm).idnum for stm in streams]
    return write(w), idnums


def flate_pdf(payload: bytes) -> tuple[BytesIO, int]:
    out, (idnum,) = pdf_with_streams(
        make_stream(zlib.compress(payload), ['/FlateDecode'])
    )
    return out, idnum


def get_object(r, idnum: int):
    return r.get_object(generic.Reference(idnum, 0, r))


def tiny_limit(purpose: DecodePurpose) -> DecodeLimits:
    return DecodeLimits(
        per_purpose={
            purpose: StreamDecodeLimits(max_ratio=None, max_output_size=10)
        }
    )


def budget_limits(base_allowance: int) -> DecodeLimits:
    return DecodeLimits(
        document_budget=DocumentDecodeBudget(
            base_allowance=base_allowance, max_ratio=0
        )
    )


@pytest.fixture(scope='module')
def stacked_bomb() -> bytes:
    return zlib.compress(zlib.compress(bytes(50 * MiB), 9), 9)


@pytest.fixture(scope='module')
def oversized_pdf() -> bytes:
    out = BytesIO()
    minimal_with_oversized_objstm().write(out)
    return out.getvalue()


# Computing limits


@pytest.mark.parametrize(
    'limits,encoded_size,expected',
    [
        (StreamDecodeLimits(), 10, MiB),
        (StreamDecodeLimits(), 100_000, 110_000_000),
        (StreamDecodeLimits(max_output_size=5 * MiB), 10 * MiB, 5 * MiB),
        (StreamDecodeLimits(max_ratio=None), 10, 256 * MiB),
        (StreamDecodeLimits(max_output_size=None), 10, MiB),
        (UNLIMITED_STREAM, 10, None),
    ],
    ids=['floor', 'ratio', 'max-output', 'no-ratio', 'no-max-output', 'none'],
)
def test_output_cap(limits, encoded_size, expected):
    assert limits.output_cap(encoded_size) == expected


@pytest.mark.parametrize(
    'limits,kwargs,expected',
    [
        (DecodeLimits(), {'purpose': DecodePurpose.CERTIFICATE}, MiB),
        (DecodeLimits(), {'purpose': DecodePurpose.OCSP_RESPONSE}, 4 * MiB),
        (DecodeLimits(), {'purpose': DecodePurpose.OBJECT_STREAM}, 64 * MiB),
        (DecodeLimits(), {'purpose': DecodePurpose.CRL}, 50_000_000),
        (DecodeLimits(), {'purpose': DecodePurpose.GENERIC}, 256 * MiB),
        (DecodeLimits(), {'purpose': DecodePurpose.XREF_STREAM}, 256 * MiB),
        (DecodeLimits.for_untrusted_input(), {'expected_size': 100}, 4196),
        (DecodeLimits(), {'expected_size': -50}, 4096),
        (TRUSTED, {'expected_size': 100}, None),
        (
            DecodeLimits(
                per_stream=StreamDecodeLimits(
                    max_ratio=None, max_output_size=1000
                ),
                per_purpose={DecodePurpose.CERTIFICATE: UNLIMITED_STREAM},
            ),
            {'purpose': DecodePurpose.CERTIFICATE},
            1000,
        ),
    ],
    ids=[
        'certificate',
        'ocsp',
        'objstm',
        'crl',
        'generic',
        'xref',
        'expected-size',
        'negative-expected-size',
        'trusted',
        'purpose-cannot-loosen',
    ],
)
def test_stream_output_cap(limits, kwargs, expected):
    ctx = DecodeContext(limits)
    assert ctx.stream_output_cap(1_000_000, **kwargs) == expected


@pytest.mark.parametrize(
    'budget,size,expected',
    [
        (DocumentDecodeBudget(1000, 10), 5, 1000),
        (DocumentDecodeBudget(1000, 10), 100, 1000),
        (DocumentDecodeBudget(1000, 10), 500, 5000),
        (DocumentDecodeBudget(1000, 0.5), 5001, 2500),
        (DocumentDecodeBudget(), 0, 256 * MiB),
        (DocumentDecodeBudget(), 10 * MiB, 1000 * MiB),
    ],
)
def test_budget_total(budget, size, expected):
    assert budget.total(size) == expected


@pytest.mark.parametrize(
    'limits,input_size',
    [
        (DecodeLimits(), None),
        (DecodeLimits(document_budget=None), 1000),
        (DecodeLimits(document_budget=None), None),
    ],
)
def test_context_without_budget(limits, input_size):
    ctx = DecodeContext(limits, input_size=input_size)
    assert ctx.remaining_budget is None
    assert ctx.stage_output_cap(123) == 123
    assert ctx.stage_output_cap(None) is None
    ctx.record_output(10**9)
    assert ctx.remaining_budget is None


@pytest.mark.parametrize(
    'stream_cap,expected',
    [(None, 1000), (500, 500), (1000, 1000), (5000, 1000)],
)
def test_context_stage_cap(stream_cap, expected):
    ctx = DecodeContext(budget_limits(1000), input_size=10)
    assert ctx.stage_output_cap(stream_cap) == expected


def test_context_record_output():
    ctx = DecodeContext(budget_limits(1000), input_size=10)
    ctx.record_output(300)
    assert ctx.remaining_budget == 700
    assert ctx.stage_output_cap(800) == 700
    assert ctx.stage_output_cap(100) == 100


# Decoders


@pytest.mark.parametrize('size,fails', [(1000, False), (1001, True)])
def test_flate_cap_boundary(size, fails):
    encoded = zlib.compress(bytes(size))
    if fails:
        with pytest.raises(PdfDecodeLimitError, match='limit of 1000 bytes'):
            FlateDecode().decode_bounded(encoded, {}, 1000)
    else:
        assert len(FlateDecode().decode_bounded(encoded, {}, 1000)) == size


@pytest.mark.parametrize('cap', [None, 10 * MiB])
def test_flate_truncated(cap):
    encoded = zlib.compress(bytes(1000))[:-6]
    with pytest.raises(zlib.error):
        FlateDecode().decode_bounded(encoded, {}, cap)


PNG_UP_ROWS = b'\x02\x01\x02\x03\x02\x04\x05\x06'


@pytest.mark.parametrize(
    'params,expected',
    [
        (None, PNG_UP_ROWS),
        ({}, PNG_UP_ROWS),
        ([None], PNG_UP_ROWS),
        ({'/Predictor': 12, '/Columns': 3}, b'\x01\x02\x03\x05\x07\x09'),
    ],
    ids=['none', 'empty', 'not-a-dict', 'png-up'],
)
@pytest.mark.parametrize('cap', [None, MiB])
def test_flate_decode_params(params, expected, cap):
    encoded = zlib.compress(PNG_UP_ROWS)
    assert FlateDecode().decode_bounded(encoded, params, cap) == expected


def test_flate_unsupported_predictor():
    with pytest.raises(NotImplementedError):
        FlateDecode().decode(
            zlib.compress(b'abc'), {'/Predictor': 2, '/Columns': 3}
        )


def test_default_decode_bounded():
    decoder = ASCIIHexDecode()
    encoded = b'48656c6c6f>'
    assert decoder.decode_bounded(encoded, {}, 5) == b'Hello'
    assert decoder.decode_bounded(encoded, {}, None) == b'Hello'
    with pytest.raises(PdfDecodeLimitError):
        decoder.decode_bounded(encoded, {}, 4)


def test_limit_error_is_read_error():
    # existing callers that handle read errors should keep working
    assert issubclass(PdfDecodeLimitError, PdfReadError)


# Per-stream limits on documents


@pytest.mark.parametrize(
    'limits,rejected',
    [(None, True), (TRUSTED, False)],
    ids=['default', 'trusted'],
)
def test_stacked_bomb(stacked_bomb, limits, rejected):
    out, (idnum,) = pdf_with_streams(
        make_stream(stacked_bomb, ['/FlateDecode'] * 2)
    )
    r = PdfFileReader(out, decode_limits=limits)
    if rejected:
        with pytest.raises(PdfDecodeLimitError, match='exceeds the limit'):
            get_object(r, idnum).data
    else:
        assert len(get_object(r, idnum).data) == 50 * MiB
        assert r.decode_context.remaining_budget is None


def test_single_layer_flate_not_rejected():
    size = 20 * MiB
    out, idnum = flate_pdf(bytes(size))
    assert len(get_object(PdfFileReader(out), idnum).data) == size


@pytest.mark.parametrize(
    'container_ref',
    [
        None,
        generic.Reference(1, 0, None),
        generic.Reference(1, 0, PdfFileWriter()),
    ],
    ids=['detached', 'no-handler', 'writer'],
)
def test_default_context_without_reader(stacked_bomb, container_ref):
    stm = make_stream(stacked_bomb, ['/FlateDecode'] * 2)
    stm.container_ref = container_ref
    with pytest.raises(PdfDecodeLimitError):
        stm.data


# Purpose-specific limits

BIG_PAYLOAD = bytes(2 * MiB)


@pytest.mark.parametrize(
    'limits,purpose,rejected',
    [
        (None, DecodePurpose.CERTIFICATE, True),
        (None, DecodePurpose.GENERIC, False),
        (
            DecodeLimits(
                per_purpose={
                    **DEFAULT_PURPOSE_LIMITS,
                    DecodePurpose.CERTIFICATE: UNLIMITED_STREAM,
                }
            ),
            DecodePurpose.CERTIFICATE,
            False,
        ),
    ],
    ids=['certificate', 'generic', 'override'],
)
def test_read_data_purpose(limits, purpose, rejected):
    out, idnum = flate_pdf(BIG_PAYLOAD)
    stm = get_object(PdfFileReader(out, decode_limits=limits), idnum)
    if rejected:
        with pytest.raises(PdfDecodeLimitError):
            stm.read_data(purpose)
    else:
        assert stm.read_data(purpose) == BIG_PAYLOAD


def test_cached_data_ignores_later_stricter_limits():
    out, idnum = flate_pdf(BIG_PAYLOAD)
    stm = get_object(PdfFileReader(out), idnum)
    assert stm.data == BIG_PAYLOAD
    assert stm.read_data(DecodePurpose.CERTIFICATE) == BIG_PAYLOAD


def read_objstm(limits):
    w = PdfFileWriter()
    ref = w.add_object(
        generic.DictionaryObject({pdf_name('/Foo'): generic.NumberObject(7)}),
        obj_stream=w.prepare_object_stream(),
    )
    r = PdfFileReader(write(w), decode_limits=limits)
    assert get_object(r, ref.idnum)['/Foo'] == 7


def read_xmp(limits):
    xmp_type = {
        pdf_name('/Type'): pdf_name('/Metadata'),
        pdf_name('/Subtype'): pdf_name('/XML'),
    }
    out, (idnum,) = pdf_with_streams(
        make_stream(zlib.compress(EMPTY_XMP), ['/FlateDecode'], xmp_type)
    )
    r = PdfFileReader(out, decode_limits=limits)
    stm = r.get_object(generic.Reference(idnum, 0, r), as_metadata_stream=True)
    assert isinstance(stm, MetadataStream)
    assert stm.xmp == []


def read_dss(limits):
    cert_der = TESTING_CA.get_cert('root').dump()
    w = PdfFileWriter()
    cert_ref = w.add_object(
        make_stream(zlib.compress(cert_der), ['/FlateDecode'])
    )
    w.root[pdf_name('/DSS')] = w.add_object(
        generic.DictionaryObject(
            {pdf_name('/Certs'): generic.ArrayObject([cert_ref])}
        )
    )
    r = PdfFileReader(write(w), decode_limits=limits)
    assert len(DocumentSecurityStore.read_dss(r).certs) == 1


@pytest.mark.parametrize(
    'purpose,read',
    [
        (DecodePurpose.OBJECT_STREAM, read_objstm),
        (DecodePurpose.XMP_METADATA, read_xmp),
        (DecodePurpose.CERTIFICATE, read_dss),
    ],
    ids=['objstm', 'xmp', 'dss'],
)
def test_purpose_applied(purpose, read):
    read(None)
    with pytest.raises(PdfDecodeLimitError):
        read(tiny_limit(purpose))


@pytest.mark.parametrize(
    'index,w,expected',
    [
        ([0, 3, 10, 2], [1, 2, 1], 25),
        ([0, None], [1, 2, 1], None),
        ([0, 3, 10], [1, 2, 1], None),
        ([0, 3], None, None),
    ],
)
def test_expected_xref_stream_size(index, w, expected):
    assert _expected_xref_stream_size(index, w) == expected


@pytest.mark.parametrize('padding,fails', [(0, False), (3 * 5 + 4096, True)])
def test_parse_xref_stream_expected_size(padding, fails):
    data = b'\x01\x00\x10\x00' * 3 + bytes(padding)
    stm = make_stream(
        zlib.compress(data),
        ['/FlateDecode'],
        {
            pdf_name('/W'): generic.ArrayObject(
                generic.NumberObject(n) for n in (1, 2, 1)
            ),
            pdf_name('/Size'): generic.NumberObject(3),
        },
    )
    if fails:
        with pytest.raises(PdfDecodeLimitError):
            list(parse_xref_stream(stm))
    else:
        assert len(list(parse_xref_stream(stm))) == 3


# Document budget


def test_budget_exhausted():
    payload = make_stream(zlib.compress(bytes(MiB)), ['/FlateDecode'])
    out, ids = pdf_with_streams(*[payload] * 4)
    r = PdfFileReader(out, decode_limits=budget_limits(3 * MiB + 100))
    start = r.decode_context.remaining_budget
    assert start <= 3 * MiB + 100
    for n, idnum in enumerate(ids[:3], start=1):
        assert len(get_object(r, idnum).data) == MiB
        assert r.decode_context.remaining_budget == start - n * MiB
    with pytest.raises(PdfDecodeLimitError):
        get_object(r, ids[3]).data


def test_budget_redecode_not_charged():
    out, idnum = flate_pdf(bytes(MiB))
    r = PdfFileReader(out, decode_limits=budget_limits(2 * MiB))
    start = r.decode_context.remaining_budget
    assert len(get_object(r, idnum).data) == MiB
    assert len(get_object(r, idnum).data) == MiB
    assert r.decode_context.remaining_budget == start - MiB


def test_budget_charges_every_stage():
    compressed = zlib.compress(bytes(MiB))
    out, (idnum,) = pdf_with_streams(
        make_stream(
            binascii.hexlify(compressed) + b'>',
            ['/ASCIIHexDecode', '/FlateDecode'],
        )
    )
    r = PdfFileReader(out, decode_limits=budget_limits(4 * MiB))
    start = r.decode_context.remaining_budget
    assert get_object(r, idnum).data == bytes(MiB)
    assert r.decode_context.remaining_budget == start - len(compressed) - MiB


def test_budget_fresh_for_historical_revisions():
    old_raw = bytes(MiB)
    new_raw = b'\1' * (2 * MiB)
    out, idnum = flate_pdf(old_raw)
    w = IncrementalPdfFileWriter(out)
    w.objects[(0, idnum)] = make_stream(
        zlib.compress(new_raw), ['/FlateDecode']
    )

    r = PdfFileReader(write(w), decode_limits=budget_limits(10 * MiB))
    start = r.decode_context.remaining_budget
    assert get_object(r, idnum).data == new_raw
    assert r.decode_context.remaining_budget == start - 2 * MiB

    hist = r.get_historical_resolver(0)
    assert hist.decode_context.limits is r.decode_context.limits
    assert hist.decode_context.remaining_budget == 10 * MiB
    old = get_object(hist, idnum)
    assert old.data == old_raw
    assert hist.decode_context.remaining_budget == 9 * MiB
    assert r.decode_context.remaining_budget == start - 2 * MiB


def test_historical_budget_enforced():
    out, idnum = flate_pdf(bytes(2 * MiB))
    w = IncrementalPdfFileWriter(out)
    w.objects[(0, idnum)] = make_stream(b'x', [])

    r = PdfFileReader(write(w), decode_limits=budget_limits(MiB))
    assert get_object(r, idnum).data == b'x'
    hist = r.get_historical_resolver(0)
    assert r.get_historical_resolver(0) is hist
    with pytest.raises(PdfDecodeLimitError):
        get_object(hist, idnum).data


# Limits survive reopening the document after signing


def open_trusted(data: bytes) -> PdfFileReader:
    return PdfFileReader(BytesIO(data), decode_limits=TRUSTED)


def test_oversized_objstm_rejected_by_default(oversized_pdf):
    with pytest.raises(PdfDecodeLimitError):
        PdfFileReader(BytesIO(oversized_pdf)).root


@freeze_time('2020-11-01')
@pytest.mark.parametrize(
    'placement',
    [
        SigDSSPlacementPreference.TOGETHER_WITH_NEXT_TS,
        SigDSSPlacementPreference.SEPARATE_REVISION,
    ],
)
def test_post_sign_reopen_keeps_limits(oversized_pdf, pki_services, placement):
    w = IncrementalPdfFileWriter(BytesIO(oversized_pdf), decode_limits=TRUSTED)
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(
            field_name='Sig1',
            validation_context=live_testing_vc(pki_services),
            subfilter=fields.SigSeedSubFilter.PADES,
            embed_validation_info=True,
            use_pades_lta=True,
            dss_settings=DSSContentSettings(placement=placement),
        ),
        signer=FROM_CA,
        timestamper=DUMMY_TS,
    )
    r = open_trusted(out.getvalue())
    assert len(r.embedded_timestamp_signatures) == 1


@freeze_time('2020-11-01')
def test_archival_timestamp_update_keeps_limits(oversized_pdf, pki_services):
    vc = live_testing_vc(pki_services)
    out = PdfTimeStamper(DUMMY_TS).update_archival_timestamp_chain(
        open_trusted(oversized_pdf), vc, in_place=False
    )
    r = open_trusted(out.getvalue())
    assert len(r.embedded_timestamp_signatures) == 1


def test_add_dss_keeps_limits(oversized_pdf):
    out = BytesIO(oversized_pdf)
    DocumentSecurityStore.add_dss(
        out,
        sig_contents=None,
        certs=(FROM_CA.signing_cert,),
        decode_limits=TRUSTED,
    )
    r = open_trusted(out.getvalue())
    assert DocumentSecurityStore.read_dss(r).certs
