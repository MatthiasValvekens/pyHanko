import os
from io import BytesIO

import pytest
from freezegun import freeze_time

from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.generic import pdf_name
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.misc import PdfReadError, PdfWriteError
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.writer import PdfFileWriter
from pyhanko.sign import fields, signers
from pyhanko.sign.general import SigningError
from pyhanko_tests.samples import (
    MINIMAL,
    MINIMAL_ONE_FIELD,
    MINIMAL_TWO_FIELDS,
    MINIMAL_TWO_PAGES,
    PDF_DATA_DIR,
    simple_page,
)
from pyhanko_tests.signing_commons import FROM_CA, val_trusted
from pyhanko_tests.test_signing import sign_test_files


def field_with_lock_sp(include_docmdp):
    return fields.SigFieldSpec(
        'SigNew', box=(10, 74, 140, 134),
        field_mdp_spec=fields.FieldMDPSpec(
            fields.FieldMDPAction.INCLUDE, fields=['blah']
        ),
        doc_mdp_update_value=(
            fields.MDPPerm.NO_CHANGES if include_docmdp else None
        )
    )


def test_append_sigfield_second_page():
    buf = BytesIO(MINIMAL_TWO_PAGES)
    w = IncrementalPdfFileWriter(buf)
    fields.append_signature_field(w, fields.SigFieldSpec('Sig1', on_page=1))
    w.write_in_place()

    r = PdfFileReader(buf)

    pg1 = r.root['/Pages']['/Kids'][0]
    assert '/Annots' not in pg1

    pg2 = r.root['/Pages']['/Kids'][1]
    assert '/Annots' in pg2
    assert len(pg2['/Annots']) == 1
    assert pg2['/Annots'][0]['/T'] == 'Sig1'


def test_append_sigfield_ap():
    buf = BytesIO(MINIMAL)
    w = IncrementalPdfFileWriter(buf)
    spec = fields.SigFieldSpec(
        sig_field_name='Sig1', empty_field_appearance=True,
        box=(20, 20, 80, 40)
    )
    fields.append_signature_field(w, sig_field_spec=spec)
    w.write_in_place()

    r = PdfFileReader(buf)

    pg1 = r.root['/Pages']['/Kids'][0]
    assert '/Annots' in pg1
    assert len(pg1['/Annots']) == 1
    annot = pg1['/Annots'][0]
    assert '/AP' in annot
    assert len(annot['/AP']['/N'].data) > 10


def test_append_sigfield_trivial_ap():
    buf = BytesIO(MINIMAL)
    w = IncrementalPdfFileWriter(buf)
    spec = fields.SigFieldSpec(sig_field_name='Sig1', box=(20, 20, 80, 40))
    fields.append_signature_field(w, sig_field_spec=spec)
    w.write_in_place()

    r = PdfFileReader(buf)

    pg1 = r.root['/Pages']['/Kids'][0]
    assert '/Annots' in pg1
    assert len(pg1['/Annots']) == 1
    annot = pg1['/Annots'][0]
    assert '/AP' in annot
    assert annot['/AP']['/N'].data == b''


@pytest.mark.parametrize('include_docmdp', [True, False])
@freeze_time('2020-11-01')
def test_add_sigfield_with_lock(include_docmdp):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    fields.append_signature_field(w, field_with_lock_sp(include_docmdp))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='SigNew'), signer=FROM_CA,
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'SigNew'
    refs = s.sig_object.get_object()['/Reference']
    assert len(refs) == 1
    ref = refs[0]
    assert ref['/TransformMethod'] == '/FieldMDP'
    assert ref['/TransformParams']['/Fields'] == generic.ArrayObject(['blah'])
    assert ref.raw_get('/Data').reference == r.root_ref
    assert '/Perms' not in r.root
    if include_docmdp:
        # test if the Acrobat-compatibility hack was included
        assert ref['/TransformParams']['/P'] == 1
    val_trusted(s)


def test_sign_field_unclear():
    # test error on signing attempt where the signature field to be used
    # is not clear
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))

    with pytest.raises(SigningError):
        signers.sign_pdf(w, signers.PdfSignatureMetadata(), signer=FROM_CA)

    with pytest.raises(SigningError):
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(), signer=FROM_CA,
            existing_fields_only=True
        )

    with pytest.raises(SigningError):
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(field_name='SigExtra'),
            signer=FROM_CA, existing_fields_only=True
        )


async def test_sign_field_unclear_async():
    # test error on signing attempt where the signature field to be used
    # is not clear
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))

    with pytest.raises(SigningError):
        await signers.async_sign_pdf(
            w, signers.PdfSignatureMetadata(), signer=FROM_CA
        )

    with pytest.raises(SigningError):
        await signers.async_sign_pdf(
            w, signers.PdfSignatureMetadata(), signer=FROM_CA,
            existing_fields_only=True
        )

    with pytest.raises(SigningError):
        await signers.async_sign_pdf(
            w, signers.PdfSignatureMetadata(field_name='SigExtra'),
            signer=FROM_CA, existing_fields_only=True
        )


@freeze_time('2020-11-01')
def test_sign_field_infer():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))

    with pytest.raises(SigningError):
        signers.sign_pdf(w, signers.PdfSignatureMetadata(), signer=FROM_CA)

    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(), signer=FROM_CA,
        existing_fields_only=True
    )

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted(s)

    w = IncrementalPdfFileWriter(out)

    # shouldn't work now since all fields are taken
    with pytest.raises(SigningError):
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(), signer=FROM_CA,
            existing_fields_only=True
        )


@freeze_time('2020-11-01')
def test_sign_field_filled():
    w1 = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))

    out1 = signers.sign_pdf(
        w1, signers.PdfSignatureMetadata(field_name='Sig1'), signer=FROM_CA,
        existing_fields_only=True
    )

    # can't sign the same field twice
    w2 = IncrementalPdfFileWriter(out1)
    with pytest.raises(SigningError):
        signers.sign_pdf(
            w2, signers.PdfSignatureMetadata(field_name='Sig1'), signer=FROM_CA,
            existing_fields_only=True
        )
    out1.seek(0)

    def val2(out_buf):
        r = PdfFileReader(out_buf)
        s = r.embedded_signatures[0]
        assert s.field_name == 'Sig1'
        val_trusted(s, extd=True)

        s = r.embedded_signatures[1]
        assert s.field_name == 'Sig2'
        val_trusted(s)

    w2 = IncrementalPdfFileWriter(out1)
    # autodetect remaining open field
    out2 = signers.sign_pdf(
        w2, signers.PdfSignatureMetadata(), signer=FROM_CA,
        existing_fields_only=True
    )
    val2(out2)

    out1.seek(0)
    w2 = IncrementalPdfFileWriter(out1)
    out2 = signers.sign_pdf(
        w2, signers.PdfSignatureMetadata(field_name='Sig2'), signer=FROM_CA,
        existing_fields_only=True
    )
    val2(out2)


@pytest.mark.parametrize('file', [0, 1])
@freeze_time('2020-11-01')
def test_sign_new(file):
    w = IncrementalPdfFileWriter(BytesIO(sign_test_files[file]))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='SigNew'), signer=FROM_CA,
    )
    r = PdfFileReader(out)
    e = r.embedded_signatures[0]
    assert e.field_name == 'SigNew'
    val_trusted(e)


@freeze_time('2020-11-01')
def test_sign_with_indir_annots():
    with open(PDF_DATA_DIR + '/minimal-one-field-indir-annots.pdf', 'rb') as f:
        w = IncrementalPdfFileWriter(f)
        out = signers.sign_pdf(
            w, signers.PdfSignatureMetadata(field_name='SigNew'), signer=FROM_CA
        )
        r = PdfFileReader(out)
        e = r.embedded_signatures[0]
        assert e.field_name == 'SigNew'
        val_trusted(e)

        annots_ref = r.root['/Pages']['/Kids'][0].raw_get('/Annots')
        assert isinstance(annots_ref, generic.IndirectObject)
        assert len(annots_ref.get_object()) == 2


@freeze_time('2020-11-01')
def test_double_sign_lock_second():
    # test if the difference analysis correctly processes /Reference
    # on a newly added signature object

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    fields.append_signature_field(w, field_with_lock_sp(True))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='SigFirst'), signer=FROM_CA,
    )
    w = IncrementalPdfFileWriter(out)

    # now sign the locked field
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='SigNew'), signer=FROM_CA,
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    val_trusted(s, extd=True)

    s = r.embedded_signatures[1]
    assert len(s.sig_object.get_object()['/Reference']) == 1

    val_trusted(s)


@pytest.mark.parametrize('file', [0, 1])
def test_sign_new_existingonly(file):
    w = IncrementalPdfFileWriter(BytesIO(sign_test_files[file]))
    with pytest.raises(SigningError):
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(field_name='SigNew'),
            signer=FROM_CA, existing_fields_only=True
        )


@pytest.mark.parametrize('file', [0, 1])
async def test_async_sign_new_existingonly(file):
    w = IncrementalPdfFileWriter(BytesIO(sign_test_files[file]))
    with pytest.raises(SigningError):
        await signers.async_sign_pdf(
            w, signers.PdfSignatureMetadata(field_name='SigNew'),
            signer=FROM_CA, existing_fields_only=True
        )


def test_sign_with_new_field_spec():

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    spec = fields.SigFieldSpec(sig_field_name='Sig1', box=(20, 20, 80, 40))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1'), signer=FROM_CA,
        new_field_spec=spec
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    assert '/AP' in s.sig_field

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    spec = fields.SigFieldSpec(sig_field_name='Sig1', box=(20, 20, 80, 40))

    with pytest.raises(SigningError):
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(field_name='Sig2'), signer=FROM_CA,
            new_field_spec=spec
        )

    with pytest.raises(SigningError):
        signers.sign_pdf(
            w, signers.PdfSignatureMetadata(field_name='Sig1'), signer=FROM_CA,
            new_field_spec=spec, existing_fields_only=True
        )


def test_append_simple_sig_field():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))

    sp = fields.SigFieldSpec('InvisibleSig')
    fields.append_signature_field(w, sp)
    assert len(w.root['/AcroForm']['/Fields']) == 1
    out = BytesIO()
    w.write(out)
    out.seek(0)
    w = IncrementalPdfFileWriter(out)
    with pytest.raises(PdfWriteError):
        fields.append_signature_field(w, sp)

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))
    fields.append_signature_field(w, sp)
    assert len(w.root['/AcroForm']['/Fields']) == 3


def test_append_visible_sig_field():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))

    sp = fields.SigFieldSpec(
        'VisibleSig', box=(10, 0, 50, 8)
    )
    fields.append_signature_field(w, sp)
    assert len(w.root['/AcroForm']['/Fields']) == 1
    out = BytesIO()
    w.write(out)
    out.seek(0)
    w = IncrementalPdfFileWriter(out)
    with pytest.raises(PdfWriteError):
        fields.append_signature_field(w, sp)

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))
    fields.append_signature_field(w, sp)
    assert len(w.root['/AcroForm']['/Fields']) == 3


def test_append_sig_field_acro_update():
    # test different configurations of the AcroForm
    w = PdfFileWriter()
    w.root['/AcroForm'] = generic.DictionaryObject({
        pdf_name('/Fields'): generic.ArrayObject()
    })
    w.insert_page(simple_page(w, 'Hello world'))
    out = BytesIO()
    w.write(out)
    out.seek(0)

    sp = fields.SigFieldSpec('InvisibleSig')
    w = IncrementalPdfFileWriter(out)
    fields.append_signature_field(w, sp)
    assert len(w.root['/AcroForm']['/Fields']) == 1

    w = PdfFileWriter()
    # Technically, this is not standards-compliant, but our routine
    # shouldn't care
    w.root['/AcroForm'] = generic.DictionaryObject()
    w.insert_page(simple_page(w, 'Hello world'))
    out = BytesIO()
    w.write(out)
    out.seek(0)

    sp = fields.SigFieldSpec('InvisibleSig')
    w = IncrementalPdfFileWriter(out)
    with pytest.raises(ValueError):
        fields.append_signature_field(w, sp)


def test_circular_form_tree_sign():
    fname = os.path.join(PDF_DATA_DIR, 'form-tree-circular-ref-input.pdf')
    with open(fname, 'rb') as inf:
        w = IncrementalPdfFileWriter(inf)
        out = signers.sign_pdf(
            w, signature_meta=signers.PdfSignatureMetadata(
                field_name='Sig'
            ), signer=FROM_CA
        )
    r = PdfFileReader(out)
    with pytest.raises(PdfReadError, match='Circular.*form tree'):
        list(r.embedded_signatures)


def test_circular_form_tree_sign_deep():
    fname = os.path.join(PDF_DATA_DIR, 'form-tree-circular-ref-input.pdf')
    with open(fname, 'rb') as inf:
        w = IncrementalPdfFileWriter(inf)
        with pytest.raises(PdfReadError, match='Circular.*form tree'):
            signers.sign_pdf(
                w, signature_meta=signers.PdfSignatureMetadata(
                    field_name='TextInput.Sig'
                ), signer=FROM_CA
            )
