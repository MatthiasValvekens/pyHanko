import os
from datetime import datetime
from io import BytesIO
from itertools import product

import pytest
import pytz
from freezegun.api import freeze_time

from pyhanko.pdf_utils import generic, misc
from pyhanko.pdf_utils.content import RawContent
from pyhanko.pdf_utils.generic import pdf_name
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.layout import BoxConstraints
from pyhanko.pdf_utils.reader import (
    HistoricalResolver,
    PdfFileReader,
    RawPdfPath,
)
from pyhanko.pdf_utils.writer import copy_into_new_writer
from pyhanko.sign import PdfTimeStamper, fields, signers
from pyhanko.sign.diff_analysis import (
    DEFAULT_DIFF_POLICY,
    NO_CHANGES_DIFF_POLICY,
    ModificationLevel,
    QualifiedWhitelistRule,
    ReferenceUpdate,
    StandardDiffPolicy,
    SuspiciousModification,
    XrefStreamRule,
    _walk_page_tree_annots,
    is_annot_visible,
    is_field_visible,
)
from pyhanko.sign.general import KeyUsageConstraints, SigningError
from pyhanko.sign.validation import (
    SignatureCoverageLevel,
    validate_pdf_signature,
)
from pyhanko_tests.samples import *
from pyhanko_tests.samples import MINIMAL, PDF_DATA_DIR
from pyhanko_tests.signing_commons import (
    DUMMY_TS,
    FROM_CA,
    FROM_ECC_CA,
    SELF_SIGN,
    SIMPLE_V_CONTEXT,
    live_testing_vc,
    val_trusted,
    val_trusted_but_modified,
    val_untrusted,
)
from pyhanko_tests.test_pades import PADES


@freeze_time('2020-11-01')
def test_no_changes_policy():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', certify=True,
            docmdp_permissions=fields.MDPPerm.FILL_FORMS
        ),
        signer=FROM_CA,
    )

    w = IncrementalPdfFileWriter(out)
    # do an /Info update
    dt = generic.pdf_date(datetime(2020, 10, 10, tzinfo=pytz.utc))
    info = generic.DictionaryObject({pdf_name('/CreationDate'): dt})
    w.set_info(info)
    w.write_in_place()

    # check with normal diff policy
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    status = val_trusted(s, extd=True)
    assert status.modification_level == ModificationLevel.LTA_UPDATES
    assert status.docmdp_ok

    # now check with the ultra-strict no-op policy
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    status = validate_pdf_signature(s, diff_policy=NO_CHANGES_DIFF_POLICY)
    assert isinstance(s.diff_result, SuspiciousModification)
    assert not status.docmdp_ok


DOUBLE_SIG_TESTDATA_FILES = [
    MINIMAL, MINIMAL_XREF, MINIMAL_ONE_FIELD
]


@freeze_time('2020-11-01')
@pytest.mark.parametrize('file_ix', [0, 1, 2])
def test_double_sig_add_field(file_ix):
    w = IncrementalPdfFileWriter(BytesIO(DOUBLE_SIG_TESTDATA_FILES[file_ix]))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1'),
        signer=FROM_CA,
    )

    # create a new signature field after signing
    w = IncrementalPdfFileWriter(out)
    # throw in an /Info update for good measure
    dt = generic.pdf_date(datetime(2020, 10, 10, tzinfo=pytz.utc))
    info = generic.DictionaryObject({pdf_name('/CreationDate'): dt})
    w.set_info(info)

    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='SigNew'), signer=FROM_CA,
    )

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    status = val_trusted(s, extd=True)
    assert status.modification_level == ModificationLevel.FORM_FILLING
    assert status.docmdp_ok

    s = r.embedded_signatures[1]
    assert s.field_name == 'SigNew'
    val_trusted(s)


@freeze_time('2020-11-01')
def test_double_sig_create_deep_field_post_sign():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    # create part of the structure already

    fields._insert_or_get_field_at(
        w, w.root['/AcroForm']['/Fields'], ('NewSigs', 'NewSig1'),
        field_obj=generic.DictionaryObject({pdf_name('/FT'): pdf_name('/Sig')})
    )

    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', certify=True,
            docmdp_permissions=fields.MDPPerm.FILL_FORMS
        ),
        signer=FROM_CA, in_place=True
    )

    w = IncrementalPdfFileWriter(out)
    fqn = 'NewSigs.NewSig2'
    meta = signers.PdfSignatureMetadata(field_name=fqn)
    out = signers.sign_pdf(w, meta, signer=FROM_CA)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    status = validate_pdf_signature(
        s, signer_validation_context=SIMPLE_V_CONTEXT()
    )
    # the /Kids array of NewSigs was modified, which we don't allow (right now)
    assert status.modification_level == ModificationLevel.OTHER


@freeze_time('2020-11-01')
def test_double_sig_fill_deep_field_post_sign():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    # create part of the structure already

    fields._insert_or_get_field_at(
        w, w.root['/AcroForm']['/Fields'], ('NewSigs', 'NewSig1'),
        field_obj=fields.SignatureFormField(
            'NewSig1', include_on_page=w.root['/Pages']['/Kids'].raw_get(0)
        )
    )

    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', certify=True,
            docmdp_permissions=fields.MDPPerm.FILL_FORMS
        ),
        signer=FROM_CA, in_place=True
    )

    w = IncrementalPdfFileWriter(out)
    fqn = 'NewSigs.NewSig1'
    meta = signers.PdfSignatureMetadata(field_name=fqn)
    out = signers.sign_pdf(w, meta, signer=FROM_CA)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted(s, extd=True)

    s = r.embedded_signatures[1]
    val_trusted(s)


@freeze_time('2020-11-01')
def test_no_field_type():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', certify=True,
            docmdp_permissions=fields.MDPPerm.FILL_FORMS
        ),
        signer=FROM_CA, in_place=True
    )

    w = IncrementalPdfFileWriter(out)
    fields._insert_or_get_field_at(
        w, w.root['/AcroForm']['/Fields'], ('Blah',),
    )
    meta = signers.PdfSignatureMetadata(field_name='NewSig')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    status = validate_pdf_signature(
        s, signer_validation_context=SIMPLE_V_CONTEXT()
    )
    assert status.modification_level == ModificationLevel.OTHER


@pytest.mark.parametrize('infile_name', [
    'minimal-two-fields-signed-twice.pdf',
    'minimal-signed-twice-second-created.pdf',
    'minimal-signed-twice-both-created.pdf'
])
@freeze_time('2021-01-05')
def test_double_sig_adobe_reader(infile_name):
    # test using a double signature created using Adobe Reader
    # (uses object streams, XMP metadata updates and all the fun stuff)

    # One file has two prepared form fields, signed one by one by Adobe Reader.
    # The other file has one prepared form field, signed by Adobe Reader,
    # and the second signature occupies a form field that was created on the fly
    # by Adobe Reader.
    # The last one involves a double signature where both fields were created
    # by Adobe Reader.

    infile = BytesIO(read_all('%s/%s' % (PDF_DATA_DIR, infile_name)))
    r = PdfFileReader(infile)

    s = r.embedded_signatures[0]
    status = val_untrusted(s, extd=True)
    assert status.modification_level == ModificationLevel.FORM_FILLING
    assert status.docmdp_ok

    s = r.embedded_signatures[1]
    val_untrusted(s)


@freeze_time('2021-01-12')
def test_double_sig_adobe_reader_second_created():
    infile = BytesIO(
        read_all(PDF_DATA_DIR + '/minimal-signed-twice-second-created.pdf')
    )
    r = PdfFileReader(infile)

    s = r.embedded_signatures[0]
    status = val_untrusted(s, extd=True)
    assert status.modification_level == ModificationLevel.FORM_FILLING
    assert status.docmdp_ok

    s = r.embedded_signatures[1]
    val_untrusted(s)


@freeze_time('2021-01-05')
def test_bogus_metadata_manipulation():
    # test using a double signature created using Adobe Reader
    # (uses object streams, XMP metadata updates and all the fun stuff)

    infile = BytesIO(
        read_all(PDF_DATA_DIR + '/minimal-two-fields-signed-twice.pdf')
    )

    bogus = b'This is bogus data, yay!'

    def do_check():
        r = PdfFileReader(out)
        s = r.embedded_signatures[0]
        status = validate_pdf_signature(s)
        assert status.modification_level == ModificationLevel.OTHER

    w = IncrementalPdfFileWriter(infile)
    w.root['/Metadata'] = w.add_object(generic.StreamObject(stream_data=bogus))
    w.update_root()
    out = BytesIO()
    w.write(out)
    do_check()

    w = IncrementalPdfFileWriter(infile)
    metadata_ref = w.root.raw_get('/Metadata')
    metadata_stream: generic.StreamObject = metadata_ref.get_object()
    metadata_stream.strip_filters()
    metadata_stream._data = bogus
    metadata_stream._encoded_data = None
    w.mark_update(metadata_ref)
    out = BytesIO()
    w.write(out)
    do_check()

    w = IncrementalPdfFileWriter(infile)
    w.root['/Metadata'] = generic.NullObject()
    w.update_root()
    out = BytesIO()
    w.write(out)
    do_check()

    w = IncrementalPdfFileWriter(infile)
    w.root['/Metadata'] = w.add_object(generic.NullObject())
    w.update_root()
    out = BytesIO()
    w.write(out)
    do_check()


@freeze_time('2020-11-01')
def test_double_sig_add_field_annots_indirect():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1'),
        signer=FROM_CA,
    )

    # create a new signature field after signing
    w = IncrementalPdfFileWriter(out)
    # ... but first make the /Annots entry of the first page an indirect one
    first_page = w.root['/Pages']['/Kids'][0]
    annots_copy = generic.ArrayObject(first_page['/Annots'])
    first_page['/Annots'] = annots_ref = w.add_object(annots_copy)
    annots_copy.container_ref = annots_ref
    w.update_container(first_page)
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='SigNew'
        ), signer=FROM_CA, new_field_spec=fields.SigFieldSpec(
            sig_field_name='SigNew', box=(10, 10, 10, 10)
        )
    )

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    status = val_trusted(s, extd=True)
    assert status.modification_level == ModificationLevel.FORM_FILLING
    assert status.docmdp_ok

    s = r.embedded_signatures[1]
    assert s.field_name == 'SigNew'
    val_trusted(s)


@freeze_time('2020-11-01')
def test_double_sig_add_visible_field_approval():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1'), signer=FROM_CA
    )

    # create a new signature field after signing
    w = IncrementalPdfFileWriter(out)

    sp = fields.SigFieldSpec(
        'SigNew', box=(10, 74, 140, 134)
    )
    fields.append_signature_field(w, sp)
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='SigNew'), signer=FROM_CA,
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    status = val_trusted(s, extd=True)
    assert status.modification_level == ModificationLevel.FORM_FILLING
    assert status.docmdp_ok

    s = r.embedded_signatures[1]
    assert s.field_name == 'SigNew'
    val_trusted(s)


@freeze_time('2020-11-01')
def test_double_sig_add_visible_field_certify():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', certify=True,
            docmdp_permissions=fields.MDPPerm.FILL_FORMS
        ), signer=FROM_CA
    )

    # create a new signature field after signing
    w = IncrementalPdfFileWriter(out)

    sp = fields.SigFieldSpec(
        'SigNew', box=(10, 74, 140, 134)
    )
    fields.append_signature_field(w, sp)
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='SigNew'), signer=FROM_CA,
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    s.compute_integrity_info(DEFAULT_DIFF_POLICY)
    assert isinstance(s.diff_result, SuspiciousModification)
    assert 'only allowed after an approval signature' in str(s.diff_result)


def set_text_field(writer, val):
    tf = writer.root['/AcroForm']['/Fields'][1].get_object()

    appearance = RawContent(
        box=BoxConstraints(height=60, width=130),
        data=b'q 0 0 1 rg BT /Ti 12 Tf (%s) Tj ET Q' % val.encode(
            'ascii')
    )
    tf['/V'] = generic.pdf_string(val)

    tf['/AP'] = generic.DictionaryObject({
        generic.pdf_name('/N'): writer.add_object(
            appearance.as_form_xobject()
        )
    })
    writer.update_container(tf)


@freeze_time('2020-11-01')
def test_form_field_ft_tamper():
    w = IncrementalPdfFileWriter(BytesIO(SIMPLE_FORM))

    # sign, then fill
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    w = IncrementalPdfFileWriter(out)
    tf = w.root['/AcroForm']['/Fields'][1].get_object()
    tf['/FT'] = pdf_name('/Sig')
    w.update_container(tf)
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted_but_modified(s)


BOGUS_KIDS_VALUES = [
    (generic.NullObject(), False),
    (generic.ArrayObject(), False),
    (generic.ArrayObject([generic.NullObject()]), False),
    (generic.ArrayObject([generic.NullObject()]), True),
]


@freeze_time('2020-11-01')
@pytest.mark.parametrize('bogus_kids, indirectify', BOGUS_KIDS_VALUES)
def test_form_field_kids_tamper(bogus_kids, indirectify):
    w = IncrementalPdfFileWriter(BytesIO(SIMPLE_FORM))

    # sign, then fill
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    w = IncrementalPdfFileWriter(out)
    tf = w.root['/AcroForm']['/Fields'][1].get_object()
    if indirectify:
        bogus_kids = generic.ArrayObject(map(w.add_object, bogus_kids))
    tf['/Kids'] = bogus_kids
    w.update_container(tf)
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted_but_modified(s)


@freeze_time('2020-11-01')
@pytest.mark.parametrize('bogus_kids, indirectify',
                         BOGUS_KIDS_VALUES + [(None, False)])
def test_pages_kids_tamper(bogus_kids, indirectify):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))

    # sign, then fill
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    w = IncrementalPdfFileWriter(out)

    # add an empty sig field to trigger the annotation parsing logic
    # in the difference analysis tool
    fields.append_signature_field(
        w, sig_field_spec=fields.SigFieldSpec(sig_field_name="Extra")
    )
    page_root = w.root['/Pages']
    if indirectify:
        bogus_kids = generic.ArrayObject(map(w.add_object, bogus_kids))
    if bogus_kids is not None:
        page_root['/Kids'] = bogus_kids
    else:
        del page_root['/Kids']
    w.update_container(page_root)
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted_but_modified(s)


@freeze_time('2020-11-01')
def test_form_field_postsign_fill():
    w = IncrementalPdfFileWriter(BytesIO(SIMPLE_FORM))

    # sign, then fill
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    w = IncrementalPdfFileWriter(out)
    set_text_field(w, "Some text")
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted(s, extd=True)


@freeze_time('2020-11-01')
def test_form_field_postsign_modify():
    w = IncrementalPdfFileWriter(BytesIO(SIMPLE_FORM))

    # fill in, then sign
    set_text_field(w, "Some text")
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    w = IncrementalPdfFileWriter(out)
    set_text_field(w, "Some other text")
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted(s, extd=True)


def set_text_field_in_group(writer, ix, val):
    tf_parent = writer.root['/AcroForm']['/Fields'][1].get_object()
    tf = tf_parent['/Kids'][ix].get_object()
    appearance = RawContent(
        box=BoxConstraints(height=60, width=130),
        data=b'''q 0 0 1 rg BT /Ti 12 Tf (%s) Tj ET Q''' % val.encode(
            'ascii')
    )
    tf['/V'] = generic.pdf_string(val)

    tf['/AP'] = generic.DictionaryObject({
        generic.pdf_name('/N'): writer.add_object(
            appearance.as_form_xobject()
        )
    })
    writer.update_container(tf)


GROUP_VARIANTS = (TEXTFIELD_GROUP, TEXTFIELD_GROUP_VAR)


@pytest.mark.parametrize('variant, existing_only', [(0, True), (1, True), (0, False), (1, False)])
def test_deep_non_sig_field(variant, existing_only):
    w = IncrementalPdfFileWriter(BytesIO(GROUP_VARIANTS[variant]))
    meta = signers.PdfSignatureMetadata(field_name='TextInput.TextField1')
    with pytest.raises(SigningError):
        signers.sign_pdf(
            w, meta, signer=FROM_CA, existing_fields_only=existing_only
        )


@pytest.mark.parametrize('variant', [0, 1])
@freeze_time('2020-11-01')
def test_create_deep_sig_field(variant):
    w = IncrementalPdfFileWriter(BytesIO(GROUP_VARIANTS[variant]))
    meta = signers.PdfSignatureMetadata(field_name='TextInput.NewSig')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'TextInput.NewSig'
    val_trusted(s)


@pytest.mark.parametrize('variant', [0, 1, None])
@freeze_time('2020-11-01')
def test_create_multi_deep_sig_field(variant):
    infile = GROUP_VARIANTS[variant] if variant is not None else MINIMAL
    w = IncrementalPdfFileWriter(BytesIO(infile))
    fqn = 'TextInput.Sigs.Blah.NewSig'
    meta = signers.PdfSignatureMetadata(field_name=fqn)
    out = signers.sign_pdf(w, meta, signer=FROM_CA)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == fqn
    val_trusted(s)


@pytest.mark.parametrize('variant', [0, 1])
@freeze_time('2020-11-01')
def test_form_field_in_group_postsign_fill(variant):
    w = IncrementalPdfFileWriter(BytesIO(GROUP_VARIANTS[variant]))

    # sign, then fill
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    w = IncrementalPdfFileWriter(out)
    set_text_field_in_group(w, 0, "Some text")
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted(s, extd=True)


@pytest.mark.parametrize('variant', [0, 1])
@freeze_time('2020-11-01')
def test_form_field_in_group_postsign_fill_other_field(variant):
    w = IncrementalPdfFileWriter(BytesIO(GROUP_VARIANTS[variant]))

    # fill in, then sign, then fill other field
    set_text_field_in_group(w, 0, "Some text")
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    w = IncrementalPdfFileWriter(out)
    set_text_field_in_group(w, 1, "Some other text")
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted(s, extd=True)


@pytest.mark.parametrize('variant', [0, 1])
@freeze_time('2020-11-01')
def test_form_field_in_group_postsign_modify(variant):
    w = IncrementalPdfFileWriter(BytesIO(GROUP_VARIANTS[variant]))

    # fill in, then sign, then override
    set_text_field_in_group(w, 0, "Some text")
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    w = IncrementalPdfFileWriter(out)
    set_text_field_in_group(w, 0, "Some other text")
    set_text_field_in_group(w, 1, "Yet other text")
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted(s, extd=True)


test_form_field_in_group_postsign_modify_failure_matrix = [
    (0, fields.FieldMDPSpec(fields.FieldMDPAction.INCLUDE,
                            fields=['TextInput.TextField1'])),
    (1, fields.FieldMDPSpec(fields.FieldMDPAction.INCLUDE,
                            fields=['TextInput.TextField1'])),
    (0, fields.FieldMDPSpec(fields.FieldMDPAction.EXCLUDE,
                            fields=['TextInput.TextField2'])),
    (1, fields.FieldMDPSpec(fields.FieldMDPAction.EXCLUDE,
                            fields=['TextInput.TextField2'])),
    (0, fields.FieldMDPSpec(fields.FieldMDPAction.INCLUDE,
                            fields=['TextInput'])),
    (1, fields.FieldMDPSpec(fields.FieldMDPAction.INCLUDE,
                            fields=['TextInput'])),
    (0, fields.FieldMDPSpec(fields.FieldMDPAction.ALL)),
    (1, fields.FieldMDPSpec(fields.FieldMDPAction.ALL)),
    (0, fields.FieldMDPSpec(fields.FieldMDPAction.EXCLUDE, fields=['Sig1'])),
    (1, fields.FieldMDPSpec(fields.FieldMDPAction.EXCLUDE, fields=['Sig1'])),
]


@pytest.mark.parametrize('field_filled, fieldmdp_spec', test_form_field_in_group_postsign_modify_failure_matrix)
@freeze_time('2020-11-01')
def test_form_field_in_group_locked_postsign_modify_failure(field_filled, fieldmdp_spec):
    # the field that is filled in after signing is always the same,
    # but the initial one varies
    w = IncrementalPdfFileWriter(BytesIO(GROUP_VARIANTS[0]))


    sp = fields.SigFieldSpec(
        'SigNew', box=(10, 74, 140, 134),
        field_mdp_spec=fieldmdp_spec,
        doc_mdp_update_value=fields.MDPPerm.FILL_FORMS
    )
    fields.append_signature_field(w, sp)
    set_text_field_in_group(w, field_filled, "Some text")
    meta = signers.PdfSignatureMetadata(field_name='SigNew')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    w = IncrementalPdfFileWriter(out)
    set_text_field_in_group(w, 0, "Some other text")
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'SigNew'
    val_trusted_but_modified(s)


test_form_field_in_group_postsign_modify_success_matrix = [
    (0, fields.FieldMDPSpec(fields.FieldMDPAction.INCLUDE,
                            fields=['TextInput.TextField1'])),
    (1, fields.FieldMDPSpec(fields.FieldMDPAction.INCLUDE,
                            fields=['TextInput.TextField1'])),
    (0, fields.FieldMDPSpec(fields.FieldMDPAction.EXCLUDE,
                            fields=['TextInput.TextField2'])),
    (1, fields.FieldMDPSpec(fields.FieldMDPAction.EXCLUDE,
                            fields=['TextInput.TextField2'])),
    (0, fields.FieldMDPSpec(fields.FieldMDPAction.EXCLUDE,
                            fields=['TextInput'])),
    (1, fields.FieldMDPSpec(fields.FieldMDPAction.EXCLUDE,
                            fields=['TextInput'])),
    (0, fields.FieldMDPSpec(fields.FieldMDPAction.INCLUDE, fields=['Sig1'])),
    (1, fields.FieldMDPSpec(fields.FieldMDPAction.INCLUDE, fields=['Sig1'])),
]


@pytest.mark.parametrize('field_filled, fieldmdp_spec', test_form_field_in_group_postsign_modify_success_matrix)
@freeze_time('2020-11-01')
def test_form_field_in_group_locked_postsign_modify_success(field_filled, fieldmdp_spec):
    # the field that is filled in after signing is always the same,
    # but the initial one varies
    w = IncrementalPdfFileWriter(BytesIO(GROUP_VARIANTS[0]))


    sp = fields.SigFieldSpec(
        'SigNew', box=(10, 74, 140, 134),
        field_mdp_spec=fieldmdp_spec,
        doc_mdp_update_value=fields.MDPPerm.FILL_FORMS
    )
    fields.append_signature_field(w, sp)
    set_text_field_in_group(w, field_filled, "Some text")
    meta = signers.PdfSignatureMetadata(field_name='SigNew')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    w = IncrementalPdfFileWriter(out)
    set_text_field_in_group(w, 1, "Some other text")
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'SigNew'
    val_trusted(s, extd=True)


@freeze_time('2020-11-01')
def test_form_field_postsign_fill_pades_lt(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(SIMPLE_FORM))
    vc = live_testing_vc(requests_mock)
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1', validation_context=vc,
        subfilter=PADES, embed_validation_info=True,
    )

    # sign, then fill
    out = signers.sign_pdf(w, meta, signer=FROM_CA, timestamper=DUMMY_TS)
    w = IncrementalPdfFileWriter(out)
    set_text_field(w, "Some text")
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted(s, extd=True)


@freeze_time('2020-11-01')
def test_fieldmdp_all_pades_lta(requests_mock):

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    vc = live_testing_vc(requests_mock)
    sp = fields.SigFieldSpec(
        'SigNew', box=(10, 74, 140, 134),
        field_mdp_spec=fields.FieldMDPSpec(action=fields.FieldMDPAction.ALL),
        doc_mdp_update_value=fields.MDPPerm.FILL_FORMS
    )
    fields.append_signature_field(w, sp)
    meta = signers.PdfSignatureMetadata(
        field_name='SigNew', validation_context=vc, embed_validation_info=True,
        subfilter=fields.SigSeedSubFilter.PADES, use_pades_lta=True
    )

    out = signers.sign_pdf(w, meta, signer=FROM_CA, timestamper=DUMMY_TS)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'SigNew'
    status = val_trusted(s, extd=True)
    assert status.modification_level == ModificationLevel.LTA_UPDATES


@freeze_time('2020-11-01')
def test_form_field_postsign_modify_pades_lt(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(SIMPLE_FORM))
    vc = live_testing_vc(requests_mock)
    meta =signers.PdfSignatureMetadata(
        field_name='Sig1', validation_context=vc,
        subfilter=PADES, embed_validation_info=True,
    )

    # sign, then fill
    set_text_field(w, "Some text")
    out = signers.sign_pdf(w, meta, signer=FROM_CA, timestamper=DUMMY_TS)
    w = IncrementalPdfFileWriter(out)
    set_text_field(w, "Some other text")
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted(s, extd=True)


@freeze_time('2020-11-01')
@pytest.mark.parametrize('certify_first', [True, False])
def test_pades_double_sign(requests_mock, certify_first):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))
    meta1 = signers.PdfSignatureMetadata(
        field_name='Sig1', validation_context=live_testing_vc(requests_mock),
        subfilter=PADES, embed_validation_info=True, certify=certify_first
    )
    meta2 = signers.PdfSignatureMetadata(
        field_name='Sig2', validation_context=live_testing_vc(requests_mock),
        subfilter=PADES, embed_validation_info=True,
    )

    out = signers.sign_pdf(w, meta1, signer=FROM_CA, timestamper=DUMMY_TS)
    w = IncrementalPdfFileWriter(out)
    out = signers.sign_pdf(w, meta2, signer=FROM_CA, timestamper=DUMMY_TS)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    if certify_first:
        assert len(s.sig_object['/Reference']) == 1
    val_trusted(s, extd=True)

    s = r.embedded_signatures[1]
    assert s.field_name == 'Sig2'
    val_trusted(s, extd=True)


@freeze_time('2020-11-01')
def test_pades_double_sign_delete_dss(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))
    meta1 = signers.PdfSignatureMetadata(
        field_name='Sig1', validation_context=live_testing_vc(requests_mock),
        subfilter=PADES, embed_validation_info=True,
    )
    meta2 = signers.PdfSignatureMetadata(
        field_name='Sig2', validation_context=live_testing_vc(requests_mock),
        subfilter=PADES, embed_validation_info=True,
    )

    out = signers.sign_pdf(w, meta1, signer=FROM_CA, timestamper=DUMMY_TS)
    w = IncrementalPdfFileWriter(out)
    out = signers.sign_pdf(w, meta2, signer=FROM_CA, timestamper=DUMMY_TS)
    w = IncrementalPdfFileWriter(out)
    # DSS is now covered by the second signature, so this is illegal
    del w.root['/DSS']
    w.update_root()
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    assert '/DSS' not in r.root
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted(s, extd=True)

    # however, the second signature is violated by the deletion of the /DSS key
    s = r.embedded_signatures[1]
    assert s.field_name == 'Sig2'
    val_trusted_but_modified(s)


@freeze_time('2020-11-01')
def test_pades_double_sign_delete_vri(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))
    meta1 = signers.PdfSignatureMetadata(
        field_name='Sig1', validation_context=live_testing_vc(requests_mock),
        subfilter=PADES, embed_validation_info=True,
    )
    meta2 = signers.PdfSignatureMetadata(
        field_name='Sig2', validation_context=live_testing_vc(requests_mock),
        subfilter=PADES, embed_validation_info=True,
    )

    out = signers.sign_pdf(w, meta1, signer=FROM_CA, timestamper=DUMMY_TS)
    w = IncrementalPdfFileWriter(out)
    out = signers.sign_pdf(w, meta2, signer=FROM_CA, timestamper=DUMMY_TS)
    w = IncrementalPdfFileWriter(out)
    del w.root['/DSS']['/VRI']
    w.update_container(w.root['/DSS'])
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    assert '/VRI' not in r.root['/DSS']
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted(s, extd=True)

    # however, the second signature is violated by the deletion of the /DSS key
    s = r.embedded_signatures[1]
    assert s.field_name == 'Sig2'
    val_trusted_but_modified(s)


@freeze_time('2020-11-01')
def test_pades_dss_object_clobber(requests_mock):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))
    meta1 = signers.PdfSignatureMetadata(
        field_name='Sig1', validation_context=live_testing_vc(requests_mock),
        subfilter=PADES, embed_validation_info=True,
    )
    dummy_ref = w.add_object(generic.pdf_string("Hi there")).reference

    out = signers.sign_pdf(w, meta1, signer=FROM_CA, timestamper=DUMMY_TS)
    w = IncrementalPdfFileWriter(out)
    # We're going to reassign the DSS object to another object ID, namely
    #  one that clobbers the dummy_ref object. This should be ample cause
    #  for suspicion.
    dss = w.root['/DSS']
    w.objects[(dummy_ref.generation, dummy_ref.idnum)] = dss
    w.root['/DSS'] = generic.IndirectObject(
        idnum=dummy_ref.idnum, generation=dummy_ref.generation, pdf=w
    )
    w.update_root()
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted_but_modified(s)


BOGUS_DSS_VALUES = [
    generic.pdf_string("Hi there"),
    generic.DictionaryObject({pdf_name('/Blah'): generic.NullObject()}),
    generic.DictionaryObject({pdf_name('/Certs'): generic.NullObject()}),
    generic.DictionaryObject({pdf_name('/VRI'): generic.NullObject()}),
    generic.DictionaryObject({
        pdf_name('/VRI'): generic.DictionaryObject({
            pdf_name('/Bleh'): generic.NullObject()
        })
    }),
    generic.DictionaryObject({
        pdf_name('/VRI'): generic.DictionaryObject({
            pdf_name('/' + 'A' * 40): generic.NullObject()
        })
    }),
    generic.DictionaryObject({
        pdf_name('/VRI'): generic.DictionaryObject({
            pdf_name('/' + 'A' * 40): generic.DictionaryObject({
                pdf_name('/Bleh'): generic.NullObject()
            })
        })
    }),
    generic.DictionaryObject({
        pdf_name('/VRI'): generic.DictionaryObject({
            pdf_name('/' + 'A' * 40): generic.DictionaryObject({
                pdf_name('/OCSP'): generic.NullObject()
            })
        })
    }),
]


@freeze_time('2020-11-01')
@pytest.mark.parametrize('bogus_dss', BOGUS_DSS_VALUES)
def test_pades_dss_object_typing_tamper(requests_mock, bogus_dss):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))
    meta1 = signers.PdfSignatureMetadata(
        field_name='Sig1', validation_context=live_testing_vc(requests_mock),
        subfilter=PADES, embed_validation_info=True,
    )
    out = signers.sign_pdf(
        w, meta1, signer=FROM_CA, timestamper=DUMMY_TS
    )
    out.seek(0)
    original_out = out.read()

    # write some bogus reference into the DSS
    w = IncrementalPdfFileWriter(BytesIO(original_out))

    w.root['/DSS'] = w.add_object(bogus_dss)
    w.update_root()
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted_but_modified(s)


@freeze_time('2020-11-01')
def test_form_field_structure_modification():
    w = IncrementalPdfFileWriter(BytesIO(SIMPLE_FORM))
    meta =signers.PdfSignatureMetadata(field_name='Sig1')

    out = signers.sign_pdf(w, meta, signer=FROM_CA, timestamper=DUMMY_TS)
    w = IncrementalPdfFileWriter(out)
    field_arr = w.root['/AcroForm']['/Fields']
    # shallow copy the text field
    tf = generic.DictionaryObject(field_arr[1].get_object())
    tf['/T'] = generic.pdf_string('OtherField')
    field_arr.append(w.add_object(tf))
    w.update_container(field_arr)
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    val_trusted_but_modified(s)


@freeze_time('2020-11-01')
def test_delete_signature():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))

    # first, we simply sign the two fields
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig1'), signer=FROM_CA,
        existing_fields_only=True
    )

    w = IncrementalPdfFileWriter(out)

    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig2'), signer=FROM_CA,
        existing_fields_only=True
    )

    # after that, we add an incremental update that deletes the first signature
    # This should invalidate the remaining one.
    w = IncrementalPdfFileWriter(out)
    sig_fields = fields.enumerate_sig_fields(w)
    field_name, sig_obj, sig_field = next(sig_fields)
    assert field_name == 'Sig1'
    del sig_field.get_object()['/V']
    w.mark_update(sig_field)
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig2'
    val_trusted_but_modified(s)


@pytest.mark.parametrize('policy, skip_diff',
                         [(None, False),
                          (NO_CHANGES_DIFF_POLICY, False),
                          (None, True)])
def test_tamper_sig_obj(policy, skip_diff):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1'
    )
    out = signers.sign_pdf(w, meta, signer=FROM_CA)

    w = IncrementalPdfFileWriter(out)
    sig_obj = w.prev.embedded_signatures[0].sig_object
    sig_obj['/Bleh'] = generic.BooleanObject(False)
    w.update_container(sig_obj)
    w.write_in_place()

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    status = validate_pdf_signature(
        emb, diff_policy=policy, skip_diff=skip_diff
    )
    if skip_diff:
        assert emb.diff_result is None
    else:
        assert isinstance(emb.diff_result, SuspiciousModification)
    assert status.coverage == SignatureCoverageLevel.CONTIGUOUS_BLOCK_FROM_START
    assert status.modification_level == ModificationLevel.OTHER


def test_rogue_backreferences():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    # intentionally refer back to the contents of the first page
    w.root['/DSS'] = w.root['/Pages']['/Kids'][0].get_object().raw_get('/Contents')
    w.update_root()
    meta = signers.PdfSignatureMetadata(
        field_name='Sig1',
    )
    out = signers.sign_pdf(w, meta, signer=FROM_CA)

    # pretend to add a new form field, but actually secretly do a page
    #  tree modification.
    sp = fields.SigFieldSpec(
        'SigNew', box=(10, 74, 140, 134),
        doc_mdp_update_value=fields.MDPPerm.FILL_FORMS
    )
    w = IncrementalPdfFileWriter(out)
    fields.append_signature_field(w, sp)
    w.write_in_place()

    w = IncrementalPdfFileWriter(out)
    contents_ref = w.root['/Pages']['/Kids'][0].get_object().raw_get('/Contents')
    content_stream: generic.StreamObject = contents_ref.get_object()
    content_stream._data = content_stream.data + b"q Q"
    content_stream._encoded_data = None
    w.mark_update(contents_ref)
    w.write_in_place()

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    emb.compute_integrity_info()
    assert isinstance(emb.diff_result, SuspiciousModification)


@freeze_time("2020-11-01")
@pytest.mark.parametrize('forbid_freeing', [True, False])
def test_sign_reject_freed(forbid_freeing):

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    w.root['/Blah'] = freed = w.add_object(generic.pdf_string('Hi there!'))
    out = signers.sign_pdf(
        w, signature_meta=signers.PdfSignatureMetadata(field_name='Sig1'),
        signer=FROM_CA
    )

    # free the dummy object we created before signing
    # since we don't have support for freeing objects in the writer (yet),
    # do it manually
    r = PdfFileReader(out)
    last_startxref = r.last_startxref

    len_out = out.seek(0, os.SEEK_END)
    out.write(
        b'\n'.join([
            b'xref',
            b'0 1',
            b'0000000000 65535 f ',
            b'%d 1' % freed.idnum,
            b'0000000000 00001 f ',
            b'trailer<</Prev %d>>' % last_startxref,
            b'startxref',
            b'%d' % len_out,
            b'%%EOF'
        ])
    )
    r = PdfFileReader(out)
    last_rev = r.xrefs.xref_sections - 1

    assert freed.reference in r.xrefs.refs_freed_in_revision(last_rev)

    sig = r.embedded_signatures[0]
    assert sig.signed_revision == 2

    # make a dummy rule that whitelists our freed object ref

    class AdHocRule(QualifiedWhitelistRule):
        def apply_qualified(self, old: HistoricalResolver,
                            new: HistoricalResolver):
            yield ModificationLevel.LTA_UPDATES, ReferenceUpdate(
                freed.reference, paths_checked=RawPdfPath('/Root', '/Pages')
            )

    val_status = validate_pdf_signature(
        sig, SIMPLE_V_CONTEXT(),
        diff_policy=StandardDiffPolicy(
            DEFAULT_DIFF_POLICY.global_rules + [AdHocRule()],
            DEFAULT_DIFF_POLICY.form_rule,
            reject_object_freeing=forbid_freeing
        )
    )
    if forbid_freeing:
        assert val_status.modification_level == ModificationLevel.OTHER
    else:
        assert val_status.modification_level == ModificationLevel.LTA_UPDATES


@freeze_time("2020-11-01")
def test_not_all_paths_cleared():

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_ONE_FIELD))
    # make /Fields indirect
    fields_arr = w.root['/AcroForm'].raw_get('/Fields')
    # just in case we ever end up declaring /Fields as indirect in the example
    assert isinstance(fields_arr, generic.ArrayObject)
    w.root['/AcroForm']['/Fields'] = w.root['/Blah'] = w.add_object(fields_arr)
    w.update_root()
    w.update_container(w.root['/AcroForm'])
    out = signers.sign_pdf(
        w, signature_meta=signers.PdfSignatureMetadata(field_name='Sig1'),
        signer=FROM_CA
    )

    # create a new signature field after signing
    w = IncrementalPdfFileWriter(out)
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='SigNew'), signer=FROM_CA,
    )

    r = PdfFileReader(out)
    val_trusted_but_modified(embedded_sig=r.embedded_signatures[0])


@freeze_time('2020-11-01')
@pytest.mark.parametrize('level,tagged', list(product(
    [fields.MDPPerm.FILL_FORMS, fields.MDPPerm.ANNOTATE],
    [True, False]
)))
def test_double_signature_certify_first(level, tagged):
    inf = MINIMAL_TWO_FIELDS_TAGGED if tagged else MINIMAL_TWO_FIELDS
    w = IncrementalPdfFileWriter(BytesIO(inf))
    # start with a certifying signature
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', certify=True, docmdp_permissions=level
        ), signer=FROM_CA
    )

    # sign other (existing) field
    w = IncrementalPdfFileWriter(out)

    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='Sig2'), signer=FROM_CA,
    )
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    status = val_trusted(s, extd=True)
    assert status.modification_level == ModificationLevel.FORM_FILLING
    assert status.docmdp_ok

    s = r.embedded_signatures[1]
    assert s.field_name == 'Sig2'
    val_trusted(s)


@freeze_time('2020-11-01')
@pytest.mark.parametrize('ignored', [True, False])
def test_orphan(ignored):
    out = BytesIO(MINIMAL_ONE_FIELD)
    w = IncrementalPdfFileWriter(out)
    signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', certify=True,
            docmdp_permissions=fields.MDPPerm.NO_CHANGES
        ),
        signer=FROM_CA, in_place=True
    )

    w = IncrementalPdfFileWriter(out)
    w.add_object(generic.pdf_string('Bleh'))
    w.write_in_place()

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    policy = StandardDiffPolicy(
        global_rules=[
            XrefStreamRule().as_qualified(ModificationLevel.LTA_UPDATES),
        ],
        form_rule=None,
        ignore_orphaned_objects=ignored
    )
    status = validate_pdf_signature(
        s, SIMPLE_V_CONTEXT(), diff_policy=policy
    )
    if ignored:
        assert status.modification_level == ModificationLevel.LTA_UPDATES
        assert status.docmdp_ok
    else:
        assert status.modification_level == ModificationLevel.OTHER
        assert not status.docmdp_ok


def test_is_field_visible():
    assert not is_annot_visible({})
    assert not is_field_visible({})
    assert not is_annot_visible({'/Rect': 1})
    assert not is_annot_visible({'/Rect': None})
    assert is_field_visible(
        {'/Kids': [
            generic.DictionaryObject({
                generic.pdf_name('/Rect'): generic.ArrayObject([1, 2, 3, 4])
            }),
        ]}
    )
    assert is_field_visible(
        {'/Kids': [
            generic.DictionaryObject({
                generic.pdf_name('/Rect'): generic.ArrayObject([0, 0, 0, 0])
            }),
            generic.DictionaryObject({
                generic.pdf_name('/Rect'): generic.ArrayObject([1, 2, 3, 4])
            }),
        ]}
    )
    assert not is_field_visible(
        {'/Kids': [
            generic.DictionaryObject({
                generic.pdf_name('/Rect'): generic.ArrayObject([0, 0, 0, 0])
            }),
        ]}
    )


@freeze_time('2020-11-01')
def test_form_field_ap_null():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))

    # sign field 1
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    w = IncrementalPdfFileWriter(out)
    # sign field 2
    meta = signers.PdfSignatureMetadata(field_name='Sig2')
    signers.sign_pdf(w, meta, signer=FROM_CA, in_place=True)
    w = IncrementalPdfFileWriter(out)
    # mess with appearance of field 2
    tf = w.root['/AcroForm']['/Fields'][1].get_object()
    tf['/AP'] = generic.NullObject()
    w.update_container(tf)
    w.write_in_place()

    # validate sig 1
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    status = val_trusted_but_modified(s)
    dr = status.diff_result
    assert 'AP entry should point to a dictionary' in str(dr)


@pytest.mark.parametrize('new_name, err', [
    (generic.NullObject(), 'must be strings'),
    (generic.pdf_string('Sig1'), 'Duplicate'),
    (generic.pdf_string('Sig2.'), 'must not contain periods')
])
@freeze_time('2020-11-01')
def test_form_field_manipulate_names(new_name, err):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS))

    # sign field 1
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)
    w = IncrementalPdfFileWriter(out)
    # mess with name of field 2
    tf = w.root['/AcroForm']['/Fields'][1].get_object()
    tf['/T'] = new_name
    w.update_container(tf)
    w.write_in_place()

    # validate sig 1
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert s.field_name == 'Sig1'
    status = val_trusted_but_modified(s)
    dr = status.diff_result
    assert err in str(dr)


@freeze_time('2020-11-01')
def test_signed_file_diff_proxied_objs():
    # Mess with the file a little to have more indirection
    #  (and more opportunities for triggering former bugs with proxied objects)
    w = copy_into_new_writer(
        PdfFileReader(BytesIO(MINIMAL_ONE_FIELD_TAGGED))
    )
    w.encrypt("secret")
    field_arr = w.root['/AcroForm']['/Fields']
    w.root['/AcroForm']['/Fields'] = w.add_object(field_arr)
    out = BytesIO()
    w.write(out)

    w = IncrementalPdfFileWriter(out)
    w.encrypt("secret")
    signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', subfilter=PADES, certify=True,
            docmdp_permissions=fields.MDPPerm.FILL_FORMS
        ),
        signer=FROM_CA, in_place=True
    )
    w = IncrementalPdfFileWriter(out)
    w.encrypt("secret")
    signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='SigNew', subfilter=PADES
        ),
        signer=FROM_CA, in_place=True
    )

    r = PdfFileReader(out)
    r.decrypt("secret")
    result = validate_pdf_signature(r.embedded_signatures[0])
    assert result.docmdp_ok


@freeze_time('2020-11-01')
def test_pades_sign_twice_indirect_arrs(requests_mock):

    testfile = PDF_DATA_DIR + '/pades-lta-dss-indirect-arrs-test.pdf'
    live_testing_vc(requests_mock)
    with open(testfile, 'rb') as f:
        w = IncrementalPdfFileWriter(f)
        meta2 = signers.PdfSignatureMetadata(
            field_name='Sig2',
            validation_context=live_testing_vc(requests_mock),
            subfilter=PADES, embed_validation_info=True,
        )
        out = signers.sign_pdf(w, meta2, signer=FROM_CA, timestamper=DUMMY_TS)

        r = PdfFileReader(out)
        s = r.embedded_regular_signatures[0]
        assert s.field_name == 'Sig1'
        val_trusted(s, extd=True)

        s = r.embedded_regular_signatures[1]
        assert s.field_name == 'Sig2'
        val_trusted(s, extd=True)


@freeze_time('2020-11-01')
def test_pades_sign_update_dss(requests_mock):

    testfile = PDF_DATA_DIR + '/pades-lta-dss-indirect-arrs-test-2.pdf'
    live_testing_vc(requests_mock)
    with open(testfile, 'rb') as f:
        w = IncrementalPdfFileWriter(f)
        # add an irrelevant cert, should be harmless
        certs = w.root['/DSS']['/Certs']
        old_len = len(certs)
        cert_stream = generic.StreamObject(
            stream_data=FROM_ECC_CA.signing_cert.dump()
        )
        certs.append(w.add_object(cert_stream))
        w.update_container(certs)
        out = BytesIO()
        w.write(out)

        r = PdfFileReader(out)
        assert len(r.root['/DSS']['/Certs']) == old_len + 1
        s = r.embedded_regular_signatures[0]
        assert s.field_name == 'Sig1'
        val_trusted(s, extd=True)
        s = r.embedded_regular_signatures[1]
        assert s.field_name == 'Sig2'
        val_trusted(s, extd=True)


def test_simple_sign_with_separate_annot():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    signer = signers.PdfSigner(
        signature_meta=meta, signer=SELF_SIGN,
        new_field_spec=fields.SigFieldSpec(
            sig_field_name='Sig1', combine_annotation=False,
            box=(20, 20, 80, 40)
        )
    )
    out = signer.sign_pdf(w)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    assert '/AP' not in emb.sig_field
    assert '/AP' in emb.sig_field['/Kids'][0]
    val_untrusted(emb)


@freeze_time('2020-11-01')
def test_double_sign_with_separate_annot():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    signer = signers.PdfSigner(
        signature_meta=meta, signer=FROM_CA,
        new_field_spec=fields.SigFieldSpec(
            sig_field_name='Sig1', combine_annotation=False,
            box=(20, 20, 80, 40)
        )
    )
    out = signer.sign_pdf(w, in_place=True)
    w = IncrementalPdfFileWriter(out)
    meta = signers.PdfSignatureMetadata(field_name='Sig2')
    signer = signers.PdfSigner(
        signature_meta=meta, signer=FROM_CA,
        new_field_spec=fields.SigFieldSpec(
            sig_field_name='Sig2', combine_annotation=False,
            box=(20, 120, 80, 140)
        )
    )
    signer.sign_pdf(w, in_place=True)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    assert '/AP' not in emb.sig_field
    assert '/AP' in emb.sig_field['/Kids'][0]
    val_trusted(emb, extd=True)

    emb = r.embedded_signatures[1]
    assert emb.field_name == 'Sig2'
    assert '/AP' not in emb.sig_field
    assert '/AP' in emb.sig_field['/Kids'][0]
    val_trusted(emb)


@freeze_time('2020-11-01')
def test_validate_separate_annot_with_indir_kids():
    with open(PDF_DATA_DIR + '/separate-annots-kids-indir.pdf', 'rb') as f:
        r = PdfFileReader(f)
        emb = r.embedded_signatures[0]
        assert emb.field_name == 'Sig1'
        assert '/AP' not in emb.sig_field
        assert '/AP' in emb.sig_field['/Kids'][0]
        val_trusted(emb, extd=True)

        emb = r.embedded_signatures[1]
        assert emb.field_name == 'Sig2'
        assert '/AP' not in emb.sig_field
        assert '/AP' in emb.sig_field['/Kids'][0]
        val_trusted(emb)


@freeze_time('2020-11-01')
def test_sign_and_update_with_orphaned_obj():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)

    w = IncrementalPdfFileWriter(out)
    w.add_object(generic.pdf_string("Hello there"))
    w.write_in_place()

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    assert emb.field_name == 'Sig1'
    val_trusted(emb, extd=True)


@freeze_time('2020-11-01')
def test_sign_and_update_with_orphaned_obj_and_other_upd():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    meta = signers.PdfSignatureMetadata(field_name='Sig1')
    out = signers.sign_pdf(w, meta, signer=FROM_CA)

    w = IncrementalPdfFileWriter(out)
    w.add_object(generic.pdf_string("Hello there"))
    w.root['/Blah'] = w.add_object(
        generic.pdf_string("Hello there too")
    )
    w.update_root()
    w.write_in_place()

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    val_trusted_but_modified(emb)


@freeze_time('2020-11-01')
def test_indir_ref_in_sigref_dict(requests_mock):
    fname = PDF_DATA_DIR + '/certified-with-indirect-refs-in-dir.pdf'
    with open(fname, 'rb') as f:
        content = f.read()

    # first, try validating without additions
    r = PdfFileReader(BytesIO(content))
    emb = r.embedded_signatures[0]
    val_trusted(emb)

    w = IncrementalPdfFileWriter(BytesIO(content))

    out = PdfTimeStamper(timestamper=DUMMY_TS).timestamp_pdf(
        w, md_algorithm='sha256',
        validation_context=live_testing_vc(requests_mock)
    )
    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    val_trusted(emb, extd=True)


@freeze_time('2020-11-01')
def test_skip_diff_scenario_1():
    # Test if skip_diff behaves as expected
    # scenario 1: sign a locked file

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='SigFirst', certify=True,
            docmdp_permissions=fields.MDPPerm.NO_CHANGES
        ), signer=FROM_CA,
    )
    w = IncrementalPdfFileWriter(out)

    pdf_signer = signers.PdfSigner(
        signers.PdfSignatureMetadata(field_name='SigNew'),
        signer=FROM_CA
    )

    # dummy out certification enforcer
    pdf_signer._enforce_certification_constraints = lambda _: None

    out = pdf_signer.sign_pdf(w)

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    # should be OK with skip_diff
    status = validate_pdf_signature(s, SIMPLE_V_CONTEXT(), skip_diff=True)
    assert status.docmdp_ok is None
    assert status.bottom_line
    assert 'skipped' in status.pretty_print_details()

    # ... but not otherwise
    status = validate_pdf_signature(s, SIMPLE_V_CONTEXT())
    assert status.docmdp_ok is False
    assert not status.bottom_line
    assert 'incompatible with the current document modification' \
           in status.pretty_print_details()


@freeze_time('2020-11-01')
def test_skip_diff_scenario_2():
    # Test if skip_diff behaves as expected
    # scenario 2: do something blatantly illegal in the second revision

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(field_name='SigFirst'),
        signer=FROM_CA,
    )

    from pyhanko.pdf_utils.content import RawContent
    w = IncrementalPdfFileWriter(out)
    w.add_content_to_page(
        0, RawContent(b'q BT /F1 18 Tf 0 50 Td (Sneaky text!) Tj ET Q')
    )
    w.write_in_place()

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    # should be OK with skip_diff
    status = validate_pdf_signature(s, SIMPLE_V_CONTEXT(), skip_diff=True)
    assert status.docmdp_ok is None
    assert status.bottom_line
    assert 'skipped' in status.pretty_print_details()

    # ... but not otherwise
    status = validate_pdf_signature(s, SIMPLE_V_CONTEXT())
    assert status.docmdp_ok is False
    assert not status.bottom_line
    report = status.pretty_print_details()
    assert 'illegitimate' in report
    assert 'incompatible with the current document modification' in report


def test_diff_analysis_circular_page_tree():
    fname = os.path.join(PDF_DATA_DIR, 'circular-page-tree.pdf')
    with open(fname, 'rb') as inf:
        w = IncrementalPdfFileWriter(inf)
        # we should be able to grab the first page, so the signer
        # shouldn't crash
        out = signers.sign_pdf(
            w, signature_meta=signers.PdfSignatureMetadata(field_name='Sig1'),
            signer=FROM_CA
        )
    w = IncrementalPdfFileWriter(out)
    # do an update, just so we trigger difference analysis
    w.add_object(generic.NullObject())
    w.write_in_place()

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    with pytest.raises(misc.PdfReadError,
                       match='Circular reference in page.*mapping'):
        validate_pdf_signature(s, SIMPLE_V_CONTEXT())

    # manually call _walk_page_tree_annots to test the defence-in-depth function
    old = r.get_historical_resolver(1)
    new = r.get_historical_resolver(2)
    walker = _walk_page_tree_annots(
        old_page_root=old.root['/Pages'],
        new_page_root=new.root['/Pages'],
        field_name_dict={},
        old=old, valid_when_locked=False, refs_seen=set()
    )
    with pytest.raises(misc.PdfReadError,
                       match='Circular reference in page.*annot'):
        list(walker)


def test_diff_analysis_circular_structure_tree():
    fname = os.path.join(PDF_DATA_DIR, 'struct-tree-circular-ref.pdf')
    with open(fname, 'rb') as inf:
        w = IncrementalPdfFileWriter(inf)
        out = signers.sign_pdf(
            w, signature_meta=signers.PdfSignatureMetadata(field_name='Sig1'),
            signer=FROM_CA
        )
    w = IncrementalPdfFileWriter(out)
    # do an update, just so we trigger difference analysis
    w.add_object(generic.NullObject())
    w.write_in_place()

    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    with pytest.raises(misc.PdfReadError,
                       match='Circular reference in struct.*mapping'):
        validate_pdf_signature(s, SIMPLE_V_CONTEXT())


LENIENT_KU = KeyUsageConstraints(key_usage=set())


@pytest.mark.parametrize('fname,expected_level', [
    ('tail-uncovered.pdf', SignatureCoverageLevel.CONTIGUOUS_BLOCK_FROM_START),
    ('signature-gap-too-big.pdf', SignatureCoverageLevel.UNCLEAR),
    ('one-byterange.pdf', SignatureCoverageLevel.UNCLEAR),
    ('weird-byterange.pdf', SignatureCoverageLevel.UNCLEAR),
])
def test_anomalous_coverage(fname, expected_level):
    fpath = os.path.join(PDF_DATA_DIR, 'coverage-anomalies', fname)
    with open(fpath, 'rb') as inf:
        r = PdfFileReader(inf)
        s = r.embedded_signatures[0]
        status = validate_pdf_signature(
            s, SIMPLE_V_CONTEXT(), key_usage_settings=LENIENT_KU
        )
        assert status.valid
        assert status.intact
        assert not status.trusted
        assert status.coverage == expected_level
        assert not status.bottom_line
        assert 'NONSTANDARD_COVERAGE' in status.summary()
