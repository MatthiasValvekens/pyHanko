import os
from datetime import datetime
from io import BytesIO

import pytest
import pytz
from freezegun.api import freeze_time

from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.content import RawContent
from pyhanko.pdf_utils.font import pdf_name
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.layout import BoxConstraints
from pyhanko.pdf_utils.reader import (
    PdfFileReader, HistoricalResolver,
    RawPdfPath,
)
from pyhanko.sign import signers, fields
from pyhanko.sign.diff_analysis import (
    ModificationLevel,
    NO_CHANGES_DIFF_POLICY, SuspiciousModification, QualifiedWhitelistRule,
    ReferenceUpdate, StandardDiffPolicy, DEFAULT_DIFF_POLICY,
)
from pyhanko.sign.general import SigningError
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_tests.samples import *
from pyhanko_tests.test_signing import (
    FROM_CA, val_trusted, val_untrusted,
    val_trusted_but_modified, live_testing_vc, PADES, DUMMY_TS,
    SIMPLE_V_CONTEXT,
)


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
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', certify=True,
            docmdp_permissions=fields.MDPPerm.FILL_FORMS
        ),
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
        print(r.get_object(generic.Reference(2, 0, r), revision=3).data)
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
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', certify=True,
            docmdp_permissions=fields.MDPPerm.FILL_FORMS
        ),
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
def test_double_sig_add_visible_field():
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
    status = val_trusted(s, extd=True)
    assert status.modification_level == ModificationLevel.FORM_FILLING
    assert status.docmdp_ok

    s = r.embedded_signatures[1]
    assert s.field_name == 'SigNew'
    val_trusted(s)


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
def test_deep_non_sig_field_nocreate(variant):
    # this case might be supported in the future, but for now we check for
    # a NotImplementedError (since creating fields with dots in their (partial)
    # names is not compliant with the standard)
    w = IncrementalPdfFileWriter(BytesIO(GROUP_VARIANTS[variant]))
    meta = signers.PdfSignatureMetadata(field_name='TextInput.NewSig')
    with pytest.raises(NotImplementedError):
        signers.sign_pdf(w, meta, signer=FROM_CA)


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
    meta =signers.PdfSignatureMetadata(
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
    out = BytesIO()
    w.write(out)

    r = PdfFileReader(out)
    emb = r.embedded_signatures[0]
    status = validate_pdf_signature(
        emb, diff_policy=policy, skip_diff=skip_diff
    )
    if skip_diff:
        assert emb.diff_result is None
        assert status.modification_level is None
    else:
        assert isinstance(emb.diff_result, SuspiciousModification)
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
def test_double_signature_tagged_file():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL_TWO_FIELDS_TAGGED))
    out = signers.sign_pdf(
        w, signers.PdfSignatureMetadata(
            field_name='Sig1', certify=True,
            docmdp_permissions=fields.MDPPerm.FILL_FORMS
        ), signer=FROM_CA
    )

    # create a new signature field after signing
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
