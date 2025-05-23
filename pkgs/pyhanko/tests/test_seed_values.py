from io import BytesIO

import pytest
from asn1crypto import algos
from asn1crypto import pdf as asn1_pdf
from asn1crypto import x509
from freezegun.api import freeze_time
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.generic import pdf_name
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, signers
from pyhanko.sign.general import SigningError, UnacceptableSignerError
from pyhanko.sign.signers import cms_embedder
from pyhanko.sign.signers.pdf_cms import PdfCMSSignedAttributes
from pyhanko.sign.signers.pdf_signer import PdfTBSDocument
from pyhanko.sign.validation import (
    EmbeddedPdfSignature,
    RevocationInfoValidationType,
    async_validate_pdf_ltv_signature,
    async_validate_pdf_signature,
)

from pyhanko_certvalidator import CertificateValidator

from .samples import MINIMAL
from .signing_commons import (
    DUMMY_HTTP_TS,
    DUMMY_TS,
    FROM_CA,
    INTERM_CERT,
    ROOT_CERT,
    SELF_SIGN,
    TRUST_ROOTS,
    dummy_ocsp_vc,
    live_testing_vc,
)
from .test_pades import PADES, ts_response_callback


def test_sv_deserialisation():
    sv_input = generic.DictionaryObject(
        {
            pdf_name('/SubFilter'): generic.ArrayObject(
                map(pdf_name, ['/foo', '/adbe.pkcs7.detached', '/bleh'])
            ),
            pdf_name('/LegalAttestation'): generic.ArrayObject(
                ['xyz', 'abc', 'def']
            ),
            pdf_name('/AppearanceFilter'): generic.pdf_string('blah'),
            pdf_name('/LockDocument'): generic.pdf_name('/true'),
        }
    )
    sv = fields.SigSeedValueSpec.from_pdf_object(sv_input)
    assert len(sv.subfilters) == 1
    assert len(sv.legal_attestations) == 3
    assert sv.lock_document == fields.SeedLockDocument.LOCK
    sv_output = sv.as_pdf_object()
    assert sv_output['/AppearanceFilter'] == sv_input['/AppearanceFilter']
    assert sv_output['/LockDocument'] == sv_input['/LockDocument']
    assert sv_output['/LegalAttestation'] == sv_input['/LegalAttestation']

    with pytest.raises(SigningError):
        fields.SigSeedValueSpec.from_pdf_object(
            generic.DictionaryObject(
                {pdf_name('/LockDocument'): generic.pdf_name('/nonsense')}
            )
        )
        fields.SigSeedValueSpec.from_pdf_object(
            generic.DictionaryObject(
                {pdf_name('/LockDocument'): generic.BooleanObject(True)}
            )
        )
    bad_filter = generic.DictionaryObject(
        {pdf_name('/Filter'): pdf_name('/unsupported')}
    )
    # this should run
    fields.SigSeedValueSpec.from_pdf_object(bad_filter)
    with pytest.raises(SigningError):
        bad_filter[pdf_name('/Ff')] = generic.NumberObject(
            fields.SigSeedValFlags.FILTER.value
        )
        fields.SigSeedValueSpec.from_pdf_object(bad_filter)


def test_sv_version():
    fields.SigSeedValueSpec.from_pdf_object(
        generic.DictionaryObject({'/Ff': fields.SigSeedValFlags.V})
    )
    fields.SigSeedValueSpec.from_pdf_object(
        fields.SigSeedValueSpec(
            flags=fields.SigSeedValFlags.V,
            sv_dict_version=fields.SeedValueDictVersion.PDF_2_0,
        ).as_pdf_object()
    )
    with pytest.raises(SigningError):
        fields.SigSeedValueSpec.from_pdf_object(
            fields.SigSeedValueSpec(
                flags=fields.SigSeedValFlags.V, sv_dict_version=4
            ).as_pdf_object()
        )


def test_sv_mdp_type():
    sv_dict = fields.SigSeedValueSpec().as_pdf_object()
    assert '/MDP' not in sv_dict
    sv_dict = fields.SigSeedValueSpec(
        seed_signature_type=fields.SeedSignatureType(None)
    ).as_pdf_object()
    assert sv_dict['/MDP'] == generic.DictionaryObject(
        {pdf_name('/P'): generic.NumberObject(0)}
    )
    sv_dict = fields.SigSeedValueSpec(
        seed_signature_type=fields.SeedSignatureType(fields.MDPPerm.NO_CHANGES)
    ).as_pdf_object()
    assert sv_dict['/MDP'] == generic.DictionaryObject(
        {pdf_name('/P'): generic.NumberObject(1)}
    )

    sv_spec = fields.SigSeedValueSpec.from_pdf_object(
        generic.DictionaryObject(
            {
                pdf_name('/MDP'): generic.DictionaryObject(
                    {pdf_name('/P'): generic.NumberObject(0)}
                )
            }
        )
    )
    assert sv_spec.seed_signature_type == fields.SeedSignatureType(None)

    sv_spec = fields.SigSeedValueSpec.from_pdf_object(
        generic.DictionaryObject(
            {
                pdf_name('/MDP'): generic.DictionaryObject(
                    {pdf_name('/P'): generic.NumberObject(2)}
                )
            }
        )
    )
    assert sv_spec.seed_signature_type == fields.SeedSignatureType(
        fields.MDPPerm.FILL_FORMS
    )

    with pytest.raises(SigningError):
        fields.SigSeedValueSpec.from_pdf_object(
            generic.DictionaryObject(
                {
                    pdf_name('/MDP'): generic.DictionaryObject(
                        {pdf_name('/P'): generic.NumberObject(5)}
                    )
                }
            )
        )
    with pytest.raises(SigningError):
        fields.SigSeedValueSpec.from_pdf_object(
            generic.DictionaryObject(
                {
                    pdf_name('/MDP'): generic.DictionaryObject(
                        {pdf_name('/P'): generic.NullObject()}
                    )
                }
            )
        )
    with pytest.raises(SigningError):
        fields.SigSeedValueSpec.from_pdf_object(
            generic.DictionaryObject(
                {pdf_name('/MDP'): generic.DictionaryObject()}
            )
        )
    with pytest.raises(SigningError):
        fields.SigSeedValueSpec.from_pdf_object(
            generic.DictionaryObject(
                {pdf_name('/MDP'): generic.NumberObject(5)}
            )
        )


def test_append_sig_field_with_simple_sv():
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))

    sv = fields.SigSeedValueSpec(
        reasons=['a', 'b', 'c'],
        cert=fields.SigCertConstraints(
            subject_dn=FROM_CA.signing_cert.subject,
            issuers=[INTERM_CERT],
            subjects=[FROM_CA.signing_cert],
            key_usage=[
                fields.SigCertKeyUsage.from_sets(
                    {'digital_signature', 'non_repudiation'}, {'key_agreement'}
                )
            ],
        ),
        digest_methods=['ssh256'],
        add_rev_info=True,
        subfilters=[fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED],
        timestamp_server_url='https://tsa.example.com',
    )
    sp = fields.SigFieldSpec('InvisibleSig', seed_value_dict=sv)
    fields.append_signature_field(w, sp)
    out = BytesIO()
    w.write(out)
    out.seek(0)
    r = PdfFileReader(out)
    _, _, sig_field_ref = next(fields.enumerate_sig_fields(r))
    sv_dict = sig_field_ref.get_object()['/SV']
    assert sv_dict['/V'] == generic.NumberObject(2)
    del sv_dict['/V']
    recovered_sv = fields.SigSeedValueSpec.from_pdf_object(sv_dict)
    # x509.Certificate doesn't have an __eq__ implementation apparently,
    # so for the purposes of the test, we replace them by byte dumps
    issuers1 = recovered_sv.cert.issuers
    issuers2 = sv.cert.issuers
    issuers1[0] = issuers1[0].dump()
    issuers2[0] = issuers2[0].dump()

    subjects1 = recovered_sv.cert.subjects
    subjects2 = sv.cert.subjects
    subjects1[0] = subjects1[0].dump()
    subjects2[0] = subjects2[0].dump()
    assert recovered_sv == sv


SV_KU_SATISFIED = "11XXXXXX0"
SV_KU_NOT_SATISFIED = "10XXXXXX0"


@pytest.mark.parametrize(
    'ku_strs', [[SV_KU_SATISFIED], [SV_KU_SATISFIED, SV_KU_NOT_SATISFIED]]
)
def test_cert_constraint_key_usage_ok(ku_strs):
    scc = fields.SigCertConstraints(
        flags=fields.SigCertConstraintFlags.KEY_USAGE,
        key_usage=[
            fields.SigCertKeyUsage.read_from_sv_string(ku) for ku in ku_strs
        ],
    )
    scc.satisfied_by(FROM_CA.signing_cert, None)


@pytest.mark.parametrize('ku_strs', [[SV_KU_NOT_SATISFIED], []])
def test_cert_constraint_key_usage_not_ok(ku_strs):
    scc = fields.SigCertConstraints(
        flags=fields.SigCertConstraintFlags.KEY_USAGE,
        key_usage=[
            fields.SigCertKeyUsage.read_from_sv_string(ku) for ku in ku_strs
        ],
    )
    with pytest.raises(UnacceptableSignerError):
        scc.satisfied_by(FROM_CA.signing_cert, None)


def test_cert_constraint_subject_dn():
    scc = fields.SigCertConstraints(
        flags=fields.SigCertConstraintFlags.SUBJECT_DN,
        subject_dn=x509.Name.build({'common_name': 'Alice'}),
    )
    scc.satisfied_by(FROM_CA.signing_cert, None)
    with pytest.raises(UnacceptableSignerError):
        scc.satisfied_by(DUMMY_TS.tsa_cert, None)

    scc = fields.SigCertConstraints(
        flags=fields.SigCertConstraintFlags.SUBJECT_DN,
        subject_dn=x509.Name.build(
            {'common_name': 'Alice', 'country_name': 'BE'}
        ),
    )
    scc.satisfied_by(FROM_CA.signing_cert, None)
    with pytest.raises(UnacceptableSignerError):
        scc.satisfied_by(DUMMY_TS.tsa_cert, None)

    scc = fields.SigCertConstraints(
        flags=fields.SigCertConstraintFlags.SUBJECT_DN,
        subject_dn=x509.Name.build(
            {'common_name': 'Alice & Bob', 'country_name': 'BE'}
        ),
    )
    with pytest.raises(UnacceptableSignerError):
        scc.satisfied_by(FROM_CA.signing_cert, None)

    # without the SUBJECT_DN flag, this should pass
    scc = fields.SigCertConstraints(
        subject_dn=x509.Name.build(
            {'common_name': 'Alice & Bob', 'country_name': 'BE'}
        )
    )
    scc.satisfied_by(FROM_CA.signing_cert, None)


def test_cert_constraint_subject():
    scc = fields.SigCertConstraints(
        flags=fields.SigCertConstraintFlags.SUBJECT,
        subjects=[FROM_CA.signing_cert],
    )
    scc.satisfied_by(FROM_CA.signing_cert, None)
    with pytest.raises(UnacceptableSignerError):
        scc.satisfied_by(DUMMY_TS.tsa_cert, None)

    scc = fields.SigCertConstraints(
        flags=fields.SigCertConstraintFlags.SUBJECT,
        subjects=[FROM_CA.signing_cert, SELF_SIGN.signing_cert],
    )
    scc.satisfied_by(FROM_CA.signing_cert, None)
    with pytest.raises(UnacceptableSignerError):
        scc.satisfied_by(DUMMY_TS.tsa_cert, None)

    scc = fields.SigCertConstraints(
        subjects=[FROM_CA.signing_cert, SELF_SIGN.signing_cert]
    )
    scc.satisfied_by(FROM_CA.signing_cert, None)
    scc.satisfied_by(DUMMY_TS.tsa_cert, None)


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_cert_constraint_issuer(requests_mock):
    vc = live_testing_vc(requests_mock)
    signer_validation_path = await CertificateValidator(
        FROM_CA.signing_cert, FROM_CA.cert_registry, validation_context=vc
    ).async_validate_usage(set())
    tsa_validation_path = await CertificateValidator(
        DUMMY_TS.tsa_cert, FROM_CA.cert_registry, validation_context=vc
    ).async_validate_usage(set())

    scc = fields.SigCertConstraints(
        flags=fields.SigCertConstraintFlags.ISSUER, issuers=[ROOT_CERT]
    )
    scc.satisfied_by(FROM_CA.signing_cert, signer_validation_path)
    scc.satisfied_by(DUMMY_TS.tsa_cert, tsa_validation_path)
    with pytest.raises(UnacceptableSignerError):
        scc.satisfied_by(FROM_CA.signing_cert, None)

    scc = fields.SigCertConstraints(
        flags=fields.SigCertConstraintFlags.ISSUER, issuers=[INTERM_CERT]
    )
    scc.satisfied_by(FROM_CA.signing_cert, signer_validation_path)
    with pytest.raises(UnacceptableSignerError):
        scc.satisfied_by(DUMMY_TS.tsa_cert, tsa_validation_path)

    scc = fields.SigCertConstraints(
        flags=fields.SigCertConstraintFlags.ISSUER,
        issuers=[INTERM_CERT, SELF_SIGN.signing_cert],
    )
    scc.satisfied_by(FROM_CA.signing_cert, signer_validation_path)
    with pytest.raises(UnacceptableSignerError):
        scc.satisfied_by(DUMMY_TS.tsa_cert, tsa_validation_path)

    scc = fields.SigCertConstraints(issuers=[INTERM_CERT])
    scc.satisfied_by(FROM_CA.signing_cert, signer_validation_path)
    scc.satisfied_by(DUMMY_TS.tsa_cert, tsa_validation_path)


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_cert_constraint_composite(requests_mock):
    vc = live_testing_vc(requests_mock)
    signer_validation_path = await CertificateValidator(
        FROM_CA.signing_cert, FROM_CA.cert_registry, validation_context=vc
    ).async_validate_usage(set())
    tsa_validation_path = await CertificateValidator(
        DUMMY_TS.tsa_cert, FROM_CA.cert_registry, validation_context=vc
    ).async_validate_usage(set())

    scc = fields.SigCertConstraints(
        flags=fields.SigCertConstraintFlags.ISSUER
        | fields.SigCertConstraintFlags.SUBJECT_DN,
        issuers=[INTERM_CERT],
        subject_dn=x509.Name.build(
            {'common_name': 'Alice', 'country_name': 'BE'}
        ),
    )
    scc.satisfied_by(FROM_CA.signing_cert, signer_validation_path)
    with pytest.raises(UnacceptableSignerError):
        scc.satisfied_by(DUMMY_TS.tsa_cert, tsa_validation_path)

    scc = fields.SigCertConstraints(
        flags=fields.SigCertConstraintFlags.ISSUER
        | fields.SigCertConstraintFlags.SUBJECT_DN,
        issuers=[INTERM_CERT],
        subject_dn=x509.Name.build(
            {'common_name': 'Alice & Bob', 'country_name': 'BE'}
        ),
    )
    with pytest.raises(UnacceptableSignerError):
        scc.satisfied_by(FROM_CA.signing_cert, signer_validation_path)


def prepare_sv_field(sv_spec, add_field_lock=False):
    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))

    if add_field_lock:
        sp = fields.SigFieldSpec(
            'Sig',
            seed_value_dict=sv_spec,
            field_mdp_spec=fields.FieldMDPSpec(
                fields.FieldMDPAction.INCLUDE, fields=['blah']
            ),
            doc_mdp_update_value=fields.MDPPerm.NO_CHANGES,
        )
    else:
        sp = fields.SigFieldSpec('Sig', seed_value_dict=sv_spec)
    fields.append_signature_field(w, sp)
    out = BytesIO()
    w.write(out)
    out.seek(0)
    return out


async def sign_with_sv(
    sv_spec,
    sig_meta,
    signer=FROM_CA,
    timestamper=DUMMY_TS,
    *,
    test_violation=False,
    add_field_lock=False,
):
    w = IncrementalPdfFileWriter(
        prepare_sv_field(sv_spec, add_field_lock=add_field_lock)
    )

    pdf_signer = signers.PdfSigner(sig_meta, signer, timestamper=timestamper)
    pdf_signer._ignore_sv = test_violation
    out = await pdf_signer.async_sign_pdf(w)
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    status = await async_validate_pdf_signature(s, dummy_ocsp_vc())
    summary = status.pretty_print_details()
    if test_violation:
        assert 'not satisfy the SV constraints' in summary
        assert not status.seed_value_ok
    else:
        assert 'no SV issues' in summary
        assert status.seed_value_ok
    return EmbeddedPdfSignature(r, s.sig_field, s.fq_name)


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_sv_sign_md_req():
    sv = fields.SigSeedValueSpec(
        flags=fields.SigSeedValFlags.DIGEST_METHOD,
        digest_methods=['sha256', 'sha512'],
    )
    with pytest.raises(SigningError):
        await sign_with_sv(
            sv,
            signers.PdfSignatureMetadata(md_algorithm='sha1', field_name='Sig'),
        )
    await sign_with_sv(
        sv,
        signers.PdfSignatureMetadata(md_algorithm='sha1', field_name='Sig'),
        test_violation=True,
    )
    emb_sig = await sign_with_sv(
        sv, signers.PdfSignatureMetadata(field_name='Sig')
    )
    assert emb_sig.md_algorithm == 'sha256'
    emb_sig = await sign_with_sv(
        sv,
        signers.PdfSignatureMetadata(md_algorithm='sha512', field_name='Sig'),
    )
    assert emb_sig.md_algorithm == 'sha512'


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_sv_sign_md_hint():
    sv = fields.SigSeedValueSpec(digest_methods=['sha256', 'sha512'])
    emb_sig = await sign_with_sv(
        sv, signers.PdfSignatureMetadata(md_algorithm='sha1', field_name='Sig')
    )
    assert emb_sig.md_algorithm == 'sha1'
    emb_sig = await sign_with_sv(
        sv, signers.PdfSignatureMetadata(field_name='Sig')
    )
    assert emb_sig.md_algorithm == 'sha256'
    emb_sig = await sign_with_sv(
        sv,
        signers.PdfSignatureMetadata(md_algorithm='sha512', field_name='Sig'),
    )
    assert emb_sig.md_algorithm == 'sha512'


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_sv_sign_subfilter_req():
    sv = fields.SigSeedValueSpec(
        flags=fields.SigSeedValFlags.SUBFILTER, subfilters=[PADES]
    )
    with pytest.raises(SigningError):
        await sign_with_sv(
            sv,
            signers.PdfSignatureMetadata(
                md_algorithm='sha1',
                field_name='Sig',
                subfilter=fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED,
            ),
        )
    await sign_with_sv(
        sv,
        signers.PdfSignatureMetadata(
            md_algorithm='sha1',
            field_name='Sig',
            subfilter=fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED,
        ),
        test_violation=True,
    )
    emb_sig = await sign_with_sv(
        sv, signers.PdfSignatureMetadata(field_name='Sig')
    )
    assert emb_sig.sig_object['/SubFilter'] == PADES.value


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_sv_sign_subfilter_hint():
    sv = fields.SigSeedValueSpec(subfilters=[PADES])
    emb_sig = await sign_with_sv(
        sv,
        signers.PdfSignatureMetadata(
            md_algorithm='sha1',
            field_name='Sig',
            subfilter=fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED,
        ),
    )
    assert emb_sig.sig_object['/SubFilter'] == '/adbe.pkcs7.detached'
    emb_sig = await sign_with_sv(
        sv, signers.PdfSignatureMetadata(field_name='Sig')
    )
    assert emb_sig.sig_object['/SubFilter'] == PADES.value


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_sv_sign_addrevinfo_req(requests_mock):
    sv = fields.SigSeedValueSpec(
        flags=fields.SigSeedValFlags.ADD_REV_INFO, add_rev_info=True
    )
    vc = live_testing_vc(requests_mock)
    meta = signers.PdfSignatureMetadata(
        field_name='Sig',
        validation_context=vc,
        subfilter=fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED,
        embed_validation_info=True,
    )
    emb_sig = await sign_with_sv(sv, meta)
    status = await async_validate_pdf_ltv_signature(
        emb_sig,
        RevocationInfoValidationType.ADOBE_STYLE,
        {'trust_roots': TRUST_ROOTS},
    )
    assert status.valid and status.trusted
    assert emb_sig.sig_object['/SubFilter'] == '/adbe.pkcs7.detached'

    meta = signers.PdfSignatureMetadata(
        field_name='Sig',
        validation_context=vc,
        subfilter=fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED,
        embed_validation_info=False,
    )
    with pytest.raises(SigningError):
        await sign_with_sv(sv, meta)
    await sign_with_sv(sv, meta, test_violation=True)
    meta = signers.PdfSignatureMetadata(
        field_name='Sig',
        validation_context=vc,
        subfilter=fields.SigSeedSubFilter.PADES,
        embed_validation_info=True,
    )
    # this shouldn't work with PAdES
    with pytest.raises(SigningError):
        await sign_with_sv(sv, meta)
    await sign_with_sv(sv, meta, test_violation=True)


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_sv_sign_addrevinfo_subfilter_conflict():
    sv = fields.SigSeedValueSpec(
        flags=fields.SigSeedValFlags.ADD_REV_INFO,
        subfilters=[PADES],
        add_rev_info=True,
    )
    with pytest.raises(SigningError):
        meta = signers.PdfSignatureMetadata(
            field_name='Sig',
            validation_context=dummy_ocsp_vc(),
            embed_validation_info=True,
        )
        await sign_with_sv(sv, meta)

    revinfo_and_subfilter = (
        fields.SigSeedValFlags.ADD_REV_INFO | fields.SigSeedValFlags.SUBFILTER
    )
    sv = fields.SigSeedValueSpec(
        flags=revinfo_and_subfilter, subfilters=[PADES], add_rev_info=True
    )
    meta = signers.PdfSignatureMetadata(
        field_name='Sig',
        validation_context=dummy_ocsp_vc(),
        embed_validation_info=True,
    )
    with pytest.raises(SigningError):
        await sign_with_sv(sv, meta)
    await sign_with_sv(sv, meta, test_violation=True)

    sv = fields.SigSeedValueSpec(
        flags=revinfo_and_subfilter, subfilters=[PADES], add_rev_info=False
    )
    meta = signers.PdfSignatureMetadata(
        field_name='Sig',
        validation_context=dummy_ocsp_vc(),
    )
    await sign_with_sv(sv, meta)


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_add_revinfo_wrong_subfilter():
    sv = fields.SigSeedValueSpec(
        flags=fields.SigSeedValFlags.ADD_REV_INFO, add_rev_info=True
    )

    sig_field_spec = fields.SigFieldSpec(
        sig_field_name='Sig',
        seed_value_dict=sv,
    )

    w = IncrementalPdfFileWriter(BytesIO(MINIMAL))
    fields.append_signature_field(w, sig_field_spec)

    cms_writer = cms_embedder.PdfCMSEmbedder().write_cms(
        field_name='Sig', writer=w
    )
    next(cms_writer)
    # wrong subfilter: PAdES
    #  but we do embed an (empty) RevInfoArchival attribute
    sig_obj = signers.SignatureObject(bytes_reserved=8192, subfilter=PADES)

    cms_writer.send(cms_embedder.SigObjSetup(sig_placeholder=sig_obj))

    prep_digest, output = cms_writer.send(
        cms_embedder.SigIOSetup(md_algorithm='sha256', in_place=True)
    )
    cms_obj = await FROM_CA.async_sign(
        data_digest=prep_digest.document_digest,
        digest_algorithm='sha256',
        signed_attr_settings=PdfCMSSignedAttributes(
            # empty
            adobe_revinfo_attr=asn1_pdf.RevocationInfoArchival({'ocsp': []})
        ),
    )
    await PdfTBSDocument.async_finish_signing(output, prep_digest, cms_obj)
    r = PdfFileReader(output)
    s = r.embedded_signatures[0]
    status = await async_validate_pdf_signature(s, dummy_ocsp_vc())
    summary = status.pretty_print_details()
    assert status.intact and status.valid
    assert 'not satisfy the SV constraints' in summary
    assert 'requires subfilter' in status.seed_value_constraint_error.args[0]
    assert not status.seed_value_ok


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_sv_sign_cert_constraint():
    # this is more thoroughly unit tested at a lower level (see further up),
    # so we simply try two basic scenarios here for now
    sv = fields.SigSeedValueSpec(
        cert=fields.SigCertConstraints(
            flags=fields.SigCertConstraintFlags.SUBJECT_DN,
            subject_dn=x509.Name.build({'common_name': 'Alice'}),
        )
    )
    await sign_with_sv(sv, signers.PdfSignatureMetadata(field_name='Sig'))
    sv = fields.SigSeedValueSpec(
        cert=fields.SigCertConstraints(
            flags=fields.SigCertConstraintFlags.SUBJECT_DN,
            subject_dn=x509.Name.build({'common_name': 'Not Alice'}),
        )
    )
    with pytest.raises(SigningError):
        await sign_with_sv(sv, signers.PdfSignatureMetadata(field_name='Sig'))
    await sign_with_sv(
        sv, signers.PdfSignatureMetadata(field_name='Sig'), test_violation=True
    )


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_sv_flag_unsupported():
    sv = fields.SigSeedValueSpec(
        flags=(
            fields.SigSeedValFlags.LEGAL_ATTESTATION
            | fields.SigSeedValFlags.APPEARANCE_FILTER
        ),
        legal_attestations=['abc'],
        appearance='test',
    )
    meta = signers.PdfSignatureMetadata(field_name='Sig')
    with pytest.raises(NotImplementedError):
        await sign_with_sv(sv, meta, test_violation=True)


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_sv_cert_flag_unsupported():
    sv = fields.SigSeedValueSpec(
        cert=fields.SigCertConstraints(
            flags=fields.SigCertConstraintFlags.RESERVED,
        )
    )
    meta = signers.PdfSignatureMetadata(field_name='Sig')
    with pytest.raises(NotImplementedError):
        await sign_with_sv(sv, meta)


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_sv_flag_appearance_required():
    sv = fields.SigSeedValueSpec(
        flags=fields.SigSeedValFlags.APPEARANCE_FILTER, appearance='test'
    )
    meta = signers.PdfSignatureMetadata(field_name='Sig')
    with pytest.raises(SigningError):
        await sign_with_sv(sv, meta)


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_sv_mdp_no_certify():
    sv = fields.SigSeedValueSpec(
        seed_signature_type=fields.SeedSignatureType(),
    )
    meta = signers.PdfSignatureMetadata(field_name='Sig')
    await sign_with_sv(sv, meta)

    meta = signers.PdfSignatureMetadata(field_name='Sig', certify=True)
    with pytest.raises(SigningError):
        await sign_with_sv(sv, meta)

    meta = signers.PdfSignatureMetadata(field_name='Sig', certify=True)
    await sign_with_sv(sv, meta, test_violation=True)


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_sv_mdp_must_certify():
    sv = fields.SigSeedValueSpec(
        seed_signature_type=fields.SeedSignatureType(fields.MDPPerm.FILL_FORMS),
    )
    meta = signers.PdfSignatureMetadata(field_name='Sig', certify=True)
    await sign_with_sv(sv, meta)

    meta = signers.PdfSignatureMetadata(field_name='Sig')
    with pytest.raises(SigningError):
        await sign_with_sv(sv, meta)

    meta = signers.PdfSignatureMetadata(field_name='Sig')
    await sign_with_sv(sv, meta, test_violation=True)

    meta = signers.PdfSignatureMetadata(
        field_name='Sig',
        certify=True,
        docmdp_permissions=fields.MDPPerm.NO_CHANGES,
    )
    await sign_with_sv(sv, meta, test_violation=True)


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_sv_mdp_must_certify_wrong_docmdp():
    sv = fields.SigSeedValueSpec(
        seed_signature_type=fields.SeedSignatureType(fields.MDPPerm.FILL_FORMS),
    )
    meta = signers.PdfSignatureMetadata(
        field_name='Sig',
        certify=True,
        docmdp_permissions=fields.MDPPerm.NO_CHANGES,
    )
    with pytest.raises(SigningError):
        await sign_with_sv(sv, meta)


@freeze_time('2020-11-01')
def test_sv_subfilter_unsupported():
    sv_spec = fields.SigSeedValueSpec(
        flags=fields.SigSeedValFlags.SUBFILTER, subfilters=[PADES]
    )
    w = IncrementalPdfFileWriter(prepare_sv_field(sv_spec))
    field_name, _, sig_field = next(fields.enumerate_sig_fields(w))
    sig_field = sig_field.get_object()
    sv_ref = sig_field.raw_get('/SV')
    w.mark_update(sv_ref)
    sv_ref.get_object()['/SubFilter'][0] = pdf_name('/this.doesnt.exist')
    out = BytesIO()
    w.write(out)
    out.seek(0)
    frozen = out.getvalue()

    with pytest.raises(NotImplementedError):
        signers.sign_pdf(
            IncrementalPdfFileWriter(BytesIO(frozen)),
            signers.PdfSignatureMetadata(field_name='Sig'),
            signer=FROM_CA,
            timestamper=DUMMY_TS,
        )
    with pytest.raises(NotImplementedError):
        signers.sign_pdf(
            IncrementalPdfFileWriter(BytesIO(frozen)),
            signers.PdfSignatureMetadata(field_name='Sig', subfilter=PADES),
            signer=FROM_CA,
            timestamper=DUMMY_TS,
        )


@freeze_time('2020-11-01')
def test_sv_subfilter_unsupported_partial():
    sv_spec = fields.SigSeedValueSpec(
        flags=fields.SigSeedValFlags.SUBFILTER,
        subfilters=[fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED, PADES],
    )
    w = IncrementalPdfFileWriter(prepare_sv_field(sv_spec))
    field_name, _, sig_field = next(fields.enumerate_sig_fields(w))
    sig_field = sig_field.get_object()
    sv_ref = sig_field.raw_get('/SV')
    w.mark_update(sv_ref)
    sv_ref.get_object()['/SubFilter'][0] = pdf_name('/this.doesnt.exist')
    out = BytesIO()
    w.write(out)
    out.seek(0)
    frozen = out.getvalue()

    signers.sign_pdf(
        IncrementalPdfFileWriter(BytesIO(frozen)),
        signers.PdfSignatureMetadata(field_name='Sig'),
        signer=FROM_CA,
        timestamper=DUMMY_TS,
    )
    with pytest.raises(SigningError):
        signers.sign_pdf(
            IncrementalPdfFileWriter(BytesIO(frozen)),
            signers.PdfSignatureMetadata(
                field_name='Sig',
                subfilter=fields.SigSeedSubFilter.ADOBE_PKCS7_DETACHED,
            ),
            signer=FROM_CA,
            timestamper=DUMMY_TS,
        )


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_sv_timestamp_url(requests_mock):
    # state issues (see comment in signers.py), so create a fresh signer
    sv = fields.SigSeedValueSpec(
        timestamp_server_url=DUMMY_HTTP_TS.url, timestamp_required=True
    )
    meta = signers.PdfSignatureMetadata(field_name='Sig')
    ts_requested = False

    def ts_callback(*args, **kwargs):
        nonlocal ts_requested
        ts_requested = True
        return ts_response_callback(*args, **kwargs)

    requests_mock.post(
        DUMMY_HTTP_TS.url,
        content=ts_callback,
        headers={'Content-Type': 'application/timestamp-reply'},
    )
    # noinspection PyTypeChecker
    await sign_with_sv(sv, meta, timestamper=None)
    assert ts_requested


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_sv_sign_reason_req():
    sv = fields.SigSeedValueSpec(
        flags=fields.SigSeedValFlags.REASONS,
        reasons=['I agree', 'Works for me'],
    )
    aw_yiss = signers.PdfSignatureMetadata(reason='Aw yiss', field_name='Sig')
    with pytest.raises(SigningError):
        await sign_with_sv(sv, aw_yiss)
    await sign_with_sv(sv, aw_yiss, test_violation=True)

    with pytest.raises(SigningError):
        await sign_with_sv(sv, signers.PdfSignatureMetadata(field_name='Sig'))
    await sign_with_sv(
        sv, signers.PdfSignatureMetadata(field_name='Sig'), test_violation=True
    )

    emb_sig = await sign_with_sv(
        sv, signers.PdfSignatureMetadata(field_name='Sig', reason='I agree')
    )
    assert emb_sig.sig_object['/Reason'] == 'I agree'


@freeze_time('2020-11-01')
@pytest.mark.parametrize('reasons_param', [None, [], ["."]])
@pytest.mark.asyncio
async def test_sv_sign_reason_prohibited(reasons_param):
    sv = fields.SigSeedValueSpec(
        flags=fields.SigSeedValFlags.REASONS, reasons=reasons_param
    )
    aw_yiss = signers.PdfSignatureMetadata(reason='Aw yiss', field_name='Sig')
    with pytest.raises(SigningError):
        await sign_with_sv(sv, aw_yiss)
    await sign_with_sv(sv, aw_yiss, test_violation=True)

    dot = signers.PdfSignatureMetadata(reason='.', field_name='Sig')
    with pytest.raises(SigningError):
        await sign_with_sv(sv, dot)
    await sign_with_sv(sv, dot, test_violation=True)

    emb_sig = await sign_with_sv(
        sv, signers.PdfSignatureMetadata(field_name='Sig')
    )
    assert pdf_name('/Reason') not in emb_sig.sig_object


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_sv_lock_certify():
    sv = fields.SigSeedValueSpec(
        flags=fields.SigSeedValFlags.LOCK_DOCUMENT,
        lock_document=fields.SeedLockDocument.LOCK,
    )
    meta = signers.PdfSignatureMetadata(
        field_name='Sig',
        certify=True,
        docmdp_permissions=fields.MDPPerm.NO_CHANGES,
    )
    await sign_with_sv(sv, meta)

    meta = signers.PdfSignatureMetadata(field_name='Sig', certify=True)
    await sign_with_sv(sv, meta)
    await sign_with_sv(sv, meta, test_violation=True)

    meta = signers.PdfSignatureMetadata(
        field_name='Sig',
        certify=True,
        docmdp_permissions=fields.MDPPerm.ANNOTATE,
    )
    await sign_with_sv(sv, meta)
    await sign_with_sv(sv, meta, test_violation=True)

    meta = signers.PdfSignatureMetadata(field_name='Sig')
    await sign_with_sv(sv, meta)


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_sv_no_lock_certify():
    sv = fields.SigSeedValueSpec(
        flags=fields.SigSeedValFlags.LOCK_DOCUMENT,
        lock_document=fields.SeedLockDocument.DO_NOT_LOCK,
    )
    meta = signers.PdfSignatureMetadata(
        field_name='Sig',
        certify=True,
        docmdp_permissions=fields.MDPPerm.FILL_FORMS,
    )
    await sign_with_sv(sv, meta)

    meta = signers.PdfSignatureMetadata(
        field_name='Sig',
        certify=True,
        docmdp_permissions=fields.MDPPerm.ANNOTATE,
    )
    await sign_with_sv(sv, meta)

    meta = signers.PdfSignatureMetadata(
        field_name='Sig',
        certify=True,
    )
    await sign_with_sv(sv, meta)

    meta = signers.PdfSignatureMetadata(field_name='Sig')
    await sign_with_sv(sv, meta)

    meta = signers.PdfSignatureMetadata(
        field_name='Sig',
        certify=True,
        docmdp_permissions=fields.MDPPerm.NO_CHANGES,
    )
    await sign_with_sv(sv, meta, test_violation=True)


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_field_lock_compat():
    sv = fields.SigSeedValueSpec(
        flags=fields.SigSeedValFlags.LOCK_DOCUMENT,
        lock_document=fields.SeedLockDocument.LOCK,
    )
    meta = signers.PdfSignatureMetadata(field_name='Sig')
    await sign_with_sv(sv, meta, add_field_lock=True)

    sv = fields.SigSeedValueSpec(
        flags=fields.SigSeedValFlags.LOCK_DOCUMENT,
        lock_document=fields.SeedLockDocument.DO_NOT_LOCK,
    )
    meta = signers.PdfSignatureMetadata(field_name='Sig')
    with pytest.raises(SigningError):
        await sign_with_sv(sv, meta, add_field_lock=True)


@freeze_time('2020-11-01')
@pytest.mark.parametrize(
    'must_have_set, forbidden_set, as_string',
    [
        ({'digital_signature', 'crl_sign'}, set(), '1XXXXX1XX'),
        (set(), {'digital_signature', 'crl_sign'}, '0XXXXX0XX'),
        (
            {'digital_signature', 'non_repudiation'},
            {'data_encipherment'},
            '11X0XXXXX',
        ),
    ],
)
def test_key_usage_decode(must_have_set, forbidden_set, as_string):
    ku_from_str = fields.SigCertKeyUsage.read_from_sv_string(as_string)
    assert ku_from_str.must_have_set() == must_have_set
    assert ku_from_str.forbidden_set() == forbidden_set
    assert ku_from_str.encode_to_sv_string() == as_string


def test_key_usage_decode_tolerance():
    empty_ku = fields.SigCertKeyUsage.read_from_sv_string('')
    assert not empty_ku.must_have_set()
    assert not empty_ku.forbidden_set()

    too_long_ku = fields.SigCertKeyUsage.read_from_sv_string('100XX1XX0XX11X')
    assert too_long_ku.must_have_set() == {'digital_signature', 'key_cert_sign'}
    assert too_long_ku.forbidden_set() == {
        'non_repudiation',
        'key_encipherment',
        'decipher_only',
    }


def test_cert_constraint_deserialisation():
    signer1 = FROM_CA.signing_cert
    signer2 = SELF_SIGN.signing_cert
    constr = fields.SigCertConstraints(subjects=[signer1, signer2])
    constr_parsed = fields.SigCertConstraints.from_pdf_object(
        constr.as_pdf_object()
    )
    signer1_parsed, signer2_parsed = constr_parsed.subjects
    assert signer1_parsed.dump() == signer1.dump()
    assert signer2_parsed.dump() == signer2.dump()
    assert not constr_parsed.issuers

    issuer1 = FROM_CA.signing_cert
    issuer2 = SELF_SIGN.signing_cert
    constr = fields.SigCertConstraints(issuers=[issuer1, issuer2])
    constr_parsed = fields.SigCertConstraints.from_pdf_object(
        constr.as_pdf_object()
    )
    issuer1_parsed, issuer2_parsed = constr_parsed.issuers
    assert issuer1_parsed.dump() == issuer1.dump()
    assert issuer2_parsed.dump() == issuer2.dump()
    assert not constr_parsed.subjects

    constr = fields.SigCertConstraints(subject_dn=signer1.subject)
    constr_ser = constr.as_pdf_object()
    assert '/C' in constr_ser['/SubjectDN'][0]
    constr_parsed = fields.SigCertConstraints.from_pdf_object(constr_ser)
    assert constr_parsed.subject_dn == signer1.subject


@freeze_time('2020-11-01')
@pytest.mark.asyncio
async def test_sign_with_sv_missing_cert():
    w = IncrementalPdfFileWriter(
        prepare_sv_field(
            fields.SigSeedValueSpec(
                cert=fields.SigCertConstraints(
                    flags=fields.SigCertConstraintFlags.SUBJECT_DN,
                    subject_dn=x509.Name.build({'common_name': 'Alice'}),
                )
            ),
        )
    )

    pdf_signer = signers.PdfSigner(
        signers.PdfSignatureMetadata(),
        signers.ExternalSigner(
            signing_cert=None,
            cert_registry=None,
            signature_value=256,
            signature_mechanism=algos.SignedDigestAlgorithm(
                {'algorithm': 'sha256_rsa'}
            ),
        ),
    )

    with pytest.raises(
        SigningError, match="Cannot verify seed value.*certificate"
    ):
        await pdf_signer.async_sign_pdf(
            w, existing_fields_only=True, bytes_reserved=8192
        )
