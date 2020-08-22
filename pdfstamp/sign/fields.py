from dataclasses import dataclass
from enum import IntFlag
from io import BytesIO
from typing import List, Optional

from asn1crypto import x509

from pdf_utils import generic
from pdf_utils.generic import pdf_name, pdf_string
from pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pdf_utils.reader import PdfFileReader

# TODO support other seed value dict entries
# TODO add more customisability appearance-wise
from pdfstamp.stamp import AnnotAppearances


class SigSeedValFlags(IntFlag):
    """
    Flags for the /Ff entry in the seed value dictionary for a dictionary field.
    These mark which of the constraints are to be strictly enforced, as opposed
    to optional ones.
    Note: not all constraint types (and hence not all flags) are supported by
    this library.
    """

    FILTER = 1
    SUBFILTER = 2
    V = 4
    REASONS = 8
    LEGAL_ATTESTATION = 16
    ADD_REV_INFO = 32
    DIGEST_METHOD = 64


class SigCertConstraintFlags:
    """
    Flags for the /Ff entry in the certificate seed value dictionary for
    a dictionary field. These mark which of the constraints are to be
    strictly enforced, as opposed to optional ones.
    """

    SUBJECT = 1
    ISSUER = 2
    OID = 4
    SUBJECT_DN = 8
    RESERVED = 16
    KEY_USAGE = 32
    URL = 64


def x509_name_keyval_pairs(name: x509.Name):
    rdns: x509.RDNSequence = name.chosen
    for rdn in rdns:
        for type_and_value in rdn:
            oid: x509.NameType = type_and_value['type']
            # these are all some kind of string, and the PDF
            # standard says that the value should be a text string object,
            # so we just have asn1crypto convert everything to strings
            value = type_and_value['value']
            yield oid.dotted, value.native
            # these should be strings


@dataclass(frozen=True)
class SigCertConstraints:
    """
    See Table 235 in ISO 32000-1
    """
    flags: SigCertConstraintFlags = 0
    subjects: List[x509.Certificate] = None
    subject_dns: List[x509.Name] = None
    issuers: List[x509.Certificate] = None
    info_url: str = None
    url_type: generic.NameObject = pdf_name('/Browser')

    # TODO support key usage and OID constraints

    def as_pdf_object(self):
        result = generic.DictionaryObject({
            pdf_name('/Type'): pdf_name('/SVCert'),
            pdf_name('/Ff'): generic.NumberObject(self.flags),
        })
        if self.subjects is not None:
            result[pdf_name('/Subject')] = generic.ArrayObject(
                generic.ByteStringObject(cert.dump())
                for cert in self.subjects
            )
        if self.subject_dns is not None:
            # FIXME Adobe Reader seems to ignore this for some reason.
            #  Should try to figure out what I'm doing wrong
            result[pdf_name('/SubjectDN')] = generic.ArrayObject(
                generic.DictionaryObject({
                    pdf_name('/' + oid): pdf_string(value)
                    for oid, value in x509_name_keyval_pairs(subj_dn)
                }) for subj_dn in self.subject_dns
            )
        if self.issuers is not None:
            result[pdf_name('/Issuer')] = generic.ArrayObject(
                generic.ByteStringObject(cert.dump())
                for cert in self.issuers
            )
        if self.info_url is not None:
            result[pdf_name('/URL')] = pdf_string(self.info_url)
            result[pdf_name('/URLType')] = self.url_type

        return result


@dataclass(frozen=True)
class SigSeedValueSpec:
    flags: SigSeedValFlags = 0
    reasons: List[str] = None
    timestamp_server_url: str = None
    cert: SigCertConstraints = None

    def as_pdf_object(self):
        result = generic.DictionaryObject({
            pdf_name('/Type'): pdf_name('/SV'),
            pdf_name('/Ff'): generic.NumberObject(self.flags),
        })
        if self.reasons is not None:
            result[pdf_name('/Reasons')] = generic.ArrayObject(
                pdf_string(reason) for reason in self.reasons
            )
        if self.timestamp_server_url is not None:
            result[pdf_name('/TimeStamp')] = generic.DictionaryObject({
                pdf_name('/URL'): pdf_string(self.timestamp_server_url),
                # why would you bother including a TSA URL and then make the
                # timestamp optional?
                pdf_name('/Ff'): generic.NumberObject(1)
            })
        if self.cert is not None:
            result[pdf_name('/Cert')] = self.cert.as_pdf_object()
        return result


@dataclass(frozen=True)
class SigFieldSpec:
    sig_field_name: str
    on_page: int = 0
    box: (int, int, int, int) = None
    seed_value_dict: SigSeedValueSpec = None

    @property
    def dimensions(self):
        if self.box is not None:
            x1, y1, x2, y2 = self.box
            return abs(x1 - x2), abs(y1 - y2)


def _prepare_sig_field(sig_field_name, root,
                       update_writer: IncrementalPdfFileWriter,
                       existing_fields_only=False, lock_sig_flags=True,
                       **kwargs):
    if sig_field_name is None:
        raise ValueError

    # Holds a reference to the object containing our form field
    # that we'll have to update IF we create a new form field.
    # In typical situations, this is either the
    # /AcroForm object itself (when its /Fields are a flat, direct array),
    # or whatever /Fields points to.
    field_container_ref = None
    try:
        form_ref = root.raw_get('/AcroForm')

        if isinstance(form_ref, generic.IndirectObject):
            # The /AcroForm exists and is indirect. Hence, we may need to write
            # an update if we end up having to add the signature field
            form = form_ref.get_object()
        else:
            # the form is a direct object, so we'll replace it with
            # an indirect one, and mark the root to be updated
            # (I think this is fairly rare, but requires testing!)
            form = form_ref
            # if updates are not active, we forgo the replacement
            #  operation; in this case, one should only update the
            #  referenced form field anyway.
            # this creates a new xref
            form_ref = update_writer.add_object(form)
            root[pdf_name('/AcroForm')] = form_ref
            update_writer.update_root()
        # try to extend the existing form object first
        # and mark it for an update if necessary
        try:
            fields_ref = form.raw_get('/Fields')
            if isinstance(fields_ref, generic.IndirectObject):
                field_container_ref = fields_ref
                fields = fields_ref.get_object()
            else:
                fields = fields_ref
                # /Fields is directly embedded into form_ref, so that's
                # what we'll have to update if we create a new field
                field_container_ref = form_ref
        except KeyError:
            # shouldn't happen, but eh
            fields = generic.ArrayObject()
            field_container_ref = form_ref
            form[pdf_name('/Fields')] = fields

        candidates = enumerate_sig_fields_in(fields, with_name=sig_field_name)
        sig_field_ref = None
        try:
            field_name, value, sig_field_ref = next(candidates)
            if value is not None:
                raise ValueError(
                    'Signature field with name %s appears to be filled already.'
                    % sig_field_name
                )
        except StopIteration:
            if existing_fields_only:
                raise ValueError(
                    'No empty signature field with name %s found.'
                    % sig_field_name
                )
    except KeyError:
        # we have to create the form
        if existing_fields_only:
            raise ValueError('This file does not contain a form.')
        # no AcroForm present, so create one
        form = generic.DictionaryObject()
        root[pdf_name('/AcroForm')] = update_writer.add_object(form)
        fields = generic.ArrayObject()
        form[pdf_name('/Fields')] = fields
        # now we need to mark the root as updated
        update_writer.update_root()
        sig_field_ref = None

    field_created = sig_field_ref is None
    if field_created:
        # no signature field exists, so create one
        if existing_fields_only:
            raise ValueError('Could not find signature field')
        sig_form_kwargs = {
            'include_on_page': root['/Pages']['/Kids'][0],
        }
        sig_form_kwargs.update(**kwargs)
        sig_field = SignatureFormField(
            sig_field_name, writer=update_writer, **sig_form_kwargs
        )
        sig_field_ref = sig_field.reference
        fields.append(sig_field_ref)

        # make sure /SigFlags is present. If not, create it
        sig_flags = 3 if lock_sig_flags else 1
        form.setdefault(pdf_name('/SigFlags'), generic.NumberObject(sig_flags))
        # if we're adding a field to an existing form, this requires
        # registering an extra update
        if field_container_ref is not None:
            update_writer.mark_update(field_container_ref)

    return field_created, sig_field_ref


def enumerate_sig_fields(reader: PdfFileReader, filled_status=None):
    """
    Enumerate signature fields.

    :param reader:
        The PDF reader to operate on.
    :param filled_status:
        Optional boolean. If True (resp. False) then all filled (resp. empty)
        fields are returned. If left None (the default), then all fields
        are returned.
    :return:
        A generator producing signature fields.
    """

    root = reader.trailer['/Root']
    try:
        form = root['/AcroForm']
        fields = form['/Fields']
    except KeyError:
        return

    yield from enumerate_sig_fields_in(fields, filled_status)


def enumerate_sig_fields_in(field_list, filled_status=None, with_name=None):
    ft_sig = pdf_name('/Sig')
    for field_ref in field_list:
        # TODO the spec mandates this, but perhaps we should be a bit more
        #  tolerant
        assert isinstance(field_ref, generic.IndirectObject)
        field = field_ref.get_object()
        # /T is the field name. Required entry, but you never know.
        try:
            field_name = field['/T']
        except KeyError:
            continue
        field_type = field.get('/FT')
        if field_type != ft_sig:
            if with_name is not None and field_name == with_name:
                raise ValueError(
                    'Field with name %s exists but is not a signature field'
                    % field_name
                )
            continue
        field_value = field.get('/V')
        # "cast" to a regular string object
        filled = field_value is not None
        status_check = filled_status is None or filled == filled_status
        name_check = with_name is None or with_name == field_name
        if status_check and name_check:
            yield str(field_name), field_value, field_ref

        try:
            yield from enumerate_sig_fields_in(field['/Kids'])
        except KeyError:
            continue


def append_signature_fields(pdf_out: IncrementalPdfFileWriter,
                            sig_field_specs: List[SigFieldSpec]):
    root = pdf_out.root

    page_list = root['/Pages']['/Kids']
    for sp in sig_field_specs:
        # use default appearance
        field_created, sig_field_ref = _prepare_sig_field(
            sp.sig_field_name, root, update_writer=pdf_out,
            existing_fields_only=False, box=sp.box,
            include_on_page=page_list[sp.on_page]
        )
        if not field_created:
            raise ValueError(
                'Signature field with name %s already exists.'
                % sp.sig_field_name
            )

        if sp.seed_value_dict is not None:
            sig_field = sig_field_ref.get_object()
            # /SV must be an indirect reference as per the spec
            sv_ref = pdf_out.add_object(sp.seed_value_dict.as_pdf_object())
            sig_field[pdf_name('/SV')] = sv_ref

    output = BytesIO()
    pdf_out.write(output)
    output.seek(0)
    return output


class SignatureFormField(generic.DictionaryObject):
    def __init__(self, field_name, include_on_page, *, writer,
                 sig_object_ref=None, box=None,
                 appearances: Optional[AnnotAppearances] = None):

        if box is not None:
            visible = True
            rect = list(map(generic.FloatObject, box))
            if appearances is not None:
                ap = appearances.as_pdf_object()
            else:
                ap = None
        else:
            rect = [generic.FloatObject(0)] * 4
            ap = None
            visible = False

        # this sets the "Print" bit, and activates "Locked" if the
        # signature field is ready to be filled
        flags = 0b100 if sig_object_ref is None else 0b10000100
        super().__init__({
            # Signature field properties
            pdf_name('/FT'): pdf_name('/Sig'),
            pdf_name('/T'): pdf_string(field_name),
            # Annotation properties: bare minimum
            pdf_name('/Type'): pdf_name('/Annot'),
            pdf_name('/Subtype'): pdf_name('/Widget'),
            pdf_name('/F'): generic.NumberObject(flags),
            pdf_name('/P'): include_on_page,
            pdf_name('/Rect'): generic.ArrayObject(rect)
        })
        if sig_object_ref is not None:
            self[pdf_name('/V')] = sig_object_ref
        if ap is not None:
            self[pdf_name('/AP')] = ap

        # register ourselves
        self.reference = self_reference = writer.add_object(self)
        # if we're building an invisible form field, this is all there is to it
        if visible:
            writer.register_annotation(include_on_page, self_reference)