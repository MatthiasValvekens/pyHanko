from dataclasses import dataclass
from enum import IntFlag
from typing import List, Optional

from asn1crypto import x509
from oscrypto import keys as oskeys

from pdf_utils import generic
from pdf_utils.generic import pdf_name, pdf_string
from pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pdf_utils.reader import PdfFileReader
from pdfstamp.stamp import AnnotAppearances

__all__ = [
    'SigSeedValFlags', 'SigCertConstraints', 'SignatureFormField',
    'SigSeedValueSpec', 'SigCertConstraintFlags', 'SigFieldSpec',
    'enumerate_sig_fields_in', 'enumerate_sig_fields',
    '_prepare_sig_field'
]

# TODO support other seed value dict entries
# TODO add more customisability appearance-wise


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


name_type_abbrevs = {
    '2.5.4.3': 'CN',
    '2.5.4.5': 'SerialNumber',
    '2.5.4.6': 'C',
    '2.5.4.7': 'L',
    '2.5.4.8': 'ST',
    '2.5.4.10': 'O',
    '2.5.4.11': 'OU',
}

name_type_abbrevs_rev = {
    v: k for k, v in name_type_abbrevs.items()
}


def x509_name_keyval_pairs(name: x509.Name):
    rdns: x509.RDNSequence = name.chosen
    for rdn in rdns:
        for type_and_value in rdn:
            oid: x509.NameType = type_and_value['type']
            # these are all some kind of string, and the PDF
            # standard says that the value should be a text string object,
            # so we just have asn1crypto convert everything to strings
            value = type_and_value['value']
            key = oid.dotted
            try:
                key = name_type_abbrevs[key]
            except KeyError:
                pass

            yield key, value.native
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

    @classmethod
    def from_pdf_object(cls, pdf_dict):
        try:
            if pdf_dict['/Type'] != '/SVCert':
                raise ValueError('Object /Type entry is not /SVCert')
        except KeyError:
            pass
        flags = pdf_dict.get('/Ff', 0)
        subjects = [
            oskeys.parse_certificate(cert.original_bytes) for cert in
            pdf_dict.get('/Subject', ())
        ]
        issuers = [
            oskeys.parse_certificate(cert.original_bytes) for cert in
            pdf_dict.get('/Issuer', ())
        ]

        def format_attr(attr):
            # strip initial /
            attr = attr[1:]
            # attempt to convert abbreviated attrs to OIDs, since build()
            # takes OIDs
            return name_type_abbrevs_rev.get(attr.upper(), attr)

        subject_dns = [
            x509.Name.build(
                {format_attr(attr): value for attr, value in dn_dir.items()}
            ) for dn_dir in pdf_dict.get('/SubjectDN', ())
        ]

        url = pdf_dict.get('/URL')
        url_type = pdf_dict.get('/URLType')
        kwargs = {
            'flags': flags, 'subjects': subjects, 'subject_dns': subject_dns,
            'issuers': issuers, 'info_url': url
        }
        if url is not None and url_type is not None:
            kwargs['url_type'] = url_type
        return cls(**kwargs)

    def as_pdf_object(self):
        result = generic.DictionaryObject({
            pdf_name('/Type'): pdf_name('/SVCert'),
            pdf_name('/Ff'): generic.NumberObject(self.flags),
        })
        if self.subjects:
            result[pdf_name('/Subject')] = generic.ArrayObject(
                generic.ByteStringObject(cert.dump())
                for cert in self.subjects
            )
        if self.subject_dns:
            # FIXME Adobe Reader seems to ignore this for some reason.
            #  Should try to figure out what I'm doing wrong
            result[pdf_name('/SubjectDN')] = generic.ArrayObject(
                generic.DictionaryObject({
                    pdf_name('/' + key): pdf_string(value)
                    for key, value in x509_name_keyval_pairs(subj_dn)
                }) for subj_dn in self.subject_dns
            )
        if self.issuers:
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


def _prepare_sig_field(sig_field_name, root,
                       update_writer: IncrementalPdfFileWriter,
                       existing_fields_only=False, lock_sig_flags=True,
                       **kwargs):
    """
    Returns a tuple of a boolean and a reference to a signature field.
    The boolean is True if the field was created, and False otherwise.
    """
    if sig_field_name is None:
        raise ValueError

    try:
        form = root['/AcroForm']

        try:
            fields = form['/Fields']
        except KeyError:
            raise ValueError('/AcroForm has no /Fields')

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
        form_created = False
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
        form_created = True
        sig_field_ref = None

    if sig_field_ref is not None:
        return False, sig_field_ref

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
    # if a field was added to an existing form, register an extra update
    if not form_created:
        update_writer.update_container(fields)
    return True, sig_field_ref


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

    try:
        fields = reader.root['/AcroForm']['/Fields']
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
