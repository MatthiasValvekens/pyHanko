"""
Utilities to deal with signature form fields and their properties in PDF files.
"""

import logging
from dataclasses import dataclass
from enum import Flag, Enum, unique
from typing import List, Optional

from asn1crypto import x509
from certvalidator.path import ValidationPath
from oscrypto import keys as oskeys

from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.generic import pdf_name, pdf_string
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.misc import OrderedEnum, PdfWriteError, get_and_apply
from pyhanko.pdf_utils.rw_common import PdfHandler
from pyhanko.sign.general import UnacceptableSignerError, SigningError
from pyhanko.stamp import AnnotAppearances

__all__ = [
    'SigFieldSpec', 'SigSeedValFlags', 'SigCertConstraints',
    'SigSeedValueSpec', 'SigCertConstraintFlags', 'SigSeedSubFilter',
    'MDPPerm', 'FieldMDPAction', 'FieldMDPSpec',
    'SignatureFormField',
    'enumerate_sig_fields', 'append_signature_field'
]

logger = logging.getLogger(__name__)

# TODO support other seed value dict entries
# TODO add more customisability appearance-wise


class SigSeedValFlags(Flag):
    """
    Flags for the ``/Ff`` entry in the seed value dictionary for a signature
    field. These mark which of the constraints are to be strictly enforced,
    as opposed to optional ones.

    .. warning::
        While this enum records values for all flags, not all corresponding
        constraint types have been implemented yet.
    """

    FILTER = 1
    SUBFILTER = 2
    V = 4
    REASONS = 8
    LEGAL_ATTESTATION = 16
    ADD_REV_INFO = 32
    DIGEST_METHOD = 64
    LOCK_DOCUMENT = 128
    APPEARANCE_FILTER = 256
    UNSUPPORTED = LEGAL_ATTESTATION | LOCK_DOCUMENT | APPEARANCE_FILTER
    """
    Flags for which the corresponding constraint is unsupported.
    """


class SigCertConstraintFlags(Flag):
    """
    Flags for the ``/Ff`` entry in the certificate seed value dictionary for
    a dictionary field. These mark which of the constraints are to be
    strictly enforced, as opposed to optional ones.

    .. warning::
        While this enum records values for all flags, not all corresponding
        constraint types have been implemented yet.
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


def x509_name_keyval_pairs(name: x509.Name, abbreviate_oids=False):
    rdns: x509.RDNSequence = name.chosen
    for rdn in rdns:
        for type_and_value in rdn:
            oid: x509.NameType = type_and_value['type']
            # these are all some kind of string, and the PDF
            # standard says that the value should be a text string object,
            # so we just have asn1crypto convert everything to strings
            value = type_and_value['value']
            key = oid.dotted
            if abbreviate_oids:
                key = name_type_abbrevs.get(key, key)

            yield key, value.native
            # these should be strings


@dataclass(frozen=True)
class SigCertConstraints:
    """
    This part of the seed value dictionary allows the document author
    to set constraints on the signer's certificate.

    See Table 235 in ISO 32000-1.
    """
    flags: SigCertConstraintFlags = SigCertConstraintFlags(0)
    """
    Enforcement flags. By default, all entries are optional.
    """

    subjects: List[x509.Certificate] = None
    """
    Explicit list of certificates that can be used to sign a signature field.
    """

    subject_dn: x509.Name = None
    """
    Certificate subject names that can be used to sign a signature field.
    Subject DN entries that are not mentioned are unconstrained.
    """

    issuers: List[x509.Certificate] = None
    """
    List of issuer certificates that the signer certificate can be issued by.
    Note that these issuers do not need to be the *direct* issuer of the
    signer's certificate; any descendant relationship will do.
    """

    info_url: str = None
    """
    Informational URL that should be opened when an appropriate signature
    cannot be found.
    """

    url_type: generic.NameObject = pdf_name('/Browser')
    """
    Handler that should be used to open :attr:`info_url`.
    ``/Browser`` is the only implementation-independent value.
    """

    # TODO support key usage and OID constraints

    @classmethod
    def from_pdf_object(cls, pdf_dict):
        """
        Read a PDF dictionary into a :class:`.SigCertConstraints` object.

        :param pdf_dict:
            A :class:`~.generic.DictionaryObject`.
        :return:
            A :class:`.SigCertConstraints` object.
        """

        if isinstance(pdf_dict, generic.IndirectObject):
            pdf_dict = pdf_dict.get_object()
        try:
            if pdf_dict['/Type'] != '/SVCert':  # pragma: nocover
                raise ValueError('Object /Type entry is not /SVCert')
        except KeyError:  # pragma: nocover
            pass
        flags = SigCertConstraintFlags(pdf_dict.get('/Ff', 0))
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

        subject_dns = x509.Name.build({
            format_attr(attr): value
            for dn_dir in pdf_dict.get('/SubjectDN', ())
            for attr, value in dn_dir.items()
        })

        url = pdf_dict.get('/URL')
        url_type = pdf_dict.get('/URLType')
        kwargs = {
            'flags': flags, 'subjects': subjects or None,
            'subject_dn': subject_dns or None,
            'issuers': issuers or None, 'info_url': url
        }
        if url is not None and url_type is not None:
            kwargs['url_type'] = url_type
        return cls(**kwargs)

    def as_pdf_object(self):
        """
        Render this :class:`.SigCertConstraints` object to a PDF dictionary.

        :return:
            A :class:`~.generic.DictionaryObject`.
        """

        result = generic.DictionaryObject({
            pdf_name('/Type'): pdf_name('/SVCert'),
            pdf_name('/Ff'): generic.NumberObject(self.flags.value),
        })
        if self.subjects is not None:
            result[pdf_name('/Subject')] = generic.ArrayObject(
                generic.ByteStringObject(cert.dump())
                for cert in self.subjects
            )
        if self.subject_dn:
            # FIXME Adobe Reader seems to ignore this for some reason.
            #  Should try to figure out what I'm doing wrong
            result[pdf_name('/SubjectDN')] = generic.ArrayObject([
                generic.DictionaryObject({
                    pdf_name('/' + key): pdf_string(value)
                    for key, value in x509_name_keyval_pairs(
                        self.subject_dn, abbreviate_oids=True
                    )
                })
            ])
        if self.issuers is not None:
            result[pdf_name('/Issuer')] = generic.ArrayObject(
                generic.ByteStringObject(cert.dump())
                for cert in self.issuers
            )
        if self.info_url is not None:
            result[pdf_name('/URL')] = pdf_string(self.info_url)
            result[pdf_name('/URLType')] = self.url_type

        return result

    def satisfied_by(self, signer: x509.Certificate,
                     validation_path: Optional[ValidationPath]):
        """
        Evaluate whether a signing certificate satisfies the required
        constraints of this :class:`.SigCertConstraints` object.

        :param signer:
            The candidate signer's certificate.
        :param validation_path:
            Validation path of the signer's certificate.
        :raises UnacceptableSignerError:
            Raised if the conditions are not met.
        """
        # this function assumes that key usage & trust checks have
        #  passed already.
        flags = self.flags
        if (flags & SigCertConstraintFlags.SUBJECT) \
                and self.subjects is not None:
            # Explicit whitelist of approved signer certificates
            # compare using issuer_serial
            acceptable = (s.issuer_serial for s in self.subjects)
            if signer.issuer_serial not in acceptable:
                raise UnacceptableSignerError(
                    "Signer certificate not on SVCert whitelist."
                )
        if (flags & SigCertConstraintFlags.ISSUER) \
                and self.issuers is not None:
            if validation_path is None:
                raise UnacceptableSignerError("Validation path not provided.")
            # Here, we need to match any issuer in the chain of trust to
            #  any of the issuers on the approved list.

            # To do so, we collect all issuer_serial identifiers in the chain
            # for all certificates except the last one (i.e. the current signer)
            path_iss_serials = {
                entry.issuer_serial for entry in validation_path.copy().pop()
            }
            for issuer in self.issuers:
                if issuer.issuer_serial in path_iss_serials:
                    break
            else:
                # raise error if the loop runs to completion
                raise UnacceptableSignerError(
                    "Signer certificate cannot be traced back to approved "
                    "issuer."
                )
        if (flags & SigCertConstraintFlags.SUBJECT_DN) and self.subject_dn:
            # I'm not entirely sure whether my reading of the standard is
            #  is correct, but I believe that this is the intention:
            # A DistinguishedName object is a sequence of
            #  relative distinguished names (RDNs). The contents of the
            #  /SubjectDN specify a list of constraints that might apply to each
            #  of these RDNs. I believe the requirement is that each of the
            #  SubjectDN entries must match one of these RDNs.

            requirement_list = list(x509_name_keyval_pairs(self.subject_dn))
            subject_name = list(x509_name_keyval_pairs(signer.subject))
            if not all(attr in subject_name for attr in requirement_list):
                raise UnacceptableSignerError(
                    "Subject does not have some of the following required "
                    "attributes: " + self.subject_dn.human_friendly
                )


@unique
class SigSeedSubFilter(Enum):
    """
    Enum declaring all supported ``/SubFilter`` values.
    """

    ADOBE_PKCS7_DETACHED = pdf_name("/adbe.pkcs7.detached")
    PADES = pdf_name("/ETSI.CAdES.detached")
    ETSI_RFC3161 = pdf_name("/ETSI.RFC3161")


# TODO support /V version indicator, other fields

@dataclass(frozen=True)
class SigSeedValueSpec:
    """
    Python representation of a PDF seed value dictionary.
    """

    flags: SigSeedValFlags = SigSeedValFlags(0)
    """
    Enforcement flags. By default, all entries are optional.
    """

    reasons: List[str] = None
    """
    Acceptable reasons for signing.
    """

    timestamp_server_url: str = None
    """
    RFC 3161 timestamp server endpoint suggestion.
    """

    timestamp_required: bool = False
    """
    Flags whether a timestamp is required.
    This flag is only meaningful if :attr:`timestamp_server_url` is specified.
    """

    cert: SigCertConstraints = None
    """
    Constraints on the signer's certificate.
    """

    subfilters: List[SigSeedSubFilter] = None
    """
    Acceptable ``/SubFilter`` values.
    """

    digest_methods: List[str] = None
    """
    Acceptable digest methods.
    """

    add_rev_info: bool = None
    """
    Indicates whether revocation information should be embedded.
    
    .. warning::
        This flag exclusively refers to the Adobe-style revocation information
        embedded within the CMS object that is written to the signature field.
        PAdES-style revocation information that is saved to the document
        security store (DSS) does *not* satisfy the requirement.
        Additionally, the standard mandates that ``/SubFilter`` be equal to
        ``/adbe.pkcs7.detached`` if this flag is ``True``.
    """

    def as_pdf_object(self):
        """
        Render this :class:`.SigSeedValueSpec` object to a PDF dictionary.

        :return:
            A :class:`~.generic.DictionaryObject`.
        """
        result = generic.DictionaryObject({
            pdf_name('/Type'): pdf_name('/SV'),
            pdf_name('/Ff'): generic.NumberObject(self.flags.value),
        })

        if self.subfilters is not None:
            result[pdf_name('/SubFilter')] = generic.ArrayObject(
                sf.value for sf in self.subfilters
            )
        if self.add_rev_info is not None:
            result[pdf_name('/AddRevInfo')] = generic.BooleanObject(
                self.add_rev_info
            )
        if self.digest_methods is not None:
            result[pdf_name('/DigestMethod')] = generic.ArrayObject(
                map(pdf_string, self.digest_methods)
            )
        if self.reasons is not None:
            result[pdf_name('/Reasons')] = generic.ArrayObject(
                pdf_string(reason) for reason in self.reasons
            )
        if self.timestamp_server_url is not None:
            result[pdf_name('/TimeStamp')] = generic.DictionaryObject({
                pdf_name('/URL'): pdf_string(self.timestamp_server_url),
                pdf_name('/Ff'): generic.NumberObject(
                    1 if self.timestamp_required else 0
                )
            })
        if self.cert is not None:
            result[pdf_name('/Cert')] = self.cert.as_pdf_object()
        return result

    @classmethod
    def from_pdf_object(cls, pdf_dict):
        """
        Read from a seed value dictionary.

        :param pdf_dict:
            A :class:`~.generic.DictionaryObject`.
        :return:
            A :class:`.SigSeedValueSpec` object.
        """
        if isinstance(pdf_dict, generic.IndirectObject):
            pdf_dict = pdf_dict.get_object()
        try:
            if pdf_dict['/Type'] != '/SV':  # pragma: nocover
                raise ValueError('Object /Type entry is not /SV')
        except KeyError:  # pragma: nocover
            pass

        flags = SigSeedValFlags(pdf_dict.get('/Ff', 0))
        try:
            sig_filter = pdf_dict['/Filter']
            if (flags & SigSeedValFlags.FILTER) and \
                    (sig_filter != '/Adobe.PPKLite'):
                raise SigningError(
                    "Signature handler '%s' is not available, only the "
                    "default /Adobe.PPKLite is supported." % sig_filter
                )
        except KeyError:
            pass

        # TODO support all PDF 2.0 values
        min_version = pdf_dict.get('/V', 1)
        if flags & SigSeedValFlags.V and min_version > 1:
            raise SigningError(
                "Seed value dictionary version %s not supported." % min_version
            )

        try:
            add_rev_info = bool(pdf_dict['/AddRevInfo'])
        except KeyError:
            add_rev_info = None

        subfilter_reqs = pdf_dict.get('/SubFilter', None)
        subfilters = None
        if subfilter_reqs is not None:
            def _subfilters():
                for s in subfilter_reqs:
                    try:
                        yield SigSeedSubFilter(s)
                    except ValueError:
                        pass
            subfilters = list(_subfilters())

        try:
            digest_methods = [s.lower() for s in pdf_dict['/DigestMethod']]
        except KeyError:
            digest_methods = None

        reasons = get_and_apply(pdf_dict, '/Reasons', list)
        timestamp_dict = pdf_dict.get('/TimeStamp', {})
        timestamp_server_url = timestamp_dict.get('/URL', None)
        timestamp_required = bool(timestamp_dict.get('/Ff', 0))
        cert_constraints = pdf_dict.get('/Cert', None)
        if cert_constraints is not None:
            cert_constraints = SigCertConstraints.from_pdf_object(
                cert_constraints
            )
        return cls(
            flags=flags, reasons=reasons,
            timestamp_server_url=timestamp_server_url,
            cert=cert_constraints, subfilters=subfilters,
            digest_methods=digest_methods, add_rev_info=add_rev_info,
            timestamp_required=timestamp_required
        )

    def build_timestamper(self):
        """
        Return a timestamper object based on the :attr:`timestamp_server_url`
        attribute of this :class:`.SigSeedValueSpec` object.

        :return:
            A :class:`~.pyhanko.sign.timestamps.HTTPTimeStamper`.
        """
        from pyhanko.sign.timestamps import HTTPTimeStamper
        if self.timestamp_server_url:
            return HTTPTimeStamper(self.timestamp_server_url)


class MDPPerm(OrderedEnum):
    """
    Indicates a ``/DocMDP`` level.

    Cf. Table 254  in ISO 32000-1.
    """

    NO_CHANGES = 1
    """
    No changes to the document are allowed.
    
    .. warning::
        This does not apply to DSS updates and the addition of document time
        stamps.
    """
    FILL_FORMS = 2
    """
    Form filling & signing is allowed.
    """

    ANNOTATE = 3
    """
    Form filling, signing and commenting are allowed.
    
    .. warning::
        Validating this ``/DocMDP`` level is not currently supported,
        but included in the list for completeness.
    """


class FieldMDPAction(Enum):
    """
    Marker for the scope of a ``/FieldMDP`` policy.
    """

    ALL = pdf_name('/All')
    """
    The policy locks all form fields.
    """

    INCLUDE = pdf_name('/Include')
    """
    The policy locks all fields in the list (see :attr:`.FieldMDPSpec.fields`).
    """

    EXCLUDE = pdf_name('/Exclude')
    """
    The policy locks all fields except those specified in the list
    (see :attr:`.FieldMDPSpec.fields`).
    """


@dataclass(frozen=True)
class FieldMDPSpec:
    """``/FieldMDP`` policy description.

    This class models both field lock dictionaries and ``/FieldMDP``
    transformation parameters.
    """

    action: FieldMDPAction
    """
    Indicates the scope of the policy.
    """

    fields: Optional[List[str]] = None
    """
    Indicates the fields subject to the policy,
    unless :attr:`action` is :attr:`.FieldMDPAction.ALL`.
    """

    def as_pdf_object(self) -> generic.DictionaryObject:
        """
        Render this ``/FieldMDP`` policy description as a PDF dictionary.

        :return:
            A :class:`~.generic.DictionaryObject`.
        """
        result = generic.DictionaryObject({
            pdf_name('/Action'): self.action.value,
        })
        if self.action != FieldMDPAction.ALL:
            result['/Fields'] = generic.ArrayObject(
                map(pdf_string, self.fields)
            )
        return result

    def as_transform_params(self) -> generic.DictionaryObject:
        """
        Render this ``/FieldMDP`` policy description as a PDF dictionary,
        ready for inclusion into the ``/TransformParams`` entry of a
        ``/FieldMDP`` dictionary associated with a signature object.

        :return:
            A :class:`~.generic.DictionaryObject`.
        """

        result = self.as_pdf_object()
        result['/Type'] = pdf_name('/TransformParams')
        result['/V'] = pdf_name('/1.2')
        return result

    def as_sig_field_lock(self) -> generic.DictionaryObject:
        """
        Render this ``/FieldMDP`` policy description as a PDF dictionary,
        ready for inclusion into the ``/Lock`` dictionary of a signature field.

        :return:
            A :class:`~.generic.DictionaryObject`.
        """

        result = self.as_pdf_object()
        result['/Type'] = pdf_name('/SigFieldLock')
        return result

    @classmethod
    def from_pdf_object(cls, pdf_dict) -> 'FieldMDPSpec':
        """
        Read a PDF dictionary into a :class:`.FieldMDPSpec` object.

        :param pdf_dict:
            A :class:`~.generic.DictionaryObject`.
        :return:
            A :class:`.FieldMDPSpec` object.
        """
        try:
            action = FieldMDPAction(pdf_dict['/Action'])
        except KeyError:  # pragma: nocover
            raise ValueError("/Action is required.")

        if action != FieldMDPAction.ALL:
            try:
                fields = pdf_dict['/Fields']
            except KeyError:  # pragma: nocover
                raise ValueError("/Fields is required when /Action is not /All")
        else:
            fields = None
        return cls(action=action, fields=fields)

    def is_locked(self, field_name: str) -> bool:
        """
        Adjudicate whether a field should be locked by the policy described by
        this :class:`.FieldMDPSpec` object.

        :param field_name:
            The name of a form field.
        :return:
            ``True`` if the field should be locked, ``False`` otherwise.
        """
        if self.action == FieldMDPAction.ALL:
            return True

        lock_result = self.action == FieldMDPAction.INCLUDE
        for scoped_field_name in self.fields:
            # treat non-terminal field in/exclusions as including the whole
            # tree beneath them
            if field_name.startswith(scoped_field_name):
                return lock_result
        return not lock_result


# TODO deal with fully qualified field names for the signature field

@dataclass(frozen=True)
class SigFieldSpec:
    """Description of a signature field to be created."""

    sig_field_name: str
    """
    Name of the signature field.
    """

    on_page: int = 0
    """
    Index of the page on which the signature field should be included (starting
    at `0`).
    
    .. note::
        This is essentially only relevant for visible signature fields, i.e.
        those that have a widget associated with them.
    """

    box: (int, int, int, int) = None
    """
    Bounding box of the signature field, if applicable.
    """

    seed_value_dict: SigSeedValueSpec = None
    """
    Specification for the seed value dictionary, if applicable.
    """

    field_mdp_spec: FieldMDPSpec = None
    """
    Specification for the field lock dictionary, if applicable.
    """

    doc_mdp_update_value: MDPPerm = None
    """
    Value to use for the document modification policy associated with the
    signature in this field.
    
    This value will be embedded into the field lock dictionary if specified, and    
    is meaningless if :attr:`field_mdp_spec` is not specified.
    
    .. warning::
        DocMDP entries for approval signatures are a PDF 2.0 feature.
        Older PDF software will likely ignore this part of the field lock
        dictionary.
    """
    # TODO add a reference to the docs on certification once those are written.

    def format_lock_dictionary(self) -> Optional[generic.DictionaryObject]:
        if self.field_mdp_spec is None:
            return
        result = self.field_mdp_spec.as_sig_field_lock()
        # this requires PDF 2.0 in principle, but meh, noncompliant
        # readers will ignore it anyway
        if self.doc_mdp_update_value is not None:
            result['/P'] = generic.NumberObject(self.doc_mdp_update_value.value)
        return result


def _prepare_sig_field(sig_field_name, root,
                       update_writer: IncrementalPdfFileWriter,
                       existing_fields_only=False, lock_sig_flags=True,
                       **kwargs):
    """
    Returns a tuple of a boolean and a reference to a signature field.
    The boolean is ``True`` if the field was created, and ``False`` otherwise.
    """
    if sig_field_name is None:  # pragma: nocover
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
                raise SigningError(
                    'Signature field with name %s appears to be filled already.'
                    % sig_field_name
                )
        except StopIteration:
            if existing_fields_only:
                raise SigningError(
                    'No empty signature field with name %s found.'
                    % sig_field_name
                )
        form_created = False
    except KeyError:
        # we have to create the form
        if existing_fields_only:
            raise SigningError('This file does not contain a form.')
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

    if '.' in sig_field_name:
        raise NotImplementedError(
            "Creating fields deep in the form hierarchy is not supported"
            "right now."
        )

    # no signature field exists, so create one
    # default: grab a reference to the first page
    page_ref = update_writer.find_page_for_modification(0)[0]
    sig_form_kwargs = {'include_on_page': page_ref}
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


def enumerate_sig_fields(handler: PdfHandler, filled_status=None):
    """
    Enumerate signature fields.

    :param handler:
        The :class:`~.rw_common.PdfHandler` to operate on.
    :param filled_status:
        Optional boolean. If ``True`` (resp. ``False``) then all filled
        (resp. empty) fields are returned. If left ``None`` (the default), then
        all fields are returned.
    :return:
        A generator producing signature fields.
    """

    try:
        fields = handler.root['/AcroForm']['/Fields']
    except KeyError:
        return

    yield from enumerate_sig_fields_in(fields, filled_status)


def enumerate_sig_fields_in(field_list, filled_status=None, with_name=None,
                            parent_name="", parents=None):
    parents = parents or ()
    for field_ref in field_list:
        # TODO the spec mandates this, but perhaps we should be a bit more
        #  tolerant
        assert isinstance(field_ref, generic.IndirectObject)
        field = field_ref.get_object()
        assert isinstance(field, generic.DictionaryObject)
        # /T is the field name. If not specified, we're dealing with a bare
        # widget, so skip it. (these should never occur in /Fields, but hey)
        try:
            field_name = field['/T']
        except KeyError:
            continue
        fq_name = field_name if not parent_name else (
                "%s.%s" % (parent_name, field_name)
        )
        explicitly_requested = with_name is not None and fq_name == with_name
        child_requested = explicitly_requested or (
            with_name is not None and with_name.startswith(fq_name)
        )
        # /FT is inheritable, so go up the chain
        current_path = (field,) + parents
        for parent_field in current_path:
            try:
                field_type = parent_field['/FT']
                break
            except KeyError:
                continue
        else:
            field_type = None

        if field_type == '/Sig':
            field_value = field.get('/V')
            # "cast" to a regular string object
            filled = field_value is not None
            status_check = filled_status is None or filled == filled_status
            name_check = with_name is None or explicitly_requested
            if status_check and name_check:
                yield fq_name, field_value, field_ref
        elif explicitly_requested:
            raise SigningError(
                'Field with name %s exists but is not a signature field'
                % fq_name
            )

        # if necessary, descend into the field hierarchy
        if with_name is None or (child_requested and not explicitly_requested):
            try:
                yield from enumerate_sig_fields_in(
                    field['/Kids'], parent_name=fq_name, parents=current_path,
                    with_name=with_name
                )
            except KeyError:
                continue


def append_signature_field(pdf_out: IncrementalPdfFileWriter,
                           sig_field_spec: SigFieldSpec):
    """
    Append signature fields to a PDF file.

    :param pdf_out:
        Incremental writer to house the objects.
    :param sig_field_spec:
        A :class:`.SigFieldSpec` object describing the signature field
        to add.
    """
    root = pdf_out.root

    page_ref = pdf_out.find_page_for_modification(sig_field_spec.on_page)[0]
    # use default appearance
    field_created, sig_field_ref = _prepare_sig_field(
        sig_field_spec.sig_field_name, root, update_writer=pdf_out,
        existing_fields_only=False,
        box=sig_field_spec.box, include_on_page=page_ref,
        lock_sig_flags=False
    )
    if not field_created:
        raise PdfWriteError(
            'Signature field with name %s already exists.'
            % sig_field_spec.sig_field_name
        )

    sig_field = sig_field_ref.get_object()
    if sig_field_spec.seed_value_dict is not None:
        # /SV must be an indirect reference as per the spec
        sv_ref = pdf_out.add_object(
            sig_field_spec.seed_value_dict.as_pdf_object()
        )
        sig_field[pdf_name('/SV')] = sv_ref

    lock = sig_field_spec.format_lock_dictionary()
    if lock is not None:
        sig_field[pdf_name('/Lock')] = pdf_out.add_object(lock)


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
