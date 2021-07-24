Signature fields
================

.. |---| unicode:: U+02014 .. em dash
   :trim:
.. |SigFieldSpec| replace:: :class:`~.pyhanko.sign.fields.SigFieldSpec`
.. |SigSeedValueSpec| replace:: :class:`~.pyhanko.sign.fields.SigSeedValueSpec`
.. |SigCertConstraints| replace:: :class:`~.pyhanko.sign.fields.SigCertConstraints`

The creation of signature fields |---| that is to say, *containers* for
(future) signatures |---| is handled by the :mod:`.pyhanko.sign.fields` module.
Depending on your requirements, you may not need to call the functions in this
module explicitly; in many simple cases, pyHanko's
:doc:`signing functionality <signing>` takes care of that for you.

However, if you want more control, or you need some of the more advanced
functionality (such as seed value support or field locking) that the
PDF standard offers, you might want to read on.


.. _sigfield-api-design:

General API design
------------------

In general terms, a signature field is described by a |SigFieldSpec| object,
which is passed to the :func:`~.pyhanko.sign.fields.append_signature_field`
function for inclusion in a PDF file.

As the name suggests, a |SigFieldSpec| is a
specification for a new signature field.
These objects are designed to be immutable and stateless.
A |SigFieldSpec| object is instantiated by
calling ``SigFieldSpec()`` with the following keyword
parameters.

* :attr:`~.pyhanko.sign.fields.SigFieldSpec.sig_field_name`:
  the field's name. This is the only mandatory parameter;
  it must not contain any period (``.``) characters.
* :attr:`~.pyhanko.sign.fields.SigFieldSpec.on_page` and
  :attr:`~.pyhanko.sign.fields.SigFieldSpec.box`:
  determine the position and page at which the
  signature field's widget should be put (see :ref:`sig-field-positioning`).
* :attr:`~.pyhanko.sign.fields.SigFieldSpec.seed_value_dict`:
  specify the seed value settings for the signature field
  (see :ref:`sig-field-seed-value-settings`).
* :attr:`~.pyhanko.sign.fields.SigFieldSpec.field_mdp_spec` and
  :attr:`~.pyhanko.sign.fields.SigFieldSpec.doc_mdp_update_value`:
  specify a template for the modification and field locking policy that the
  signer should apply (see :ref:`sig-field-docmdp`).


Hence, to create a signature field specification for an invisible signature
field named ``Sig1``, and add it to a file ``document.pdf``, you would proceed
as follows.

.. code-block:: python

    from pyhanko.sign.fields import SigFieldSpec, append_signature_field
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

    with open('document.pdf', 'rb+') as doc:
        w = IncrementalPdfFileWriter(doc)
        append_signature_field(w, SigFieldSpec(sig_field_name="Sig1"))
        w.write_in_place()

.. _sig-field-positioning:

Positioning
-----------

The position of a signature field is essentially only relevant for visible
signatures.
The following |SigFieldSpec| parameters determine where a signature widget will
end up:

* :attr:`~.pyhanko.sign.fields.SigFieldSpec.on_page`:
  index of the page on which the signature field should appear (default: ``0``);
* :attr:`~.pyhanko.sign.fields.SigFieldSpec.box`:
  bounding box of the signature field, represented as a 4-tuple
  ``(x1, y1, x2, y2)`` in Cartesian coordinates (i.e. the vertical axis runs
  bottom to top).

.. caution::
    In contrast with the CLI, pages are zero-indexed in the API.



.. _sig-field-seed-value-settings:

Seed value settings
-------------------

The PDF standard provides a way for document authors to provide so-called "seed
values" for signature fields.
These instruct the signer about the possible values for certain signature
properties and metadata. They can be purely informative, but can also be used to
restrict the signer in various ways.

Below is a non-exhaustive list of things that seed values can do.

* Put restrictions on the signer's certificate, including

  * the issuer,
  * the subject's distinguished name,
  * key usage extensions.

* Force the signer to embed a timestamp (together with a suggested time stamping
  server URL).
* Offer the signer a list of choices to choose from when selecting a reason for
  signing.
* Instruct the signer to use a particular signature (sub-)handler (e.g. tell
  the signer to produce PAdES-style signatures).


Most of these recommendations can be marked as mandatory using flags.
In this case, they also introduce a validation burden.

.. _sig-field-seed-value-usage-warning:

.. caution::
    Before deciding whether seed values are right for your use case, please
    consider the following factors.

    1. Seed values are a (relatively) obscure feature of the PDF specification,
       and not all PDF software offers support for it.
       Using mandatory seed values is therefore probably only viable in a
       closed, controlled environment with well-defined document workflows.
       When using seed values in an advisory manner, you may want to provide
       alternative hints, perhaps in the form of written instructions in the
       document, or in the form of other metadata.
    2. At this time, pyHanko only supports a subset of the seed value
       specification in the standard, but this should be resolved in due time.
       The extent of what is supported is recorded in the API reference for
       :class:`~.pyhanko.sign.fields.SigSeedValFlags`.
    3. Since incremental updates can modify documents in arbitrary ways,
       mandatory seed values can only be (reliably) enforced if the author
       includes a certification signature, to prevent later signers from
       surreptitiously changing the rules.

       If this is not an option for whatever reason, then you'll have to make
       sure that the entity validating the signatures is aware of the
       restrictions the author intended through out-of-band means.
    4. Consider whether using signatures with explicitly identified signature
       policies would be more appropriate (see e.g. :rfc:`5126`, § 5.8).
       Processing signature policies requires more specialised validation tools,
       but they are standardised much more rigorously than seed values in PDF.
       In particular, it is the superior choice when working with signatures in
       an AdES context. However, pyHanko's support for these workflows is currently
       limited\ [#policysupport]_.


Seed values for a new signature field are configured through the
:attr:`~.pyhanko.sign.fields.SigFieldSpec.seed_value_dict` attribute
of |SigFieldSpec|. This attribute takes a |SigSeedValueSpec| object, containing
the desired seed value configuration.
For a detailed overview of the seed values that can be specified, follow the
links to the API reference; we only discuss the most important points below.

The mandatory seed values are indicated by the
:attr:`~.pyhanko.sign.fields.SigSeedValueSpec.flags` attribute, which takes a
:class:`~.pyhanko.sign.fields.SigSeedValFlags` object as its value.
This is a subclass of :class:`.Flag`, so you can combine different flags using
bitwise operations.

Restrictions and suggestions pertaining to the signer's certificate deserve
special mention, since they're a bit special.
These are encoded the :attr:`~.pyhanko.sign.fields.SigSeedValueSpec.cert`
attribute of |SigSeedValueSpec|, in the form of a |SigCertConstraints| object.
This class has a :attr:`~.pyhanko.sign.fields.SigCertConstraints.flags`
attribute of its own, indicating which of the |SigCertConstraints| are to be
enforced.
Its value is a :class:`~.pyhanko.sign.fields.SigCertConstraintFlags` object.
In other words, the enforceability of certificate constraints is *not*
controlled by the :attr:`~.pyhanko.sign.fields.SigSeedValueSpec.flags`
attribute of |SigSeedValueSpec|, but by the
:attr:`~.pyhanko.sign.fields.SigCertConstraints.flags` attribute of the
|SigCertConstraints| object inside the
:attr:`~.pyhanko.sign.fields.SigSeedValueSpec.cert` attribute.
This mirrors the way in which these restrictions are defined in the PDF
specification.

Since this is all rather abstract, let's discuss a concrete example.
The code below shows how you might instantiate a signature field specification
for a ballot form of sorts, subject to the following requirements.

 * Only people with voting rights should be able to sign the ballot.
   This is enforced by requiring that the certificates be issued by
   a specific certificate authority.
 * The signer can either vote for or against the proposed measure, or abstain.
   For the sake of the example, let's encode that by one of three possible
   reasons for signing.
 * Since we want to avoid cast ballots being modified after the fact, we require
   a strong hash function to be used (at least ``sha256``).

.. code-block:: python

    from pyhanko.sign import fields
    from pyhanko.sign.general import load_cert_from_pemder

    franchising_ca = load_cert_from_pemder('path/to/certfile')
    sv = fields.SigSeedValueSpec(
        reasons=[
            'I vote in favour of the proposed measure',
            'I vote against the proposed measure',
            'I formally abstain from voting on the proposed measure'
        ],
        cert=fields.SigCertConstraints(
            issuers=[franchising_ca],
            flags=fields.SigCertConstraintFlags.ISSUER
        ),
        digest_methods=['sha256', 'sha384', 'sha512'],
        flags=fields.SigSeedValFlags.REASONS | fields.SigSeedValFlags.DIGEST_METHOD
    )

    sp = fields.SigFieldSpec('BallotSignature', seed_value_dict=sv)


Note the use of the bitwise-or operator ``|`` to combine multiple flags.

.. _sig-field-docmdp:

Document modification policy settings
-------------------------------------

Broadly speaking, the PDF specification outlines two ways to specify the degree
to which a document may be modified after a signature is applied, *without*
these modifications affecting the validity of the signature.

* The **document modification detection policy** (DocMDP) is an integer between
  one and three, indicating on a document-wide level which classes of
  modification are permissible. The three levels are defined as follows:

    * level 1: no modifications are allowed;
    * level 2: form filling and signing are allowed;
    * level 3: form filling, signing and commenting are allowed.

  The default value is 2.

* The **field modification detection policy** (FieldMDP), as the name suggests,
  specifies the form fields that can be modified after signing.
  FieldMDPs can be inclusive or exclusive, and as such allow fairly granular
  control.

When creating a signature field, the document author can suggest policies that
the signer should apply in the signature object.

.. warning::
    There are a number of caveats that apply to MDP settings in general; see
    :ref:`pdf-signing-background`.

Traditionally, the DocMDP settings are exclusive to certification signatures
(i.e. the first, specially marked signature included by the document author),
but in PDF 2.0 it is possible for approval (counter)signatures to set the DocMDP
level to a stricter value than the one already in force |---| although this
uses a setting in the field's locking dictionary rather than an explicit DocMDP
dictionary on the signature itself.

In pyHanko, these settings are controlled by the
:attr:`~.pyhanko.sign.fields.SigFieldSpec.field_mdp_spec` and
:attr:`~.pyhanko.sign.fields.SigFieldSpec.doc_mdp_update_value` parameters
of |SigFieldSpec|.
The example below specifies a field with instructions for the signer to
lock a field called ``SomeTextField``, and set the DocMDP value for that
signature to :attr:`~.pyhanko.sign.fields.MDPPerm.FORM_FILLING` (i.e. level 2).
PyHanko will respect these settings when signing, but other software might not.

.. code-block:: python

    from pyhanko.sign import fields

    fields.SigFieldSpec(
        'Sig1', box=(10, 74, 140, 134),
        field_mdp_spec=fields.FieldMDPSpec(
            fields.FieldMDPAction.INCLUDE, fields=['SomeTextField']
        ),
        doc_mdp_update_value=fields.MDPPerm.FORM_FILLING
    )

The :attr:`~.pyhanko.sign.fields.SigFieldSpec.doc_mdp_update_value` value is
more or less self-explanatory, since it's little more than a numerical constant.
The value passed to :attr:`~.pyhanko.sign.fields.SigFieldSpec.field_mdp_spec`
is an instance of :class:`~.pyhanko.sign.fields.FieldMDPSpec`.
:class:`~.pyhanko.sign.fields.FieldMDPSpec` objects take two parameters:

* :attr:`~.pyhanko.sign.fields.FieldMDPSpec.fields`:
  The fields that are subject to the policy, which can be specified exclusively
  or inclusively, depending on the value of
  :attr:`~.pyhanko.sign.fields.FieldMDPSpec.action` (see below).
* :attr:`~.pyhanko.sign.fields.FieldMDPSpec.action`:
  This is an instance of the enum :class:`~.pyhanko.sign.fields.FieldMDPAction`.
  The possible values are as follows.

  * :attr:`~.pyhanko.sign.fields.FieldMDPAction.ALL`: all fields should be
    locked after signing. In this case, the value of the
    :attr:`~.pyhanko.sign.fields.FieldMDPSpec.fields` parameter is irrelevant.
  * :attr:`~.pyhanko.sign.fields.FieldMDPAction.INCLUDE`: all fields specified
    in :attr:`~.pyhanko.sign.fields.FieldMDPSpec.fields` should be locked, while
    the others remain unlocked (in the absence of other more restrictive policies).
  * :attr:`~.pyhanko.sign.fields.FieldMDPAction.EXCLUDE`: all fields *except*
    the ones specified in :attr:`~.pyhanko.sign.fields.FieldMDPSpec.fields`
    should be locked.


.. rubric:: Footnotes
.. [#policysupport]
    Currently, pyHanko doesn't yet support automatic enforcement of signature policies
    (to the extent that they can be machine-verified in the first place, obviously).
    This goes for both the signer and the validator.
    However, you can still *declare* signature policies by extending your favourite
    :class:`~.pyhanko.sign.signers.pdf_cms.Signer` subclass and adding the relevant
    signed attributes.
    Validators that do not support signature policy processing will typically ignore
    the policy setting altogether.

