Signature fields
================

.. |---| unicode:: U+02014 .. em dash
   :trim:
.. |SigFieldSpec| replace:: :class:`~.pyhanko.sign.fields.SigFieldSpec`

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

* ``sig_field_name``: the field's name. This is the only mandatory parameter;
  it must not contain any period (``.``) characters.
* ``on_page`` and ``box``: determine the position and page at which the
  signature field's widget should be put (see :ref:`sig-field-positioning`).
* ``seed_value_dict``: specify the seed value settings for the signature field
  (see :ref:`sig-field-seed-value-settings`).
* ``field_mdp_spec`` and ``doc_mdp_update_value``: specify a template for
  the modification and field locking policy that the signer should apply
  (see :ref:`sig-field-docmdp`).


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

* ``on_page``: index of the page on which the signature field should appear
  (default: ``0``);
* ``box``: bounding box of the signature field, represented as a 4-tuple
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


.. _sig-field-docmdp:

Document modification policy settings
-------------------------------------

TODO