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

TODO

.. _sig-field-docmdp:

Document modification policy settings
-------------------------------------

TODO