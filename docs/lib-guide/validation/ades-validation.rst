.. _ades-validation:

The AdES validation engine
==========================

.. versionchanged:: 0.31.0

    The AdES validation API in :mod:`pyhanko.sign.validation.ades` became the
    recommended entry point for long-term validation.


.. |AdESLTAValidationResult| replace:: :class:`~.pyhanko.sign.validation.ades.AdESLTAValidationResult`
.. |SignatureValidationSpec| replace:: :class:`~.pyhanko.sign.validation.policy_decl.SignatureValidationSpec`
.. |PdfSignatureValidationSpec| replace:: :class:`~.pyhanko.sign.validation.policy_decl.PdfSignatureValidationSpec`
.. |CertValidationPolicySpec| replace:: :class:`~.pyhanko_certvalidator.context.CertValidationPolicySpec`
.. |LocalKnowledge| replace:: :class:`~.pyhanko.sign.validation.policy_decl.LocalKnowledge`
.. |ValidationContext| replace:: :class:`~.pyhanko_certvalidator.ValidationContext`
.. |PdfSignatureStatus| replace:: :class:`~.pyhanko.sign.validation.status.PdfSignatureStatus`


.. testsetup:: *

    globals().update(make_doc_env(DocEnvSpec(
        files={},
        signers=(),
        signed_documents=(
            SignedDocSpec(profile=SignatureProfile.PADES_LTA),
        ),
        trust=TrustSpec(fetch_revocation=True),
    )))

.. testcleanup:: *

    teardown_doc_env(_doc_env)


.. _ades-ltv-validation:

Long-term verifiability checking
---------------------------------

.. versionchanged:: 0.31.0

    Updated to reference newer AdES-based API in
    :mod:`pyhanko.sign.validation.ades`.


As explained :ref:`here <pdf-signing-background>` and
:ref:`here <ltv-signing>` in the CLI documentation, making sure that PDF
signatures remain verifiable over long time scales requires special care.
Signatures that have this property are called "LTV enabled" in some
implementations, where LTV is short for *long-term verifiable*.

The notion of what it means to be "LTV enabled" is not entirely well-defined
(since it inherently depends on the set of trust roots and policies
used by the validator).
One way to model this is to ask what a future validator would conclude
given the validation information embedded into the document at the time of
signing (assuming reasonable timestamp chain maintenance).
See :func:`~.pyhanko.sign.validation.ades.simulate_future_ades_lta_validation`
for a standards-based attempt to formalise this, and
:ref:`ades-lta-maintainability` for how to apply it in practice.


To validate a signature while taking into account embedded historical
validation data, we recommend using
:func:`~.pyhanko.sign.validation.ades.ades_lta_validation`.
This function is part of pyHanko's AdES validation API, which
aims to implement the validation methodology laid out in
ETSI EN 319 102-1. Rather than a stateful |ValidationContext|, it takes a
declarative-style *validation spec* describing what to trust and how to gather
revocation information; see :ref:`ades-why-separate` for the rationale.

The status object it returns also includes more information than just
the "regular" |PdfSignatureStatus|: |AdESLTAValidationResult| also contains
some AdES-specific status codes and structured validation outputs; the
pyHanko-specific |PdfSignatureStatus| is included as an attribute.


.. _ades-why-separate:

Why a separate engine?
----------------------

The functions in :mod:`pyhanko.sign.validation.ades` implement the validation
methodology of ETSI EN 319 102-1, the standard underpinning AdES (and therefore
PAdES) signatures. The core validation logic is largely the same as the "classic"
:func:`~.pyhanko.sign.validation.validate_pdf_signature`, but the AdES
engine enhances this in three important ways.

* It is standards-based: the methodology in ETSI EN 319 102-1
  forms the basis of the implementation, with some additions.
  This mainly systematises how validation data is collected and managed.
* Its configuration is largely [#]_ declarative. Instead of handing it a stateful
  :class:`~.pyhanko_certvalidator.ValidationContext`, you describe *what* should
  be trusted and *how* revocation information should be gathered through a
  |SignatureValidationSpec|. The engine constructs and juggles the necessary
  validation contexts internally, including the separate contexts needed to
  reason about historical proofs of existence.
* It is proof-of-existence (PoE) aware, and enforces restrictions on
  validation data based on these PoE records (or lack thereof).
  The engine tracks when each object (the signature, certificates,
  revocation responses) was demonstrably known to
  exist, typically using embedded timestamps as evidence.

The remainder of this page works through the building blocks of a
|SignatureValidationSpec| and some of the options it offers.

.. [#] Technically, :class:`~.pyhanko_certvalidator.registry.TrustManager`
    is an interface that need not be implemented in a stateless manner, but
    morally it is supposed to be.


Anatomy of a validation spec
----------------------------

A |SignatureValidationSpec| bundles everything the engine needs to validate a
signature from the AdES point of view.
The only required ingredient is a |CertValidationPolicySpec| for the
signer's certificate, which in turn ties together a *trust manager* (the source
of trust anchors) and a *revocation trust policy*.

For PDF signatures, the |SignatureValidationSpec| is wrapped in a
|PdfSignatureValidationSpec| that combines the above with
:ref:`an incremental update analysis policy <diff-analysis>`,
which is something particular to PDF and not part of the AdES model.
As explained in the referenced section on difference analysis, this
process is not standardised and therefore necessarily somewhat
ad-hoc.

The most straightforward trust manager is
:class:`~.pyhanko_certvalidator.registry.SimpleTrustManager`, which trusts a
fixed set of root certificates that you supply explicitly.

.. testcode::

    from pyhanko.keys import load_cert_from_pemder
    from pyhanko.sign.validation.policy_decl import (
        PdfSignatureValidationSpec,
        SignatureValidationSpec,
    )
    from pyhanko_certvalidator.context import CertValidationPolicySpec
    from pyhanko_certvalidator.policy_decl import (
        CertRevTrustPolicy,
        REQUIRE_REVINFO,
    )
    from pyhanko_certvalidator.registry import SimpleTrustManager

    root_cert = load_cert_from_pemder('path/to/certfile')
    cert_policy = CertValidationPolicySpec(
        trust_manager=SimpleTrustManager.build(trust_roots=[root_cert]),
        revinfo_policy=CertRevTrustPolicy(REQUIRE_REVINFO),
    )
    validation_spec = PdfSignatureValidationSpec(
        SignatureValidationSpec(cert_validation_policy=cert_policy)
    )

The :data:`~.pyhanko_certvalidator.policy_decl.REQUIRE_REVINFO` revocation
checking policy tells the engine that a signature is only acceptable if
revocation information is available for every certificate in the chain.
This is the appropriate default for long-term validation: a signature you cannot
revocation-check today is one you certainly cannot vouch for years from now.


Running an LTA validation
-------------------------

With a spec in hand, validating a PAdES signature with long-term archival data
is a single call to
:func:`~.pyhanko.sign.validation.ades.ades_lta_validation`. The function walks
the chain of document timestamps embedded in the file, treats it as the
signature's evidence record, and reports a structured result.

.. testcode::

    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation.ades import ades_lta_validation

    async def validate_lta():
        with open('document.pdf', 'rb') as doc:
            r = PdfFileReader(doc)
            sig = r.embedded_signatures[0]
            result = await ades_lta_validation(sig, validation_spec)
            print(result.ades_subindic)
        return result

.. testcode::
    :hide:

    import asyncio
    _result = asyncio.run(validate_lta())

.. testoutput::

    AdESPassed.OK

The :attr:`~.pyhanko.sign.validation.ades.AdESBasicValidationResult.ades_subindic`
attribute is the standards-defined verdict. A successful validation reports
:attr:`~.pyhanko.sign.ades.report.AdESPassed.OK`; failures and
indeterminate outcomes carry one of the
:class:`~.pyhanko.sign.ades.report.AdESFailure` or
:class:`~.pyhanko.sign.ades.report.AdESIndeterminate` codes, which give a general
indication as to *why* the engine could validate the signature.

The returned status codes are part of the AdES spec.
This information is necessarily somewhat coarse: most AdES error codes
can be caused by a variety of problems. For detailed pyhanko-specific
error data, you may need to drill into the error information in
:attr:`~.pyhanko.sign.validation.ades.AdESBasicValidationResult.api_status`.


Reading the result
-------------------

The |AdESLTAValidationResult| returned by
:func:`~.pyhanko.sign.validation.ades.ades_lta_validation` carries considerably
more than the subindication. The most useful attributes are the following.

* :attr:`~.pyhanko.sign.validation.ades.AdESBasicValidationResult.api_status`
  is pyHanko's own
  :class:`~.pyhanko.sign.validation.status.PdfSignatureStatus`, the same object
  the classic API returns.
* :attr:`~.pyhanko.sign.validation.ades.AdESWithTimeValidationResult.best_signature_time`
  is the earliest time at which the signature is proven to have existed, derived
  from the timestamp chain.
* :attr:`~.pyhanko.sign.validation.ades.AdESLTAValidationResult.oldest_evidence_record_timestamp`
  is the oldest document timestamp covering the signature.
* :attr:`~.pyhanko.sign.validation.ades.AdESLTAValidationResult.signature_timestamp_status`
  reports on the signature timestamp specifically, if one is present.
* :attr:`~.pyhanko.sign.validation.ades.AdESBasicValidationResult.validation_objects`
  enumerates every certificate, CRL and OCSP response the engine considered.

.. testcode::

    async def inspect_result():
        with open('document.pdf', 'rb') as doc:
            r = PdfFileReader(doc)
            sig = r.embedded_signatures[0]
            result = await ades_lta_validation(sig, validation_spec)

            print("Verdict:", result.api_status.bottom_line)
            print("Proven to exist since:", result.best_signature_time)
            objs = list(result.validation_objects)
            print("Validation objects considered:", len(objs))

.. testcode::
    :hide:

    asyncio.run(inspect_result())

.. testoutput::
    :hide:

    Verdict: True
    Proven to exist since: 2020-08-01 00:00:00+00:00
    Validation objects considered: 8


Validating against a fixed point in time
-----------------------------------------

By default the engine validates "as of now". To reproduce the verdict a
validator would have reached at some other moment---e.g. to re-check an archive
at the time it was received---pass a
:class:`~.pyhanko_certvalidator.ltv.types.ValidationTimingInfo`.

.. testcode::

    from datetime import datetime, timezone
    from pyhanko_certvalidator.ltv.types import ValidationTimingInfo

    async def validate_at(reference_time):
        timing = ValidationTimingInfo(
            validation_time=reference_time,
            best_signature_time=reference_time,
            point_in_time_validation=True,
        )
        with open('document.pdf', 'rb') as doc:
            r = PdfFileReader(doc)
            sig = r.embedded_signatures[0]
            result = await ades_lta_validation(
                sig, validation_spec, timing_info=timing
            )
            print(result.ades_subindic)

.. testcode::
    :hide:

    asyncio.run(validate_at(datetime(2020, 9, 1, tzinfo=timezone.utc)))

.. testoutput::

    AdESPassed.OK

You can also tell the engine about a time *before* which the signature is known
not to have existed, via the ``signature_not_before_time`` parameter in
:func:`~.pyhanko.sign.validation.ades.ades_lta_validation`. This is
occasionally useful, provided you have
independent evidence of when the signing actually took place, to
allow the engine to treat certain timing-related failure conditions
as permanent (as opposed to returning a cryptic error about missing
existence proofs).


Validating the signer and its timestamps differently
-----------------------------------------------------

PAdES signatures embed timestamp tokens issued by a TSA, and a TSA may
chain up to a different source of trust than the signer. The |SignatureValidationSpec|
lets you supply a dedicated policy for timestamps through
``ts_cert_validation_policy``; when it is omitted, timestamps are validated
against the same policy as the signer.

.. code-block:: python

    tsa_policy = CertValidationPolicySpec(
        trust_manager=SimpleTrustManager.build(trust_roots=[root_cert]),
        revinfo_policy=CertRevTrustPolicy(REQUIRE_REVINFO),
    )
    spec_with_tsa_trust = PdfSignatureValidationSpec(
        SignatureValidationSpec(
            cert_validation_policy=cert_policy,
            ts_cert_validation_policy=tsa_policy,
        )
    )


There is also an ``ac_validation_policy`` slot for validating attribute
certificates carrying signer attributes, should your signatures use them.


Controlling revocation gathering
--------------------------------

How aggressively the engine reaches out to the network is governed by a
:class:`~.pyhanko.sign.validation.policy_decl.RevocationInfoGatheringSpec`,
whose
:class:`~.pyhanko.sign.validation.policy_decl.RevinfoOnlineFetchingRule`
offers three settings:

* :attr:`~.pyhanko.sign.validation.policy_decl.RevinfoOnlineFetchingRule.ALWAYS_FETCH`
  always permits online fetching;
* :attr:`~.pyhanko.sign.validation.policy_decl.RevinfoOnlineFetchingRule.NO_HISTORICAL_FETCH`
  (the default) fetches when validating at the current time, but relies on
  cached/embedded data when reasoning about the past;
* :attr:`~.pyhanko.sign.validation.policy_decl.RevinfoOnlineFetchingRule.LOCAL_ONLY`
  never touches the network.

A properly archived PAdES-LTA document already carries all the revocation
material it needs in its document security store (DSS), so it can be validated
entirely offline, with the possible exception of the outermost timestamp signature.
In this setting,
:attr:`~.pyhanko.sign.validation.policy_decl.RevinfoOnlineFetchingRule.NO_HISTORICAL_FETCH`
is often a good first choice, but
:attr:`~.pyhanko.sign.validation.policy_decl.RevinfoOnlineFetchingRule.LOCAL_ONLY`
with some :ref:`fiat PoE <local-knowledge>` can be very useful as a sanity check.


.. testcode::

    from pyhanko.sign.validation.policy_decl import (
        RevinfoOnlineFetchingRule,
        RevocationInfoGatheringSpec,
    )

    offline_spec = PdfSignatureValidationSpec(
        SignatureValidationSpec(
            cert_validation_policy=cert_policy,
            revinfo_gathering_policy=RevocationInfoGatheringSpec(
                online_fetching_rule=RevinfoOnlineFetchingRule.NO_HISTORICAL_FETCH,
            ),
        )
    )

    async def validate_offline():
        with open('document.pdf', 'rb') as doc:
            sig = PdfFileReader(doc).embedded_signatures[0]
            result = await ades_lta_validation(sig, offline_spec)
            print(result.ades_subindic)

.. testcode::
    :hide:

    asyncio.run(validate_offline())

.. testoutput::

    AdESPassed.OK

.. _local-knowledge:

Supplying additional validation material
-----------------------------------------

Sometimes the data needed to validate a signature lives outside the document:
an intermediate certificate the signer forgot to embed, an OCSP response you
obtained out of band, or a known proof of existence from a trusted archive.
You can feed all of this to the engine through a |LocalKnowledge| object on the
spec, and the engine will treat it as if it had been part of the document.

.. testcode::

    from pyhanko.sign.validation.policy_decl import LocalKnowledge

    extra_cert = load_cert_from_pemder('path/to/certfile')
    spec_with_extras = PdfSignatureValidationSpec(
        SignatureValidationSpec(
            cert_validation_policy=cert_policy,
            local_knowledge=LocalKnowledge(
                known_certs=[extra_cert],
            ),
        )
    )

.. testcode::
    :hide:

    async def _run():
        with open('document.pdf', 'rb') as doc:
            sig = PdfFileReader(doc).embedded_signatures[0]
            result = await ades_lta_validation(sig, spec_with_extras)
            assert result.ades_subindic.name == 'OK', result.ades_subindic
    asyncio.run(_run())

|LocalKnowledge| also accepts ``known_crls`` and ``known_ocsps`` (revocation
data containers), ``known_poes`` (asserted proofs of existence, see
:class:`~.pyhanko_certvalidator.ltv.poe.KnownPOE`) and ``nonrevoked_assertions``
(out-of-band assurances that a particular certificate was not revoked at a given
time). The last two are how you encode trust in an external archival service
that vouches for material a future validator could no longer fetch.


.. _ades-lta-maintainability:

Will this signature survive long-term archival?
------------------------------------------------

A signature that validates today is not necessarily one that will *keep*
validating. If the document was archived without contemporaneous revocation
information, a future validator---even one with a perfectly maintained
timestamp chain---may be unable to confirm that the signer's certificate was
in good standing at signing time.

:func:`~.pyhanko.sign.validation.ades.simulate_future_ades_lta_validation` lets
signers and archivists check for this *before* it becomes a problem. It assigns,
by fiat, proofs of existence to everything currently in the document, disables
all network fetching, and then runs the LTA algorithm against a hypothetical
future validation time. If the simulated validation fails while a normal
validation succeeds, the document is missing material it needs to remain
verifiable.

.. testcode::

    from pyhanko.sign.validation.ades import (
        simulate_future_ades_lta_validation,
    )

    async def check_maintainability():
        future = datetime(2030, 1, 1, tzinfo=timezone.utc)
        with open('document.pdf', 'rb') as doc:
            sig = PdfFileReader(doc).embedded_signatures[0]
            result = await simulate_future_ades_lta_validation(
                sig, validation_spec, future_validation_time=future
            )
            if result.api_status.bottom_line:
                print("LTA-maintainable")
            else:
                print("Missing material:", result.ades_subindic)

.. testcode::
    :hide:

    asyncio.run(check_maintainability())

.. testoutput::
    :hide:

    LTA-maintainable

.. warning::

    :func:`~.pyhanko.sign.validation.ades.simulate_future_ades_lta_validation`
    is experimental API and is intended as a sanity check, not as a substitute
    for a real validation at the time material is actually consulted.


Next steps
----------

To validate against EU trusted lists and impose eIDAS qualification
requirements on top of the machinery described here, continue to
:ref:`qualified-validation`.
