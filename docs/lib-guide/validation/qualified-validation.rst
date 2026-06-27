.. _qualified-validation:

EU trusted lists and qualified signatures
=========================================

.. versionadded:: 0.30.0

With the optional ``[etsi]`` dependency group installed, pyHanko can use
EU trusted lists (as published under eIDAS) as a source of trust, and assess
whether a signature was produced with a *qualified* certificate.

This page assumes familiarity with :ref:`the AdES validation engine
<ades-validation>`; trusted-list support slots into the same
|SignatureValidationSpec| machinery described there.


.. |SignatureValidationSpec| replace:: :class:`~.pyhanko.sign.validation.policy_decl.SignatureValidationSpec`
.. |TSPTrustManager| replace:: :class:`~.pyhanko.sign.validation.qualified.tsp.TSPTrustManager`
.. |TSPRegistry| replace:: :class:`~.pyhanko.sign.validation.qualified.tsp.TSPRegistry`
.. |QualificationRequirements| replace:: :class:`~.pyhanko.sign.validation.policy_decl.QualificationRequirements`
.. |CertValidationPolicySpec| replace:: :class:`~.pyhanko_certvalidator.context.CertValidationPolicySpec`


.. testsetup:: *

    globals().update(make_doc_env(DocEnvSpec(
        arch=ArchLabel('testing-ca-qualified'),
        files={},
        signers=(),
        signed_documents=(
            SignedDocSpec(
                profile=SignatureProfile.PADES,
                signer_cert=CertLabel('eseal-qualified'),
                signer_chain=(
                    CertLabel('root'), CertLabel('interm-qualified'),
                ),
            ),
        ),
        timestamping=TimestampSpec(service=ServiceLabel('tsa-qualified')),
        trust=TrustSpec(fetch_revocation=True),
        trust_list=TrustListSpec(),
    )))

.. testcleanup:: *

    teardown_doc_env(_doc_env)


How trust lists fit in
----------------------

Under eIDAS, every member state publishes a signed *trusted list* (TL)
enumerating its qualified trust service providers, and the European Commission
publishes a *list of the lists* (LOTL) pointing at all of them. Rather than a
flat set of root certificates, a trusted list associates each trust service
with rich metadata.

PyHanko models this through a |TSPRegistry|, which a |TSPTrustManager| then
exposes to the validation engine as a trust source. Because the trust manager
plugs into the ordinary |CertValidationPolicySpec|, everything from the
:ref:`AdES engine guide <ades-validation>`---revocation gathering, local
knowledge, LTA validation---continues to work unchanged.


Building a registry from a trusted list
---------------------------------------

In production you will normally bootstrap the registry from the live LOTL (see
:ref:`below <qualified-live-lotl>`). The underlying operation, however, is to
parse a single signed trusted list into a |TSPRegistry|, verifying its XML
signature against the scheme operator's certificate. That is exactly what
:func:`~.pyhanko.sign.validation.qualified.eutl_parse.trust_list_to_registry`
does, and it works fully offline given a trusted-list document on disk.

.. testcode::

    from pyhanko.keys import load_cert_from_pemder
    from pyhanko.sign.validation.qualified.eutl_parse import (
        trust_list_to_registry,
    )

    # The scheme operator's certificate, used to verify the list signature.
    tlso_cert = load_cert_from_pemder('path/to/certfile')
    with open('trusted-list.xml', 'r', encoding='utf-8') as tl_file:
        registry, recoverable_errors = trust_list_to_registry(
            tl_file.read(), tlso_certs=[tlso_cert]
        )

    # 'recoverable_errors' flags services that could not be parsed; the rest
    # of the registry is still usable.
    cas = list(registry.known_certificate_authorities)
    print("CAs registered:", len(cas))

.. testoutput::

    CAs registered: 1


Validating against the registry
-------------------------------

To use the registry, wrap it in a |TSPTrustManager| and drop that into a
|CertValidationPolicySpec| exactly where a
:class:`~.pyhanko_certvalidator.registry.SimpleTrustManager` would go.

.. testcode::

    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation.ades import ades_basic_validation
    from pyhanko.sign.validation.policy_decl import SignatureValidationSpec
    from pyhanko.sign.validation.qualified.tsp import TSPTrustManager
    from pyhanko_certvalidator.context import CertValidationPolicySpec
    from pyhanko_certvalidator.policy_decl import (
        CertRevTrustPolicy,
        REQUIRE_REVINFO,
    )

    validation_spec = SignatureValidationSpec(
        cert_validation_policy=CertValidationPolicySpec(
            trust_manager=TSPTrustManager(registry),
            revinfo_policy=CertRevTrustPolicy(REQUIRE_REVINFO),
        ),
    )

    async def validate():
        with open('document.pdf', 'rb') as doc:
            sig = PdfFileReader(doc).embedded_signatures[0]
            result = await ades_basic_validation(
                sig.signed_data,
                validation_spec=validation_spec,
                raw_digest=sig.compute_digest(),
            )
            print(result.ades_subindic)
        return result

.. testcode::
    :hide:

    import asyncio
    _result = asyncio.run(validate())

.. testoutput::

    AdESPassed.OK


Inspecting the qualification verdict
------------------------------------

When validation succeeds against a trusted list, the resulting
:class:`~.pyhanko.sign.validation.status.PdfSignatureStatus` carries a
:class:`~.pyhanko.sign.validation.qualified.q_status.QualificationResult`
describing *how* the certificate qualifies. Its
:class:`~.pyhanko.sign.validation.qualified.q_status.QualifiedStatus` reports
whether the certificate is qualified, the
:class:`~.pyhanko.sign.validation.qualified.tsp.QcCertType` (an e-signature,
e-seal or website-authentication certificate), and the private-key management
type (e.g. whether the key resides in a qualified signature creation device).

.. testcode::

    async def report_qualification():
        with open('document.pdf', 'rb') as doc:
            sig = PdfFileReader(doc).embedded_signatures[0]
            result = await ades_basic_validation(
                sig.signed_data,
                validation_spec=validation_spec,
                raw_digest=sig.compute_digest(),
            )
        qualification = result.api_status.qualification_result
        status = qualification.status
        print("Qualified:", status.qualified)
        print("Type:", status.qc_type.name)

.. testcode::
    :hide:

    asyncio.run(report_qualification())

.. testoutput::

    Qualified: True
    Type: QC_ESEAL


Imposing qualification requirements
-----------------------------------

Knowing the qualification status is one thing; *requiring* a particular status
is another. Attach a |QualificationRequirements| to the
|SignatureValidationSpec| to make the engine reject signatures that do not meet
your eIDAS policy. A signature that validates cryptographically but fails the
qualification requirements is reported as
:attr:`~.pyhanko.sign.ades.report.AdESIndeterminate.SIG_CONSTRAINTS_FAILURE`.

.. testcode::

    from pyhanko.sign.validation.policy_decl import QualificationRequirements
    from pyhanko.sign.validation.qualified.tsp import QcCertType

    eseal_spec = SignatureValidationSpec(
        cert_validation_policy=CertValidationPolicySpec(
            trust_manager=TSPTrustManager(registry),
            revinfo_policy=CertRevTrustPolicy(REQUIRE_REVINFO),
        ),
        qualification_requirements=QualificationRequirements(
            permit_cert_types=frozenset([QcCertType.QC_ESEAL]),
        ),
    )

    async def validate_eseal_only():
        with open('document.pdf', 'rb') as doc:
            sig = PdfFileReader(doc).embedded_signatures[0]
            result = await ades_basic_validation(
                sig.signed_data,
                validation_spec=eseal_spec,
                raw_digest=sig.compute_digest(),
            )
            print(result.ades_subindic)

.. testcode::
    :hide:

    asyncio.run(validate_eseal_only())

.. testoutput::

    AdESPassed.OK

By default, |QualificationRequirements| permits e-signature and e-seal
certificates. Its other knobs let you tighten the policy further:

* ``permit_key_mgmt_types`` restricts which
  :class:`~.pyhanko.sign.validation.qualified.q_status.QcPrivateKeyManagementType`
  values are acceptable---e.g. require a QSCD-resident key;
* ``require_service_type`` demands that the end-entity certificate be listed
  directly as a service of a given type. This is the natural way to insist that
  a *timestamp* come from a qualified timestamping authority (QTST), by passing
  the corresponding requirement as ``ts_qualification_requirements`` on the
  spec.

.. note::

    Qualification requirements only make sense against a |TSPTrustManager|;
    a plain root-certificate trust manager carries no qualification metadata.


.. _qualified-live-lotl:

Bootstrapping from the live LOTL
--------------------------------

The example above parses a trusted list already on disk. In production you will
instead fetch the whole hierarchy starting from the EU list-of-the-lists, which
pyHanko handles with
:func:`~.pyhanko.sign.validation.qualified.eutl_fetch.lotl_to_registry`. The
default bootstrap keys for the LOTL signature are bundled with the library, and
results are cached on disk so you do not refetch dozens of national lists on
every run.

.. testcode::

    import aiohttp
    from datetime import timedelta
    from pyhanko.sign.validation.qualified.eutl_fetch import (
        FileSystemTLCache,
        lotl_to_registry,
    )

    async def prepare_registry(cache_dir):
        # In production, point the cache at a persistent location such as
        # '/var/cache/trust-lists' so national lists are not refetched unnecessarily.
        cache = FileSystemTLCache(cache_dir, expire_after=timedelta(days=14))
        async with aiohttp.ClientSession() as client:
            registry, errors = await lotl_to_registry(
                # 'None' bootstraps from the official list-of-the-lists.
                lotl_xml=None,
                client=client,
                cache=cache,
                # Limit the member states taken into account; a cold full
                # fetch covers the whole EU and can take a while.
                only_territories={'be'},
            )
            return registry

.. testcode::
    :hide:

    # run_with_seeded_lotl pre-populates the cache with the bundled LOTL and
    # the Belgian list, so the sample above runs without network access.
    _registry = run_with_seeded_lotl(prepare_registry)
    assert list(_registry.known_certificate_authorities)

The |TSPRegistry| it returns is interchangeable with the one built offline
above, so everything else on this page applies verbatim.
