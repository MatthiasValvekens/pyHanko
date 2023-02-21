pyhanko.sign.diff\_analysis package
===================================


.. versionchanged:: 0.2.0

    Module extracted from :mod:`pyhanko.sign.validation`
    and restructured into a more rule-based format.

.. versionchanged:: 0.11.0

    Module refactored into sub-package.

This package defines utilities for difference analysis between revisions
of the same PDF file.
PyHanko uses this functionality to validate signatures on files
that have been modified after signing (using PDF's incremental update feature).

In pyHanko's validation model, every incremental update is disallowed by
default. For a change to be accepted, it must be cleared by at least one
whitelisting rule.
These rules can moreover *qualify* the modification level at which they accept
the change (see :class:`.ModificationLevel`).
Additionally, any rule can veto an entire revision as suspect by raising
a :class:`.SuspiciousModification` exception.
Whitelisting rules are encouraged to apply their vetoes liberally.


Whitelisting rules are bundled in :class:`.DiffPolicy` objects for use by the
validator.


Guidelines for developing rules for use with :class:`.StandardDiffPolicy`
-------------------------------------------------------------------------

.. caution::
    These APIs aren't fully stable yet, so some changes might still occur
    between now and the first major release.

In general, you should keep the following informal guidelines in mind when
putting together custom diff rules.

* All rules are either executed completely (i.e. their generators exhausted)
  or aborted.
* If the diff runner aborts a rule, this always means that the entire
  revision is rejected. In other words, for accepted revisions, all rules
  will always have run to completion.
* Whitelisting rules are allowed to informally delegate some checking to
  other rules, provided that this is documented clearly.

  .. note::
      Example: :class:`.CatalogModificationRule` ignores ``/AcroForm``,
      which is validated by another rule entirely.

* Rules should be entirely stateless.
  "Clearing" a reference by yielding it does not imply that the revision
  cannot be vetoed by that same rule further down the road (this is why
  the first point is important).


Subpackages
-----------

.. toctree::
   :maxdepth: 4

   pyhanko.sign.diff_analysis.rules

Submodules
----------

pyhanko.sign.diff\_analysis.commons module
------------------------------------------

.. automodule:: pyhanko.sign.diff_analysis.commons
   :members:
   :undoc-members:
   :show-inheritance:

pyhanko.sign.diff\_analysis.constants module
--------------------------------------------

.. automodule:: pyhanko.sign.diff_analysis.constants
   :members:
   :undoc-members:
   :show-inheritance:

pyhanko.sign.diff\_analysis.form\_rules\_api module
---------------------------------------------------

.. automodule:: pyhanko.sign.diff_analysis.form_rules_api
   :members:
   :undoc-members:
   :show-inheritance:

pyhanko.sign.diff\_analysis.policies module
-------------------------------------------

.. automodule:: pyhanko.sign.diff_analysis.policies
   :members:
   :undoc-members:
   :show-inheritance:

pyhanko.sign.diff\_analysis.policy\_api module
----------------------------------------------

.. automodule:: pyhanko.sign.diff_analysis.policy_api
   :members:
   :undoc-members:
   :show-inheritance:

pyhanko.sign.diff\_analysis.rules\_api module
---------------------------------------------

.. automodule:: pyhanko.sign.diff_analysis.rules_api
   :members:
   :undoc-members:
   :show-inheritance:
