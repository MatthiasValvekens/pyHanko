Code generation from XSD data files is handled by `xsdata`.
The version of `xsdata` used to generate these files should be kept in
sync with the version in `pyproject.toml` to ensure compatibility,
and to keep the cumulative maintenance burden for `xsdata` upgrades low.

Generated APIs are not part of pyHanko's public API for the purposes
of semver, and hence care should be exercised not to expose generated
types in public API signatures.

Always generate code by running `genxml.sh` from the project's root directory.