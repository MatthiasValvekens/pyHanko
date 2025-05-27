![Codecov](https://img.shields.io/codecov/c/github/MatthiasValvekens/pyHanko)
![pypi](https://img.shields.io/pypi/v/pyHanko.svg)


``pyhanko`` is a library for working with signatures in PDF documents.

**Note:** pyHanko's CLI is no longer bundled together with the library. This functionality is now
distributed separately as ``pyhanko-cli``.

### Documentation

The [documentation for pyHanko is hosted on ReadTheDocs](https://pyhanko.readthedocs.io/en/latest/)
and includes information on CLI usage, library usage, and API reference documentation derived from
inline docstrings.

### Installing

PyHanko is hosted on [PyPI](https://pypi.org/project/pyHanko/),
and can be installed using `pip`:

```bash
pip install 'pyHanko[pkcs11,image-support,opentype,qr]'
```

Depending on your shell, you might have to leave off the quotes:

```bash
pip install pyHanko[pkcs11,image-support,opentype,qr]
```

This `pip` invocation includes the optional dependencies required for PKCS#11, image handling,
OpenType/TrueType support and QR code generation.

PyHanko requires Python 3.9 or later.