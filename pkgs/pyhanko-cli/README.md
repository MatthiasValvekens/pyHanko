The lack of open-source CLI tooling to handle digitally signing and stamping PDF files was bothering me, so I went ahead and rolled my own.

### Installing

PyHanko is hosted on [PyPI](https://pypi.org/project/pyHanko/),
and can be installed using `pip`:

```bash
pip install pyhanko-cli
```

### Documentation

The [documentation for pyHanko is hosted on ReadTheDocs](https://docs.pyhanko.eu/en/latest/)
and includes information on CLI usage, library usage, and API reference documentation derived from
inline docstrings.


### Optional features

Optional dependencies are managed at the level of the ``pyhanko`` package.

```bash
pip install 'pyHanko[pkcs11,image-support,opentype,qr]' pyhanko-cli
```

Depending on your shell, you might have to leave off the quotes:

```bash
pip install pyHanko[pkcs11,image-support,opentype,qr] pyhanko-cli
```

This `pip` invocation includes the optional dependencies required for PKCS#11, image handling,
OpenType/TrueType support and QR code generation.
