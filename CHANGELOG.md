# PyJKS CHANGELOG

Broadly speaking, the PyJKS has been stable since 2017. The JKS
formats themselves do not change rapidly, either. The original author
no longer uses JKS on a daily basis, but the team is happy to respond
to issues, review PRs, and make new releases as new features are
submitted by active PyJKS users.

PyJKS uses the [CalVer](https://calver.org) versioning scheme (`YY.MINOR.MICRO`).

v20.0.0
-------
*(April 18, 2020)*

* Mirrors keytool support for keystores with empty passphrases [#57][i57]
* Add Python 3.7 and 3.8 to support matrix
* Docs and examples fixes

[i46]: https://github.com/kurtbrose/pyjks/pull/57

v19.0.0
-------
*(April 22, 2019)*

A small update, switching to [pycryptodomex][pycryptodomex], for users who may also
need pycrypto for 3rd-party libraries. [#46][i46]

[pycryptodomex]: https://pycryptodome.readthedocs.io/en/latest/src/installation.html
[i46]: https://github.com/kurtbrose/pyjks/pull/46

v18.0.0
-------
*(September 1, 2018)*

A smallish bugfix release:

* Adjusted asn1 encoding so that empty attributes are not included
  (fixes [#34][i34])
* Automatically convert aliases to lowercase for keytool compatibility
  (fixes [#38][i38])

Note that PyJKS now relies on PyASN1 0.3.5+ (released 2017-09-16).

[i34]: https://github.com/kurtbrose/pyjks/issues/34
[i38]: https://github.com/kurtbrose/pyjks/issues/38

v17.1.1
-------
*(November 6, 2017)*

Fix packaging with a MANIFEST.in. See #35 for details.

v17.1.0
-------
*(May 15, 2017)*

No API changes with PyJKS itself. This release switches PyJKS to rely
on [pycryptodome](https://github.com/Legrandin/pycryptodome), a
maintained fork of [pycrypto](https://github.com/dlitz/pycrypto). This
upstream dependency has wheels, so installs should be less painless.

v17.0.0
-------
*(March 26, 2017)*

First public release, now featuring documentation and support for
creating and saving JKS keystores. Big thanks to Magnus Watn and
voetsjoeba for making this possible!

* `version` attribute on BksKeyStore and UberKeyStore
* Documentation across several modules
* Factored out common AbstractKeystore superclass
* JKS creation and saving using the new `save()` method of KeyStore
  objects. See the
  [Examples doc](http://pyjks.readthedocs.io/en/latest/examples.html)
  for a demo.

v0.5.1
------
*(August 25, 2016)*

Support more Python versions and runtimes. Python 2.6, 3.3, 3.5, and
PyPy are all now tested and supported. Also, improved error messages
when parsing JKS and BKS.

No security critical changes or bugfixes.

v0.5.0
------

*(June 19, 2016)*

Support more keystore formats and fix a couple issues.

* Support for [Bouncy Castle][bc] BKS and UBER keystores.
* Fix an issue with trailing data. ([#21][i21])
* Added `__version__` and `__version_info__` package-level attributes.
* Created this CHANGELOG.

[bc]: https://www.bouncycastle.org/
[i21]: https://github.com/kurtbrose/pyjks/issues/21

v0.4.0
------

*(May 4, 2016)*

First public beta release, complete with support for Sun JKS/JCE, on
both Python 2 and 3.
