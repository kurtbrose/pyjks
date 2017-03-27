# PyJKS Changelog

Since August 14, 2013 there have been 4 releases and 146 commits for an
average of one 36-commit release every year.

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
