# PyJKS Changelog

Since August 14, 2013 there have been 2 releases and 107 commits.

v0.5.0
------

Support more keystore formats and fix a couple issues.

* Support for [Bouncy Castle][bc] BKS and UBER keystores.
* Fix an issue with trailing data. ([#21][i21])
* Added `__version__` and `__version_info__` package-level attributes.
* Created this CHANGELOG.

[bc]: https://www.bouncycastle.org/
[i21]: https://github.com/doublereedkurt/pyjks/issues/21

v0.4.0
------

First public beta release, complete with support for Sun JKS/JCE, on
both Python 2 and 3.
