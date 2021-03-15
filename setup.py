"""PyJKS enables Python projects to load and manipulate Java KeyStore
(JKS) data without a JVM dependency. PyJKS supports JKS, JCEKS, BKS
and UBER (BouncyCastle) keystores. Simply::

  pip install pyjks

Or::

  easy_install pyjks

Then::

  import jks

  keystore = jks.KeyStore.load('keystore.jks', 'passphrase')

  print(keystore.private_keys)
  print(keystore.certs)
  print(keystore.secret_keys)

And that's barely scratching the surface. Check out `the usage examples on
GitHub <https://github.com/kurtbrose/pyjks#usage-examples>`_ for
more!

"""

from setuptools import setup, find_packages


setup(
    name='pyjks',
    version='20.0.1dev',
    author="Kurt Rose, Jeroen De Ridder",
    author_email="kurt@kurtrose.com",
    description='Pure-Python Java Keystore (JKS) library',
    keywords="JKS JCEKS java keystore security ssl",
    license="MIT",
    url="http://github.com/kurtbrose/pyjks",
    long_description=__doc__,
    classifiers=[
        'Development Status :: 6 - Mature',
        'License :: OSI Approved :: MIT License',
        'Topic :: Utilities',
        'Topic :: Software Development :: Libraries',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: Implementation :: PyPy',
    ],
    packages=find_packages(exclude=['tests']),
    test_suite="tests.test_jks",
)


"""
Releasing:

* Update version in setup.py, as well as __version__ and __version_info__ in jks.py
* Final test (currently, tox)
* Commit: "bumping version for x.x.x release"
* Run: python setup.py sdist bdist_wheel upload
* git tag -a vx.x.x -m "summary"
* Update CHANGELOG.md
* Update versions again for dev
* Commit: "bumping version for x.x.x+1 dev"
* git push && git push --tags
"""
