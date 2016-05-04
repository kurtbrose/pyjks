"""PyJKS enables Python projects to load and manipulate Java KeyStore
(JKS) data without a JVM dependency. PyJKS supports a wide variety of
JKS subformats. Simply::

  pip install pyjks

Or::

  easy_install pyjks

Then::

  import jks

  keystore = jks.KeyStore.load('keystore.jks', 'passphrase')

  print(ks.private_keys)
  print(ks.certs)
  print(ks.secret_keys)

Of course PyJKS can do much more. Check out `the usage examples on
GitHub <https://github.com/doublereedkurt/pyjks#usage-examples>`_ for
more!
"""

import os
from setuptools import setup, find_packages


setup(
    name='pyjks',
    version='0.3.1',
    author="Kurt Rose",
    author_email="kurt@kurtrose.com",
    description='Pure-Python Java Keystore (JKS) library',
    keywords="JKS JCEKS java keystore security ssl",
    license="MIT",
    url="http://github.com/doublereedkurt/pyjks",
    long_description=__doc__,
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
        'Topic :: Utilities',
        'Topic :: Software Development :: Libraries',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: Implementation :: PyPy',
    ],
    packages=find_packages(),
    install_requires=['pyasn1',
                      'pyasn1_modules',
                      'javaobj-py3',
                      'pycrypto'],
    test_suite="tests.test_jks",
)
