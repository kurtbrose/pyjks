.. PyJKS documentation master file, created by
   sphinx-quickstart on Fri Jun  3 00:40:21 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

PyJKS
=====

PyJKS is *the* pure-Python library for Java KeyStore (JKS) parsing,
decryption, and manipulation. PyJKS supports vanilla JKS, JCEKS, BKS,
and UBER (BouncyCastle) keystore formats.

In the past, Python projects relied on external tools (*keytool*),
intermediate formats (*PKCS12* and *PEM*), and the JVM to work with
encrypted material locked within JKS files. Now, PyJKS changes that.

Examples
--------

See the :doc:`examples` page for usage examples of PyJKS.

Installation
------------
You can install ``pyjks`` with ``pip``:

.. code-block:: console

    $ pip install pyjks

Contents:
---------

.. toctree::
   :maxdepth: 2

   examples
   concepts
   jks
   bks
   exceptions


Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
