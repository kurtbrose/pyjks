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

If you receive an error like:

.. code-block:: console

    error: Microsoft Visual C++ 14.0 is required. Get it with "Microsoft Visual C++ Build Tools": https://visualstudio.microsoft.com/downloads/

on Windows you will need to download the Visual C++ build tools by visiting https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=BuildTools&rel=16

Save the file, then run it. Choose "Workloads" tab, then select the "C++ build tools". Under the "Optional" installed items, be certain to select all of ``MSVC vxxx - VS 2019 C++ build tools``, ``Windows 10 SDK`` (latest version), and ``C++/CLI support for build tools``.  Reboot, then run the ``pip`` command again.

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
