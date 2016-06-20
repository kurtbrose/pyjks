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

Here is a complete and fully-functional example of building an OpenSSL
context using a JKS through PyJKS::

  import jks
  import OpenSSL

  _ASN1 = OpenSSL.crypto.FILETYPE_ASN1

  def jksfile2context(jks_file, passphrase, key_alias, key_password=None):

      keystore = jks.KeyStore.load(jks_file, passphrase)

      pk_entry = keystore.private_keys[key_alias]

      # if the key could not be decrypted using the store password,
      # decrypt with a custom password now
      if not pk_entry.is_decrypted():
          pk_entry.decrypt(key_password)

      pkey = OpenSSL.crypto.load_privatekey(_ASN1, pk_entry.pkey)
      public_cert = OpenSSL.crypto.load_certificate(_ASN1, pk_entry.cert_chain[0][1])
      trusted_certs = [OpenSSL.crypto.load_certificate(_ASN1, cert.cert)
                       for alias, cert in keystore.certs]

      ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
      ctx.use_privatekey(pkey)
      ctx.use_certificate(public_cert)
      ctx.check_privatekey() # want to know ASAP if there is a problem
      cert_store = ctx.get_cert_store()
      for cert in trusted_certs:
          cert_store.add_cert(cert)

      return ctx

And that's just the beginning! Take a look at PyJKS's always-expanding
API for more possibilities.



Contents:

.. toctree::
   :maxdepth: 2



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
