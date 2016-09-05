Examples
========

Building an OpenSSL context using a JKS through PyJKS::

  import jks
  import OpenSSL

  ASN1 = OpenSSL.crypto.FILETYPE_ASN1

  def jksfile2context(jks_file, passphrase, key_alias, key_password=None):

      keystore = jks.KeyStore.load(jks_file, passphrase)
      pk_entry = keystore.private_keys[key_alias]

      # if the key could not be decrypted using the store password,
      # decrypt with a custom password now
      if not pk_entry.is_decrypted():
          pk_entry.decrypt(key_password)

      pkey = OpenSSL.crypto.load_privatekey(ASN1, pk_entry.pkey)
      public_cert = OpenSSL.crypto.load_certificate(ASN1, pk_entry.cert_chain[0][1])
      trusted_certs = [OpenSSL.crypto.load_certificate(ASN1, cert.cert)
                       for alias, cert in keystore.certs]

      ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
      ctx.use_privatekey(pkey)
      ctx.use_certificate(public_cert)
      ctx.check_privatekey() # want to know ASAP if there is a problem
      cert_store = ctx.get_cert_store()
      for cert in trusted_certs:
          cert_store.add_cert(cert)

      return ctx

Reading a JKS or JCEKS keystore and dumping out its contents in the PEM format::

  from __future__ import print_function
  import sys, base64, textwrap
  import jks

  def print_pem(der_bytes, type):
      print("-----BEGIN %s-----" % type)
      print("\r\n".join(textwrap.wrap(base64.b64encode(der_bytes).decode('ascii'), 64)))
      print("-----END %s-----" % type)

  ks = jks.KeyStore.load("keystore.jks", "XXXXXXXX")
  # if any of the keys in the store use a password that is not the same as the store password:
  # ks.entries["key1"].decrypt("key_password")

  for alias, pk in ks.private_keys.items():
      print("Private key: %s" % pk.alias)
      if pk.algorithm_oid == jks.util.RSA_ENCRYPTION_OID:
          print_pem(pk.pkey, "RSA PRIVATE KEY")
      else:
          print_pem(pk.pkey_pkcs8, "PRIVATE KEY")

      for c in pk.cert_chain:
          print_pem(c[1], "CERTIFICATE")
      print()

  for alias, c in ks.certs.items():
      print("Certificate: %s" % c.alias)
      print_pem(c.cert, "CERTIFICATE")
      print()

  for alias, sk in ks.secret_keys.items():
      print("Secret key: %s" % sk.alias)
      print("  Algorithm: %s" % sk.algorithm)
      print("  Key size: %d bits" % sk.key_size)
      print("  Key: %s" % "".join("{:02x}".format(b) for b in bytearray(sk.key)))
      print()
