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

Generating a basic self signed certificate with OpenSSL and saving it in a jks keystore::

	import OpenSSL
	import jks

	# generate key
	key = OpenSSL.crypto.PKey()
	key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

	# generate a self signed certificate
	cert = OpenSSL.crypto.X509()
	cert.get_subject().CN = 'my.server.example.com'
	cert.set_serial_number(473289472)
	cert.gmtime_adj_notBefore(0)
	cert.gmtime_adj_notAfter(365*24*60*60)
	cert.set_issuer(cert.get_subject())
	cert.set_pubkey(key)
	cert.sign(key, 'sha256')

	# dumping the key and cert to ASN1
	dumped_cert = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
	dumped_key = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_ASN1, key)

	# creating a private key entry
	pke = jks.PrivateKeyEntry.new('self signed cert', [dumped_cert], dumped_key, 'rsa_raw')

	# if we want the private key entry to have a unique password, we can encrypt it beforehand
	# if it is not ecrypted when saved, it will be encrypted with the same password as the keystore
	#pke.encrypt('my_private_key_password')

	# creating a jks keystore with the private key, and saving it
	keystore = jks.KeyStore.new('jks', [pke])
	keystore.save('./my_keystore.jks', 'my_password')
