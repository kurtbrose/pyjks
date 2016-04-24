pyjks
=====

A pure python Java KeyStore file parser, including private/secret key decryption. Can read both JKS and JCEKS key stores.

The best way to utilize a certificate stored in a jks file up to this point has been
to use the java keytool command to transform to pkcs12, and then openssl to transform to pem.

This is better:
 -  no security concerns in passwords going into command line arguments, or unencrypted files being left around
 -  no dependency on a JVM

## Requirements:

 * Python 2.6+ (no Python 3 support yet)
 * pyasn1 0.1.7+
 * pyasn1_modules 0.0.8+
 * javaobj-py3 0.1.4+
 * pycrypto, if you need to read JCEKS keystores

## Usage examples:

Reading a JKS or JCEKS keystore and dumping out its contents in the PEM format:
```python
import sys, base64, textwrap
import jks

def print_pem(der_bytes, type):
    print "-----BEGIN %s-----" % type
    print "\r\n".join(textwrap.wrap(base64.b64encode(der_bytes).decode('ascii'), 64))
    print "-----END %s-----" % type

ks = jks.KeyStore.load("keystore.jks", "XXXXXXXX")

for pk in ks.private_keys:
    print "Private key: %s" % pk.alias
    if pk.algorithm_oid == jks.RSA_ENCRYPTION_OID:
        print_pem(pk.pkey, "RSA PRIVATE KEY")
    else:
        print_pem(pk.pkey_pkcs8, "PRIVATE KEY")

    for c in pk.cert_chain:
        print_pem(c[1], "CERTIFICATE")
    print

for c in ks.certs:
    print "Certificate: %s" % c.alias
    print_pem(c.cert, "CERTIFICATE")
    print

for sk in ks.secret_keys:
    print "Secret key: %s" % sk.alias
    print "  Algorithm: %s" % sk.algorithm
    print "  Key size: %d bits" % sk.size
    print "  Key: "+(''.join(x.encode('hex') for x in sk.key))
```


Transforming an encrypted JKS/JCEKS file into an OpenSSL context):
```python
import OpenSSL
import jks

_ASN1 = OpenSSL.crypto.FILETYPE_ASN1

def jksfile2context(jks_file, passphrase):
    keystore = jks.KeyStore.load(jks_file, passphrase)
    pkey = OpenSSL.crypto.load_privatekey(_ASN1, keystore.private_keys[0].pkey)
    trusted_certs = [OpenSSL.crypto.load_certificate(_ASN1, cert.cert)
                     for cert in keystore.certs]
    public_cert = OpenSSL.crypto.load_certificate(
        _ASN1, keystore.private_keys[0].cert_chain[0][1])

    ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
    ctx.use_privatekey(pkey)
    ctx.use_certificate(public_cert)
    #want to know ASAP if there is a problem with the protected
    ctx.check_privatekey()
    cert_store = ctx.get_cert_store()
    for cert in trusted_certs:
        cert_store.add_cert(cert)
    return ctx

```

