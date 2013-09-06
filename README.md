pyjks
=====

A pure python Java KeyStore file parser, including private key decryption.

Usage example (transforming an encrypted jks file into an OpenSSL context):
```python
import OpenSSL
import jks

_ASN1 = OpenSSL.crypto.FILETYPE_ASN1

def jksfile2context(jks_file, passphrase):
    keystore = jks.KeyStore.load(jks_file, passphrase)
    pkey = OpenSSL.crypto.load_privatekey(_ASN1, keystore.private_key.pkey)
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

The best way to utilize a certificate stored in a jks file up to this point has been
to use the java keytool command to transform to pkcs12, and then openssl to transform to pem.

This is better:

1-  no security concerns in passwords going into command line arguments, or unencrypted files being left around

2-  no dependency on a JVM

