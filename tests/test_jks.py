#!/usr/bin/env python
# vim: set ai et ts=4 sw=4 sts=4:
"""
Tests for pyjks.
Note: run 'mvn test' in the tests/java directory to reproduce keystore files (requires a working Maven installation)
"""

import os, sys
import jks
import unittest
import subprocess
from pprint import pprint
from . import expected

class cd:
    def __init__(self, newdir):
        self.newdir = newdir
    def __enter__(self):
        self.olddir = os.getcwd()
        os.chdir(self.newdir)
    def __exit__(self, etype, value, trace):
        os.chdir(self.olddir)

class AbstractTest(unittest.TestCase):
    def find_private_key(self, ks, alias):
        for pk in ks.private_keys:
            if pk.alias == alias:
                self.assertTrue(isinstance(pk.pkey, bytes))
                self.assertTrue(isinstance(pk.pkey_pkcs8, bytes))
                self.assertTrue(isinstance(pk.cert_chain, list))
                self.assertTrue(all(isinstance(c[1], bytes) for c in pk.cert_chain))
                return pk
        self.fail("Private key entry not found: %s" % alias)

    def find_secret_key(self, ks, alias):
        for sk in ks.secret_keys:
            if sk.alias == alias:
                self.assertTrue(isinstance(sk.key, bytes))
                return sk
        self.fail("Secret key entry not found: %s" % alias)

    def find_cert(self, ks, alias):
        for c in ks.certs:
            if c.alias == alias:
                self.assertTrue(isinstance(c.cert, bytes))
                return c
        self.fail("Certificate entry not found: %s" % alias)

    def check_pkey_and_certs_equal(self, pk, algorithm_oid, pkey_pkcs8, certs):
        self.assertEqual(pk.algorithm_oid, algorithm_oid)
        self.assertEqual(pk.pkey_pkcs8, pkey_pkcs8)
        self.assertEqual(len(pk.cert_chain), len(certs))
        for i in range(len(certs)):
            self.assertEqual(pk.cert_chain[i][1], certs[i])

    def check_secret_key_equal(self, sk, algorithm_name, key_size, key_bytes):
        self.assertEqual(sk.algorithm, algorithm_name)
        self.assertEqual(sk.size, key_size)
        self.assertEqual(sk.key, key_bytes)

class JksTests(AbstractTest):
    def test_empty_store(self):
        store = jks.KeyStore.load("tests/keystores/jks/empty.jks", "")
        self.assertEqual(store.store_type, "jks")
        self.assertEqual(len(store.private_keys), 0)
        self.assertEqual(len(store.secret_keys), 0)
        self.assertEqual(len(store.certs), 0)

    def test_rsa_1024(self):
        store = jks.KeyStore.load("tests/keystores/jks/RSA1024.jks", "12345678")
        pk = self.find_private_key(store, "mykey")
        self.assertEqual(store.store_type, "jks")
        self.check_pkey_and_certs_equal(pk, jks.RSA_ENCRYPTION_OID, expected.RSA1024.private_key, expected.RSA1024.certs)

    def test_rsa_2048_3certs(self):
        store = jks.KeyStore.load("tests/keystores/jks/RSA2048_3certs.jks", "12345678")
        pk = self.find_private_key(store, "mykey")
        self.assertEqual(store.store_type, "jks")
        self.check_pkey_and_certs_equal(pk, jks.RSA_ENCRYPTION_OID, expected.RSA2048_3certs.private_key, expected.RSA2048_3certs.certs)

    def test_dsa_2048(self):
        store = jks.KeyStore.load("tests/keystores/jks/DSA2048.jks", "12345678")
        pk = self.find_private_key(store, "mykey")
        self.assertEqual(store.store_type, "jks")
        self.check_pkey_and_certs_equal(pk, jks.DSA_OID, expected.DSA2048.private_key, expected.DSA2048.certs)

    def test_certs(self):
        store = jks.KeyStore.load("tests/keystores/jks/3certs.jks", "12345678")
        cert1 = self.find_cert(store, "cert1")
        cert2 = self.find_cert(store, "cert2")
        cert3 = self.find_cert(store, "cert3")
        self.assertEqual(cert1.cert, expected.RSA2048_3certs.certs[0])
        self.assertEqual(cert2.cert, expected.RSA2048_3certs.certs[1])
        self.assertEqual(cert3.cert, expected.RSA2048_3certs.certs[2])
        self.assertEqual(store.store_type, "jks")

    def test_non_ascii_jks_password(self):
        store = jks.KeyStore.load("tests/keystores/jks/non_ascii_password.jks", u"\u10DA\u0028\u0CA0\u76CA\u0CA0\u10DA\u0029")
        pk = self.find_private_key(store, "mykey")
        self.assertEqual(store.store_type, "jks")
        self.check_pkey_and_certs_equal(pk, jks.RSA_ENCRYPTION_OID, expected.jks_non_ascii_password.private_key, expected.jks_non_ascii_password.certs)

class JceTests(AbstractTest):
    def test_empty_store(self):
        store = jks.KeyStore.load("tests/keystores/jceks/empty.jceks", "")
        self.assertEqual(store.store_type, "jceks")
        self.assertEqual(len(store.private_keys), 0)
        self.assertEqual(len(store.secret_keys), 0)
        self.assertEqual(len(store.certs), 0)

    def test_rsa_1024(self):
        store = jks.KeyStore.load("tests/keystores/jceks/RSA1024.jceks", "12345678")
        pk = self.find_private_key(store, "mykey")
        self.assertEqual(store.store_type, "jceks")
        self.check_pkey_and_certs_equal(pk, jks.RSA_ENCRYPTION_OID, expected.RSA1024.private_key, expected.RSA1024.certs)

    def test_rsa_2048_3certs(self):
        store = jks.KeyStore.load("tests/keystores/jceks/RSA2048_3certs.jceks", "12345678")
        pk = self.find_private_key(store, "mykey")
        self.assertEqual(store.store_type, "jceks")
        self.check_pkey_and_certs_equal(pk, jks.RSA_ENCRYPTION_OID, expected.RSA2048_3certs.private_key, expected.RSA2048_3certs.certs)

    def test_dsa_2048(self):
        store = jks.KeyStore.load("tests/keystores/jceks/DSA2048.jceks", "12345678")
        pk = self.find_private_key(store, "mykey")
        self.assertEqual(store.store_type, "jceks")
        self.check_pkey_and_certs_equal(pk, jks.DSA_OID, expected.DSA2048.private_key, expected.DSA2048.certs)

    def test_certs(self):
        store = jks.KeyStore.load("tests/keystores/jceks/3certs.jceks", "12345678")
        cert1 = self.find_cert(store, "cert1")
        cert2 = self.find_cert(store, "cert2")
        cert3 = self.find_cert(store, "cert3")
        self.assertEqual(cert1.cert, expected.RSA2048_3certs.certs[0])
        self.assertEqual(cert2.cert, expected.RSA2048_3certs.certs[1])
        self.assertEqual(cert3.cert, expected.RSA2048_3certs.certs[2])
        self.assertEqual(store.store_type, "jceks")

class JceOnlyTests(AbstractTest):
    def test_des_secret_key(self):
        store = jks.KeyStore.load("tests/keystores/jceks/DES.jceks", "12345678")
        sk = self.find_secret_key(store, "mykey")
        self.assertEqual(store.store_type, "jceks")
        self.check_secret_key_equal(sk, "DES", 64, b"\x4c\xf2\xfe\x91\x5d\x08\x2a\x43")

    def test_desede_secret_key(self):
        store = jks.KeyStore.load("tests/keystores/jceks/DESede.jceks", "12345678")
        sk = self.find_secret_key(store, "mykey")
        self.assertEqual(store.store_type, "jceks")
        self.check_secret_key_equal(sk, "DESede", 192, b"\x67\x5e\x52\x45\xe9\x67\x3b\x4c\x8f\xc1\x94\xce\xec\x43\x3b\x31\x8c\x45\xc2\xe0\x67\x5e\x52\x45")

    def test_aes128_secret_key(self):
        store = jks.KeyStore.load("tests/keystores/jceks/AES128.jceks", "12345678")
        sk = self.find_secret_key(store, "mykey")
        self.assertEqual(store.store_type, "jceks")
        self.check_secret_key_equal(sk, "AES", 128, b"\x66\x6e\x02\x21\xcc\x44\xc1\xfc\x4a\xab\xf4\x58\xf9\xdf\xdd\x3c")

    def test_aes256_secret_key(self):
        store = jks.KeyStore.load("tests/keystores/jceks/AES256.jceks", "12345678")
        sk = self.find_secret_key(store, "mykey")
        self.assertEqual(store.store_type, "jceks")
        self.check_secret_key_equal(sk, "AES", 256, b"\xe7\xd7\xc2\x62\x66\x82\x21\x78\x7b\x6b\x5a\x0f\x68\x77\x12\xfd\xe4\xbe\x52\xe9\xe7\xd7\xc2\x62\x66\x82\x21\x78\x7b\x6b\x5a\x0f")

    def test_pbkdf2_hmac_sha1(self):
        store = jks.KeyStore.load("tests/keystores/jceks/PBKDF2WithHmacSHA1.jceks", "12345678")
        sk = self.find_secret_key(store, "mykey")
        self.assertEqual(store.store_type, "jceks")
        self.check_secret_key_equal(sk, "PBKDF2WithHmacSHA1", 256, b"\x57\x95\x36\xd9\xa2\x7f\x7e\x31\x4e\xf4\xe3\xff\xa5\x76\x26\xef\xe6\x70\xe8\xf4\xd2\x96\xcd\x31\xba\x1a\x82\x7d\x9a\x3b\x1e\xe1")

    def test_unknown_type_of_sealed_object(self):
        """Verify that an exception is raised when encountering a (serialized) Java object inside a SecretKey entry that is not of type javax.crypto.SealedObject"""
        self.assertRaises(jks.UnexpectedJavaTypeException, lambda: \
            jks.KeyStore.load("tests/keystores/jceks/unknown_type_of_sealed_object.jceks", "12345678"))

    def test_unknown_type_inside_sealed_object(self):
        """Verify that an exception is raised when encountering a (serialized) Java object inside of a SealedObject in a SecretKey entry (after decryption) that is not of a recognized/supported type"""
        self.assertRaises(jks.UnexpectedJavaTypeException, lambda: \
            jks.KeyStore.load("tests/keystores/jceks/unknown_type_inside_sealed_object.jceks", "12345678"))

    def test_unknown_sealed_object_sealAlg(self):
        self.assertRaises(jks.UnexpectedAlgorithmException, lambda: \
            jks.KeyStore.load("tests/keystores/jceks/unknown_sealed_object_sealAlg.jceks", "12345678"))

class MiscTests(AbstractTest):
    def test_strip_pkcs5_padding(self):
        self.assertEqual(jks.jks._strip_pkcs5_padding(b"\x08\x08\x08\x08\x08\x08\x08\x08"), b"")
        self.assertEqual(jks.jks._strip_pkcs5_padding(b"\x01\x07\x07\x07\x07\x07\x07\x07"), b"\x01")
        self.assertEqual(jks.jks._strip_pkcs5_padding(b"\x01\x02\x03\x04\x05\x06\x07\x01"), b"\x01\x02\x03\x04\x05\x06\x07")

        self.assertRaises(jks.BadPaddingException, jks.jks._strip_pkcs5_padding, b"")
        self.assertRaises(jks.BadPaddingException, jks.jks._strip_pkcs5_padding, b"\x01")
        self.assertRaises(jks.BadPaddingException, jks.jks._strip_pkcs5_padding, b"\x01\x02\x03\x04\x08\x08")
        self.assertRaises(jks.BadPaddingException, jks.jks._strip_pkcs5_padding, b"\x07\x07\x07\x07\x07\x07\x07")
        self.assertRaises(jks.BadPaddingException, jks.jks._strip_pkcs5_padding, b"\x00\x00\x00\x00\x00\x00\x00\x00")

if __name__ == "__main__":
    unittest.main()
