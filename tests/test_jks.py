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
        for i in xrange(len(certs)):
            self.assertEqual(pk.cert_chain[i][1], certs[i])

class JksTests(AbstractTest):
    def test_empty_store(self):
        store = jks.KeyStore.load("tests/keystores/jks/empty.jks", "")
        self.assertEqual(len(store.private_keys), 0)
        self.assertEqual(len(store.secret_keys), 0)
        self.assertEqual(len(store.certs), 0)

    def test_rsa_1024(self):
        store = jks.KeyStore.load("tests/keystores/jks/RSA1024.jks", "12345678")
        pk = self.find_private_key(store, "mykey")
        self.check_pkey_and_certs_equal(pk, jks.RSA_ENCRYPTION_OID, expected.RSA1024.private_key, expected.RSA1024.certs)

    def test_rsa_2048_3certs(self):
        store = jks.KeyStore.load("tests/keystores/jks/RSA2048_3certs.jks", "12345678")
        pk = self.find_private_key(store, "mykey")
        self.check_pkey_and_certs_equal(pk, jks.RSA_ENCRYPTION_OID, expected.RSA2048_3certs.private_key, expected.RSA2048_3certs.certs)

class JceTests(AbstractTest):
    def test_empty_store(self):
        store = jks.KeyStore.load("tests/keystores/jceks/empty.jceks", "")
        self.assertEqual(len(store.private_keys), 0)
        self.assertEqual(len(store.secret_keys), 0)
        self.assertEqual(len(store.certs), 0)

    def test_rsa_1024(self):
        store = jks.KeyStore.load("tests/keystores/jceks/RSA1024.jceks", "12345678")
        pk = self.find_private_key(store, "mykey")
        self.check_pkey_and_certs_equal(pk, jks.RSA_ENCRYPTION_OID, expected.RSA1024.private_key, expected.RSA1024.certs)

    def test_rsa_2048_3certs(self):
        store = jks.KeyStore.load("tests/keystores/jceks/RSA2048_3certs.jceks", "12345678")
        pk = self.find_private_key(store, "mykey")
        self.check_pkey_and_certs_equal(pk, jks.RSA_ENCRYPTION_OID, expected.RSA2048_3certs.private_key, expected.RSA2048_3certs.certs)

class JceOnlyTests(AbstractTest):
    def test_des_secret_key(self):
        store = jks.KeyStore.load("tests/keystores/jceks/DES.jceks", "12345678")
        sk = self.find_secret_key(store, "mykey")
        self.assertEqual(sk.key, "\x4c\xf2\xfe\x91\x5d\x08\x2a\x43")
        self.assertEqual(sk.algorithm, "DES")
        self.assertEqual(sk.size, 64)

    def test_desede_secret_key(self):
        store = jks.KeyStore.load("tests/keystores/jceks/DESede.jceks", "12345678")
        sk = self.find_secret_key(store, "mykey")
        self.assertEqual(sk.key, "\x67\x5e\x52\x45\xe9\x67\x3b\x4c\x8f\xc1\x94\xce\xec\x43\x3b\x31\x8c\x45\xc2\xe0\x67\x5e\x52\x45")
        self.assertEqual(sk.algorithm, "DESede")
        self.assertEqual(sk.size, 192)

    def test_aes128_secret_key(self):
        store = jks.KeyStore.load("tests/keystores/jceks/AES128.jceks", "12345678")
        sk = self.find_secret_key(store, "mykey")
        self.assertEqual(sk.key, "\x66\x6e\x02\x21\xcc\x44\xc1\xfc\x4a\xab\xf4\x58\xf9\xdf\xdd\x3c")
        self.assertEqual(sk.algorithm, "AES")
        self.assertEqual(sk.size, 128)

    def test_aes256_secret_key(self):
        store = jks.KeyStore.load("tests/keystores/jceks/AES256.jceks", "12345678")
        sk = self.find_secret_key(store, "mykey")
        self.assertEqual(sk.key, "\xe7\xd7\xc2\x62\x66\x82\x21\x78\x7b\x6b\x5a\x0f\x68\x77\x12\xfd\xe4\xbe\x52\xe9\xe7\xd7\xc2\x62\x66\x82\x21\x78\x7b\x6b\x5a\x0f")
        self.assertEqual(sk.algorithm, "AES")
        self.assertEqual(sk.size, 256)

    def test_pbkdf2_hmac_sha1(self):
        store = jks.KeyStore.load("tests/keystores/jceks/PBKDF2WithHmacSHA1.jceks", "12345678")
        sk = self.find_secret_key(store, "mykey")
        self.assertEqual(sk.key, "\x57\x95\x36\xd9\xa2\x7f\x7e\x31\x4e\xf4\xe3\xff\xa5\x76\x26\xef\xe6\x70\xe8\xf4\xd2\x96\xcd\x31\xba\x1a\x82\x7d\x9a\x3b\x1e\xe1")
        self.assertEqual(sk.algorithm, "PBKDF2WithHmacSHA1")
        self.assertEqual(sk.size, 256)

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

if __name__ == "__main__":
    unittest.main()
