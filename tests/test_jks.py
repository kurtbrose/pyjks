#!/usr/bin/env python
# vim: set ai et ts=4 sw=4 sts=4:
"""
Tests for pyjks.
Note: run 'mvn test' in the tests/java directory to reproduce keystore files (requires a working Maven installation)
"""

from __future__ import print_function
import os, sys
import jks
import unittest
import hashlib
from . import expected
from jks.util import py23basestring

CUR_PATH = os.path.dirname(os.path.abspath(__file__))
KS_PATH = os.path.join(CUR_PATH, 'keystores')


class AbstractTest(unittest.TestCase):
    def find_private_key(self, ks, alias):
        pk = ks.entries[alias]
        if not isinstance(pk, jks.PrivateKeyEntry):
            self.fail("Private key entry not found: %s" % alias)

        if pk.is_decrypted():
            self.assertTrue(isinstance(pk.pkey, bytes))
            self.assertTrue(isinstance(pk.pkey_pkcs8, bytes))
        self.assertTrue(isinstance(pk.cert_chain, list))
        self.assertTrue(all(isinstance(c[1], bytes) for c in pk.cert_chain))
        return pk

    def find_secret_key(self, ks, alias):
        sk = ks.entries[alias]
        if not isinstance(sk, jks.SecretKeyEntry):
            self.fail("Secret key entry not found: %s" % alias)

        if sk.is_decrypted():
            self.assertTrue(isinstance(sk.key, bytes))
        return sk

    def find_cert(self, ks, alias):
        c = ks.entries[alias]
        if not isinstance(c, jks.TrustedCertEntry):
            self.fail("Certificate entry not found: %s" % alias)

        self.assertTrue(isinstance(c.cert, bytes))
        self.assertTrue(isinstance(c.type, py23basestring))
        return c

    def check_pkey_and_certs_equal(self, pk, algorithm_oid, pkey_pkcs8, certs):
        self.assertEqual(pk.algorithm_oid, algorithm_oid)
        self.assertEqual(pk.pkey_pkcs8, pkey_pkcs8)
        self.assertEqual(len(pk.cert_chain), len(certs))
        for i in range(len(certs)):
            self.assertEqual(pk.cert_chain[i][1], certs[i])

    def check_secret_key_equal(self, sk, algorithm_name, key_size, key_bytes):
        self.assertEqual(sk.algorithm, algorithm_name)
        self.assertEqual(sk.key_size, key_size)
        self.assertEqual(sk.key, key_bytes)

class JksTests(AbstractTest):
    def test_empty_store(self):
        store = jks.KeyStore.load(KS_PATH + "/jks/empty.jks", "")
        self.assertEqual(store.store_type, "jks")
        self.assertEqual(len(store.entries), 0)

    def test_bad_keystore_format(self):
        self.assertRaises(jks.util.BadKeystoreFormatException, jks.KeyStore.loads, b"\x00\x00\x00\x00", "") # bad magic bytes
        self.assertRaises(jks.util.BadKeystoreFormatException, jks.KeyStore.loads, b"\xFE\xED\xFE\xED\x00", "") # insufficient store version bytes
        self.assertRaises(jks.util.UnsupportedKeystoreVersionException, jks.KeyStore.loads, b"\xFE\xED\xFE\xED\x00\x00\x00\x00", "") # unknown store version
        self.assertRaises(jks.util.KeystoreSignatureException, jks.KeyStore.loads, b"\xFE\xED\xFE\xED\x00\x00\x00\x02\x00\x00\x00\x00" + b"\x00"*20, "") # bad signature
        self.assertRaises(jks.util.BadKeystoreFormatException, jks.KeyStore.loads, b"\xFE\xED\xFE\xED\x00\x00\x00\x02\x00\x00\x00\x00" + b"\x00"*19, "") # insufficient signature bytes

    def test_trailing_data(self):
        """Issue #21 on github; Portecle is able to load keystores with trailing data after the hash, so we should be as well."""
        store_bytes = None
        with open(KS_PATH + "/jks/RSA1024.jks", "rb") as f:
            store_bytes = f.read()
        store = jks.KeyStore.loads(store_bytes + b"\x00"*1,    "12345678")
        store = jks.KeyStore.loads(store_bytes + b"\x00"*1000, "12345678")

    def test_rsa_1024(self):
        store = jks.KeyStore.load(KS_PATH + "/jks/RSA1024.jks", "12345678")
        pk = self.find_private_key(store, "mykey")
        self.assertEqual(store.store_type, "jks")
        self.check_pkey_and_certs_equal(pk, jks.util.RSA_ENCRYPTION_OID, expected.RSA1024.private_key, expected.RSA1024.certs)

    def test_rsa_2048_3certs(self):
        store = jks.KeyStore.load(KS_PATH + "/jks/RSA2048_3certs.jks", "12345678")
        pk = self.find_private_key(store, "mykey")
        self.assertEqual(store.store_type, "jks")
        self.check_pkey_and_certs_equal(pk, jks.util.RSA_ENCRYPTION_OID, expected.RSA2048_3certs.private_key, expected.RSA2048_3certs.certs)

    def test_dsa_2048(self):
        store = jks.KeyStore.load(KS_PATH + "/jks/DSA2048.jks", "12345678")
        pk = self.find_private_key(store, "mykey")
        self.assertEqual(store.store_type, "jks")
        self.check_pkey_and_certs_equal(pk, jks.util.DSA_OID, expected.DSA2048.private_key, expected.DSA2048.certs)

    def test_certs(self):
        store = jks.KeyStore.load(KS_PATH + "/jks/3certs.jks", "12345678")
        cert1 = self.find_cert(store, "cert1")
        cert2 = self.find_cert(store, "cert2")
        cert3 = self.find_cert(store, "cert3")
        self.assertEqual(cert1.cert, expected.RSA2048_3certs.certs[0])
        self.assertEqual(cert2.cert, expected.RSA2048_3certs.certs[1])
        self.assertEqual(cert3.cert, expected.RSA2048_3certs.certs[2])
        self.assertEqual(store.store_type, "jks")

    def test_custom_entry_passwords(self):
        store = jks.KeyStore.load(KS_PATH + "/jks/custom_entry_passwords.jks", "store_password")
        self.assertEqual(store.store_type, "jks")
        self.assertEqual(len(store.entries), 2)
        self.assertEqual(len(store.certs), 1)
        self.assertEqual(len(store.private_keys), 1)
        self.assertEqual(len(store.secret_keys), 0)

        pk = self.find_private_key(store, "private")
        self.assertRaises(jks.DecryptionFailureException, pk.decrypt, "wrong_password")
        self.assertTrue(not pk.is_decrypted())
        pk.decrypt("private_password")
        self.assertTrue(pk.is_decrypted())
        self.check_pkey_and_certs_equal(pk, jks.util.RSA_ENCRYPTION_OID, expected.custom_entry_passwords.private_key, expected.custom_entry_passwords.certs)

        cert = self.find_cert(store, "cert")
        self.assertEqual(cert.cert, expected.custom_entry_passwords.certs[0])

    def test_duplicate_aliases(self):
        self.assertRaises(jks.DuplicateAliasException, jks.KeyStore.load, KS_PATH + "/jks/duplicate_aliases.jks", "12345678")

    def test_non_ascii_jks_password(self):
        store = jks.KeyStore.load(KS_PATH + "/jks/non_ascii_password.jks", u"\u10DA\u0028\u0CA0\u76CA\u0CA0\u10DA\u0029")
        pk = self.find_private_key(store, "mykey")
        self.assertEqual(store.store_type, "jks")
        self.check_pkey_and_certs_equal(pk, jks.util.RSA_ENCRYPTION_OID, expected.jks_non_ascii_password.private_key, expected.jks_non_ascii_password.certs)

    def test_load_and_save_rsa_keystore(self):
        with open(KS_PATH + "/jks/RSA2048_3certs.jks", 'rb') as file:
            keystore_bytes = file.read()
        store = jks.KeyStore.loads(keystore_bytes, "12345678", False)
        resaved_keystore_bytes = store.saves('12345678')
        # since we didn't decrypt the key, the keystores should be identical
        self.assertEqual(keystore_bytes, resaved_keystore_bytes)

    def test_load_and_save_dsa_keystore(self):
        with open(KS_PATH + "/jks/DSA2048.jks", 'rb') as file:
            keystore_bytes = file.read()
        store = jks.KeyStore.loads(keystore_bytes, "12345678", False)
        resaved_keystore_bytes = store.saves('12345678')
        # since we didn't decrypt the key, the keystores should be identical
        self.assertEqual(keystore_bytes, resaved_keystore_bytes)

    def test_load_and_save_keystore_non_ascii_password(self):
        with open(KS_PATH + "/jks/non_ascii_password.jks", 'rb') as file:
            keystore_bytes = file.read()
        store = jks.KeyStore.loads(keystore_bytes, u"\u10DA\u0028\u0CA0\u76CA\u0CA0\u10DA\u0029", False)
        resaved_keystore_bytes = store.saves(u"\u10DA\u0028\u0CA0\u76CA\u0CA0\u10DA\u0029")
        # since we didn't decrypt the key, the keystores should be identical
        self.assertEqual(keystore_bytes, resaved_keystore_bytes)

    def test_create_and_load_keystore_non_ascii_password(self):
        cert = jks.PrivateKeyEntry.new('mykey', expected.jks_non_ascii_password.certs, expected.jks_non_ascii_password.private_key)
        store = jks.KeyStore.new('jks', [cert])
        store_bytes = store.saves(u"\u10DA\u0028\u0CA0\u76CA\u0CA0\u10DA\u0029")
        store2 = jks.KeyStore.loads(store_bytes, u"\u10DA\u0028\u0CA0\u76CA\u0CA0\u10DA\u0029")
        pk = self.find_private_key(store2, "mykey")
        self.assertEqual(store2.store_type, "jks")
        self.check_pkey_and_certs_equal(pk, jks.util.RSA_ENCRYPTION_OID, expected.jks_non_ascii_password.private_key, expected.jks_non_ascii_password.certs)

    def test_create_and_load_non_ascii_alias(self):
        cert = jks.PrivateKeyEntry.new(u'\xe6\xe6\xe6\xf8\xf8\xf8\xe5\xe5\xf8\xe6', expected.RSA1024.certs, expected.RSA1024.private_key)
        store = jks.KeyStore.new('jks', [cert])
        store_bytes = store.saves('12345678')
        store2 = jks.KeyStore.loads(store_bytes, '12345678')
        pk = self.find_private_key(store2, u'\xe6\xe6\xe6\xf8\xf8\xf8\xe5\xe5\xf8\xe6')
        self.assertEqual(store2.store_type, "jks")
        self.check_pkey_and_certs_equal(pk, jks.util.RSA_ENCRYPTION_OID, expected.RSA1024.private_key, expected.RSA1024.certs)

    def test_create_and_load_custom_entry_passwords(self):
        cert = jks.PrivateKeyEntry.new('mykey', expected.custom_entry_passwords.certs, expected.custom_entry_passwords.private_key)
        store = jks.KeyStore.new('jks', [cert])
        pk = self.find_private_key(store, "mykey")
        self.assertTrue(pk.is_decrypted())
        pk.encrypt("private_password")
        self.assertTrue(not pk.is_decrypted())
        store_bytes = store.saves("store_password")
        store2 = jks.KeyStore.loads(store_bytes, 'store_password')
        pk2 = self.find_private_key(store2, "mykey")
        self.assertTrue(not pk2.is_decrypted())
        pk2.decrypt("private_password")
        self.assertTrue(pk2.is_decrypted())
        self.assertEqual(store2.store_type, "jks")
        self.check_pkey_and_certs_equal(pk2, jks.util.RSA_ENCRYPTION_OID, expected.custom_entry_passwords.private_key, expected.custom_entry_passwords.certs)

    def test_create_and_load_keystore_pkcs8_rsa(self):
        cert = jks.PrivateKeyEntry.new('mykey', expected.RSA2048_3certs.certs, expected.RSA2048_3certs.private_key)
        store = jks.KeyStore.new('jks', [cert])
        store_bytes = store.saves('12345678')
        store2 = jks.KeyStore.loads(store_bytes, '12345678')
        pk = self.find_private_key(store2, "mykey")
        self.assertEqual(store2.store_type, "jks")
        self.check_pkey_and_certs_equal(pk, jks.util.RSA_ENCRYPTION_OID, expected.RSA2048_3certs.private_key, expected.RSA2048_3certs.certs)

    def test_create_and_load_keystore_pkcs8_dsa(self):
        cert = jks.PrivateKeyEntry.new('mykey', expected.DSA2048.certs, expected.DSA2048.private_key)
        store = jks.KeyStore.new('jks', [cert])
        store_bytes = store.saves('12345678')
        store2 = jks.KeyStore.loads(store_bytes, '12345678')
        pk = self.find_private_key(store2, "mykey")
        self.assertEqual(store2.store_type, "jks")
        self.check_pkey_and_certs_equal(pk, jks.util.DSA_OID, expected.DSA2048.private_key, expected.DSA2048.certs)

    def test_create_and_load_keystore_raw_rsa(self):
        cert = jks.PrivateKeyEntry.new('mykey', expected.RSA2048_3certs.certs, expected.RSA2048_3certs.raw_private_key, 'rsa_raw')
        store = jks.KeyStore.new('jks', [cert])
        store_bytes = store.saves('12345678')
        store2 = jks.KeyStore.loads(store_bytes, '12345678')
        pk = self.find_private_key(store2, "mykey")
        self.assertEqual(store2.store_type, "jks")
        self.check_pkey_and_certs_equal(pk, jks.util.RSA_ENCRYPTION_OID, expected.RSA2048_3certs.private_key, expected.RSA2048_3certs.certs)

    def test_create_and_load_keystore_trusted_certs(self):
        cert1 = jks.TrustedCertEntry(type='X.509', cert=expected.RSA2048_3certs.certs[0], timestamp=1463338684456, alias='cert1')
        cert2 = jks.TrustedCertEntry(type='X.509', cert=expected.RSA2048_3certs.certs[1], timestamp=1463338684456, alias='cert2')
        cert3 = jks.TrustedCertEntry(type='X.509', cert=expected.RSA2048_3certs.certs[2], timestamp=1463338684456, alias='cert3')
        store = jks.KeyStore.new('jks', [cert1, cert2, cert3])
        store_bytes = store.saves('12345678')
        store2 = jks.KeyStore.loads(store_bytes, '12345678')
        cert1_2 = self.find_cert(store2, "cert1")
        cert2_2 = self.find_cert(store2, "cert2")
        cert3_2 = self.find_cert(store2, "cert3")
        self.assertEqual(cert1_2.cert, expected.RSA2048_3certs.certs[0])
        self.assertEqual(cert2_2.cert, expected.RSA2048_3certs.certs[1])
        self.assertEqual(cert3_2.cert, expected.RSA2048_3certs.certs[2])

    def test_create_and_load_keystore_both_trusted_and_private(self):
        pk = jks.PrivateKeyEntry.new('mykey', expected.RSA2048_3certs.certs, expected.RSA2048_3certs.raw_private_key, 'rsa_raw')
        cert1 = jks.TrustedCertEntry.new('cert1', expected.RSA2048_3certs.certs[0])
        cert2 = jks.TrustedCertEntry.new('cert2', expected.RSA2048_3certs.certs[1])
        cert3 = jks.TrustedCertEntry.new('cert3', expected.RSA2048_3certs.certs[2])
        store = jks.KeyStore.new('jks', [pk, cert1, cert2, cert3])
        store_bytes = store.saves('12345678')
        store2 = jks.KeyStore.loads(store_bytes, '12345678')
        cert1_2 = self.find_cert(store2, "cert1")
        cert2_2 = self.find_cert(store2, "cert2")
        cert3_2 = self.find_cert(store2, "cert3")
        pk2 = self.find_private_key(store2, "mykey")
        self.assertEqual(cert1_2.cert, expected.RSA2048_3certs.certs[0])
        self.assertEqual(cert2_2.cert, expected.RSA2048_3certs.certs[1])
        self.assertEqual(cert3_2.cert, expected.RSA2048_3certs.certs[2])
        self.assertEqual(store.store_type, "jks")
        self.check_pkey_and_certs_equal(pk2, jks.util.RSA_ENCRYPTION_OID, expected.RSA2048_3certs.private_key, expected.RSA2048_3certs.certs)

    def test_new_keystore_duplicate_alias(self):
        cert1 = jks.TrustedCertEntry.new('cert1', expected.RSA2048_3certs.certs[0])
        cert2 = jks.TrustedCertEntry.new('cert1', expected.RSA2048_3certs.certs[1])
        self.assertRaises(jks.util.DuplicateAliasException, jks.KeyStore.new, 'jks', [cert1, cert2])

    def test_save_invalid_keystore_format(self):
        self.assertRaises(jks.util.UnsupportedKeystoreTypeException, jks.KeyStore.new, 'invalid', [])

    def test_save_invalid_keystore_entry(self):
        self.assertRaises(jks.util.UnsupportedKeystoreEntryTypeException, jks.KeyStore.new, 'jks', ['string'])

    def test_create_unknown_key_format(self):
        self.assertRaises(jks.util.UnsupportedKeyFormatException, jks.PrivateKeyEntry.new, 'alias','cert', 'key', 'ecdsa')

    def test_save_jks_keystore_with_secret_key(self):
        store = jks.KeyStore.load(KS_PATH + "/jceks/AES128.jceks", "12345678")
        store.store_type = 'jks' # changing it to a jks keystore
        self.assertRaises(jks.util.UnsupportedKeystoreEntryTypeException, store.saves, '12345678')

    def test_create_jks_keystore_with_secret_key(self):
        store = jks.KeyStore.load(KS_PATH + "/jceks/AES128.jceks", "12345678")
        sk = self.find_secret_key(store, "mykey")
        self.assertRaises(jks.util.UnsupportedKeystoreEntryTypeException, jks.KeyStore.new, 'jks', [sk])

class JceTests(AbstractTest):
    def test_empty_store(self):
        store = jks.KeyStore.load(KS_PATH + "/jceks/empty.jceks", "")
        self.assertEqual(store.store_type, "jceks")
        self.assertEqual(len(store.entries), 0)

    def test_bad_keystore_format(self):
        self.assertRaises(jks.util.BadKeystoreFormatException, jks.KeyStore.loads, b"\x00\x00\x00\x00", "") # bad magic bytes
        self.assertRaises(jks.util.BadKeystoreFormatException, jks.KeyStore.loads, b"\xCE\xCE\xCE\xCE\x00", "") # insufficient store version bytes
        self.assertRaises(jks.util.UnsupportedKeystoreVersionException, jks.KeyStore.loads, b"\xCE\xCE\xCE\xCE\x00\x00\x00\x00", "") # unknown store version
        self.assertRaises(jks.util.KeystoreSignatureException, jks.KeyStore.loads, b"\xCE\xCE\xCE\xCE\x00\x00\x00\x02\x00\x00\x00\x00" + b"\x00"*20, "") # bad signature
        self.assertRaises(jks.util.BadKeystoreFormatException, jks.KeyStore.loads, b"\xCE\xCE\xCE\xCE\x00\x00\x00\x02\x00\x00\x00\x00" + b"\x00"*19, "") # insufficient signature bytes

    def test_trailing_data(self):
        """Issue #21 on github; Portecle is able to load keystores with trailing data after the hash, so we should be as well."""
        store_bytes = None
        with open(KS_PATH + "/jceks/RSA1024.jceks", "rb") as f:
            store_bytes = f.read()
        store = jks.KeyStore.loads(store_bytes + b"\x00"*1,    "12345678")
        store = jks.KeyStore.loads(store_bytes + b"\x00"*1000, "12345678")

    def test_rsa_1024(self):
        store = jks.KeyStore.load(KS_PATH + "/jceks/RSA1024.jceks", "12345678")
        pk = self.find_private_key(store, "mykey")
        self.assertEqual(store.store_type, "jceks")
        self.check_pkey_and_certs_equal(pk, jks.util.RSA_ENCRYPTION_OID, expected.RSA1024.private_key, expected.RSA1024.certs)

    def test_rsa_2048_3certs(self):
        store = jks.KeyStore.load(KS_PATH + "/jceks/RSA2048_3certs.jceks", "12345678")
        pk = self.find_private_key(store, "mykey")
        self.assertEqual(store.store_type, "jceks")
        self.check_pkey_and_certs_equal(pk, jks.util.RSA_ENCRYPTION_OID, expected.RSA2048_3certs.private_key, expected.RSA2048_3certs.certs)

    def test_dsa_2048(self):
        store = jks.KeyStore.load(KS_PATH + "/jceks/DSA2048.jceks", "12345678")
        pk = self.find_private_key(store, "mykey")
        self.assertEqual(store.store_type, "jceks")
        self.check_pkey_and_certs_equal(pk, jks.util.DSA_OID, expected.DSA2048.private_key, expected.DSA2048.certs)

    def test_certs(self):
        store = jks.KeyStore.load(KS_PATH + "/jceks/3certs.jceks", "12345678")
        cert1 = self.find_cert(store, "cert1")
        cert2 = self.find_cert(store, "cert2")
        cert3 = self.find_cert(store, "cert3")
        self.assertEqual(cert1.cert, expected.RSA2048_3certs.certs[0])
        self.assertEqual(cert2.cert, expected.RSA2048_3certs.certs[1])
        self.assertEqual(cert3.cert, expected.RSA2048_3certs.certs[2])
        self.assertEqual(store.store_type, "jceks")

    def test_custom_entry_passwords(self):
        store = jks.KeyStore.load(KS_PATH + "/jceks/custom_entry_passwords.jceks", "store_password") # shouldn't throw, we're not yet trying to decrypt anything at this point
        self.assertEqual(store.store_type, "jceks")
        self.assertEqual(len(store.entries), 3)
        self.assertEqual(len(store.certs), 1)
        self.assertEqual(len(store.private_keys), 1)
        self.assertEqual(len(store.secret_keys), 1)

        pk = self.find_private_key(store, "private")
        self.assertRaises(jks.DecryptionFailureException, pk.decrypt, "wrong_password")
        self.assertTrue(not pk.is_decrypted())
        pk.decrypt("private_password")
        self.assertTrue(pk.is_decrypted())
        self.check_pkey_and_certs_equal(pk, jks.util.RSA_ENCRYPTION_OID, expected.custom_entry_passwords.private_key, expected.custom_entry_passwords.certs)

        sk = self.find_secret_key(store, "secret")
        self.assertRaises(jks.DecryptionFailureException, sk.decrypt, "wrong_password")
        sk.decrypt("secret_password")
        self.assertTrue(sk.is_decrypted())
        self.assertEqual(sk.key, b"\x3f\x68\x05\x04\xc6\x6c\xc2\x5a\xae\x65\xd0\xfa\x49\xc5\x26\xec")
        self.assertEqual(sk.algorithm, "AES")
        self.assertEqual(sk.key_size, 128)

        cert = self.find_cert(store, "cert")
        self.assertEqual(cert.cert, expected.custom_entry_passwords.certs[0])

    def test_duplicate_aliases(self):
        self.assertRaises(jks.DuplicateAliasException, jks.KeyStore.load, KS_PATH + "/jceks/duplicate_aliases.jceks", "12345678")

class JceOnlyTests(AbstractTest):
    def test_des_secret_key(self):
        store = jks.KeyStore.load(KS_PATH + "/jceks/DES.jceks", "12345678")
        sk = self.find_secret_key(store, "mykey")
        self.assertEqual(store.store_type, "jceks")
        self.check_secret_key_equal(sk, "DES", 64, b"\x4c\xf2\xfe\x91\x5d\x08\x2a\x43")

    def test_desede_secret_key(self):
        store = jks.KeyStore.load(KS_PATH + "/jceks/DESede.jceks", "12345678")
        sk = self.find_secret_key(store, "mykey")
        self.assertEqual(store.store_type, "jceks")
        self.check_secret_key_equal(sk, "DESede", 192, b"\x67\x5e\x52\x45\xe9\x67\x3b\x4c\x8f\xc1\x94\xce\xec\x43\x3b\x31\x8c\x45\xc2\xe0\x67\x5e\x52\x45")

    def test_aes128_secret_key(self):
        store = jks.KeyStore.load(KS_PATH + "/jceks/AES128.jceks", "12345678")
        sk = self.find_secret_key(store, "mykey")
        self.assertEqual(store.store_type, "jceks")
        self.check_secret_key_equal(sk, "AES", 128, b"\x66\x6e\x02\x21\xcc\x44\xc1\xfc\x4a\xab\xf4\x58\xf9\xdf\xdd\x3c")

    def test_aes256_secret_key(self):
        store = jks.KeyStore.load(KS_PATH + "/jceks/AES256.jceks", "12345678")
        sk = self.find_secret_key(store, "mykey")
        self.assertEqual(store.store_type, "jceks")
        self.check_secret_key_equal(sk, "AES", 256, b"\xe7\xd7\xc2\x62\x66\x82\x21\x78\x7b\x6b\x5a\x0f\x68\x77\x12\xfd\xe4\xbe\x52\xe9\xe7\xd7\xc2\x62\x66\x82\x21\x78\x7b\x6b\x5a\x0f")

    def test_pbkdf2_hmac_sha1(self):
        store = jks.KeyStore.load(KS_PATH + "/jceks/PBKDF2WithHmacSHA1.jceks", "12345678")
        sk = self.find_secret_key(store, "mykey")
        self.assertEqual(store.store_type, "jceks")
        self.check_secret_key_equal(sk, "PBKDF2WithHmacSHA1", 256, b"\x57\x95\x36\xd9\xa2\x7f\x7e\x31\x4e\xf4\xe3\xff\xa5\x76\x26\xef\xe6\x70\xe8\xf4\xd2\x96\xcd\x31\xba\x1a\x82\x7d\x9a\x3b\x1e\xe1")

    def test_unknown_type_of_sealed_object(self):
        """Verify that an exception is raised when encountering a (serialized) Java object inside a SecretKey entry that is not of type javax.crypto.SealedObject"""
        self.assertRaises(jks.UnexpectedJavaTypeException, lambda: \
            jks.KeyStore.load(KS_PATH + "/jceks/unknown_type_of_sealed_object.jceks", "12345678"))

    def test_unknown_type_inside_sealed_object(self):
        """Verify that an exception is raised when encountering a (serialized) Java object inside of a SealedObject in a SecretKey entry (after decryption) that is not of a recognized/supported type"""
        self.assertRaises(jks.UnexpectedJavaTypeException, lambda: \
            jks.KeyStore.load(KS_PATH + "/jceks/unknown_type_inside_sealed_object.jceks", "12345678"))

    def test_unknown_sealed_object_sealAlg(self):
        self.assertRaises(jks.UnexpectedAlgorithmException, lambda: \
            jks.KeyStore.load(KS_PATH + "/jceks/unknown_sealed_object_sealAlg.jceks", "12345678"))

class BksOnlyTests(AbstractTest):
    def check_bks_entry(self, entry, store_type):
        """Checks that apply to BKS entries of any type"""
        self.assertEqual(entry.store_type, store_type)
        self.assertTrue(isinstance(entry.alias, py23basestring))
        self.assertTrue(isinstance(entry.timestamp, (int, long)))
        self.assertTrue(isinstance(entry.cert_chain, list))
        self.assertTrue(all(isinstance(c, jks.bks.BksTrustedCertEntry) for c in entry.cert_chain))

    def check_cert_entry(self, entry, store_type):
        self.check_bks_entry(entry, store_type)
        self.assertTrue(isinstance(entry.cert, bytes))
        self.assertTrue(isinstance(entry.type, py23basestring))
        self.assertTrue(entry.is_decrypted())

    def check_sealed_key_entry(self, entry, store_type):
        self.check_bks_entry(entry, store_type)
        self.assertTrue(isinstance(entry, jks.bks.BksSealedKeyEntry))
        if entry.is_decrypted():
            # all attributes of the nested entry should also be directly accessible through the parent sealed entry,
            # so run the same check twice with the two different objects
            self.check_plain_key_entry(entry.nested, store_type)
            self.check_plain_key_entry(entry, store_type, check_type=False)

    def check_secret_key_entry(self, entry, store_type):
        self.check_bks_entry(entry, store_type)
        self.assertTrue(isinstance(entry, jks.bks.BksSecretKeyEntry))
        self.assertTrue(isinstance(entry.key, bytes))

    def check_plain_key_entry(self, key_entry, store_type, check_type=True):
        self.check_bks_entry(key_entry, store_type)
        if check_type:
            self.assertTrue(isinstance(key_entry, jks.bks.BksKeyEntry))
        self.assertTrue(isinstance(key_entry.format, py23basestring))
        self.assertTrue(isinstance(key_entry.algorithm, py23basestring))
        self.assertTrue(isinstance(key_entry.encoded, bytes))
        self.assertTrue(key_entry.is_decrypted())

        if key_entry.type == jks.bks.KEY_TYPE_PRIVATE:
            self.assertTrue(isinstance(key_entry.pkey_pkcs8, bytes))
            self.assertTrue(isinstance(key_entry.pkey, bytes))
            self.assertTrue(isinstance(key_entry.algorithm_oid, tuple))

        elif key_entry.type == jks.bks.KEY_TYPE_PUBLIC:
            self.assertTrue(isinstance(key_entry.public_key_info, bytes))
            self.assertTrue(isinstance(key_entry.public_key, bytes))
            self.assertTrue(isinstance(key_entry.algorithm_oid, tuple))

        elif key_entry.type == jks.bks.KEY_TYPE_SECRET:
            self.assertTrue(isinstance(key_entry.key, bytes))

        else:
            self.fail("No such key type: %s" % repr(key_entry.type))

    # TODO: code duplication with JKS' check_pkey_and_certs_equal; only difference is that in JKS entries
    # the cert_chain is stored as a tuple instead of a TrustedCertEntry object.
    # consider changing that so this logic can be reused
    def check_pkey_and_certs_equal(self, pk, algorithm_oid, pkey_pkcs8, certs):
        self.assertEqual(pk.algorithm_oid, algorithm_oid)
        self.assertEqual(pk.pkey_pkcs8, pkey_pkcs8)
        self.assertEqual(len(pk.cert_chain), len(certs))
        for i in range(len(certs)):
            self.assertEqual(pk.cert_chain[i].cert, certs[i])

    # ----------------------------------------------

    def test_bad_bks_keystore_format(self):
        self.assertRaises(jks.util.BadKeystoreFormatException, jks.bks.BksKeyStore.loads, b"\x00\x00\x00", "") # insufficient store version bytes
        self.assertRaises(jks.util.UnsupportedKeystoreVersionException, jks.bks.BksKeyStore.loads, b"\x00\x00\x00\x00" + b"\x00\x00\x00\x08" + (b"\xFF"*8) + b"\x00\x00\x00\x14" + b"\x00" + (b"\x00"*20), "") # unknown store version
        self.assertRaises(jks.util.KeystoreSignatureException, jks.bks.BksKeyStore.loads, b"\x00\x00\x00\x02" + b"\x00\x00\x00\x08" + (b"\xFF"*8) + b"\x00\x00\x00\x14" + b"\x00" + (b"\x00"*20), "") # bad HMAC
        self.assertRaises(jks.util.BadKeystoreFormatException, jks.bks.BksKeyStore.loads, b"\x00\x00\x00\x02" + b"\x00\x00\x00\x08" + (b"\xFF"*8) + b"\x00\x00\x00\x14" + b"\x00" + (b"\x00"*19), "") # insufficient HMAC bytes

    def test_bad_uber_keystore_format(self):
        self.assertRaises(jks.util.BadKeystoreFormatException, jks.bks.UberKeyStore.loads, b"\x00\x00\x00", "") # insufficient store version bytes
        self.assertRaises(jks.util.UnsupportedKeystoreVersionException, jks.bks.UberKeyStore.loads, b"\x00\x00\x00\x00" + b"\x00\x00\x00\x08" + (b"\xFF"*8) + b"\x00\x00\x00\x14", "") # unknown store version

        password = ""
        salt = b"\xFF"*8
        self.assertRaises(jks.util.KeystoreSignatureException, jks.bks.UberKeyStore.loads,
            b"\x00\x00\x00\x01" + \
            b"\x00\x00\x00\x08" + salt + \
            b"\x00\x00\x00\x14" + \
            jks.rfc7292.encrypt_PBEWithSHAAndTwofishCBC(b"\x00" + b"\00"*20, password, salt, 0x14), password) # empty embedded BKS entries + bad SHA-1 hash of that 0-byte store

        self.assertRaises(jks.util.BadKeystoreFormatException, jks.bks.UberKeyStore.loads,
            b"\x00\x00\x00\x01" + \
            b"\x00\x00\x00\x08" + salt + \
            b"\x00\x00\x00\x14" + \
            jks.rfc7292.encrypt_PBEWithSHAAndTwofishCBC(b"\x00" + b"\00"*10, password, salt, 0x14), password) # insufficient signature bytes

    def test_empty_store_v1(self):
        store = jks.bks.BksKeyStore.load(KS_PATH + "/bks/empty.bksv1", "")
        self.assertEqual(store.version, 1)
    def test_empty_store_v2(self):
        store = jks.bks.BksKeyStore.load(KS_PATH + "/bks/empty.bksv2", "")
        self.assertEqual(store.version, 2)
    def test_empty_store_uber(self):
        store = jks.bks.UberKeyStore.load(KS_PATH + "/uber/empty.uber", "")
        self.assertEqual(store.version, 1)

    def test_christmas_store_v1(self):
        store = jks.bks.BksKeyStore.load(KS_PATH + "/bks/christmas.bksv1", "12345678")
        self.assertEqual(store.version, 1)
        self._test_christmas_store(store, "bks")
    def test_christmas_store_v2(self):
        store = jks.bks.BksKeyStore.load(KS_PATH + "/bks/christmas.bksv2", "12345678")
        self.assertEqual(store.version, 2)
        self._test_christmas_store(store, "bks")
    def test_christmas_store_uber(self):
        store = jks.bks.UberKeyStore.load(KS_PATH + "/uber/christmas.uber", "12345678")
        self.assertEqual(store.version, 1)
        self._test_christmas_store(store, "uber")

    def test_custom_entry_passwords_v1(self):
        store = jks.bks.BksKeyStore.load(KS_PATH + "/bks/custom_entry_passwords.bksv1", "store_password")
        self.assertEqual(store.version, 1)
        self._test_custom_entry_passwords(store, "bks")
    def test_custom_entry_passwords_v2(self):
        store = jks.bks.BksKeyStore.load(KS_PATH + "/bks/custom_entry_passwords.bksv2", "store_password")
        self.assertEqual(store.version, 2)
        self._test_custom_entry_passwords(store, "bks")
    def test_custom_entry_passwords_uber(self):
        store = jks.bks.UberKeyStore.load(KS_PATH + "/uber/custom_entry_passwords.uber", "store_password")
        self.assertEqual(store.version, 1)
        self._test_custom_entry_passwords(store, "uber")

    def _test_christmas_store(self, store, store_type):
        self.assertEqual(store.store_type, store_type)
        self.assertEqual(len(store.entries), 6)
        self.assertEqual(len(store.certs), 1)
        self.assertEqual(len(store.sealed_keys), 3)
        self.assertEqual(len(store.secret_keys), 1)
        self.assertEqual(len(store.plain_keys), 1)

        sealed_public = store.entries["sealed_public_key"]
        self.check_sealed_key_entry(sealed_public, store_type)
        self.assertTrue(sealed_public.is_decrypted())
        self.assertEqual(sealed_public.type, jks.bks.KEY_TYPE_PUBLIC)
        self.assertEqual(sealed_public.algorithm, "RSA")
        self.assertEqual(sealed_public.algorithm_oid, jks.util.RSA_ENCRYPTION_OID)
        self.assertEqual(sealed_public.public_key_info, expected.bks_christmas.public_key)

        sealed_private = store.entries["sealed_private_key"]
        self.check_sealed_key_entry(sealed_private, store_type)
        self.assertEqual(sealed_private.type, jks.bks.KEY_TYPE_PRIVATE)
        self.assertEqual(sealed_private.algorithm, "RSA")
        self.assertTrue(sealed_private.is_decrypted())
        self.check_pkey_and_certs_equal(sealed_private, jks.util.RSA_ENCRYPTION_OID, expected.bks_christmas.private_key, expected.bks_christmas.certs)

        sealed_secret = store.entries["sealed_secret_key"]
        self.check_sealed_key_entry(sealed_secret, store_type)
        self.assertEqual(sealed_secret.type, jks.bks.KEY_TYPE_SECRET)
        self.assertEqual(sealed_secret.algorithm, "AES")
        self.check_secret_key_equal(sealed_secret, "AES", 128, b"\x3f\x68\x05\x04\xc6\x6c\xc2\x5a\xae\x65\xd0\xfa\x49\xc5\x26\xec")

        plain_key = store.entries["plain_key"]
        self.check_plain_key_entry(plain_key, store_type)
        self.assertEqual(plain_key.type, jks.bks.KEY_TYPE_SECRET)
        self.assertEqual(plain_key.algorithm, "DES")
        self.check_secret_key_equal(plain_key, "DES", 64, b"\x4c\xf2\xfe\x91\x5d\x08\x2a\x43")

        cert = store.entries["cert"]
        self.check_cert_entry(cert, store_type)
        self.assertEqual(cert.cert, expected.bks_christmas.certs[0])

        stored_value = store.entries["stored_value"]
        self.check_secret_key_entry(stored_value, store_type)
        self.assertEqual(stored_value.key, b"\x02\x03\x05\x07\x0B\x0D\x11\x13\x17")

    def _test_custom_entry_passwords(self, store, store_type):
        self.assertEqual(store.store_type, store_type)
        self.assertEqual(len(store.entries), 3)
        self.assertEqual(len(store.certs), 0)
        self.assertEqual(len(store.sealed_keys), 3)
        self.assertEqual(len(store.secret_keys), 0)
        self.assertEqual(len(store.plain_keys), 0)

        attrs_non_encrypted = ["alias", "timestamp", "store_type", "cert_chain"]
        attrs_encrypted_common = ["type", "format", "algorithm", "encoded"]
        attrs_encrypted_public  = attrs_encrypted_common + ["public_key_info", "public_key", "algorithm_oid"]
        attrs_encrypted_private = attrs_encrypted_common + ["pkey", "pkey_pkcs8", "algorithm_oid"]
        attrs_encrypted_secret  = attrs_encrypted_common + ["key", "key_size"]

        sealed_public = store.entries["sealed_public_key"]
        self.assertFalse(sealed_public.is_decrypted())
        for a in attrs_encrypted_public: self.assertRaises(jks.util.NotYetDecryptedException, getattr, sealed_public, a)
        for a in attrs_non_encrypted: getattr(sealed_public, a) # shouldn't throw
        self.assertRaises(jks.util.DecryptionFailureException, sealed_public.decrypt, "wrong_password")
        sealed_public.decrypt("public_password")
        self.assertTrue(sealed_public.is_decrypted())
        for a in attrs_encrypted_public: getattr(sealed_public, a) # shouldn't throw

        sealed_private = store.entries["sealed_private_key"]
        self.assertFalse(sealed_private.is_decrypted())
        for a in attrs_encrypted_private: self.assertRaises(jks.util.NotYetDecryptedException, getattr, sealed_private, a)
        for a in attrs_non_encrypted: getattr(sealed_private, a) # shouldn't throw
        self.assertRaises(jks.util.DecryptionFailureException, sealed_private.decrypt, "wrong_password")
        sealed_private.decrypt("private_password")
        self.assertTrue(sealed_private.is_decrypted())
        for a in attrs_encrypted_private: getattr(sealed_private, a) # shouldn't throw

        sealed_secret = store.entries["sealed_secret_key"]
        self.assertFalse(sealed_secret.is_decrypted())
        for a in attrs_encrypted_secret: self.assertRaises(jks.util.NotYetDecryptedException, getattr, sealed_secret, a)
        for a in attrs_non_encrypted: getattr(sealed_secret, a) # shouldn't throw
        self.assertRaises(jks.util.DecryptionFailureException, sealed_secret.decrypt, "wrong_password")
        sealed_secret.decrypt("secret_password")
        self.assertTrue(sealed_secret.is_decrypted())
        for a in attrs_encrypted_secret: getattr(sealed_secret, a) # shouldn't throw

    def test_trailing_data_v1(self):
        """Issue #21 on github; Portecle is able to load keystores with trailing data after the HMAC signature, so we should be as well."""
        christmas_store_bytes = None
        with open(KS_PATH + "/bks/christmas.bksv1", "rb") as f:
            christmas_store_bytes = f.read()
        store = jks.bks.BksKeyStore.loads(christmas_store_bytes + b"\x00"*1,    "12345678")
        store = jks.bks.BksKeyStore.loads(christmas_store_bytes + b"\x00"*1000, "12345678")
        self._test_christmas_store(store, "bks")

    def test_trailing_data_v2(self):
        """Issue #21 on github; Portecle is able to load keystores with trailing data after the HMAC signature, so we should be as well."""
        christmas_store_bytes = None
        with open(KS_PATH + "/bks/christmas.bksv2", "rb") as f:
            christmas_store_bytes = f.read()
        store = jks.bks.BksKeyStore.loads(christmas_store_bytes + b"\x00"*1,    "12345678")
        store = jks.bks.BksKeyStore.loads(christmas_store_bytes + b"\x00"*1000, "12345678")
        self._test_christmas_store(store, "bks")

    def test_trailing_data_uber(self):
        # Note: trailing data in an UBER keystore should always be a fatal error because there is no way to distinguish
        # the trailing data from the encrypted store blob in advance.
        christmas_store_bytes = None
        with open(KS_PATH + "/uber/christmas.uber", "rb") as f:
            christmas_store_bytes = f.read()
        self.assertRaises(jks.util.DecryptionFailureException, jks.bks.UberKeyStore.loads, christmas_store_bytes + b"\x00"*256, "12345678") # maintain multiple of 16B -> decryption failure
        self.assertRaises(jks.util.BadKeystoreFormatException, jks.bks.UberKeyStore.loads, christmas_store_bytes + b"\x00"*255, "12345678") # break multiple of 16B -> bad format


class MiscTests(AbstractTest):
    def test_bitstring_to_bytes(self):
        def bs2b(t, _str):
            bits_tuple = tuple(map(int, _str.replace(" ", "")))
            result = jks.util.bitstring_to_bytes(bits_tuple)
            t.assertTrue(isinstance(result, bytes))
            return result

        self.assertEqual(bs2b(self, ""), b"")

        self.assertEqual(bs2b(self, "        0"), b"\x00")
        self.assertEqual(bs2b(self, "        1"), b"\x01")
        self.assertEqual(bs2b(self, "0110 1010"), b"\x6a")
        self.assertEqual(bs2b(self, "1111 1111"), b"\xff")

        self.assertEqual(bs2b(self, "   0 1111 1111"), b"\x00\xff")
        self.assertEqual(bs2b(self, "   1 1111 1111"), b"\x01\xff")

    def test_strip_pkcs5_padding(self):
        self.assertEqual(jks.util.strip_pkcs5_padding(b"\x08\x08\x08\x08\x08\x08\x08\x08"), b"")
        self.assertEqual(jks.util.strip_pkcs5_padding(b"\x01\x07\x07\x07\x07\x07\x07\x07"), b"\x01")
        self.assertEqual(jks.util.strip_pkcs5_padding(b"\x01\x02\x03\x04\x05\x06\x07\x01"), b"\x01\x02\x03\x04\x05\x06\x07")

        self.assertRaises(jks.util.BadPaddingException, jks.util.strip_pkcs5_padding, b"")
        self.assertRaises(jks.util.BadPaddingException, jks.util.strip_pkcs5_padding, b"\x01")
        self.assertRaises(jks.util.BadPaddingException, jks.util.strip_pkcs5_padding, b"\x01\x02\x03\x04\x08\x08")
        self.assertRaises(jks.util.BadPaddingException, jks.util.strip_pkcs5_padding, b"\x07\x07\x07\x07\x07\x07\x07")
        self.assertRaises(jks.util.BadPaddingException, jks.util.strip_pkcs5_padding, b"\x00\x00\x00\x00\x00\x00\x00\x00")

    def test_sun_jce_pbe_decrypt(self):
        self.assertEqual(b"sample", jks.sun_crypto.jce_pbe_decrypt(b"\xc4\x20\x59\xac\x54\x03\xc7\xbf", "my_password", b"\x01\x02\x03\x04\x05\x06\x07\x08", 42))
        self.assertEqual(b"sample", jks.sun_crypto.jce_pbe_decrypt(b"\xef\x9f\xbd\xc5\x91\x5f\x49\x50", "my_password", b"\x01\x02\x03\x04\x01\x02\x03\x05", 42))
        self.assertEqual(b"sample", jks.sun_crypto.jce_pbe_decrypt(b"\x72\x8f\xd8\xcc\x21\x41\x25\x80", "my_password", b"\x01\x02\x03\x04\x01\x02\x03\x04", 42))

    def test_pkcs12_key_derivation(self):
        self.assertEqual(jks.rfc7292.derive_key(hashlib.sha1, jks.rfc7292.PURPOSE_MAC_MATERIAL, "", b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000, 16), b"\xe7\x76\x85\x01\x6a\x53\x62\x1e\x9a\x2a\x8a\x0f\x80\x00\x2e\x70")
        self.assertEqual(jks.rfc7292.derive_key(hashlib.sha1, jks.rfc7292.PURPOSE_MAC_MATERIAL, "", b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000, 17), b"\xe7\x76\x85\x01\x6a\x53\x62\x1e\x9a\x2a\x8a\x0f\x80\x00\x2e\x70\xfe")
        self.assertEqual(jks.rfc7292.derive_key(hashlib.sha1, jks.rfc7292.PURPOSE_KEY_MATERIAL, "", b"\xbf\x0a\xaa\x4f\x84\xb4\x4e\x41\x16\x0a\x11\xb7\xed\x98\x58\xa0\x95\x3b\x4b\xf8", 2010, 2), b"\x1b\xee")

        self.assertEqual(jks.rfc7292.derive_key(hashlib.sha1, jks.rfc7292.PURPOSE_MAC_MATERIAL, "password", b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000, 0), b"")
        self.assertEqual(jks.rfc7292.derive_key(hashlib.sha1, jks.rfc7292.PURPOSE_MAC_MATERIAL, "password", b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000, 16), b"\x21\x2b\xab\x71\x42\x2d\x31\xa5\xd3\x93\x4c\x20\xe5\xe7\x7e\xb7")

        self.assertEqual(jks.rfc7292.derive_key(hashlib.sha1, jks.rfc7292.PURPOSE_MAC_MATERIAL, "password", b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000, 17), b"\x21\x2b\xab\x71\x42\x2d\x31\xa5\xd3\x93\x4c\x20\xe5\xe7\x7e\xb7\xed")
        self.assertEqual(jks.rfc7292.derive_key(hashlib.sha1, jks.rfc7292.PURPOSE_KEY_MATERIAL, "password", b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000, 17), b"\xe8\x0b\xdd\x02\x01\x55\x31\x7f\x30\xb8\x54\xcb\x9f\x78\x11\x81\x76")
        self.assertEqual(jks.rfc7292.derive_key(hashlib.sha1, jks.rfc7292.PURPOSE_IV_MATERIAL,  "password", b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000, 17), b"\x27\x68\x91\x7c\xf9\xf4\x33\xb0\xa6\x4a\x9f\xcc\xbc\x80\x5f\xd6\x48")

        fancy_password = u"\u10DA\u0028\u0CA0\u76CA\u0CA0\u10DA\u0029"
        self.assertEqual(jks.rfc7292.derive_key(hashlib.sha1, jks.rfc7292.PURPOSE_KEY_MATERIAL, fancy_password, b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000, 129),
            b"\x5e\x3d\xab\x11\xd7\x55\x2c\xaf\x58\x2f\x61\xbd\x95\xdd\x03\xa7\x83\xa4\xf0\x2a\xeb\xdc\x86\x5c\xdb\x1e\xae\x2c\x8f\x91\x82\xa5" + \
            b"\x84\xbf\xab\x23\x75\x1c\x83\x96\x34\xcf\x0e\xc1\x6c\x84\xd7\x15\xd1\x7c\x10\x3d\x8b\xa8\xef\x1f\x63\xb4\x71\xdf\x15\x4f\xc2\x86" + \
            b"\xf9\x5c\xba\x37\xad\xd3\xe2\xb2\xaa\xb3\x37\x60\x42\x3d\x69\x29\xd1\x96\x47\x32\x6c\x41\x57\xfa\x0e\x20\x87\xd6\xa7\x40\xae\x0f" + \
            b"\xe8\x17\xd8\x8e\xda\x12\x53\xac\x7e\x19\x99\xc6\x26\x20\xed\x5d\xcd\x44\xe4\xed\x05\xb9\xdc\x39\x6a\x91\x1b\x00\xbb\x39\x3e\xd8" + \
            b"\x9b")

    def test_decrypt_PBEWithSHAAnd3KeyTripleDESCBC(self):
        fancy_password = u"\u10DA\u0028\u0CA0\u76CA\u0CA0\u10DA\u0029"
        self.assertEqual(b"sample", jks.rfc7292.decrypt_PBEWithSHAAnd3KeyTripleDESCBC(b"\x69\xea\xff\x28\x65\x85\x0a\x68", "mypassword",   b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000))
        self.assertEqual(b"sample", jks.rfc7292.decrypt_PBEWithSHAAnd3KeyTripleDESCBC(b"\x73\xf1\xc7\x14\x74\xa3\x04\x59", fancy_password, b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000))

        self.assertEqual(b"-------16-------", jks.rfc7292.decrypt_PBEWithSHAAnd3KeyTripleDESCBC(b"\x4c\xbb\xc8\x03\x09\x35\x27\xcb\xd6\x98\x81\xba\x93\x75\x7a\x96\x60\xf2\x5b\xa9\x1e\x32\xe2\x4d", "mypassword",   b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000))
        self.assertEqual(b"-------16-------", jks.rfc7292.decrypt_PBEWithSHAAnd3KeyTripleDESCBC(b"\xe1\xce\x6d\xa1\x5b\x81\x0c\xdd\x1c\x7c\xbd\x14\x4a\x64\xc4\xa1\xda\x26\x27\xe3\x50\x87\x9d\xd1", fancy_password, b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000))

        self.assertRaises(jks.util.BadDataLengthException, jks.rfc7292.decrypt_PBEWithSHAAnd3KeyTripleDESCBC, b"\x00", "", b"", 20)

    def test_decrypt_PBEWithSHAAndTwofishCBC(self):
        fancy_password = u"\u10DA\u0028\u0CA0\u76CA\u0CA0\u10DA\u0029"
        self.assertEqual(b"sample", jks.rfc7292.decrypt_PBEWithSHAAndTwofishCBC(b"\xc5\x22\x81\xc9\xa2\x24\x4b\x10\xf9\x1c\x6c\xbc\x67\x10\x42\x3e", "mypassword",   b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000))
        self.assertEqual(b"sample", jks.rfc7292.decrypt_PBEWithSHAAndTwofishCBC(b"\xc8\xc4\x7a\xe6\xa7\xc2\x80\xd7\x05\x5f\xe2\x4f\xf4\x20\x30\x7c", fancy_password, b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000))

        self.assertEqual(b"-------16-------", jks.rfc7292.decrypt_PBEWithSHAAndTwofishCBC(
            b"\xf3\x4e\x3a\xd9\x3c\x48\x42\x53\xec\x07\xef\x00\x82\x56\x30\xee\x4f\xdf\x52\x0b\x5a\xd4\x8c\x9e\xa6\x72\x19\xe4\x90\x0b\xf1\x0c", "mypassword", b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000))
        self.assertEqual(b"-------16-------", jks.rfc7292.decrypt_PBEWithSHAAndTwofishCBC(
            b"\xe0\xc7\x1a\xe8\xf4\x90\xca\x17\xa8\x0c\xc1\x1c\xea\x2e\x96\x38\x9d\x8d\xcc\xa4\x20\x15\x05\xa8\x57\xfa\x47\xa3\x0b\x97\xf5\x00", fancy_password, b"\x01\x02\x03\x04\x05\x06\x07\x08", 1000))

        self.assertRaises(jks.util.BadDataLengthException, jks.rfc7292.decrypt_PBEWithSHAAndTwofishCBC, b"\x00", "", b"", 20)

    def test_filter_attributes(self):
        ks = jks.KeyStore("jks", {})
        self.assertEqual(len(list(ks.private_keys)), 0)
        self.assertEqual(len(list(ks.secret_keys)), 0)
        self.assertEqual(len(list(ks.certs)), 0)

        dummy_entries = {
            "1": jks.SecretKeyEntry(),
            "2": jks.SecretKeyEntry(),
            "3": jks.SecretKeyEntry(),
            "4": jks.TrustedCertEntry(),
            "5": jks.TrustedCertEntry(),
            "6": jks.PrivateKeyEntry()
        }
        ks = jks.KeyStore("jks", dummy_entries)
        self.assertEqual(len(ks.private_keys), 1)
        self.assertEqual(len(ks.secret_keys), 3)
        self.assertEqual(len(ks.certs), 2)
        self.assertTrue(all(a in ks.secret_keys for a in ["1", "2", "3"]))
        self.assertTrue(all(a in ks.private_keys for a in ["6"]))
        self.assertTrue(all(a in ks.certs for a in ["4", "5"]))

    def test_try_decrypt_keys(self):
        # as applied to secret keys
        store = jks.KeyStore.load(KS_PATH + "/jceks/AES128.jceks", "12345678", try_decrypt_keys=False)
        sk = self.find_secret_key(store, "mykey")
        self.assertTrue(not sk.is_decrypted())
        self.assertRaises(jks.NotYetDecryptedException, lambda: sk.key)
        self.assertRaises(jks.NotYetDecryptedException, lambda: sk.key_size)
        self.assertRaises(jks.NotYetDecryptedException, lambda: sk.algorithm)

        store = jks.KeyStore.load(KS_PATH + "/jceks/AES128.jceks", "12345678", try_decrypt_keys=True)
        sk = self.find_secret_key(store, "mykey")
        self.assertTrue(sk.is_decrypted())
        dummy = sk.key
        dummy = sk.key_size
        dummy = sk.algorithm

        # as applied to private keys
        store = jks.KeyStore.load(KS_PATH + "/jceks/RSA1024.jceks", "12345678", try_decrypt_keys=False)
        pk = self.find_private_key(store, "mykey")
        self.assertTrue(not pk.is_decrypted())
        self.assertRaises(jks.NotYetDecryptedException, lambda: pk.pkey)
        self.assertRaises(jks.NotYetDecryptedException, lambda: pk.pkey_pkcs8)
        self.assertRaises(jks.NotYetDecryptedException, lambda: pk.algorithm_oid)
        dummy = pk.cert_chain # not stored in encrypted form in the store, shouldn't require decryption to access

        store = jks.KeyStore.load(KS_PATH + "/jceks/RSA1024.jceks", "12345678", try_decrypt_keys=True)
        pk = self.find_private_key(store, "mykey")
        self.check_pkey_and_certs_equal(pk, jks.util.RSA_ENCRYPTION_OID, expected.RSA1024.private_key, expected.RSA1024.certs)
        dummy = pk.cert_chain

if __name__ == "__main__":
    unittest.main()
