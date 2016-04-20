#!/usr/bin/env python
# vim: set ai et ts=4 sw=4 sts=4:
"""
Tests for pyjks
"""

import os, sys
import jks
import unittest
import subprocess
from pprint import pprint

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
                return pk
        return None

    def find_secret_key(self, ks, alias):
        for sk in ks.secret_keys:
            if sk.alias == alias:
                return sk
        return None

    def find_cert(self, ks, alias):
        for c in ks.certs:
            if c.alias == alias:
                return c
        return None

class JceksTests(AbstractTest):
    @classmethod
    def setUpClass(cls):
        # Note: cwd is expected to be in the top-level pyjks directory
        test_dir = os.path.dirname(__file__)
        java_path = os.path.join(test_dir, "java")
        with cd(java_path):
            subprocess.call(["mvn", "test"])
        # back at the top-level pyjks directory

    def test_empty_store(self):
        store = jks.KeyStore.load("tests/keystores/jceks/empty.jceks", "")
        self.assertEqual(len(store.private_keys), 0)
        self.assertEqual(len(store.secret_keys), 0)
        self.assertEqual(len(store.certs), 0)

    def test_des_secret_key(self):
        store = jks.KeyStore.load("tests/keystores/jceks/DES.jceks", "12345678")
        sk = self.find_secret_key(store, "mykey")
        self.assertEqual(sk.key, "\x4c\xf2\xfe\x91\x5d\x08\x2a\x43")

    def test_desede_secret_key(self):
        store = jks.KeyStore.load("tests/keystores/jceks/DESede.jceks", "12345678")
        sk = self.find_secret_key(store, "mykey")
        self.assertEqual(sk.key, "\x67\x5e\x52\x45\xe9\x67\x3b\x4c\x8f\xc1\x94\xce\xec\x43\x3b\x31\x8c\x45\xc2\xe0\x67\x5e\x52\x45")

    def test_aes128_secret_key(self):
        store = jks.KeyStore.load("tests/keystores/jceks/AES128.jceks", "12345678")
        sk = self.find_secret_key(store, "mykey")
        self.assertEqual(sk.key, "\x66\x6e\x02\x21\xcc\x44\xc1\xfc\x4a\xab\xf4\x58\xf9\xdf\xdd\x3c")

    def test_aes256_secret_key(self):
        store = jks.KeyStore.load("tests/keystores/jceks/AES256.jceks", "12345678")
        sk = self.find_secret_key(store, "mykey")
        self.assertEqual(sk.key, "\xe7\xd7\xc2\x62\x66\x82\x21\x78\x7b\x6b\x5a\x0f\x68\x77\x12\xfd\xe4\xbe\x52\xe9\xe7\xd7\xc2\x62\x66\x82\x21\x78\x7b\x6b\x5a\x0f")

    def test_pbkdf2_hmac_sha1(self):
        store = jks.KeyStore.load("tests/keystores/jceks/PBKDF2WithHmacSHA1.jceks", "12345678")
        sk = self.find_secret_key(store, "mykey")
        self.assertEqual(sk.key, "\x57\x95\x36\xd9\xa2\x7f\x7e\x31\x4e\xf4\xe3\xff\xa5\x76\x26\xef\xe6\x70\xe8\xf4\xd2\x96\xcd\x31\xba\x1a\x82\x7d\x9a\x3b\x1e\xe1")

if __name__ == "__main__":
    unittest.main()
