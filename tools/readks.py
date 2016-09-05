#!/usr/bin/env python
# vim: set et ai ts=4 sts=4 sw=4:
from __future__ import print_function
import sys, base64, textwrap
import logging
import jks
import datetime
import base64
from jks.util import pkey_as_pem, as_pem, as_hex, print_pem
from argparse import ArgumentParser

def get_entry_metadata(entry):
    result = "Alias: %s\n" % entry.alias
    result += "  Type: %s\n" % type(entry).__name__
    result += "  Timestamp: %s\n" % datetime.datetime.utcfromtimestamp(entry.timestamp//1000).strftime('%Y-%m-%dT%H:%M:%SZ')

    if entry.is_decrypted():
        if isinstance(entry, jks.PrivateKeyEntry):
            result += "  Algorithm OID: %s\n" % (entry.algorithm_oid,)
            result += "  Certificate chain: %d certificate(s)\n" % len(entry.cert_chain)
        if isinstance(entry, jks.SecretKeyEntry):
            result += "  Algorithm: %s\n" % (entry.algorithm,)
            result += "  Key size: %d bits\n" % (entry.key_size,)
        if isinstance(entry, jks.BksKeyEntry) or \
           isinstance(entry, jks.BksSealedKeyEntry):
            result += "  Key type: %s\n" % jks.bks.BksKeyEntry.type2str(entry.type)
            result += "  Key format: %s\n" % (entry.format,)
            result +="  Key algorithm: %s\n" % (entry.algorithm,)
            if entry.type in [jks.bks.KEY_TYPE_PRIVATE, jks.bks.KEY_TYPE_PUBLIC]:
                result += "  Key algorithm OID: %s\n" % (entry.algorithm_oid,)
            elif entry.type == jks.bks.KEY_TYPE_SECRET:
                result += "  Key size: %d bits\n" % (entry.key_size,)
        if isinstance(entry, jks.TrustedCertEntry) or \
           isinstance(entry, jks.bks.TrustedCertEntry):
            result += "  Certificate type: %s\n" % (entry.type,)
    else:
        result += "  <not yet decrypted>\n"

    return result

def get_entry_bits(entry):
    if isinstance(entry, jks.PrivateKeyEntry):
        result = pkey_as_pem(entry)
        for c in entry.cert_chain:
            result += "\n" + as_pem(c[1], "CERTIFICATE")
        return result

    if isinstance(entry, jks.SecretKeyEntry):
        return base64.b64encode(entry.key)

    if isinstance(entry, jks.bks.BksKeyEntry) or \
       isinstance(entry, jks.bks.BksSealedKeyEntry):
        if entry.type == jks.bks.KEY_TYPE_PRIVATE:
            result = pkey_as_pem(entry)
            for c in entry.cert_chain:
                result += "\n" + as_pem(c.cert, "CERTIFICATE")
            return result
        elif entry.type == jks.bks.KEY_TYPE_PUBLIC:
            return as_pem(entry.public_key_info, "PUBLIC KEY")
        elif entry.type == jks.bks.KEY_TYPE_SECRET:
            return base64.b64encode(entry.key)

    if isinstance(entry, jks.bks.BksSecretKeyEntry):
        return base64.b64encode(entry.key)

    if isinstance(entry, jks.TrustedCertEntry) or \
       isinstance(entry, jks.bks.TrustedCertEntry):
        return as_pem(entry.cert, "CERTIFICATE")

if __name__ == "__main__":
    parser = ArgumentParser(description="Utility for reading Java keystores.")
    parser.add_argument("keystore_file")
    parser.add_argument("keystore_password")
    parser.add_argument("--type", default="jks", choices=["jks", "jceks", "bks", "uber"], help="The type of input keystore. Defaults to 'jks'.")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-l", "--list", action="store_true", default=True, help="Print a list of entries/aliases in the keystore and some metadata about each one.")
    group.add_argument("-x", "--extract", metavar="ALIAS", dest="extract_alias", help="Extract the relevant key and/or certificates for the given alias and print them in the PEM format.")
    args = parser.parse_args()

    args.type = args.type.lower()

    ks_class = jks.KeyStore
    if args.type == "bks":
        ks_class = jks.BksKeyStore
    elif args.type == "uber":
        ks_class = jks.UberKeyStore

    ks = ks_class.load(args.keystore_file, args.keystore_password)

    if args.extract_alias:
        entry = ks.entries[args.extract_alias]
        if not entry.is_decrypted():
            # call entry.decrypt("password") here
            raise Exception("Entry is still encrypted; password needed")
        print(get_entry_bits(entry))

    elif args.list:
        for alias, entry in ks.entries.items():
            print(get_entry_metadata(entry))

