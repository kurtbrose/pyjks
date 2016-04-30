# vim: set et ai ts=4 sts=4 sw=4:
from __future__ import print_function
import textwrap
import base64

def as_hex(ba):
    return "".join("{:02x}".format(b) for b in bytearray(ba))

def as_pem(der_bytes, type):
    result = "-----BEGIN %s-----\n" % type
    result += "\n".join(textwrap.wrap(base64.b64encode(der_bytes).decode('ascii'), 64))
    result += "\n-----END %s-----" % type
    return result

def print_pem(der_bytes, type):
    print(as_pem(der_bytes, type))

def pkey_as_pem(pk):
    if pk.algorithm_oid == (1,2,840,113549,1,1,1): # rsaEncryption
        return as_pem(pk.pkey, "RSA PRIVATE KEY")
    else:
        return as_pem(pk.pkey_pkcs8, "PRIVATE KEY")

