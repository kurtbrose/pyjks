# vim: set et ai ts=4 sts=4 sw=4:
from __future__ import print_function
import textwrap
import base64
import struct

b8 = struct.Struct('>Q')
b4 = struct.Struct('>L')  # unsigned
b2 = struct.Struct('>H')
b1 = struct.Struct('B')  # unsigned

py23basestring = ("".__class__, u"".__class__)  # useful for isinstance checks

RSA_ENCRYPTION_OID = (1, 2, 840, 113549, 1, 1, 1)
DSA_OID = (1, 2, 840, 10040, 4,
           1)  # identifier for DSA public/private keys; see RFC 3279, section 2.2.2 (e.g. in PKCS#8 PrivateKeyInfo or X.509 SubjectPublicKeyInfo)
DSA_WITH_SHA1_OID = (1, 2, 840, 10040, 4,
                     3)  # identifier for the DSA signature algorithm; see RFC 3279, section 2.3.2 (e.g. in X.509 signatures)


class KeystoreException(Exception): pass


class KeystoreSignatureException(KeystoreException): pass


class DuplicateAliasException(KeystoreException): pass


class NotYetDecryptedException(KeystoreException): pass


class BadKeystoreFormatException(KeystoreException): pass


class BadDataLengthException(KeystoreException): pass


class BadPaddingException(KeystoreException): pass


class BadHashCheckException(KeystoreException): pass


class DecryptionFailureException(KeystoreException): pass


class UnsupportedKeystoreVersionException(KeystoreException): pass


class UnexpectedJavaTypeException(KeystoreException): pass


class UnexpectedAlgorithmException(KeystoreException): pass


class UnexpectedKeyEncodingException(KeystoreException): pass


class AbstractKeystoreEntry(object):
    def __init__(self, **kwargs):
        super(AbstractKeystoreEntry, self).__init__()
        self.store_type = kwargs.get("store_type")
        self.alias = kwargs.get("alias")
        self.timestamp = kwargs.get("timestamp")


def as_hex(ba):
    return "".join("{:02x}".format(b) for b in bytearray(ba))


def as_pem(der_bytes, type):
    result = "-----BEGIN %s-----\n" % type
    result += "\n".join(textwrap.wrap(base64.b64encode(der_bytes).decode('ascii'), 64))
    result += "\n-----END %s-----" % type
    return result


def bitstring_to_bytes(bitstr):
    """
    Converts a pyasn1 univ.BitString instance to byte sequence of type 'bytes'.
    The bit string is interpreted big-endian and is left-padded with 0 bits to form a multiple of 8.
    """
    bitlist = list(bitstr)
    bits_missing = (8 - len(bitlist) % 8) % 8
    bitlist = [0] * bits_missing + bitlist  # pad with 0 bits to a multiple of 8
    result = bytearray()
    for i in range(0, len(bitlist), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bitlist[i + j]
        result.append(byte)
    return bytes(result)


def xor_bytearrays(a, b):
    return bytearray([x ^ y for x, y in zip(a, b)])


def print_pem(der_bytes, type):
    print(as_pem(der_bytes, type))


def pkey_as_pem(pk):
    if pk.algorithm_oid == RSA_ENCRYPTION_OID:
        return as_pem(pk.pkey, "RSA PRIVATE KEY")
    else:
        return as_pem(pk.pkey_pkcs8, "PRIVATE KEY")


def strip_pkcs5_padding(m):
    """
    Drop PKCS5 padding:  8-(||M|| mod 8) octets each with value 8-(||M|| mod 8)
    Note: ideally we would use pycrypto for this, but it doesn't provide padding functionality and the project is virtually dead at this point.
    """
    return strip_pkcs7_padding(m, 8)


def strip_pkcs7_padding(m, block_size):
    """
    Same as PKCS#5 padding, except generalized to block sizes other than 8.
    """
    if len(m) < block_size or len(m) % block_size != 0:
        raise BadPaddingException("Unable to strip padding: invalid message length")

    m = bytearray(m)  # py2/3 compatibility: always returns individual indexed elements as ints
    last_byte = m[-1]
    # the <last_byte> bytes of m must all have value <last_byte>, otherwise something's wrong
    if (last_byte <= 0 or last_byte > block_size) or (m[-last_byte:] != bytearray([last_byte]) * last_byte):
        raise BadPaddingException("Unable to strip padding: invalid padding found")

    return bytes(m[:-last_byte])  # back to 'str'/'bytes'


def add_pkcs7_padding(m, block_size):
    if block_size <= 0 or block_size > 255:
        raise ValueError("Invalid block size")

    m = bytearray(m)
    num_padding_bytes = block_size - (len(m) % block_size)
    m = m + bytearray([num_padding_bytes] * num_padding_bytes)
    return bytes(m)
