'''
JKS file format decoder.
Use in conjunction with PyOpenSSL to translate to PEM, or load private key and certs
directly into openssl structs and wrap sockets.

See http://grepcode.com/file/repository.grepcode.com/java/root/jdk/openjdk/6-b14/sun/security/provider/JavaKeyStore.java#JavaKeyStore.engineLoad%28java.io.InputStream%2Cchar%5B%5D%29

'''
import struct
import hashlib
import collections
from pyasn1.codec.ber import decoder


class KeyStore(object):
    def __init__(self, private_keys, certs):
        self.private_keys = private_keys
        self.certs = certs

    @classmethod
    def load(cls, filename, password):
        with open(filename, 'rb') as file:
            return cls.loads(file.read(), password)

    @classmethod
    def loads(cls, data, password):
        password = ''.join([b'\0'+c.encode('latin-1')
                            for c in password])  # Java uses UTF16-BE so insert 0 bytes
        if data[:4] != MAGIC_NUMBER:
            raise ValueError('not keystore data (magic number wrong)')
        version = b4.unpack_from(data, 4)[0]
        if version != 2:
            raise ValueError('only jks format v2 supported (got v'+repr(version)+')')
        entry_count = b4.unpack_from(data, 8)[0]
        pos = 12
        private_keys = []
        certs = []

        for i in range(entry_count):
            tag = b4.unpack_from(data, pos)[0]
            pos += 4
            alias, pos = _read_utf(data, pos)
            timestamp = b8.unpack_from(data, pos)[0]
            pos += 8

            if tag == 1:  # private key
                ber_data, pos = _read_data(data, pos)
                chain_len = b4.unpack_from(data, pos)[0]
                pos += 4
                cert_chain = []
                for j in range(chain_len):
                    cert_type, pos = _read_utf(data, pos)
                    cert_data, pos = _read_data(data, pos)
                    cert_chain.append((cert_type, cert_data))
                asn1_data = decoder.decode(ber_data)
                algo_id = asn1_data[0][0][0].asTuple()
                if algo_id != SUN_ALGO_ID:
                    raise ValueError("unable to handle algorithm"
                                     " identifier: {0}".format(algo_id))
                plaintext = _sun_pkey_decrypt(asn1_data[0][1].asOctets(), password)
                key = decoder.decode(plaintext)[0][2].asOctets()
                private_keys.append(PrivateKey(
                    alias, timestamp, key, cert_chain))
            elif tag == 2:  # cert
                cert_type, pos = _read_utf(data, pos)
                cert_data, pos = _read_data(data, pos)
                certs.append(Cert(alias, timestamp, cert_type, cert_data))

        if hashlib.sha1(password + SIGNATURE + data[:pos]).digest() != data[pos:]:
            raise ValueError("Hash mismatch; incorrect password or data corrupted")

        return cls(private_keys, certs)


Cert = collections.namedtuple("Cert", "alias timestamp type cert")
PrivateKey = collections.namedtuple("PrivateKey", "alias timestamp pkey cert_chain")

b8 = struct.Struct('>Q')
b4 = struct.Struct('>L')
b2 = struct.Struct('>H')

MAGIC_NUMBER = b4.pack(0xFEEDFEED)
VERSION = b4.pack(2)
SIGNATURE = b"Mighty Aphrodite"
SUN_ALGO_ID = (1, 3, 6, 1, 4, 1, 42, 2, 17, 1, 1)


def _read_utf(data, pos):
    size = b2.unpack_from(data, pos)[0]
    pos += 2
    return unicode(data[pos:pos+size], 'utf-8'), pos+size


def _read_data(data, pos):
    size = b4.unpack_from(data, pos)[0]
    pos += 4
    return data[pos:pos+size], pos+size


def _sun_pkey_decrypt(data, password):
    'implements private key crypto algorithm used by JKS files'
    iv, data, check = data[:20], data[20:-20], data[-20:]
    xoring = zip(data, _keystream(iv, password))
    key = ''.join([chr(ord(a) ^ ord(b)) for a, b in xoring])
    if hashlib.sha1(password + key).digest() != check:
        raise ValueError("bad hash check on private key")
    return key


def _keystream(iv, password):
    'helper generator for _sun_pkey_decrypt'
    cur = iv
    while 1:
        cur = hashlib.sha1(password + cur).digest()
        for byte in cur:
            yield byte
