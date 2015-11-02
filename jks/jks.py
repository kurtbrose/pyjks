'''
JKS/JCEKS file format decoder.
Use in conjunction with PyOpenSSL to translate to PEM, or load private key and certs
directly into openssl structs and wrap sockets.

See http://grepcode.com/file/repository.grepcode.com/java/root/jdk/openjdk/6-b14/sun/security/provider/JavaKeyStore.java#JavaKeyStore.engineLoad%28java.io.InputStream%2Cchar%5B%5D%29
See http://grepcode.com/file/repository.grepcode.com/java/root/jdk/openjdk/6-b27/com/sun/crypto/provider/JceKeyStore.java#JceKeyStore
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
        filetype = ''
        magic_number = data[:4]
        if magic_number == MAGIC_NUMBER_JKS:
            filetype = 'jks'
        elif magic_number == MAGIC_NUMBER_JCEKS:
            filetype = 'jceks'
        else:
            raise ValueError('Not a JKS or JCEKS keystore (magic number wrong; expected FEEDFEED resp. CECECECE)')

        version = b4.unpack_from(data, 4)[0]
        if version != 2:
            raise ValueError('Unsupported keystore version; only v2 supported, found v'+repr(version))

        entry_count = b4.unpack_from(data, 8)[0]
        pos = 12
        private_keys = []
        certs = []

        for i in range(entry_count):
            tag = b4.unpack_from(data, pos)[0]
            pos += 4
            alias, pos = _read_utf(data, pos)
            timestamp = b8.unpack_from(data, pos)[0] # milliseconds since UNIX epoch
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

                # at this point, ber_data is a PKCS#8 EncryptedPrivateKeyInfo
                asn1_data = decoder.decode(ber_data)
                algo_id = asn1_data[0][0][0].asTuple()
                encrypted_private_key = asn1_data[0][1].asOctets()

                if filetype == 'jks':
                    if algo_id != SUN_JKS_ALGO_ID:
                        raise ValueError("Unknown JKS private key algorithm OID: {0}".format(algo_id))
                    plaintext = _sun_jks_pkey_decrypt(encrypted_private_key, password)

                elif filetype == 'jceks':
                    if algo_id == SUN_JKS_ALGO_ID:
                        plaintext = _sun_jks_pkey_decrypt(encrypted_private_key, password)
                    elif algo_id == SUN_JCE_ALGO_ID:
                        salt = asn1_data[0][0][1][0].asOctets() # see section A.3: PBES1 and definitions of AlgorithmIdentifier and PBEParameter in RFC 2898
                        iteration_count = int(asn1_data[0][0][1][1])
                        plaintext = _sun_jce_pkey_decrypt(encrypted_private_key, password, salt, iteration_count)
                    else:
                        raise ValueError("Unknown JCEKS private key algorithm OID: {0}".format(algo_id))

                key = decoder.decode(plaintext)[0][2].asOctets()
                private_keys.append(PrivateKey(alias, timestamp, key, cert_chain))

            elif tag == 2:  # cert
                cert_type, pos = _read_utf(data, pos)
                cert_data, pos = _read_data(data, pos)
                certs.append(Cert(alias, timestamp, cert_type, cert_data))

            elif tag == 3:
                if filetype != 'jceks':
                    raise ValueError("Unexpected entry tag {0} encountered in JKS keystore; only supported in JCEKS keystores".format(tag))
                # TODO: implement me

        # the keystore integrity check uses the UTF-16BE encoding of the password
        password_utf16 = password.encode('utf-16be')
        if hashlib.sha1(password_utf16 + SIGNATURE_WHITENING + data[:pos]).digest() != data[pos:]:
            raise ValueError("Hash mismatch; incorrect password or data corrupted")

        return cls(private_keys, certs)

Cert = collections.namedtuple("Cert", "alias timestamp type cert")
PrivateKey = collections.namedtuple("PrivateKey", "alias timestamp pkey cert_chain")

b8 = struct.Struct('>Q')
b4 = struct.Struct('>L')
b2 = struct.Struct('>H')

MAGIC_NUMBER_JKS = b4.pack(0xFEEDFEED)
MAGIC_NUMBER_JCEKS = b4.pack(0xCECECECE)
VERSION = b4.pack(2)
SIGNATURE_WHITENING = b"Mighty Aphrodite"
SUN_JKS_ALGO_ID = (1,3,6,1,4,1,42,2,17,1,1) # JavaSoft proprietary key-protection algorithm
SUN_JCE_ALGO_ID = (1,3,6,1,4,1,42,2,19,1)   # PBE_WITH_MD5_AND_DES3_CBC_OID

def _read_utf(data, pos):
    size = b2.unpack_from(data, pos)[0]
    pos += 2
    return data[pos:pos+size].decode('utf-8'), pos+size

def _read_data(data, pos):
    size = b4.unpack_from(data, pos)[0]
    pos += 4
    return data[pos:pos+size], pos+size

def _sun_jks_pkey_decrypt(data, password):
    'implements private key crypto algorithm used by JKS files'
    password = password.encode('UTF-16BE') # the JKS algorithm uses a regular Java UTF16-BE string for the password, so insert 0 bytes
    iv, data, check = data[:20], data[20:-20], data[-20:]
    xoring = zip(data, _jks_keystream(iv, password))
    key = bytes([a ^ b for a, b in xoring])
    if hashlib.sha1(password + key).digest() != check:
        raise ValueError("bad hash check on private key")
    return key

def _jks_keystream(iv, password):
    'helper generator for _sun_pkey_decrypt'
    cur = iv
    while 1:
        cur = hashlib.sha1(password + cur).digest()
        for byte in cur:
            yield byte

def _sun_jce_pkey_decrypt(data, password, salt, iteration_count):
    key, iv = _sun_jce_derive_cipher_key_iv(password, salt, iteration_count)

    from Crypto.Cipher import DES3
    des3 = DES3.new(key, DES3.MODE_CBC, IV=iv) # apparently uses EDE, although there's no apparent way to tell it what to use ...
    padded = des3.decrypt(data)

    result = _strip_pkcs5_padding(padded)
    return result

def _sun_jce_derive_cipher_key_iv(password, salt, iteration_count):
    '''
    PKCS#8-formatted private key with a proprietary password-based encryption algorithm.
    It is based on password-based encryption as defined by the PKCS #5 standard, except that is uses triple DES instead of DES.
    Here's how this algorithm works:
      1. Create random salt and split it in two halves. If the two halves are identical, invert one of them.
      2. Concatenate password with each of the halves.
      3. Digest each concatenation with c iterations, where c is the iterationCount. Concatenate the output from each digest round with the password,
         and use the result as the input to the next digest operation. The digest algorithm is MD5.
      4. After c iterations, use the 2 resulting digests as follows: The 16 bytes of the first digest and the 1st 8 bytes of the 2nd digest
         form the triple DES key, and the last 8 bytes of the 2nd digest form the IV.
    See http://grepcode.com/file/repository.grepcode.com/java/root/jdk/openjdk/6-b27/com/sun/crypto/provider/PBECipherCore.java#PBECipherCore.deriveCipherKey%28java.security.Key%29'''
    # Note: unlike JKS, the JCE algorithm uses an ASCII string for the password, not a regular Java/UTF-16BE string; no need to double up on the password bytes
    if len(salt) != 8:
        raise ValueError("Expected 8-byte salt for JCE private key encryption algorithm (OID %s), found %d bytes" % (".".join(str(i) for i in SUN_JCE_ALGO_ID), len(salt)))

    salt_halves = [salt[0:4], salt[4:8]]
    if salt_halves[0] == salt_halves[1]:
        salt_halves[0] = salt_halves[0][::-1] # reversed

    derived = ''
    for i in range(2):
        to_be_hashed = salt_halves[i]
        for k in range(iteration_count):
            to_be_hashed = hashlib.md5(to_be_hashed + password).digest()
        derived += to_be_hashed

    key = derived[:-8] # = 24 bytes
    iv = derived[-8:]
    return key, iv

def _strip_pkcs5_padding(m):
    # drop PKCS5 padding:  8-(||M|| mod 8) octets each with value 8-(||M|| mod 8)
    last_byte = ord(m[-1:])
    if last_byte <= 0 or last_byte > 8:
        raise ValueError("Unable to strip PKCS5 padding: invalid padding found")
    # the <last_byte> bytes of m must all have value <last_byte>, otherwise something's wrong
    if m[-last_byte:] != chr(last_byte)*last_byte:
        raise ValueError("Unable to strip PKCS5 padding: invalid padding found")

    return m[:-last_byte]
