# vim: set et ai ts=4 sts=4 sw=4:
'''
JKS/JCEKS file format decoder.
Use in conjunction with PyOpenSSL to translate to PEM, or load private key and certs
directly into openssl structs and wrap sockets.

See http://grepcode.com/file/repository.grepcode.com/java/root/jdk/openjdk/6-b14/sun/security/provider/JavaKeyStore.java#JavaKeyStore.engineLoad%28java.io.InputStream%2Cchar%5B%5D%29
See http://grepcode.com/file/repository.grepcode.com/java/root/jdk/openjdk/6-b27/com/sun/crypto/provider/JceKeyStore.java#JceKeyStore
'''
import struct
import ctypes
import hashlib
import collections
import StringIO
import javaobj
from pyasn1.codec.ber import decoder
from pyasn1_modules import rfc5208
from . import rfc2898

Cert = collections.namedtuple("Cert", "alias timestamp type cert")
PrivateKey = collections.namedtuple("PrivateKey", "alias timestamp pkey_pkcs8 algorithm_oid pkey cert_chain")
SecretKey = collections.namedtuple("SecretKey", "alias timestamp algorithm key size")

b8 = struct.Struct('>Q')
b4 = struct.Struct('>L')
b2 = struct.Struct('>H')
b1 = struct.Struct('B')

MAGIC_NUMBER_JKS = b4.pack(0xFEEDFEED)
MAGIC_NUMBER_JCEKS = b4.pack(0xCECECECE)
VERSION = b4.pack(2)
SIGNATURE_WHITENING = b"Mighty Aphrodite"
SUN_JKS_ALGO_ID = (1,3,6,1,4,1,42,2,17,1,1) # JavaSoft proprietary key-protection algorithm
SUN_JCE_ALGO_ID = (1,3,6,1,4,1,42,2,19,1)   # PBE_WITH_MD5_AND_DES3_CBC_OID (non-published, modified version of PKCS#5 PBEWithMD5AndDES)
RSA_ENCRYPTION_OID = (1,2,840,113549,1,1,1)

class KeystoreException(Exception): pass
class KeystoreSignatureException(KeystoreException): pass
class BadKeystoreFormatException(KeystoreException): pass
class BadPaddingException(KeystoreException): pass
class DecryptionFailureException(KeystoreException): pass
class UnsupportedKeystoreFormatException(KeystoreException): pass
class UnexpectedJavaTypeException(KeystoreException): pass
class UnexpectedAlgorithmException(KeystoreException): pass
class UnexpectedKeyEncodingException(KeystoreException): pass

class KeyStore(object):
    def __init__(self, store_type, private_keys, certs, secret_keys):
        self.store_type = store_type
        self.private_keys = private_keys
        self.certs = certs
        self.secret_keys = secret_keys

    @classmethod
    def load(cls, filename, password):
        with open(filename, 'rb') as file:
            return cls.loads(file.read(), password)

    @classmethod
    def loads(cls, data, password):
        store_type = ""
        magic_number = data[:4]
        if magic_number == MAGIC_NUMBER_JKS:
            store_type = "jks"
        elif magic_number == MAGIC_NUMBER_JCEKS:
            store_type = "jceks"
        else:
            raise BadKeystoreFormatException('Not a JKS or JCEKS keystore (magic number wrong; expected FEEDFEED resp. CECECECE)')

        version = b4.unpack_from(data, 4)[0]
        if version != 2:
            raise UnsupportedKeystoreFormatException('Unsupported keystore version; only v2 supported, found v'+repr(version))

        private_keys = []
        secret_keys = []
        certs = []

        entry_count = b4.unpack_from(data, 8)[0]
        pos = 12
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

                # at this point, 'ber_data' is a PKCS#8 EncryptedPrivateKeyInfo (see RFC 5208)
                encrypted_info = decoder.decode(ber_data, asn1Spec=rfc5208.EncryptedPrivateKeyInfo())[0]
                algo_id = encrypted_info['encryptionAlgorithm']['algorithm'].asTuple()
                algo_params = encrypted_info['encryptionAlgorithm']['parameters'].asOctets()
                encrypted_private_key = encrypted_info['encryptedData'].asOctets()

                if store_type == "jks":
                    if algo_id != SUN_JKS_ALGO_ID:
                        raise UnexpectedAlgorithmException("Unknown JKS private key algorithm OID: {0}".format(algo_id))
                    plaintext = _sun_jks_pkey_decrypt(encrypted_private_key, password)

                elif store_type == "jceks":
                    if algo_id == SUN_JKS_ALGO_ID:
                        plaintext = _sun_jks_pkey_decrypt(encrypted_private_key, password)
                    elif algo_id == SUN_JCE_ALGO_ID:
                        # see RFC 2898, section A.3: PBES1 and definitions of AlgorithmIdentifier and PBEParameter
                        params = decoder.decode(algo_params, asn1Spec=rfc2898.PBEParameter())[0]
                        salt = params['salt'].asOctets()
                        iteration_count = int(params['iterationCount'])
                        try:
                            plaintext = _sun_jce_pbe_decrypt(encrypted_private_key, password, salt, iteration_count)
                        except BadPaddingException:
                            raise DecryptionFailureException("Failed to decrypt data for private key '%s'; wrong password?" % alias)
                    else:
                        raise UnexpectedAlgorithmException("Unknown JCEKS private key algorithm OID: {0}".format(algo_id))

                # at this point, 'plaintext' is a PKCS#8 PrivateKeyInfo (see RFC 5208)
                private_key_info = decoder.decode(plaintext, asn1Spec=rfc5208.PrivateKeyInfo())[0]
                key = private_key_info['privateKey'].asOctets()
                algorithm_oid = private_key_info['privateKeyAlgorithm']['algorithm'].asTuple()
                private_keys.append(PrivateKey(alias, timestamp, plaintext, algorithm_oid, key, cert_chain))

            elif tag == 2:  # cert
                cert_type, pos = _read_utf(data, pos)
                cert_data, pos = _read_data(data, pos)
                certs.append(Cert(alias, timestamp, cert_type, cert_data))

            elif tag == 3: # secret key
                if store_type != "jceks":
                    raise BadKeystoreFormatException("Unexpected entry tag {0} encountered in JKS keystore; only supported in JCEKS keystores".format(tag))

                # SecretKeys are stored in the key store file through Java's serialization mechanism, i.e. as an actual serialized Java object
                # embedded inside the file. The objects that get stored are not the SecretKey instances themselves though, as that would trivially
                # expose the key without the need for a passphrase to gain access to it.
                #
                # Instead, an object of type javax.crypto.SealedObject is written. The purpose of this class is specifically to securely
                # serialize objects that contain secret values by applying a password-based encryption scheme to the serialized form of the object
                # to be protected. Only the resulting ciphertext is then stored by the serialized form of the SealedObject instance.
                #
                # To decrypt the SealedObject, the correct passphrase must be given to be able to decrypt the underlying object's serialized form.
                # Once decrypted, one more de-serialization will result in the original object being restored.
                #
                # The default key protector used by the SunJCE provider returns an instance of type SealedObjectForKeyProtector, a (direct)
                # subclass of SealedObject, which uses Java's custom/unpublished PBEWithMD5AndTripleDES algorithm.
                #
                # Class member structure:
                #
                # SealedObjectForKeyProtector:
                #   static final long serialVersionUID = -3650226485480866989L;
                #
                # SealedObject:
                #   static final long serialVersionUID = 4482838265551344752L;
                #   private byte[] encryptedContent;         # The serialized underlying object, in encrypted format.
                #   private String sealAlg;                  # The algorithm that was used to seal this object.
                #   private String paramsAlg;                # The algorithm of the parameters used.
                #   protected byte[] encodedParams;          # The cryptographic parameters used by the sealing Cipher, encoded in the default format.

                sealed_obj, pos = _read_java_obj(data, pos, ignore_remaining_data=True)
                if not _java_is_subclass(sealed_obj, "javax.crypto.SealedObject"):
                    raise UnexpectedJavaTypeException("Unexpected sealed object type '%s'; not a subclass of javax.crypto.SealedObject" % sealed_obj.get_class().name)

                sealed_obj.encryptedContent = _java_bytestring(sealed_obj.encryptedContent)

                plaintext = ""
                if sealed_obj.sealAlg == "PBEWithMD5AndTripleDES":
                    # if the object was sealed with PBEWithMD5AndTripleDES then the parameters should apply to the same algorithm and not be empty or null
                    if sealed_obj.paramsAlg != sealed_obj.sealAlg:
                        raise UnexpectedAlgorithmException("Unexpected parameters algorithm used in SealedObject; should match sealing algorithm '%s' but found '%s'" % (sealed_obj.sealAlg, sealed_obj.paramsAlg))
                    if sealed_obj.encodedParams is None or len(sealed_obj.encodedParams) == 0:
                        raise UnexpectedJavaTypeException("No parameters found in SealedObject instance for sealing algorithm '%s'; need at least a salt and iteration count to decrypt" % sealed_obj.sealAlg)

                    sealed_obj.encodedParams = _java_bytestring(sealed_obj.encodedParams)

                    params_asn1 = decoder.decode(sealed_obj.encodedParams, asn1Spec=rfc2898.PBEParameter())[0]
                    salt = params_asn1['salt'].asOctets()
                    iteration_count = int(params_asn1['iterationCount'])
                    try:
                        plaintext = _sun_jce_pbe_decrypt(sealed_obj.encryptedContent, password, salt, iteration_count)
                    except BadPaddingException:
                        raise DecryptionFailureException("Failed to decrypt data for secret key '%s'; bad password?" % alias)
                else:
                    raise UnexpectedAlgorithmException("Unexpected algorithm used for encrypting SealedObject: sealAlg=%s" % sealed_obj.sealAlg)

                # The plaintext here is another serialized Java object; this time it's an object implementing the javax.crypto.SecretKey interface.
                # When using the default SunJCE provider, these are usually either javax.crypto.spec.SecretKeySpec objects, or some other specialized ones
                # like those found in the com.sun.crypto.provider package (e.g. DESKey and DESedeKey).
                #
                # Additionally, things are further complicated by the fact that some of these specialized SecretKey implementations (i.e. other than SecretKeySpec)
                # implement a writeReplace() method, causing Java's serialization runtime to swap out the object for a completely different one at serialization time.
                # Again for SunJCE, the subsitute object that gets serialized is usually a java.security.KeyRep object.

                obj, dummy = _read_java_obj(plaintext, 0)
                clazz = obj.get_class()
                if clazz.name == "javax.crypto.spec.SecretKeySpec":
                    key_algorithm = obj.algorithm
                    key_bytes = _java_bytestring(obj.key)
                    key_size = len(key_bytes)*8
                    secret_keys.append(SecretKey(alias, timestamp, key_algorithm, key_bytes, key_size))

                elif clazz.name == "java.security.KeyRep":
                    assert (obj.type.constant == "SECRET"), "Expected value 'SECRET' for KeyRep.type enum value, found '%s'" % obj.type.constant
                    key_algorithm = obj.algorithm
                    key_encoding = obj.format
                    key_bytes = _java_bytestring(obj.encoded)
                    if key_encoding == "RAW":
                        pass # ok, no further processing needed
                    elif key_encoding == "X.509":
                        raise NotImplementedError("X.509 encoding for KeyRep objects not yet implemented")
                    elif key_encoding == "PKCS#8":
                        raise NotImplementedError("PKCS#8 encoding for KeyRep objects not yet implemented")
                    else:
                        raise UnexpectedKeyEncodingException("Unexpected key encoding '%s' found in serialized java.security.KeyRep object; expected one of 'RAW', 'X.509', 'PKCS#8'." % key_encoding)

                    key_size = len(key_bytes)*8
                    secret_keys.append(SecretKey(alias, timestamp, key_algorithm, key_bytes, key_size))
                else:
                    raise UnexpectedJavaTypeException("Unexpected object of type '%s' found inside SealedObject; don't know how to handle it" % clazz.name)

            else:
                raise BadKeystoreFormatException("Unexpected keystore entry tag %d", tag)

        # the keystore integrity check uses the UTF-16BE encoding of the password
        password_utf16 = password.encode('utf-16be')
        expected_hash = hashlib.sha1(password_utf16 + SIGNATURE_WHITENING + data[:pos]).digest()
        if expected_hash != data[pos:]:
            raise KeystoreSignatureException("Hash mismatch; incorrect keystore password?")

        return cls(store_type, private_keys, certs, secret_keys)

def _java_is_subclass(obj, class_name):
    """Given a deserialized JavaObject as returned by the javaobj library, determine whether it's a subclass of the given class name."""
    clazz = obj.get_class()
    while clazz:
        if clazz.name == class_name:
            return True
        clazz = clazz.superclass
    return False

def _java_bytestring(java_byte_list):
    """
    Convert the value returned by javaobj for a byte[] to a byte string.
    Java's bytes are signed and numeric (i.e. not chars), so javaobj returns Java byte arrays as a list of Python integers in the range [-128, 127].
    For ease of use we want to get a byte string representation of that, so we reinterpret each integer as an unsigned byte, take its new value
    as another Python int (now remapped to the range [0, 255]), and use struct.pack() to create the matching byte string.
    """
    return struct.pack("%dB" % len(java_byte_list), *[ctypes.c_ubyte(sb).value for sb in java_byte_list])

def _read_utf(data, pos):
    size = b2.unpack_from(data, pos)[0]
    pos += 2
    return unicode(data[pos:pos+size], 'utf-8'), pos+size

def _read_data(data, pos):
    size = b4.unpack_from(data, pos)[0]
    pos += 4
    return data[pos:pos+size], pos+size

def _read_java_obj(data, pos, ignore_remaining_data=False):
    data_stream = StringIO.StringIO(data[pos:])
    obj = javaobj.load(data_stream, ignore_remaining_data=ignore_remaining_data)
    obj_size = data_stream.tell()

    return obj, pos + obj_size

def _sun_jks_pkey_decrypt(data, password):
    """
    Decrypts the private key password protection algorithm used by JKS keystores.
    The JDK sources state that 'the password is expected to be in printable ASCII', though this does not appear to be enforced;
    the password is converted into bytes simply by taking each individual Java char and appending its raw 2-byte representation.
    See sun/security/provider/KeyProtector.java in the JDK sources.
    """
    password = password.encode('utf-16be') # Java chars are UTF-16BE code units
    iv, data, check = data[:20], data[20:-20], data[-20:]
    xoring = zip(data, _jks_keystream(iv, password))
    key = ''.join([chr(ord(a) ^ ord(b)) for a, b in xoring])
    if hashlib.sha1(password + key).digest() != check:
        raise DecryptionFailureException("Bad hash check on private key; wrong password?")
    return key

def _jks_keystream(iv, password):
    """Helper keystream generator for _sun_jks_pkey_decrypt"""
    cur = iv
    while 1:
        cur = hashlib.sha1(password + cur).digest()
        for byte in cur:
            yield byte

def _sun_jce_pbe_decrypt(data, password, salt, iteration_count):
    """
    Decrypts Sun's custom PBEWithMD5AndTripleDES password-based encryption scheme.
    It is based on password-based encryption as defined by the PKCS #5 standard, except that it uses triple DES instead of DES.
    Here's how this algorithm works:
      1. Create random salt and split it in two halves. If the two halves are identical, invert one of them.
      2. Concatenate password with each of the halves.
      3. Digest each concatenation with c iterations, where c is the iterationCount. Concatenate the output from each digest round with the password,
         and use the result as the input to the next digest operation. The digest algorithm is MD5.
      4. After c iterations, use the 2 resulting digests as follows: The 16 bytes of the first digest and the 1st 8 bytes of the 2nd digest
         form the triple DES key, and the last 8 bytes of the 2nd digest form the IV.
    See http://grepcode.com/file/repository.grepcode.com/java/root/jdk/openjdk/6-b27/com/sun/crypto/provider/PBECipherCore.java#PBECipherCore.deriveCipherKey%28java.security.Key%29
    """
    key, iv = _sun_jce_pbe_derive_key_and_iv(password, salt, iteration_count)

    from Crypto.Cipher import DES3
    des3 = DES3.new(key, DES3.MODE_CBC, IV=iv)
    padded = des3.decrypt(data)

    result = _strip_pkcs5_padding(padded)
    return result

def _sun_jce_pbe_derive_key_and_iv(password, salt, iteration_count):
    if len(salt) != 8:
        raise ValueError("Expected 8-byte salt for PBEWithMD5AndTripleDES (OID %s), found %d bytes" % (".".join(str(i) for i in SUN_JCE_ALGO_ID), len(salt)))

    # Note: unlike JKS, the PBEWithMD5AndTripleDES algorithm as implemented for JCE keystores uses an ASCII string for the password, not a regular Java/UTF-16BE string.
    # It validates this explicitly and will throw an InvalidKeySpecException if non-ASCII byte codes are present in the password.
    # See PBEKey's constructor in com/sun/crypto/provider/PBEKey.java.
    try:
        password.encode('ascii')
    except (UnicodeDecodeError, UnicodeEncodeError):
        raise ValueError("Key password contains non-ASCII characters")

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
        raise BadPaddingException("Unable to strip PKCS5 padding: invalid padding found")
    # the <last_byte> bytes of m must all have value <last_byte>, otherwise something's wrong
    if m[-last_byte:] != chr(last_byte)*last_byte:
        raise BadPaddingException("Unable to strip PKCS5 padding: invalid padding found")

    return m[:-last_byte]
