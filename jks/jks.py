# vim: set et ai ts=4 sts=4 sw=4:
"""
JKS/JCEKS file format decoder.
Use in conjunction with PyOpenSSL to translate to PEM, or load private key and certs directly into openssl structs and wrap sockets.

Notes on Python2/3 compatibility:
  - Whereever possible, we rely on the 'natural' byte string representation of each Python version, i.e. 'str' in Python2 and 'bytes' in Python3.
    Python2.6+ aliases the 'bytes' type to 'str', so we can universally write bytes(...) or b"" to get each version's natural byte string representation.
    The libraries we interact with are written to expect these natural types in their respective Py2/Py3 versions, so this works well.

    Things get slightly more complicated when we need to manipulate individual bytes from a byte string. str[x] returns a 'str' in Python2 and an
    'int' in Python3. You can't do 'int' operations on a 'str' and vice-versa, so we need some form of common data type.
    We use bytearray() for this purpose; in both Python2 and Python3, this will return individual elements as an 'int'.
"""
from __future__ import print_function
import struct
import ctypes
import hashlib
import javaobj
from pyasn1.codec.ber import decoder
from pyasn1_modules import rfc5208
from . import rfc2898
from . import sun_crypto
from .util import *

try:
    from StringIO import StringIO as BytesIO # python 2
except ImportError:
    from io import BytesIO # python3

__version_info__ = (0,4,0)
__version__ = ".".join(str(x) for x in __version_info__)

MAGIC_NUMBER_JKS = b4.pack(0xFEEDFEED)
MAGIC_NUMBER_JCEKS = b4.pack(0xCECECECE)
SIGNATURE_WHITENING = b"Mighty Aphrodite"

class TrustedCertEntry(AbstractKeystoreEntry):
    def __init__(self, **kwargs):
        super(TrustedCertEntry, self).__init__(**kwargs)
        self.type = kwargs.get("type")
        self.cert = kwargs.get("cert")

    def is_decrypted(self):
        return True
    def decrypt(self, password):
        return

class PrivateKeyEntry(AbstractKeystoreEntry):
    def __init__(self, **kwargs):
        super(PrivateKeyEntry, self).__init__(**kwargs)
        self.cert_chain = kwargs.get("cert_chain")
        self._encrypted = kwargs.get("encrypted")
        self._pkey = kwargs.get("pkey")
        self._pkey_pkcs8 = kwargs.get("pkey_pkcs8")
        self._algorithm_oid = kwargs.get("algorithm_oid")

    def __getattr__(self, name):
        if not self.is_decrypted():
            raise NotYetDecryptedException("Cannot access attribute '%s'; entry not yet decrypted, call decrypt() with the correct password first" % name)
        return self.__dict__['_' + name]

    def is_decrypted(self):
        return (not self._encrypted)

    def decrypt(self, key_password):
        if self.is_decrypted():
            return

        encrypted_info = decoder.decode(self._encrypted, asn1Spec=rfc5208.EncryptedPrivateKeyInfo())[0]
        algo_id = encrypted_info['encryptionAlgorithm']['algorithm'].asTuple()
        algo_params = encrypted_info['encryptionAlgorithm']['parameters'].asOctets()
        encrypted_private_key = encrypted_info['encryptedData'].asOctets()

        plaintext = None
        try:
            if self.store_type == "jks":
                if algo_id != sun_crypto.SUN_JKS_ALGO_ID:
                    raise UnexpectedAlgorithmException("Unknown JKS private key algorithm OID: {0}".format(algo_id))
                plaintext = sun_crypto.jks_pkey_decrypt(encrypted_private_key, key_password)

            elif self.store_type == "jceks":
                if algo_id == sun_crypto.SUN_JKS_ALGO_ID:
                    plaintext = sun_crypto.jks_pkey_decrypt(encrypted_private_key, key_password)
                elif algo_id == sun_crypto.SUN_JCE_ALGO_ID:
                    # see RFC 2898, section A.3: PBES1 and definitions of AlgorithmIdentifier and PBEParameter
                    params = decoder.decode(algo_params, asn1Spec=rfc2898.PBEParameter())[0]
                    salt = params['salt'].asOctets()
                    iteration_count = int(params['iterationCount'])
                    plaintext = sun_crypto.jce_pbe_decrypt(encrypted_private_key, key_password, salt, iteration_count)
                else:
                    raise UnexpectedAlgorithmException("Unknown JCEKS private key algorithm OID: {0}".format(algo_id))

            else:
                raise BadKeystoreFormatException("Unknown store type '%s', cannot determine encryption algorithm" % self.store_type)
        except (BadHashCheckException, BadPaddingException):
            raise DecryptionFailureException("Failed to decrypt data for private key '%s'; wrong password?" % self.alias)

        # at this point, 'plaintext' is a PKCS#8 PrivateKeyInfo (see RFC 5208)
        private_key_info = decoder.decode(plaintext, asn1Spec=rfc5208.PrivateKeyInfo())[0]
        key = private_key_info['privateKey'].asOctets()
        algorithm_oid = private_key_info['privateKeyAlgorithm']['algorithm'].asTuple()

        self._encrypted = None
        self._pkey = key
        self._pkey_pkcs8 = plaintext
        self._algorithm_oid = algorithm_oid


class SecretKeyEntry(AbstractKeystoreEntry):
    def __init__(self, **kwargs):
        super(SecretKeyEntry, self).__init__(**kwargs)
        self._encrypted = kwargs.get("sealed_obj")
        self._algorithm = kwargs.get("algorithm")
        self._key = kwargs.get("key")
        self._key_size = kwargs.get("key_size")

    def __getattr__(self, name):
        if not self.is_decrypted():
            raise NotYetDecryptedException("Cannot access attribute '%s'; entry not yet decrypted, call decrypt() with the correct password first" % name)
        return self.__dict__['_' + name]

    def is_decrypted(self):
        return (not self._encrypted)

    def decrypt(self, key_password):
        if self.is_decrypted():
            return

        plaintext = None
        sealed_obj = self._encrypted
        if sealed_obj.sealAlg == "PBEWithMD5AndTripleDES":
            # if the object was sealed with PBEWithMD5AndTripleDES then the parameters should apply to the same algorithm and not be empty or null
            if sealed_obj.paramsAlg != sealed_obj.sealAlg:
                raise UnexpectedAlgorithmException("Unexpected parameters algorithm used in SealedObject; should match sealing algorithm '%s' but found '%s'" % (sealed_obj.sealAlg, sealed_obj.paramsAlg))
            if sealed_obj.encodedParams is None or len(sealed_obj.encodedParams) == 0:
                raise UnexpectedJavaTypeException("No parameters found in SealedObject instance for sealing algorithm '%s'; need at least a salt and iteration count to decrypt" % sealed_obj.sealAlg)

            params_asn1 = decoder.decode(sealed_obj.encodedParams, asn1Spec=rfc2898.PBEParameter())[0]
            salt = params_asn1['salt'].asOctets()
            iteration_count = int(params_asn1['iterationCount'])
            try:
                plaintext = sun_crypto.jce_pbe_decrypt(sealed_obj.encryptedContent, key_password, salt, iteration_count)
            except sun_crypto.BadPaddingException:
                raise DecryptionFailureException("Failed to decrypt data for secret key '%s'; bad password?" % self.alias)
        else:
            raise UnexpectedAlgorithmException("Unexpected algorithm used for encrypting SealedObject: sealAlg=%s" % sealed_obj.sealAlg)

        # The plaintext here is another serialized Java object; this time it's an object implementing the javax.crypto.SecretKey interface.
        # When using the default SunJCE provider, these are usually either javax.crypto.spec.SecretKeySpec objects, or some other specialized ones
        # like those found in the com.sun.crypto.provider package (e.g. DESKey and DESedeKey).
        #
        # Additionally, things are further complicated by the fact that some of these specialized SecretKey implementations (i.e. other than SecretKeySpec)
        # implement a writeReplace() method, causing Java's serialization runtime to swap out the object for a completely different one at serialization time.
        # Again for SunJCE, the subsitute object that gets serialized is usually a java.security.KeyRep object.
        obj, dummy = KeyStore._read_java_obj(plaintext, 0)
        clazz = obj.get_class()
        if clazz.name == "javax.crypto.spec.SecretKeySpec":
            algorithm = obj.algorithm
            key = KeyStore._java_bytestring(obj.key)
            key_size = len(key)*8

        elif clazz.name == "java.security.KeyRep":
            assert (obj.type.constant == "SECRET"), "Expected value 'SECRET' for KeyRep.type enum value, found '%s'" % obj.type.constant
            key_bytes = KeyStore._java_bytestring(obj.encoded)
            key_encoding = obj.format
            if key_encoding == "RAW":
                pass # ok, no further processing needed
            elif key_encoding == "X.509":
                raise NotImplementedError("X.509 encoding for KeyRep objects not yet implemented")
            elif key_encoding == "PKCS#8":
                raise NotImplementedError("PKCS#8 encoding for KeyRep objects not yet implemented")
            else:
                raise UnexpectedKeyEncodingException("Unexpected key encoding '%s' found in serialized java.security.KeyRep object; expected one of 'RAW', 'X.509', 'PKCS#8'." % key_encoding)

            algorithm = obj.algorithm
            key = key_bytes
            key_size = len(key)*8
        else:
            raise UnexpectedJavaTypeException("Unexpected object of type '%s' found inside SealedObject; don't know how to handle it" % clazz.name)

        self._encrypted = None
        self._algorithm = algorithm
        self._key = key
        self._key_size = key_size

# --------------------------------------------------------------------------

class KeyStore(object):
    def __init__(self, store_type, entries):
        self.store_type = store_type
        self.entries = dict(entries)

    @property
    def certs(self):
        return {a:e for (a,e) in self.entries.items() if isinstance(e, TrustedCertEntry)}

    @property
    def secret_keys(self):
        return {a:e for (a,e) in self.entries.items() if isinstance(e, SecretKeyEntry)}

    @property
    def private_keys(self):
        return {a:e for (a,e) in self.entries.items() if isinstance(e, PrivateKeyEntry)}

    @classmethod
    def load(cls, filename, store_password, try_decrypt_keys=True):
        """
        Loads the given keystore file using the supplied password for verifying its integrity, and returns a jks.KeyStore instance.

        Note that entries in the store that represent some form of cryptographic key material are stored in encrypted form, and
        therefore require decryption before becoming accessible.

        Upon original creation of a key entry in a Java keystore, users are presented with the choice to either use the same password
        as the store password, or use a custom one. The most common choice is to use the store password for the individual key entries as well.

        For ease of use in this typical scenario, this function will attempt to decrypt each key entry it encounters with the store password:
         - If the key can be successfully decrypted with the store password, the entry is returned in its decrypted form, and its attributes
           are immediately accessible.
         - If the key cannot be decrypted with the store password, the entry is returned in its encrypted form, and requires a manual follow-up
           decrypt(key_password) call from the user before its individual attributes become accessible.

        Setting try_decrypt_keys to False disables this automatic decryption attempt, and returns all key entries in encrypted form.

        You can query whether a returned entry object has already been decrypted by calling the .is_decrypted() method on it.
        Attempting to access attributes of an entry that has not yet been decrypted will result in a NotYetDecryptedException.
        """
        with open(filename, 'rb') as file:
            return cls.loads(file.read(), store_password, try_decrypt_keys=try_decrypt_keys)

    @classmethod
    def loads(cls, data, store_password, try_decrypt_keys=True):
        """
        See the documentation on the load() function.
        """
        store_type = ""
        magic_number = data[:4]
        if magic_number == MAGIC_NUMBER_JKS:
            store_type = "jks"
        elif magic_number == MAGIC_NUMBER_JCEKS:
            store_type = "jceks"
        else:
            raise BadKeystoreFormatException('Not a JKS or JCEKS keystore (magic number wrong; expected FEEDFEED resp. CECECECE)')

        try:
            version = b4.unpack_from(data, 4)[0]
            if version != 2:
                raise UnsupportedKeystoreVersionException('Unsupported keystore version; only v2 supported, found v'+repr(version))

            entries = {}

            entry_count = b4.unpack_from(data, 8)[0]
            pos = 12
            for i in range(entry_count):
                tag = b4.unpack_from(data, pos)[0]
                pos += 4
                alias, pos = cls._read_utf(data, pos)
                timestamp = b8.unpack_from(data, pos)[0] # milliseconds since UNIX epoch
                pos += 8

                if tag == 1:
                    entry, pos = cls._read_private_key(data, pos, store_type)
                elif tag == 2:
                    entry, pos = cls._read_trusted_cert(data, pos, store_type)
                elif tag == 3:
                    if store_type != "jceks":
                        raise BadKeystoreFormatException("Unexpected entry tag {0} encountered in JKS keystore; only supported in JCEKS keystores".format(tag))
                    entry, pos = cls._read_secret_key(data, pos, store_type)
                else:
                    raise BadKeystoreFormatException("Unexpected keystore entry tag %d", tag)

                entry.alias = alias
                entry.timestamp = timestamp

                if try_decrypt_keys:
                    try:
                        entry.decrypt(store_password)
                    except DecryptionFailureException:
                        pass # ok, let user call decrypt() manually

                if alias in entries:
                    raise DuplicateAliasException("Found duplicate alias '%s'" % alias)
                entries[alias] = entry

        except struct.error as e:
            raise BadKeystoreFormatException(e)

        # the keystore integrity check uses the UTF-16BE encoding of the password
        store_password_utf16 = store_password.encode('utf-16be')
        expected_hash = hashlib.sha1(store_password_utf16 + SIGNATURE_WHITENING + data[:pos]).digest()
        if expected_hash != data[pos:]:
            raise KeystoreSignatureException("Hash mismatch; incorrect keystore password?")

        return cls(store_type, entries)

    @classmethod
    def _read_trusted_cert(cls, data, pos, store_type):
        cert_type, pos = cls._read_utf(data, pos)
        cert_data, pos = cls._read_data(data, pos)
        entry = TrustedCertEntry(type=cert_type, cert=cert_data, store_type=store_type)
        return entry, pos

    @classmethod
    def _read_private_key(cls, data, pos, store_type):
        ber_data, pos = cls._read_data(data, pos)
        chain_len = b4.unpack_from(data, pos)[0]
        pos += 4

        cert_chain = []
        for j in range(chain_len):
            cert_type, pos = cls._read_utf(data, pos)
            cert_data, pos = cls._read_data(data, pos)
            cert_chain.append((cert_type, cert_data))

        entry = PrivateKeyEntry(cert_chain=cert_chain, encrypted=ber_data, store_type=store_type)
        return entry, pos

    @classmethod
    def _read_secret_key(cls, data, pos, store_type):
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

        sealed_obj, pos = cls._read_java_obj(data, pos, ignore_remaining_data=True)
        if not cls._java_is_subclass(sealed_obj, "javax.crypto.SealedObject"):
            raise UnexpectedJavaTypeException("Unexpected sealed object type '%s'; not a subclass of javax.crypto.SealedObject" % sealed_obj.get_class().name)

        if sealed_obj.encryptedContent:
            sealed_obj.encryptedContent = cls._java_bytestring(sealed_obj.encryptedContent)
        if sealed_obj.encodedParams:
            sealed_obj.encodedParams = KeyStore._java_bytestring(sealed_obj.encodedParams)

        entry = SecretKeyEntry(sealed_obj=sealed_obj, store_type=store_type)
        return entry, pos


    @classmethod
    def _read_utf(cls, data, pos):
        size = b2.unpack_from(data, pos)[0]
        pos += 2
        return data[pos:pos+size].decode('utf-8'), pos+size

    @classmethod
    def _read_data(cls, data, pos):
        size = b4.unpack_from(data, pos)[0]
        pos += 4
        return data[pos:pos+size], pos+size

    @classmethod
    def _read_java_obj(cls, data, pos, ignore_remaining_data=False):
        data_stream = BytesIO(data[pos:])
        obj = javaobj.load(data_stream, ignore_remaining_data=ignore_remaining_data)
        obj_size = data_stream.tell()

        return obj, pos + obj_size

    @classmethod
    def _java_is_subclass(cls, obj, class_name):
        """Given a deserialized JavaObject as returned by the javaobj library, determine whether it's a subclass of the given class name."""
        clazz = obj.get_class()
        while clazz:
            if clazz.name == class_name:
                return True
            clazz = clazz.superclass
        return False

    @classmethod
    def _java_bytestring(cls, java_byte_list):
        """
        Convert the value returned by javaobj for a byte[] to a byte string.
        Java's bytes are signed and numeric (i.e. not chars), so javaobj returns Java byte arrays as a list of Python integers in the range [-128, 127].
        For ease of use we want to get a byte string representation of that, so we reinterpret each integer as an unsigned byte, take its new value
        as another Python int (now remapped to the range [0, 255]), and use struct.pack() to create the matching byte string.
        """
        return struct.pack("%dB" % len(java_byte_list), *[ctypes.c_ubyte(sb).value for sb in java_byte_list])

