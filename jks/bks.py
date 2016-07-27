# vim: set et ai ts=4 sts=4 sw=4:
"""
BKS file format decoder.
"""
import struct
import hashlib
from pyasn1.codec.ber import decoder
from pyasn1_modules import rfc5208, rfc2459
from Crypto.Hash import HMAC, SHA

from .util import *
from .jks import KeyStore, TrustedCertEntry
from . import rfc7292

ENTRY_TYPE_CERTIFICATE = 1
ENTRY_TYPE_KEY = 2  # plaintext key entry as would otherwise be stored inside a sealed entry (type 4);
# no longer supported at the time of writing (BC 1.54)
ENTRY_TYPE_SECRET = 3  # for keys that were added to the store in already-protected form; can be arbitrary data
ENTRY_TYPE_SEALED = 4  # for keys that were protected by the BC keystore implementation upon adding
KEY_TYPE_PRIVATE = 0
KEY_TYPE_PUBLIC = 1
KEY_TYPE_SECRET = 2


class AbstractBksEntry(AbstractKeystoreEntry):
    """Abstract superclass for BKS keystore entry types"""

    def __init__(self, **kwargs):
        super(AbstractBksEntry, self).__init__(**kwargs)
        # All BKS entries can carry an arbitrary number of associated certificates
        self.cert_chain = kwargs.get("cert_chain", [])
        self._encrypted = kwargs.get("encrypted")


class BksTrustedCertEntry(TrustedCertEntry):
    pass  # identical


class BksKeyEntry(AbstractBksEntry):
    """
    Represents a non-encrypted cryptographic key (public, private or secret) stored in a BKS keystore.
    May exceptionally appear as a top-level entry type in (very) old keystores, but you are most likely
    to encounter these as the plaintext inside a SealedKeyEntry.
    """

    def __init__(self, type, format, algorithm, encoded, **kwargs):
        super(BksKeyEntry, self).__init__(**kwargs)
        self.type = type
        self.format = format
        self.algorithm = algorithm
        self.encoded = encoded

        if self.type == KEY_TYPE_PRIVATE:
            if self.format not in ["PKCS8", "PKCS#8"]:
                raise UnexpectedKeyEncodingException("Unexpected encoding for private key entry: '%s'" % self.format)
            # self.encoded is a PKCS#8 PrivateKeyInfo
            private_key_info = decoder.decode(self.encoded, asn1Spec=rfc5208.PrivateKeyInfo())[0]
            self.pkey_pkcs8 = self.encoded
            self.pkey = private_key_info['privateKey'].asOctets()
            self.algorithm_oid = private_key_info['privateKeyAlgorithm']['algorithm'].asTuple()

        elif self.type == KEY_TYPE_PUBLIC:
            if self.format not in ["X.509", "X509"]:
                raise UnexpectedKeyEncodingException("Unexpected encoding for public key entry: '%s'" % self.format)
            # self.encoded is an X.509 SubjectPublicKeyInfo
            spki = decoder.decode(self.encoded, asn1Spec=rfc2459.SubjectPublicKeyInfo())[0]
            self.public_key_info = self.encoded
            self.public_key = bitstring_to_bytes(spki['subjectPublicKey'])
            self.algorithm_oid = spki['algorithm']['algorithm'].asTuple()

        elif self.type == KEY_TYPE_SECRET:
            if self.format != "RAW":
                raise UnexpectedKeyEncodingException("Unexpected encoding for raw key entry: '%s'" % self.format)
            # self.encoded is an unwrapped/raw cryptographic key
            self.key = encoded
            self.key_size = len(encoded) * 8

        else:
            raise UnexpectedKeyEncodingException("Key format '%s' not recognized" % self.format)

    def is_decrypted(self):
        return True

    def decrypt(self, key_password):
        pass

    @classmethod
    def type2str(cls, t):
        if t == KEY_TYPE_PRIVATE:
            return "PRIVATE"
        elif t == KEY_TYPE_PUBLIC:
            return "PUBLIC"
        elif t == KEY_TYPE_SECRET:
            return "SECRET"
        return None


class BksSecretKeyEntry(AbstractBksEntry):
    # TODO: consider renaming this to SecretValueEntry, since it's arbitrary secret data
    """
    Conceptually similar to, but not to be confused with, BksKeyEntry objects of type SECRET:

      - BksSecretKeyEntry objects store the result of arbitrary user-supplied byte[]s, which, per the Java Keystore SPI, keystores are
        obligated to assume have already been protected by the user in some unspecified way. Because of this assumption, no password is
        provided for these entries when adding them to the keystore, and keystores are thus forced to store these bytes as-is.
        Produced through a KeyStore.setKeyEntry(String alias, byte[] key, Certificate[] chain) call.

        The bouncycastle project appears to have completely abandoned these entry types well over a decade ago now, and it is no
        longer possible to retrieve these entries through the Java APIs in any (remotely) recent BC version.

      - BksKeyEntry objects of .type == "SECRET" store the result of a getEncoded() call on proper Java objects of type SecretKey.
        Produced by a call to KeyStore.setKeyEntry(String alias, Key key, char[] password, Certificate[] chain).

        The difference here is that the KeyStore implementation knows it's getting a proper (Secret)Key Java object, and can decide
        for itself how to store it given the password supplied by the user. I.e., in this version of setKeyEntry it is left up to
        the keystore implementation to encode and protect the supplied Key object, instead of in advance by the user.
    """

    def __init__(self, **kwargs):
        super(BksSecretKeyEntry, self).__init__(**kwargs)
        self.key = self._encrypted

    # secret keys contain arbitrary data, unclear how to decrypt (may not be encrypted at all)
    def is_decrypted(self):
        return True

    def decrypt(self, key_password):
        pass


class BksSealedKeyEntry(AbstractBksEntry):
    """
    PBEWithSHAAnd3-KeyTripleDES-CBC-encrypted wrapper around a BksKeyEntry. The contained key type is unknown until decrypted.
    """

    def __init__(self, **kwargs):
        super(BksSealedKeyEntry, self).__init__(**kwargs)
        self._nested = None  # nested BksKeyEntry once decrypted

    def __getattr__(self, name):
        if not self.is_decrypted():
            raise NotYetDecryptedException(
                "Cannot access attribute '%s'; entry not yet decrypted, call decrypt() with the correct password first" % name)
        # if it's an attribute that exists here, return it; otherwise forward the request to the nested entry
        if "_" + name in self.__dict__:
            return self.__dict__["_" + name]
        else:
            return getattr(self._nested, name)

    def is_decrypted(self):
        return (not self._encrypted)

    def decrypt(self, key_password):
        if self.is_decrypted():
            return

        pos = 0
        data = self._encrypted

        salt, pos = BksKeyStore._read_data(data, pos)
        iteration_count = b4.unpack_from(data, pos)[0]
        pos += 4
        encrypted_blob = data[pos:]

        # BKS entry decryption routine intention in BcKeyStoreSpi.StoreEntry.getObject(char[] password) appears to be:
        #  - try to decrypt with "PBEWithSHAAnd3-KeyTripleDES-CBC" first (1.2.840.113549.1.12.1.3);
        #  - if that fails, try again with "BrokenPBEWithSHAAnd3-KeyTripleDES-CBC";
        #  - if that still fails, try again with "OldPBEWithSHAAnd3-KeyTripleDES-CBC"
        #  - give up with an UnrecoverableKeyException
        #
        # However, at the time of writing (bcprov-jdk15on-1.53 and 1.54), the 2nd & 3rd cases never successfully execute
        # because their implementation requests non-existent SecretKeyFactory objects for Broken/Old algorithm names.
        # BC developer mailing list confirms that this is indeed old functionality that has been retired long ago
        # and is not expected to be operational anymore, and should be cleaned up.
        #
        # So in practice, the real behaviour is:
        #  - try to decrypt with "PBEWithSHAAnd3-KeyTripleDES-CBC" (1.2.840.113549.1.12.1.3);
        #  - give up with an UnrecoverableKeyException
        #
        # Implementation classes:
        #  PBEWithSHAAnd3-KeyTripleDES-CBC  ->
        #     org.bouncycastle.jcajce.provider.symmetric.DESede$PBEWithSHAAndDES3Key
        #  BrokenPBEWithSHAAnd3-KeyTripleDES-CBC  ->
        #     org.bouncycastle.jce.provider.BrokenJCEBlockCipher$BrokePBEWithSHAAndDES3Key
        #  OldPBEWithSHAAnd3-KeyTripleDES-CBC  ->
        #     org.bouncycastle.jce.provider.BrokenJCEBlockCipher$OldPBEWithSHAAndDES3Key
        try:
            decrypted = rfc7292.decrypt_PBEWithSHAAnd3KeyTripleDESCBC(encrypted_blob, key_password, salt,
                                                                      iteration_count)
        except BadDataLengthException:
            raise BadKeystoreFormatException("Bad BKS entry format: %s" % str(e))
        except BadPaddingException:
            raise DecryptionFailureException("Failed to decrypt data for key '%s'; wrong password?" % self.alias)

        # the plaintext content of a SealedEntry is a KeyEntry
        key_entry, dummy = BksKeyStore._read_bks_key(decrypted, 0, self.store_type)
        key_entry.store_type = self.store_type
        key_entry.cert_chain = self.cert_chain
        key_entry.alias = self.alias
        key_entry.timestamp = self.timestamp

        self._nested = key_entry
        self._encrypted = None


class BksKeyStore(KeyStore):
    """
    Bouncycaste "BKS" keystore parser. Supports both the old V1 and current V2 format.
    """

    def __init__(self, store_type, entries):
        super(BksKeyStore, self).__init__(store_type, entries)

    @property
    def certs(self):
        return dict([(a, e) for a, e in self.entries.items()
                     if isinstance(e, BksTrustedCertEntry)])

    @property
    def secret_keys(self):
        return dict([(a, e) for a, e in self.entries.items()
                     if isinstance(e, BksSecretKeyEntry)])

    @property
    def sealed_keys(self):
        return dict([(a, e) for a, e in self.entries.items()
                     if isinstance(e, BksSealedKeyEntry)])

    @property
    def plain_keys(self):
        return dict([(a, e) for a, e in self.entries.items()
                     if isinstance(e, BksKeyEntry)])

    @classmethod
    def loads(cls, data, store_password, try_decrypt_keys=True):
        try:
            pos = 0
            version = b4.unpack_from(data, pos)[0]
            pos += 4
            if version not in [1, 2]:
                raise UnsupportedKeystoreVersionException(
                    "Unsupported BKS keystore version; only V1 and V2 supported, found v %r" % version)

            salt, pos = cls._read_data(data, pos)
            iteration_count = b4.unpack_from(data, pos)[0]
            pos += 4

            store_type = "bks"
            entries, size = cls._load_bks_entries(data[pos:], store_type, store_password,
                                                  try_decrypt_keys=try_decrypt_keys)

            hmac_fn = hashlib.sha1
            hmac_digest_size = hmac_fn().digest_size
            hmac_key_size = hmac_digest_size * 8 if version != 1 else hmac_digest_size
            hmac_key = rfc7292.derive_key(hmac_fn, rfc7292.PURPOSE_MAC_MATERIAL, store_password, salt, iteration_count,
                                          hmac_key_size // 8)

            store_data = data[pos:pos + size]
            store_hmac = data[pos + size:pos + size + hmac_digest_size]
            if len(store_hmac) != hmac_digest_size:
                raise BadKeystoreFormatException(
                    "Bad HMAC size; found %d bytes, expected %d bytes" % (len(store_hmac), hmac_digest_size))

            hmac = HMAC.new(hmac_key, digestmod=SHA)
            hmac.update(store_data)

            computed_hmac = hmac.digest()
            if store_hmac != computed_hmac:
                raise KeystoreSignatureException("Hash mismatch; incorrect keystore password?")
            return cls(store_type, entries)

        except struct.error as e:
            raise BadKeystoreFormatException(e)

    @classmethod
    def _load_bks_entries(cls, data, store_type, store_password, try_decrypt_keys=False):
        entries = {}
        pos = 0
        while pos < len(data):
            _type = b1.unpack_from(data, pos)[0]
            pos += 1
            if _type == 0:
                break

            alias, pos = cls._read_utf(data, pos)
            timestamp = int(b8.unpack_from(data, pos)[0])
            pos += 8
            chain_length = b4.unpack_from(data, pos)[0]
            pos += 4

            cert_chain = []
            for n in range(chain_length):
                entry, pos = cls._read_bks_cert(data, pos, store_type)
                cert_chain.append(entry)

            if _type == 1:  # certificate
                entry, pos = cls._read_bks_cert(data, pos, store_type)
            elif _type == 2:  # key: plaintext key entry, sealed key but without the PBEWithSHAAnd3KeyTripleDESCBC layer
                entry, pos = cls._read_bks_key(data, pos, store_type)
            elif _type == 3:  # secret key: opaque arbitrary data blob, stored as-is by the keystore; can be anything
                # (assumed to already be protected when supplied).
                entry, pos = cls._read_bks_secret(data, pos, store_type)
            elif _type == 4:  # sealed key; a well-formatted certificate, private key or public key
                # encrypted by the BKS implementation with a standard algorithm at save time
                entry, pos = cls._read_bks_sealed(data, pos, store_type)
            else:
                raise BadKeystoreFormatException("Unexpected keystore entry type %d", tag)

            entry.alias = alias
            entry.timestamp = timestamp
            entry.cert_chain = cert_chain

            if try_decrypt_keys:
                try:
                    entry.decrypt(store_password)
                except DecryptionFailureException:
                    pass  # ok, let user call .decrypt() manually afterwards

            if alias in entries:
                raise DuplicateAliasException("Found duplicate alias '%s'" % alias)
            entries[alias] = entry

        return (entries, pos)

    @classmethod
    def _read_bks_cert(cls, data, pos, store_type):
        cert_type, pos = cls._read_utf(data, pos)
        cert_data, pos = cls._read_data(data, pos)
        entry = BksTrustedCertEntry(type=cert_type, cert=cert_data, store_type=store_type)
        return entry, pos

    @classmethod
    def _read_bks_key(cls, data, pos, store_type):
        """Given a data stream, attempt to parse a stored BKS key entry at the given position
        return it as a BksKeyEntry."""
        key_type = b1.unpack_from(data, pos)[0]
        pos += 1
        key_format, pos = BksKeyStore._read_utf(data, pos)
        key_algorithm, pos = BksKeyStore._read_utf(data, pos)
        key_enc, pos = BksKeyStore._read_data(data, pos)

        entry = BksKeyEntry(key_type, key_format, key_algorithm, key_enc, store_type=store_type)
        return entry, pos

    @classmethod
    def _read_bks_secret(cls, data, pos, store_type):
        secret_data, pos = cls._read_data(data, pos)
        entry = BksSecretKeyEntry(store_type=store_type, encrypted=secret_data)
        return entry, pos

    @classmethod
    def _read_bks_sealed(cls, data, pos, store_type):
        sealed_data, pos = cls._read_data(data, pos)
        entry = BksSealedKeyEntry(store_type=store_type, encrypted=sealed_data)
        return entry, pos


class UberKeyStore(BksKeyStore):
    """
    BouncyCastle "UBER" keystore format parser.
    """

    @classmethod
    def loads(cls, data, store_password, try_decrypt_keys=True):
        # Uber keystores contain the same entry data as BKS keystores, except they wrap it differently:
        #    BKS  = BKS_store || HMAC-SHA1(BKS_store)
        #    UBER = PBEWithSHAAndTwofish-CBC(BKS_store || SHA1(BKS_store))
        #
        # where BKS_store represents the entry format shared by both keystore types.
        #
        # The Twofish key size is 256 bits, the PBE key derivation scheme is that as outlined by PKCS#12 (RFC 7292),
        # and the padding scheme for the Twofish cipher is PKCS#7.
        try:
            pos = 0
            version = b4.unpack_from(data, pos)[0]
            pos += 4
            if version != 1:
                raise UnsupportedKeystoreVersionException(
                    'Unsupported UBER keystore version; only v1 supported, found v' + repr(version))

            salt, pos = cls._read_data(data, pos)
            iteration_count = b4.unpack_from(data, pos)[0]
            pos += 4

            encrypted_bks_store = data[pos:]
            try:
                decrypted = rfc7292.decrypt_PBEWithSHAAndTwofishCBC(encrypted_bks_store, store_password, salt,
                                                                    iteration_count)
            except BadDataLengthException as e:
                raise BadKeystoreFormatException("Bad UBER keystore format: %s" % str(e))
            except BadPaddingException as e:
                raise DecryptionFailureException("Failed to decrypt UBER keystore: bad password?")

            # Note: we can assume that the hash must be present at the last 20 bytes of the decrypted data
            # (i.e. without first parsing through to see where the entry data actually ends), because
            # valid UBER keystores generators should not put any trailing bytes after the hash prior to encrypting.
            hash_fn = hashlib.sha1
            hash_digest_size = hash_fn().digest_size

            bks_store = decrypted[:-hash_digest_size]
            bks_hash = decrypted[-hash_digest_size:]
            if len(bks_hash) != hash_digest_size:
                raise BadKeystoreFormatException("Insufficient signature bytes; found %d bytes, expected %d bytes" % (
                    len(bks_hash), hash_digest_size))
            if hash_fn(bks_store).digest() != bks_hash:
                raise KeystoreSignatureException("Hash mismatch; incorrect keystore password?")

            store_type = "uber"
            entries, size = cls._load_bks_entries(bks_store, store_type, store_password,
                                                  try_decrypt_keys=try_decrypt_keys)
            return cls(store_type, entries)

        except struct.error as e:
            raise BadKeystoreFormatException(e)
