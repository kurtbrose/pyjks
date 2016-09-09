Concepts
========

Store and entry passwords
-------------------------

Java keystores usually involve two kinds of passwords:
    - Passwords to protect individual key entries
    - A password to protect the integrity of the keystore as a whole

These passwords serve different purposes: the individual key passwords serve as secret material for encrypting the
entries with a PBE algorithm (Password-Based Encryption). The store password is typically used to detect tampering of the
store by using it as part of the input to a cryptographic hash calculation or as a key for a MAC.

In the general case, each entry in the store can have a different password associated with it, with an additional final
password being used for the keystore integrity check. To reduce the amount of passwords that needs to be kept track of
though, it is common for a single password to be used for both the store integrity as well as all individual key entries.

To support the common case where key entries are protected using the store password, the ``load`` and ``loads`` class functions
exposed by the different supported store types in pyjks contain a ``try_decrypt_keys`` keyword argument.

If set to ``True``, the function will automatically try to decrypt each key entry it encounters using the store password.
Any entry that fails to decrypt with the store password must therefore have been stored using a different password,
and is left alone for the user to manually call ``decrypt()`` on afterwards.


Store types
-----------

JKS:
    - Key protection algorithm: proprietary JavaSoft algorithm (1.3.6.1.4.1.42.2.17.1.1)
    - Store signature algorithm: SHA-1 hash

JCEKS:
    - Key protection algorithm: proprietary PBE_WITH_MD5_AND_DES3_CBC (1.3.6.1.4.1.42.2.19.1)
    - Store signature algorithm: SHA-1 hash

BKS:
    - Key protection algorithm: PBEWithSHAAnd3KeyTripleDESCBC (1.2.840.113549.1.12.1.3)
    - Store signature algorithm: HMAC-SHA1

UBER:
    - Key protection algorithm: PBEWithSHAAnd3KeyTripleDESCBC (1.2.840.113549.1.12.1.3)
    - Store signature algorithm: SHA-1 hash
    - Store encryption algorithm: PBEWithSHAAndTwofishCBC (unknown OID, proprietary?)
