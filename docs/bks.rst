BouncyCastle Keystores (BKS and UBER)
=====================================

.. py:module:: jks.bks

This module implements readers for keystores created by the BouncyCastle cryptographic provider for Java.

Store types
-----------

Pyjks supports two BouncyCastle store types:
    - BKS
    - UBER

Neither BKS or JKS/JCEKS stores make any effort to hide how many entries are present in the store, what their aliases are, and what type of key each
entry contains. The keys *inside* each entry are still protected, and the store is protected against tampering via the store password,
but anyone can still see the names and types of keys inside.

UBER keystores are similar to BKS, but they have an additional design goal: protect the store from introspection. This is done by additionally
encrypting the entire keystore using (a key derived from) the store password.

.. autoclass:: BksKeyStore
    :members:
    :show-inheritance:
    :member-order: groupwise
    :inherited-members:

    .. (Note: Explicit py:attribute definitions are needed here because :inherited-members: does not properly inherit
        instance variables at the moment)
    .. attribute:: entries

        A dictionary of all entries in the keystore, mapped by alias.

    .. attribute:: store_type

        A string indicating the type of keystore that was loaded. Equals ``bks`` for instances of this class.

.. autoclass:: UberKeyStore
    :members:
    :show-inheritance:
    :member-order: groupwise
    :inherited-members:

    .. (Note: Explicit py:attribute definitions are needed here because :inherited-members: does not properly inherit
        instance variables at the moment)
    .. attribute:: entries

        A dictionary of all entries in the keystore, mapped by alias.

    .. attribute:: store_type

        A string indicating the type of keystore that was loaded. Equals ``uber`` for instances of this class.

Entry types
-----------

.. automodule:: jks.bks
    :members: KEY_TYPE_PRIVATE, KEY_TYPE_PUBLIC, KEY_TYPE_SECRET
    :noindex:

.. autoclass:: BksTrustedCertEntry
    :members:
    :show-inheritance:
    :member-order: bysource
    :inherited-members:

    .. (Note: Explicit py:attribute definitions are needed here because :inherited-members: does not properly inherit
        instance variables at the moment)
    .. attribute:: type

        A string indicating the type of certificate. Unless in exotic applications, this is usually ``X.509``.

    .. attribute:: cert

        A byte string containing the actual certificate data. In the case of X.509 certificates, this is the DER-encoded
        X.509 representation of the certificate.

.. autoclass:: BksKeyEntry
    :members:
    :show-inheritance:
    :member-order: bysource
    :inherited-members:

    When :attr:`type` is :data:`KEY_TYPE_PRIVATE`, the following attributes are available:

        .. attribute:: pkey

            .. note:: Only accessible after a call to :func:`decrypt`; until then, accessing this attribute will raise
                      a :class:`~jks.util.NotYetDecryptedException`. See also ``try_decrypt_keys`` on :meth:`~jks.bks.BksKeyStore.loads`.

            A byte string containing the value of the ``privateKey`` field of the PKCS#8 ``PrivateKeyInfo`` representation of the private key.
            See `RFC 5208, section 5: Private-Key Information Syntax <https://tools.ietf.org/html/rfc5208#section-5>`_.

        .. attribute:: pkey_pkcs8

            .. note:: Only accessible after a call to :func:`decrypt`; until then, accessing this attribute will raise
                      a :class:`~jks.util.NotYetDecryptedException`. See also ``try_decrypt_keys`` on :meth:`~jks.bks.BksKeyStore.loads`.

            A byte string containing the DER-encoded PKCS#8 ``PrivateKeyInfo`` representation of the private key.
            See `RFC 5208, section 5: Private-Key Information Syntax <https://tools.ietf.org/html/rfc5208#section-5>`_.

        .. attribute:: algorithm_oid

            .. note:: Only accessible after a call to :func:`decrypt`; until then, accessing this attribute will raise
                      a :class:`~jks.util.NotYetDecryptedException`. See also ``try_decrypt_keys`` on :meth:`~jks.bks.BksKeyStore.loads`.

            A tuple of integers corresponding to the algorithm OID for which the private key is valid.

            Common values include:

                - ``(1,2,840,113549,1,1,1)`` (alias ``rsaEncryption``)
                - ``(1,2,840,10040,4,1)`` (alias ``id-dsa``).

    When :attr:`type` is :data:`KEY_TYPE_PUBLIC`, the following attributes are available:

        .. attribute:: public_key

            .. note:: Only accessible after a call to :func:`decrypt`; until then, accessing this attribute will raise
                      a :class:`~jks.util.NotYetDecryptedException`. See also ``try_decrypt_keys`` on :meth:`~jks.bks.BksKeyStore.loads`.

            A byte string containing the value of the ``subjectPublicKey`` field of the X.509 ``SubjectPublicKeyInfo`` representation of the public key.
            See `RFC 5280, Appendix A. Pseudo-ASN.1 Structures and OIDs <https://tools.ietf.org/html/rfc5280#appendix-A>`_.

        .. attribute:: public_key_info

            .. note:: Only accessible after a call to :func:`decrypt`; until then, accessing this attribute will raise
                      a :class:`~jks.util.NotYetDecryptedException`. See also ``try_decrypt_keys`` on :meth:`~jks.bks.BksKeyStore.loads`.

            A byte string containing the DER-encoded X.509 ``SubjectPublicKeyInfo`` representation of the public key.
            See `RFC 5280, Appendix A. Pseudo-ASN.1 Structures and OIDs <https://tools.ietf.org/html/rfc5280#appendix-A>`_.

        .. attribute:: algorithm_oid

            .. note:: Only accessible after a call to :func:`decrypt`; until then, accessing this attribute will raise
                      a :class:`~jks.util.NotYetDecryptedException`. See also ``try_decrypt_keys`` on :meth:`~jks.bks.BksKeyStore.loads`.

            A tuple of integers corresponding to the algorithm OID for which the public key is valid.

            Common values include:

                - ``(1,2,840,113549,1,1,1)`` (alias ``rsaEncryption``)
                - ``(1,2,840,10040,4,1)`` (alias ``id-dsa``).

    When :attr:`type` is :data:`KEY_TYPE_SECRET`, the following attributes are available:

        .. attribute:: key

            .. note:: Only accessible after a call to :func:`decrypt`; until then, accessing this attribute will raise
                      a :class:`~jks.util.NotYetDecryptedException`. See also ``try_decrypt_keys`` on :meth:`~jks.bks.BksKeyStore.loads`.

            A byte string containing the raw secret key.

        .. attribute:: key_size

            .. note:: Only accessible after a call to :func:`decrypt`; until then, accessing this attribute will raise
                      a :class:`~jks.util.NotYetDecryptedException`. See also ``try_decrypt_keys`` on :meth:`~jks.bks.BksKeyStore.loads`.

            An integer containing the size of the key, in bits. For DES and 3DES keys, the sizes 64 bits resp. 192 bits are returned.

.. autoclass:: BksSecretKeyEntry
    :members:
    :show-inheritance:
    :member-order: bysource
    :inherited-members:

.. autoclass:: BksSealedKeyEntry
    :members:
    :show-inheritance:
    :member-order: bysource
    :inherited-members:
