JKS and JCEKS keystores
=======================

.. py:module:: jks.jks

Background
----------

The JKS keystore format is the format that originally shipped with Java.
It is implemented by the traditional "Sun" cryptography provider.

JCEKS is an improved keystore format introduced with the Java Cryptography Extension (JCE).
It is implemented by the SunJCE cryptography provider.

JCEKS keystores improve upon JKS keystores in 2 ways:
 - A stronger key protection algorithm is used
 - They allow for arbitrary (symmetric) secret keys to be stored (e.g. AES, DES, etc.)

Store types
-----------

.. autoclass:: KeyStore
    :members:
    :show-inheritance:
    :member-order: groupwise
    :inherited-members:

    .. (Note: Explicit py:attribute definitions are needed here because :inherited-members: does not properly inherit
        instance variables at the moment)
    .. attribute:: entries

        A dictionary of all entries in the keystore, mapped by alias.

    .. attribute:: store_type

        A string indicating the type of keystore that was loaded. Can be one of ``jks``, ``jceks``.

Entry types
-----------

.. autoclass:: TrustedCertEntry
    :members:
    :show-inheritance:
    :member-order: groupwise
    :inherited-members:

.. autoclass:: PrivateKeyEntry
    :members:
    :show-inheritance:
    :member-order: bysource
    :inherited-members:

    .. attribute:: pkey

        .. note:: Only accessible after a call to :func:`decrypt`; until then, accessing this attribute will raise
                  a :class:`~jks.util.NotYetDecryptedException`. See also ``try_decrypt_keys`` on :meth:`jks.jks.KeyStore.loads`.

        A byte string containing the value of the ``privateKey`` field of the PKCS#8 ``PrivateKeyInfo`` representation of the private key.
        See `RFC 5208, section 5: Private-Key Information Syntax <https://tools.ietf.org/html/rfc5208#section-5>`_.

    .. attribute:: pkey_pkcs8

        .. note:: Only accessible after a call to :func:`decrypt`; until then, accessing this attribute will raise
                  a :class:`~jks.util.NotYetDecryptedException`. See also ``try_decrypt_keys`` on :meth:`jks.jks.KeyStore.loads`.

        A byte string containing the DER-encoded PKCS#8 ``PrivateKeyInfo`` representation of the private key.
        See `RFC 5208, section 5: Private-Key Information Syntax <https://tools.ietf.org/html/rfc5208#section-5>`_.

    .. attribute:: algorithm_oid

        .. note:: Only accessible after a call to :func:`decrypt`; until then, accessing this attribute will raise
                  a :class:`~jks.util.NotYetDecryptedException`. See also ``try_decrypt_keys`` on :meth:`jks.jks.KeyStore.loads`.

        A tuple of integers corresponding to the algorithm OID for which the private key is valid.

        Common values include:

            - ``(1,2,840,113549,1,1,1)`` (alias ``rsaEncryption``)
            - ``(1,2,840,10040,4,1)`` (alias ``id-dsa``).


.. autoclass:: SecretKeyEntry
    :members:
    :show-inheritance:
    :member-order: bysource
    :inherited-members:

    .. attribute:: algorithm

        .. note:: Only accessible after a call to :func:`decrypt`; until then, accessing this attribute will raise
                  a :class:`~jks.util.NotYetDecryptedException`. See also ``try_decrypt_keys`` on :meth:`jks.jks.KeyStore.loads`.

        A string containing the name of the algorithm for which the key is valid, as known to the Java cryptography provider
        that supplied the corresponding SecretKey object.

    .. attribute:: key

        .. note:: Only accessible after a call to :func:`decrypt`; until then, accessing this attribute will raise
                  a :class:`~jks.util.NotYetDecryptedException`. See also ``try_decrypt_keys`` on :meth:`jks.jks.KeyStore.loads`.

        A byte string containing the raw secret key.

    .. attribute:: key_size

        .. note:: Only accessible after a call to :func:`decrypt`; until then, accessing this attribute will raise
                  a :class:`~jks.util.NotYetDecryptedException`. See also ``try_decrypt_keys`` on :meth:`jks.jks.KeyStore.loads`.

        An integer containing the size of the key, in bits. For DES and 3DES keys, the sizes 64 bits resp. 192 bits are returned.
