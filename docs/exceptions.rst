Exceptions
==========

All exceptions related to keystore loading or parsing derive from a common superclass type :class:`~jks.util.KeystoreException`.

Exception types
---------------

.. automodule:: jks.util
    :show-inheritance:
    :members: KeystoreException, KeystoreSignatureException, DuplicateAliasException, NotYetDecryptedException,
              BadKeystoreFormatException, BadDataLengthException, BadPaddingException, BadHashCheckException,
              DecryptionFailureException, UnsupportedKeystoreVersionException, UnexpectedJavaTypeException,
              UnexpectedAlgorithmException, UnexpectedKeyEncodingException, UnsupportedKeystoreTypeException,
              UnsupportedKeystoreEntryTypeException, UnsupportedKeyFormatException
