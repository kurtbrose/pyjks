# vim: set ai et ts=4 sts=4 sw=4:
from __future__ import print_function
import hashlib
import ctypes
from pyasn1.type import univ, namedtype
from Crypto.Cipher import DES3

PBE_WITH_SHA1_AND_TRIPLE_DES_CBC_OID = (1,2,840,113549,1,12,1,3)
PURPOSE_KEY_MATERIAL = 1
PURPOSE_IV_MATERIAL = 2
PURPOSE_MAC_MATERIAL = 3

class Pkcs12PBEParams(univ.Sequence):
    """Virtually identical to PKCS#5's PBEParameter, but nevertheless has its own definition in its own RFC, so gets its own class."""
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('salt', univ.OctetString()),
        namedtype.NamedType('iterations', univ.Integer())
    )

def derive_key(hashfn, purpose_byte, password_str, salt, iteration_count, desired_key_size):
    """
    Implements PKCS#12 key derivation as specified in RFC 7292, Appendix B, "Deriving Keys and IVs from Passwords and Salt".
    Ported from BC's implementation in org.bouncycastle.crypto.generators.PKCS12ParametersGenerator.

    hashfn:            hash function to use (expected to support the hashlib interface and attributes)
    password_str:      text string (not yet transformed into bytes)
    salt:              byte sequence
    purpose:           "purpose byte", signifies the purpose of the generated pseudorandom key material
    desired_key_size:  desired amount of bytes of key material to generate
    """
    password_bytes = password_str.encode('utf-16be') + b"\x00\x00"
    u = hashfn().digest_size # in bytes
    v = hashfn().block_size  # in bytes

    _salt = bytearray(salt)
    _password_bytes = bytearray(password_bytes)

    D = bytearray([purpose_byte])*v
    S_len = ((len(_salt) + v -1)//v)*v
    S = bytearray([_salt[n % len(_salt)] for n in range(S_len)])
    P_len = ((len(_password_bytes) + v -1)//v)*v
    P = bytearray([_password_bytes[n % len(_password_bytes)] for n in range(P_len)])

    I = S + P
    c = (desired_key_size + u - 1)//u
    derived_key = b""

    for i in range(1,c+1):
        A = hashfn(bytes(D + I)).digest()
        for j in range(iteration_count - 1):
            A = hashfn(A).digest()

        A = bytearray(A)
        B = bytearray([A[n % len(A)] for n in range(v)])

        # Treating I as a concatenation I_0, I_1, ..., I_(k-1) of v-bit
        # blocks, where k=ceiling(s/v)+ceiling(p/v), modify I by
        # setting I_j=(I_j+B+1) mod 2^v for each j.
        for j in range(len(I)//v):
            _adjust(I, j*v, B)

        derived_key += bytes(A)

    # truncate derived_key to the desired size
    derived_key = derived_key[:desired_key_size]
    return derived_key

def _adjust(a, a_offset, b):
    """
    a = bytearray
    a_offset = int
    b = bytearray
    """
    x = (b[-1] & 0xFF) + (a[a_offset + len(b) - 1] & 0xFF) + 1
    a[a_offset + len(b) - 1] = ctypes.c_ubyte(x).value
    x >>= 8

    for i in range(len(b)-2, -1, -1):
        x += (b[i] & 0xFF) + (a[a_offset + i] & 0xFF)
        a[a_offset + i] = ctypes.c_ubyte(x).value
        x >>= 8

def decrypt_PBEWithSHAAnd3KeyTripleDESCBC(data, password_str, salt, iteration_count):
    key = derive_key(hashlib.sha1, PURPOSE_KEY_MATERIAL, password_str, salt, iteration_count, 192//8)
    iv = derive_key(hashlib.sha1, PURPOSE_IV_MATERIAL, password_str, salt, iteration_count, 64//8)
    des3 = DES3.new(key, DES3.MODE_CBC, IV=iv)
    decrypted = des3.decrypt(data)
    return decrypted
