# Copyright (c) 2019, Neil Booth
#
# All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

'''Signatures of various kinds.'''

__all__ = (
    'Signature', 'SigHash',
    'der_signature_to_compact', 'compact_signature_to_der', 'InvalidSignatureError',
)

from base64 import b64decode
from binascii import Error as binascii_Error

from electrumsv_secp256k1 import ffi, lib

from .misc import CONTEXT, be_bytes_to_int
from .packing import pack_byte


CDATA_SIG_LENGTH = 64
MAX_SIG_LENGTH = 72
MISSING_SIG_BYTES = b'\xff'


class InvalidSignatureError(ValueError):
    pass


def _cdata_recsig(recoverable_sig):
    if len(recoverable_sig) != 65:
        raise InvalidSignatureError('invalid recoverable signature')
    cdata_recsig = ffi.new('secp256k1_ecdsa_recoverable_signature *')
    recid = recoverable_sig[-1]
    if not 0 <= recid <= 3:
        raise InvalidSignatureError('invalid recoverable signature')
    if not lib.secp256k1_ecdsa_recoverable_signature_parse_compact(
            CONTEXT, cdata_recsig, recoverable_sig, recid):
        raise InvalidSignatureError('invalid recoverable signature')
    return cdata_recsig


def public_key_from_recoverable_signature(recoverable_sig, msg_hash):
    cdata_recsig = _cdata_recsig(recoverable_sig)
    public_key = ffi.new('secp256k1_pubkey *')
    if not lib.secp256k1_ecdsa_recover(CONTEXT, public_key, cdata_recsig, msg_hash):
        raise InvalidSignatureError('invalid recoverable signature')
    return public_key


def _cdata_signature_to_der(signature):
    '''Return a DER-serialized signature; bytes of length at most 72.'''
    size = ffi.new('size_t *', MAX_SIG_LENGTH)
    data = ffi.new(f'unsigned char [{MAX_SIG_LENGTH}]')
    result = lib.secp256k1_ecdsa_signature_serialize_der(CONTEXT, data, size, signature)
    # Failure should never happen - MAX_SIG_LENGTH bytes is always enough
    assert result
    return bytes(ffi.buffer(data, size[0]))


def _der_signature_to_cdata(der_sig):
    cdata_sig = ffi.new('secp256k1_ecdsa_signature *')
    if not lib.secp256k1_ecdsa_signature_parse_der(CONTEXT, cdata_sig, der_sig, len(der_sig)):
        raise InvalidSignatureError('invalid DER-encoded signature')
    return cdata_sig


def der_signature_to_compact(der_sig):
    '''Returns 64 bytes representing r and s as concatenated 32-byte big-endian numbers.'''
    cdata_sig = _der_signature_to_cdata(der_sig)
    compact_sig = ffi.new('unsigned char [64]')
    lib.secp256k1_ecdsa_signature_serialize_compact(CONTEXT, compact_sig, cdata_sig)
    return bytes(ffi.buffer(compact_sig))


def compact_signature_to_der(compact_sig):
    if not (isinstance(compact_sig, bytes) and len(compact_sig) == 64):
        raise InvalidSignatureError('compact signature must be 64 bytes')
    cdata_sig = ffi.new('secp256k1_ecdsa_signature *')
    lib.secp256k1_ecdsa_signature_parse_compact(CONTEXT, cdata_sig, compact_sig)
    return _cdata_signature_to_der(cdata_sig)


def sign_der(msg_hash, secret):
    cdata_sig = ffi.new('secp256k1_ecdsa_signature *')
    if not lib.secp256k1_ecdsa_sign(CONTEXT, cdata_sig, msg_hash, secret, ffi.NULL, ffi.NULL):
        raise ValueError('invalid private key')
    return _cdata_signature_to_der(cdata_sig)


def sign_recoverable(msg_hash, secret):
    '''Sign a message hash and return a 65-byte recoverable signature.  This is a 64-byte
    compact signature with a recovery ID byte appended; and from which the public key can
    be immediately recovered.
    '''
    rec_signature = ffi.new('secp256k1_ecdsa_recoverable_signature *')
    if not lib.secp256k1_ecdsa_sign_recoverable(CONTEXT, rec_signature, msg_hash,
                                                secret, ffi.NULL, ffi.NULL):
        raise ValueError('invalid private key')

    # Serialize its as a 65-byte compact recoverable signature
    output = ffi.new(f'unsigned char [{CDATA_SIG_LENGTH}]')
    recid = ffi.new('int *')

    lib.secp256k1_ecdsa_recoverable_signature_serialize_compact(
        CONTEXT, output, recid, rec_signature)

    # recid is 0, 1, 2 or 3.
    return bytes(ffi.buffer(output, CDATA_SIG_LENGTH)) + bytes([recid[0]])


def verify_recoverable_signature(recoverable_sig, msg_hash, public_key):
    # Convert a 65-byte recoverable sig to a CDATA one
    cdata_sig = ffi.new('secp256k1_ecdsa_signature *')
    cdata_recsig = _cdata_recsig(recoverable_sig)
    # Always succeeds
    lib.secp256k1_ecdsa_recoverable_signature_convert(CONTEXT, cdata_sig, cdata_recsig)
    return bool(lib.secp256k1_ecdsa_verify(CONTEXT, cdata_sig, msg_hash, public_key))


def verify_der_signature(der_sig, msg_hash, public_key):
    '''Verify a der-encoded signature.  Return True if good otherwise False.'''
    cdata_sig = _der_signature_to_cdata(der_sig)
    return bool(lib.secp256k1_ecdsa_verify(CONTEXT, cdata_sig, msg_hash, public_key))


def to_recoverable_signature(message_sig):
    '''Return a recoverable signature from a message signature.'''
    if isinstance(message_sig, str):
        try:
            message_sig = b64decode(message_sig, validate=True)
        except binascii_Error:
            raise InvalidSignatureError('invalid base64 encoding of message signature')
    if not isinstance(message_sig, bytes) or len(message_sig) != 65:
        raise InvalidSignatureError('message signature must be 65 bytes')
    if not 27 <= message_sig[0] < 35:
        raise InvalidSignatureError('invalid message signature format')
    return message_sig[1:] + pack_byte((message_sig[0] - 27) & 3)


def to_message_signature(recoverable_sig, compressed):
    leading_byte = 27 + (4 if compressed else 0) + recoverable_sig[-1]
    return pack_byte(leading_byte) + recoverable_sig[:64]


class SigHash(int):

    @property
    def base(self):
        return SigHash(self & 0x1f)

    @property
    def anyone_can_pay(self):
        '''Returns True if ANYONE_CAN_PAY is set.'''
        return bool(self & SigHash.ANYONE_CAN_PAY)


class Signature:
    '''A bitcoin DER signature, as raw bytes.'''

    def __init__(self, raw):
        '''Raw is a der-encoded signature plus a single sighash byte, or MISSING_SIG_BYTES.'''
        if raw != MISSING_SIG_BYTES:
            # Validate the DER encoding
            der_signature_to_compact(raw[:-1])
        self._raw = raw

    def __eq__(self, other):
        '''A signature equals anything buffer-like with the same bytes representation.'''
        return (isinstance(other, (bytes, bytearray, memoryview))
                or hasattr(other, '__bytes__')) and self._raw == bytes(other)

    def __hash__(self):
        return hash(self._raw)

    @classmethod
    def from_hex(cls, hex_str):
        '''Instantiate from a hexadecimal string.'''
        return cls(bytes.fromhex(hex_str))

    def to_hex(self):
        '''Return the script signature as a hexadecimal string.'''
        return self._raw.hex()

    @classmethod
    def from_der_sig(cls, der_sig, sighash):
        return cls(der_sig + pack_byte(sighash))

    def __bytes__(self):
        return self._raw

    def to_bytes(self):
        return self._raw

    def is_present(self):
        return self._raw != MISSING_SIG_BYTES

    def to_compact(self):
        '''The 32-byte r and s values concatenated.'''
        return der_signature_to_compact(self.der_signature)

    def r_value(self):
        '''The r value as an integer.'''
        return be_bytes_to_int(self.to_compact()[:32])

    def s_value(self):
        '''The s value as an integer.'''
        return be_bytes_to_int(self.to_compact()[32:])

    @property
    def der_signature(self):
        if self._raw == MISSING_SIG_BYTES:
            raise InvalidSignatureError('signature is missing')
        return self._raw[:-1]

    @property
    def sighash(self):
        if self._raw == MISSING_SIG_BYTES:
            raise InvalidSignatureError('signature is missing')
        return SigHash(self._raw[-1])


# Sighash values
SigHash.ALL = SigHash(0x01)
SigHash.NONE = SigHash(0x02)
SigHash.SINGLE = SigHash(0x03)
SigHash.FORKID = SigHash(0x40)
SigHash.ANYONE_CAN_PAY = SigHash(0x80)

Signature.MISSING = Signature(MISSING_SIG_BYTES)
