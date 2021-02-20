# Copyright (c) 2018-2021, Neil Booth
#
# All rights reserved.
#
# Licensed under the the Open BSV License version 3; see LICENCE for details.
#

'''Signatures of various kinds.'''

__all__ = (
    'Signature', 'SigHash', 'SigEncoding',
    'der_signature_to_compact', 'compact_signature_to_der',
)

from base64 import b64decode
from binascii import Error as binascii_Error
from enum import IntEnum

from electrumsv_secp256k1 import ffi, lib
from .consts import CURVE_ORDER, HALF_CURVE_ORDER
from .errors import InvalidSignature
from .misc import CONTEXT, be_bytes_to_int, int_to_be_bytes
from .packing import pack_byte


CDATA_SIG_LENGTH = 64
# This is for the ECDSA signature without the sighash suffix
MIN_SIG_LENGTH = 8
MAX_SIG_LENGTH = 72


def _cdata_recsig(recoverable_sig):
    if len(recoverable_sig) != 65:
        raise InvalidSignature('invalid recoverable signature')
    cdata_recsig = ffi.new('secp256k1_ecdsa_recoverable_signature *')
    recid = recoverable_sig[-1]
    if not 0 <= recid <= 3:
        raise InvalidSignature('invalid recoverable signature')
    if not lib.secp256k1_ecdsa_recoverable_signature_parse_compact(
            CONTEXT, cdata_recsig, recoverable_sig, recid):
        raise InvalidSignature('invalid recoverable signature')
    return cdata_recsig


def public_key_from_recoverable_signature(recoverable_sig, msg_hash):
    cdata_recsig = _cdata_recsig(recoverable_sig)
    public_key = ffi.new('secp256k1_pubkey *')
    if not lib.secp256k1_ecdsa_recover(CONTEXT, public_key, cdata_recsig, msg_hash):
        raise InvalidSignature('invalid recoverable signature')
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
        raise InvalidSignature('invalid DER-encoded signature')
    return cdata_sig


def der_signature_to_compact(der_sig):
    '''Returns 64 bytes representing r and s as concatenated 32-byte big-endian numbers.'''
    cdata_sig = _der_signature_to_cdata(der_sig)
    compact_sig = ffi.new('unsigned char [64]')
    # Always succeeds
    lib.secp256k1_ecdsa_signature_serialize_compact(CONTEXT, compact_sig, cdata_sig)
    return bytes(ffi.buffer(compact_sig))


def compact_signature_to_der(compact_sig, raise_on_overflow=False):
    '''If R or S are too large (>= the curve order) returns a der signature with both set to
    zero, unless raise_on_overflow is True.
    '''
    if not (isinstance(compact_sig, bytes) and len(compact_sig) == 64):
        raise InvalidSignature('compact signature must be 64 bytes')
    cdata_sig = ffi.new('secp256k1_ecdsa_signature *')
    overflow = not lib.secp256k1_ecdsa_signature_parse_compact(CONTEXT, cdata_sig, compact_sig)
    if overflow and raise_on_overflow:
        raise InvalidSignature('R or S value overflows')
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
            raise InvalidSignature('invalid base64 encoding of message signature') from None
    if not isinstance(message_sig, bytes) or len(message_sig) != 65:
        raise InvalidSignature('message signature must be 65 bytes')
    if not 27 <= message_sig[0] < 35:
        raise InvalidSignature('invalid message signature format')
    return message_sig[1:] + pack_byte((message_sig[0] - 27) & 3)


def to_message_signature(recoverable_sig, compressed):
    leading_byte = 27 + (4 if compressed else 0) + recoverable_sig[-1]
    return pack_byte(leading_byte) + recoverable_sig[:64]


class SigEncoding(IntEnum):
    STRICT_DER = 1 << 0
    LOW_S = 1 << 1


class SigHash(int):

    @property
    def base(self):
        return SigHash(self & 0x1f)

    @property
    def anyone_can_pay(self):
        '''Return True if ANYONE_CAN_PAY is set.'''
        return bool(self & SigHash.ANYONE_CAN_PAY)

    @classmethod
    def from_sig_bytes(cls, sig_bytes):
        if sig_bytes:
            return cls(sig_bytes[-1])
        return cls(0)

    def has_forkid(self):
        '''Return True if the FORKID bit is set.'''
        return bool(self & SigHash.FORKID)

    def is_defined(self):
        '''Return True if the sighash "is defined".'''
        return SigHash.ALL <= self & ~(SigHash.FORKID | SigHash.ANYONE_CAN_PAY) <= SigHash.SINGLE

    def to_string(self):
        kinds = []
        if self & 3:
            kinds.append(('ALL', 'NONE', 'SINGLE')[(self & 3) - 1])
        if self & self.ANYONE_CAN_PAY:
            kinds.append('ANYONE_CAN_PAY')
        if self & self.FORKID:
            kinds.append('FORKID')
        residual = self & ~(self.ANYONE_CAN_PAY | self.FORKID | 3)
        if residual:
            kinds.append(f'0x{residual:02x}')
        return '|'.join(kinds)


class Signature:
    '''Utility functions for handling bitcoin and DER signatures.'''

    @classmethod
    def parse_lax_to_r_s(cls, der_sig, force_low_S=True):
        '''Converts a lossely-enforced DER signature to a pair (r, s).

        Implementation of ecdsa_signature_parse_der_lax() from bitcoin-sv/src/pubkey.cpp.

        Raises InvalidSignature if the signature format is invalid.  Returns a pair of
        zeroes if the R or S values overflow.  Forces S to be low if force_low_S is True.
        '''
        def read_byte(pos):
            if pos >= len(der_sig):
                raise SyntaxError
            return der_sig[pos]

        def require_byte(value, pos):
            if read_byte(pos) != value:
                raise SyntaxError
            return pos + 1

        def _read_be_integer(n, pos):
            if pos + n > len(der_sig):
                raise SyntaxError
            return be_bytes_to_int(der_sig[pos: pos + n]), pos + n

        def read_length(pos):
            length = read_byte(pos)
            pos += 1
            if length & 0x80:
                length, pos = _read_be_integer(length - 0x80, pos)
            return length, pos

        def read_integer(pos):
            pos = require_byte(0x02, pos)
            length, pos = read_length(pos)
            return _read_be_integer(length, pos)

        try:
            pos = require_byte(0x30, 0)
            # Signature length is unchecked
            _ignore, pos = read_length(pos)
            r, pos = read_integer(pos)
            s, pos = read_integer(pos)
        except SyntaxError:
            raise InvalidSignature('invalid lax DER encoding') from None

        if 0 <= r < CURVE_ORDER and 0 <= s < CURVE_ORDER:
            if force_low_S and s > HALF_CURVE_ORDER:
                s = CURVE_ORDER - s
            return r, s

        return 0, 0

    @classmethod
    def parse_lax_to_compact(cls, der_sig, force_low_S=True):
        r, s = cls.parse_lax_to_r_s(der_sig, force_low_S)
        return int_to_be_bytes(r, size=32) + int_to_be_bytes(s, size=32)

    @classmethod
    def parse_lax_to_der(cls, der_sig, force_low_S=True):
        compact = cls.parse_lax_to_compact(der_sig, force_low_S)
        return compact_signature_to_der(compact)

    @classmethod
    def r_value(cls, der_sig):
        '''The r value as an integer.'''
        r, _ = cls.parse_lax_to_r_s(der_sig)
        return r

    @classmethod
    def s_value(cls, der_sig, force_low_S=True):
        '''The s value as an integer.'''
        _, s = cls.parse_lax_to_r_s(der_sig, force_low_S)
        return s

    @classmethod
    def to_string(cls, sig_bytes):
        '''The signature as an ASM string.  Raises InvalidSignature if invalid.'''
        der_sig = sig_bytes[:-1]
        # Check validity
        cls.parse_lax_to_r_s(der_sig)
        return der_sig.hex() + '[' + cls.sighash(sig_bytes).to_string() + ']'

    @classmethod
    def sighash(cls, sig_bytes):
        return SigHash.from_sig_bytes(sig_bytes)

    @classmethod
    def split_and_normalize(cls, sig_bytes):
        '''Given a bitcoin signature taken from script (including the trailing sighash byte),
        return a normalized DER signature and a SigHash object.

        Raises InvalidSignature if the signature is not an acceptable DER encoding.
        Acceptable encodings are rather lax to account for on-chain signatures accepted
        in earlier times by OpenSSL.
        '''
        return cls.parse_lax_to_der(sig_bytes[:-1]), cls.sighash(sig_bytes)

    @classmethod
    def analyze_encoding(cls, sig_bytes):
        '''Analyzes the encoding of the signature (including sighash byte) returning a
        SigEncoding enum.

        Enforces stricter standard for DER encoding than libsecp256k.  In DER, r and s are
        positive 32-bit numbers encoded as big-endian numbers with a sign-bit.

        0x30 LEN 0x02 RLEN R 0x02 SLEN S SIGHASH.
        '''
        # Valid size range (including sighash byte)
        if not 9 <= len(sig_bytes) <= 73:
            return 0

        # Must be compound
        if sig_bytes[0] != 0x30:
            return 0
        # Length must cover everything
        if sig_bytes[1] != len(sig_bytes) - 3:
            return 0

        # Validate lengths
        lenR = sig_bytes[3]
        if 5 + lenR >= len(sig_bytes):
            return 0
        lenS = sig_bytes[5 + lenR]
        if lenR + lenS + 7 != len(sig_bytes):
            return 0

        # R must be an integer
        if sig_bytes[2] != 0x02:
            return 0
        # R cannot have length 0
        if not lenR:
            return 0
        # R cannot be negative
        if sig_bytes[4] & 0x80:
            return 0
        # Leading zero only if otherwise negative
        if lenR > 1 and sig_bytes[4] == 0x00 and not sig_bytes[5] & 0x80:
            return 0

        # S must be an integer
        if sig_bytes[lenR + 4] != 0x02:
            return 0
        # S cannot have length 0
        if not lenS:
            return 0
        # S cannot be negative
        if sig_bytes[lenR + 6] & 0x80:
            return 0
        # Leading zero only if otherwise negative
        if lenS > 1 and sig_bytes[lenR + 6] == 0x00 and not sig_bytes[lenR + 7] & 0x80:
            return 0

        result = SigEncoding.STRICT_DER
        s = be_bytes_to_int(sig_bytes[6 + lenR:6 + lenR + lenS])
        if s <= HALF_CURVE_ORDER:
            result |= SigEncoding.LOW_S
        return result


# Sighash values
SigHash.ALL = SigHash(0x01)
SigHash.NONE = SigHash(0x02)
SigHash.SINGLE = SigHash(0x03)
SigHash.FORKID = SigHash(0x40)
SigHash.ANYONE_CAN_PAY = SigHash(0x80)
