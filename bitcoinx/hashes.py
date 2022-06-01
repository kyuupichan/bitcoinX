# Copyright (c) 2016-2021, Neil Booth
#
# All rights reserved.
#
# Licensed under the the Open BSV License version 3; see LICENCE for details.
#

'''Cryptographic hash functions and related classes.'''

__all__ = (
    'sha1', 'sha256', 'sha512', 'double_sha256',
    'ripemd160', 'hash160',
    'hmac_digest', 'hmac_sha512', 'hmac_sha512_halves',
    'hash_to_hex_str', 'hex_str_to_hash', 'hash_to_value',
    'merkle_root',
)

import hashlib
import hmac

from .misc import chunks
from Cryptodome.Hash import RIPEMD160


_sha1 = hashlib.sha1
_sha256 = hashlib.sha256
_sha512 = hashlib.sha512
_new_hash = hashlib.new
bytes_fromhex = bytes.fromhex
hmac_digest = hmac.digest


def sha1(x):
    '''Simple wrapper of hashlib sha1.'''
    return _sha1(x).digest()


def sha256(x):
    '''Simple wrapper of hashlib sha256.'''
    return _sha256(x).digest()


def sha512(x):
    '''Simple wrapper of hashlib sha256.'''
    return _sha512(x).digest()


def ripemd160(x):
    '''Simple wrapper of hashlib ripemd160.'''
    h = RIPEMD160.new()
    h.update(x)
    return h.digest()


def double_sha256(x):
    '''SHA-256 of SHA-256, as used extensively in bitcoin.'''
    return sha256(sha256(x))


def hash160(x):
    '''RIPEMD-160 of SHA-256.

    Used to make bitcoin addresses from pubkeys.'''
    return ripemd160(sha256(x))


def hash_to_hex_str(x):
    '''Convert a little-endian binary hash to displayed hex string.

    Display form of a binary hash is reversed and converted to hex.
    '''
    return bytes(reversed(x)).hex()


def hash_to_value(x):
    '''Convert a little-endian binary hash to an integer value (to e.g. compare to a proof of
    work target).
    '''
    return int.from_bytes(x, 'little')


def hex_str_to_hash(x):
    '''Convert a displayed hex string to a binary hash.'''
    return bytes(reversed(bytes_fromhex(x)))


def hmac_sha512(key, msg):
    return hmac_digest(key, msg, _sha512)


def hmac_sha512_halves(key, msg):
    hmacd = hmac_sha512(key, msg)
    return hmacd[:32], hmacd[32:]


def merkle_root(tx_hashes):
    '''Return the merkle root of an iterable of transaction hashes.'''
    if not isinstance(tx_hashes, list):
        tx_hashes = list(tx_hashes)

    if not tx_hashes:
        raise ValueError('tx_hashes must contain at least one hash')

    while len(tx_hashes) > 1:
        if len(tx_hashes) % 2:
            tx_hashes.append(tx_hashes[-1])
        tx_hashes = [double_sha256(lhs + rhs) for lhs, rhs in chunks(tx_hashes, 2)]

    return tx_hashes[0]
