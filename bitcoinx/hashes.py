# Copyright (c) 2016-2018, Neil Booth
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

'''Cryptographic hash functions and related classes.'''

__all__ = (
    'sha1', 'sha256', 'sha512', 'double_sha256',
    'ripemd160', 'hash160',
    'hmac_digest', 'hmac_sha512_halves',
    'hash_to_hex_str', 'hex_str_to_hash', 'hash_to_value',
)

import hashlib
import hmac


_sha1 = hashlib.sha1
_sha256 = hashlib.sha256
_sha512 = hashlib.sha512
_new_hash = hashlib.new
bytes_fromhex = bytes.fromhex


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
    h = _new_hash('ripemd160')
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


if hasattr(hmac, 'digest'):
    # Python 3.7+
    hmac_digest = hmac.digest   # pylint: disable=no-member
else:
    def hmac_digest(key, msg, digest):
        return hmac.new(key, msg, digest).digest()


def hmac_sha512_halves(key, msg):
    hmacd = hmac_digest(key, msg, _sha512)
    return hmacd[:32], hmacd[32:]
