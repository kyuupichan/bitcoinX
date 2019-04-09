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

'''Bitcoin addresses.'''

__all__ = (
    'Address', 'P2PKH_Address', 'P2SH_Address',
)

from .base58 import base58_decode_check, base58_encode_check
from .coin import Bitcoin, all_coins
from .packing import pack_byte
from .script import P2PKH_Script, P2SH_Script
from bitcoinx import cashaddr


class Address:

    def __eq__(self, other):
        return str(self) == str(other)

    def __hash__(self):
        return hash(str(self))

    @classmethod
    def from_string(cls, text, *, coin=None):
        '''Construct from an address string.'''
        if len(text) > 35:
            try:
                return cls._from_cashaddr_string(text, coin=coin)
            except ValueError as e:
                pass

        raw = base58_decode_check(text)

        if len(raw) != 21:
            raise ValueError(f'invalid address: {text}')

        verbyte, hash160 = raw[0], raw[1:]
        coins = all_coins if coin is None else [coin]
        for coin in coins:
            if verbyte == coin.P2PKH_verbyte:
                return P2PKH_Address(hash160, coin=coin)
            if verbyte == coin.P2SH_verbyte:
                return P2SH_Address(hash160, coin=coin)

        raise ValueError(f'unknown version byte: {verbyte}')

    @classmethod
    def _from_cashaddr_string(cls, text, *, coin=None):
        '''Construct from a cashaddress string.'''
        coin = coin or Bitcoin
        prefix = coin.cashaddr_prefix
        if text.upper() == text:
            prefix = prefix.upper()
        if not text.startswith(prefix + ':'):
            text = ':'.join((prefix, text))
        addr_prefix, kind, hash160 = cashaddr.decode(text)
        assert prefix == addr_prefix

        if kind == cashaddr.PUBKEY_TYPE:
            return P2PKH_Address(hash160, coin=coin)
        else:
            return P2SH_Address(hash160, coin=coin)

    def coin(self):
        return self._coin

    def __str__(self):
        return self.to_string()


def _validate_hash160(hash160):
    if not isinstance(hash160, bytes):
        raise TypeError('hash160 must be bytes')
    if len(hash160) != 20:
        raise ValueError('hash160 must be 20 bytes')
    return hash160


class P2PKH_Address(Address):

    def __init__(self, hash160, *, coin=None):
        self._hash160 = _validate_hash160(hash160)
        self._coin = coin or Bitcoin

    def hash160(self):
        return self._hash160

    def to_string(self, *, coin=None):
        coin = coin or self._coin
        return base58_encode_check(pack_byte(coin.P2PKH_verbyte) + self._hash160)

    def to_script(self):
        return P2PKH_Script(self)


class P2SH_Address(Address):

    def __init__(self, hash160, *, coin=None):
        self._hash160 = _validate_hash160(hash160)
        self._coin = coin or Bitcoin

    def hash160(self):
        return self._hash160

    def to_string(self, *, coin=None):
        coin = coin or self._coin
        return base58_encode_check(pack_byte(coin.P2SH_verbyte) + self._hash160)

    def to_script(self):
        return P2SH_Script(self)
