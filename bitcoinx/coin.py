# Copyright (c) 2018, Neil Booth
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

__all__ = (
    'Bitcoin', 'BitcoinTestnet', 'BitcoinScalingTestnet', 'Coin', 'Header', 'all_coins',
)

import attr

from bitcoinx.hashes import double_sha256, hash_to_hex_str, hash_to_value
from bitcoinx.packing import unpack_header, unpack_le_uint32
from bitcoinx.work import (
    bits_to_work, bits_to_target, required_bits_mainnet, required_bits_testnet,
    required_bits_scaling_testnet
)


@attr.s(slots=True)
class Header(object):
    version = attr.ib()
    prev_hash = attr.ib()
    merkle_root = attr.ib()
    timestamp = attr.ib()
    bits = attr.ib()
    nonce = attr.ib()

    # Extra metadata
    hash = attr.ib()
    raw = attr.ib()
    height = attr.ib()

    def work(self):
        return bits_to_work(self.bits)

    def target(self):
        return bits_to_target(self.bits)

    def hash_value(self):
        return hash_to_value(self.hash)

    def hex_str(self):
        return hash_to_hex_str(self.hash)

    def difficulty(self):
        return Bitcoin.bits_to_difficulty(self.bits)

    def __str__(self):
        return (f'Header(version=0x{self.version:x}, prev_hash={hash_to_hex_str(self.prev_hash)}, '
                f'merkle_root={hash_to_hex_str(self.merkle_root)}, timestamp={self.timestamp}, '
                f'bits=0x{self.bits}, nonce={self.nonce}, hash={self.hex_str()}, '
                f'height={self.height})')


class Coin(object):

    def __init__(self, name, genesis_header, required_bits, P2PKH_verbyte, WIF_byte,
                 xpub_verbytes, xprv_verbytes):
        self.name = name
        self.genesis_header = bytes.fromhex(genesis_header)
        self.genesis_bits = self.header_bits(self.genesis_header)
        self.max_target = bits_to_target(self.genesis_bits)
        # Signature:  def required_bits(self, headers, chain, height, timestamp=None)
        self.required_bits = required_bits
        self.P2PKH_verbyte = P2PKH_verbyte
        self.WIF_byte = WIF_byte
        self.xpub_verbytes = xpub_verbytes
        self.xprv_verbytes = xprv_verbytes

    def bits_to_difficulty(self, bits):
        return Bitcoin.max_target / bits_to_target(bits)

    def deserialized_header(self, raw, height):
        '''Returns a deserialized header object.'''
        return Header(*unpack_header(raw), self.header_hash(raw), raw, height)

    def header_hash(self, raw_header):
        return double_sha256(raw_header)

    def header_prev_hash(self, raw_header):
        return raw_header[4:36]

    def header_timestamp(self, raw_header):
        timestamp, = unpack_le_uint32(raw_header[68:72])
        return timestamp

    def header_bits(self, raw_header):
        bits, = unpack_le_uint32(raw_header[72:76])
        return bits

    def header_work(self, raw_header):
        return bits_to_work(self.header_bits(raw_header))

    @classmethod
    def from_WIF_byte(cls, WIF_byte):
        '''Return the coin using the given WIF byte.'''
        for coin in all_coins:
            if WIF_byte == coin.WIF_byte:
                return coin
        raise ValueError(f'invalid WIF byte {WIF_byte}')

    @classmethod
    def lookup_xver_bytes(cls, xver_bytes):
        '''Returns a (coin, is_public_key) pair.'''
        for coin in all_coins:
            if xver_bytes == coin.xpub_verbytes:
                return coin, True
            if xver_bytes == coin.xprv_verbytes:
                return coin, False
        raise ValueError(f'invalid xver_bytes {xver_bytes}')


Bitcoin = Coin(
    'Bitcoin mainnet',
    '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd'
    '7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c',
    required_bits_mainnet,
    0x00,
    0x80,
    bytes.fromhex("0488b21e"),
    bytes.fromhex("0488ade4"),
)


BitcoinTestnet = Coin(
    'Bitcoin testnet',
    '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd'
    '7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18',
    required_bits_testnet,
    0x6f,
    0xef,
    bytes.fromhex("043587cf"),
    bytes.fromhex("04358394"),
)

BitcoinScalingTestnet = Coin(
    'Bitcoin scaling testnet',
    '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd'
    '7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18',
    required_bits_scaling_testnet,
    0x6f,
    0xef,
    bytes.fromhex("043587cf"),
    bytes.fromhex("04358394"),
)

# rt12 -- Scaling testnet has same settings as regular testnet, so will cause conflicts.
all_coins = (Bitcoin, BitcoinTestnet, BitcoinScalingTestnet)
