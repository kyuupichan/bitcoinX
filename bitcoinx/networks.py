# Copyright (c) 2018-2021, Neil Booth
#
# All right reserved.
#
# Licensed under the the Open BSV License version 3; see LICENCE for details.
#

'''Specifics of Bitcoin mainnet and its test networks.'''

__all__ = (
    'Bitcoin', 'BitcoinTestnet', 'BitcoinScalingTestnet', 'BitcoinRegtest',
    'Network', 'Header', 'all_networks', 'networks_by_name',
)

import attr

from bitcoinx.hashes import double_sha256, hash_to_hex_str, hash_to_value
from bitcoinx.packing import unpack_header, unpack_le_uint32
from bitcoinx.work import (
    bits_to_work, bits_to_target, required_bits_mainnet, required_bits_testnet,
    required_bits_regtest, required_bits_scaling_testnet
)


@attr.s(slots=True)
class Header:
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


class Network:

    def __init__(self, *, name, full_name, magic_hex, genesis_header_hex, required_bits,
                 BIP65_height, BIP66_height, CSV_height, UAHF_height, DAA_height,
                 genesis_height, P2PKH_verbyte, P2SH_verbyte, WIF_byte,
                 xpub_verbytes_hex, xprv_verbytes_hex, cashaddr_prefix):
        self.name = name
        self.full_name = full_name
        self.magic = bytes.fromhex(magic_hex)
        self.genesis_header = bytes.fromhex(genesis_header_hex)
        assert len(self.genesis_header) == 80
        self.genesis_bits = self.header_bits(self.genesis_header)
        self.max_target = bits_to_target(self.genesis_bits)
        # Signature:  def required_bits(self, headers, chain, height, timestamp=None)
        self.required_bits = required_bits
        self.BIP65_height = BIP65_height,
        self.BIP66_height = BIP66_height
        self.CSV_height = CSV_height
        self.UAHF_height = UAHF_height
        self.DAA_height = DAA_height
        self.genesis_height = genesis_height
        self.P2PKH_verbyte = P2PKH_verbyte
        self.P2SH_verbyte = P2SH_verbyte
        self.WIF_byte = WIF_byte
        self.xpub_verbytes = bytes.fromhex(xpub_verbytes_hex)
        self.xprv_verbytes = bytes.fromhex(xprv_verbytes_hex)
        self.cashaddr_prefix = cashaddr_prefix
        # A cache
        self.output_script_templates = None

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
        '''Return the network using the given WIF byte.'''
        for network in all_networks:
            if WIF_byte == network.WIF_byte:
                return network
        raise ValueError(f'invalid WIF byte {WIF_byte}')

    @classmethod
    def lookup_xver_bytes(cls, xver_bytes):
        '''Returns a (network, is_public_key) pair.'''
        for network in all_networks:
            if xver_bytes == network.xpub_verbytes:
                return network, True
            if xver_bytes == network.xprv_verbytes:
                return network, False
        raise ValueError(f'invalid xver_bytes {xver_bytes}')


Bitcoin = Network(
    name='mainnet',
    full_name='Bitcoin mainnet',
    magic_hex='e3e1f3e8',
    genesis_header_hex='01000000000000000000000000000000000000000000000000000000000000000000000'
    '03ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c',
    required_bits=required_bits_mainnet,
    BIP65_height=388_381,
    BIP66_height=363_725,
    CSV_height=419_328,
    UAHF_height=478_558,
    DAA_height=504_031,
    genesis_height=620_538,
    P2PKH_verbyte=0x00,
    P2SH_verbyte=0x05,
    WIF_byte=0x80,
    xpub_verbytes_hex="0488b21e",
    xprv_verbytes_hex="0488ade4",
    cashaddr_prefix='bitcoincash',
)


BitcoinScalingTestnet = Network(
    name='STN',
    full_name='Bitcoin scaling testnet',
    magic_hex='fbcec4f9',
    genesis_header_hex='01000000000000000000000000000000000000000000000000000000000000000000000'
    '03ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18',
    required_bits=required_bits_scaling_testnet,
    BIP65_height=0,
    BIP66_height=0,
    CSV_height=0,
    UAHF_height=15,
    DAA_height=2_200,
    genesis_height=100,
    P2PKH_verbyte=0x6f,
    P2SH_verbyte=0xc4,
    WIF_byte=0xef,
    xpub_verbytes_hex="043587cf",
    xprv_verbytes_hex="04358394",
    cashaddr_prefix='bchtest',
)


BitcoinTestnet = Network(
    name='testnet',
    full_name='Bitcoin testnet',
    magic_hex='f4e5f3f4',
    genesis_header_hex='01000000000000000000000000000000000000000000000000000000000000000000000'
    '03ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18',
    required_bits=required_bits_testnet,
    BIP65_height=581_885,
    BIP66_height=330_776,
    CSV_height=770_112,
    UAHF_height=1_155_875,
    DAA_height=1_188_697,
    genesis_height=1_344_302,
    P2PKH_verbyte=0x6f,
    P2SH_verbyte=0xc4,
    WIF_byte=0xef,
    xpub_verbytes_hex="043587cf",
    xprv_verbytes_hex="04358394",
    cashaddr_prefix='bchtest',
)


BitcoinRegtest = Network(
    name='regtest',
    full_name='Bitcoin regression testnet',
    magic_hex='dab5bffa',
    genesis_header_hex='01000000000000000000000000000000000000000000000000000000000000000000000'
    '03ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f2002000000',
    required_bits=required_bits_regtest,
    BIP65_height=1_351,
    BIP66_height=1_251,
    CSV_height=576,
    UAHF_height=0,
    DAA_height=0,
    genesis_height=10_000,
    P2PKH_verbyte=0x6f,
    P2SH_verbyte=0xc4,
    WIF_byte=0xef,
    xpub_verbytes_hex="043587cf",
    xprv_verbytes_hex="04358394",
    cashaddr_prefix='bchtest',
)


all_networks = (Bitcoin, BitcoinTestnet, BitcoinScalingTestnet, BitcoinRegtest)
networks_by_name = {network.name: network for network in all_networks}

# rt12 -- Scaling testnet has same settings as regular testnet, so will cause conflicts.
