# Copyright (c) 2018-2024 Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.


__all__ = (
    'Bitcoin', 'BitcoinTestnet', 'BitcoinScalingTestnet', 'BitcoinRegtest',
    'Network', 'all_networks', 'networks_by_name', 'bits_to_difficulty',
)

from .base58 import base58_encode_check
from .headers import SimpleHeader
from .packing import pack_byte
from .work import bits_to_target


class Network:

    def __init__(self, *, name, full_name, magic_hex, genesis_header_hex,
                 default_port, seeds,  BIP65_height, BIP66_height, CSV_height, UAHF_height,
                 DAA_height, genesis_height, P2PKH_verbyte, P2SH_verbyte, WIF_byte,
                 xpub_verbytes_hex, xprv_verbytes_hex, cashaddr_prefix):
        self.name = name
        self.full_name = full_name
        self.magic = bytes.fromhex(magic_hex)
        self.genesis_header = SimpleHeader(bytes.fromhex(genesis_header_hex))
        assert self.genesis_header.prev_hash == bytes(32)
        assert len(self.genesis_header.raw) == 80
        self.max_target = bits_to_target(self.genesis_header.bits)

        self.default_port = default_port
        self.seeds = seeds
        self.BIP65_height = BIP65_height,
        self.BIP66_height = BIP66_height
        self.CSV_height = CSV_height
        self.UAHF_height = UAHF_height
        self.DAA_height = DAA_height
        # Genesis upgrade activation
        self.genesis_height = genesis_height
        self.P2PKH_verbyte = P2PKH_verbyte
        self.P2SH_verbyte = P2SH_verbyte
        self.WIF_byte = WIF_byte
        self.xpub_verbytes = bytes.fromhex(xpub_verbytes_hex)
        self.xprv_verbytes = bytes.fromhex(xprv_verbytes_hex)
        self.cashaddr_prefix = cashaddr_prefix
        # A cache
        self.output_script_templates = None

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

    def to_address(self, hash160):
        '''Return a P2PKH address string.'''
        return base58_encode_check(pack_byte(self.P2PKH_verbyte) + hash160)

    def to_P2SH_address(self, hash160):
        '''Return a P2SH address string.'''
        return base58_encode_check(pack_byte(self.P2SH_verbyte) + hash160)

    def __str__(self):
        return self.name


Bitcoin = Network(
    name='mainnet',
    full_name='Bitcoin mainnet',
    magic_hex='e3e1f3e8',
    genesis_header_hex='01000000000000000000000000000000000000000000000000000000000000000000000'
    '03ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c',
    default_port=8333,
    seeds=[
        'seed.bitcoinsv.io',
        'seed.satoshisvision.network',
        'seed.bitcoinseed.directory',
    ],
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
    default_port=9333,
    seeds=[
        'stn-seed.bitcoinsv.io',
        'stn-seed.bitcoinseed.directory',
    ],
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
    default_port=18333,
    seeds=[
        'testnet-seed.bitcoinsv.io',
        'testnet-seed.bitcoincloud.net',
        'testnet-seed.bitcoinseed.directory',
    ],
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
    default_port=18444,
    seeds=[],
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


def bits_to_difficulty(bits):
    return Bitcoin.max_target / bits_to_target(bits)


all_networks = (Bitcoin, BitcoinTestnet, BitcoinScalingTestnet, BitcoinRegtest)
networks_by_name = {network.name: network for network in all_networks}
