# Copyright (c) 2018-2023, Neil Booth
#
# All right reserved.
#
# Licensed under the the Open BSV License version 3; see LICENCE for details.
#

'''Header and chain handling.  Bitcoin network parameters.'''


import math

import attr

from .errors import MissingHeader, IncorrectBits, InsufficientPoW
from .hashes import double_sha256, hash_to_hex_str, hash_to_value
from .misc import chunks
from .packing import unpack_header, unpack_le_uint32
from .work import bits_to_target, bits_to_work, target_to_bits


__all__ = (
    'Chain', 'Header', 'Headers',
    'bits_to_difficulty', 'deserialized_header', 'header_bits', 'header_hash',
    'header_prev_hash', 'header_timestamp', 'header_work', 'log2_work',
    # Networks
    'Bitcoin', 'BitcoinTestnet', 'BitcoinScalingTestnet', 'BitcoinRegtest',
    'Network', 'all_networks', 'networks_by_name',
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
        return bits_to_difficulty(self.bits)

    def __str__(self):
        return (f'Header(version=0x{self.version:x}, prev_hash={hash_to_hex_str(self.prev_hash)}, '
                f'merkle_root={hash_to_hex_str(self.merkle_root)}, timestamp={self.timestamp}, '
                f'bits=0x{self.bits}, nonce={self.nonce}, hash={self.hex_str()}, '
                f'height={self.height})')


# Raw header operations

header_hash = double_sha256


def deserialized_header(raw, height):
    '''Returns a deserialized header object.'''
    return Header(*unpack_header(raw), header_hash(raw), raw, height)


def header_prev_hash(raw_header):
    return raw_header[4:36]


def header_timestamp(raw_header):
    timestamp, = unpack_le_uint32(raw_header[68:72])
    return timestamp


def header_bits(raw_header):
    bits, = unpack_le_uint32(raw_header[72:76])
    return bits


def header_work(raw_header):
    return bits_to_work(header_bits(raw_header))


def log2_work(work):
    return math.log(work, 2)


def bits_to_difficulty(bits):
    return Bitcoin.max_target / bits_to_target(bits)


class Chain:
    '''A dumb object representing a chain of headers back to the genesis block (implemented
    through parent chains).

    Public attributes:
        parent        the parent chain this one forks from, can be None
        first_height  the first height not in common with the parent (0 for the base chain)
        headers       the headers unique to this chain
    '''

    def __init__(self, parent, first_height):
        self.parent = parent
        self.first_height = first_height
        self._raw_headers = bytearray()
        self.chainwork = parent.chainwork_at_height(first_height - 1) if parent else 0

    def append(self, raw_header):
        '''Append a header to the chain.'''
        self._raw_headers.extend(raw_header)
        self.chainwork += header_work(raw_header)

    @property
    def height(self):
        return self.first_height + len(self._raw_headers) // 80 - 1

    def tip(self):
        return deserialized_header(self._raw_headers[-80:], self.height)

    def chainwork_range(self, start_height, end_height):
        '''Returns the chainwork for the half-open range [start_height, end_height).'''
        raw_header = self.raw_header_at_height
        work = header_work
        return sum(work(raw_header(height)) for height in range(start_height, end_height))

    def chainwork_at_height(self, height):
        '''Returns the chainwork to and including height on a chain.'''
        if self.height >= height >= self.first_height:
            return self.chainwork - self.chainwork_range(height + 1, self.height + 1)
        elif self.parent:
            return self.parent.chainwork_at_height(height)
        raise MissingHeader(f'no header at height {height}')

    def raw_header_at_height(self, height):
        '''Returns an 80-byte header.'''
        if height >= self.first_height:
            start = (height - self.first_height) * 80
            header = self._raw_headers[start: start + 80]
            if len(header) == 80:
                return bytes(header)
        elif self.parent:
            return self.parent.raw_header_at_height(height)
        raise MissingHeader(f'no header at height {height}')

    def header_hash_at_height(self, height):
        '''Return the hash of the header.'''
        return header_hash(self.raw_header_at_height(height))

    def header_at_height(self, height):
        '''Returns a deserialized Header object.'''
        return deserialized_header(self.raw_header_at_height(height), height)

    def walk_parents(self):
        '''An iterator that yields (chain, height) pairs, starting with this chain, and then its
        parent, recursively.  The height is the greatest height on that chain which is
        also part of this chain.
        '''
        chain, height = self, self.height
        while chain:
            yield chain, height
            height = chain.first_height - 1
            chain = chain.parent

    def parent_chains(self):
        '''Returns a list of parent chains in decreasing order of height.  Therefore this chain is
        first.
        '''
        return [chain for chain, _height in self.walk_parents()]

    def common_chain_and_height(self, other_chain):
        '''Returns a pair (chain, height).  The height is the greatest height common between this
        chain and another chain back to the genesis block, and chain is the chain of that
        height.
        '''
        other_heights = dict(other_chain.walk_parents())
        for chain, height in self.walk_parents():
            other_height = other_heights.get(chain)
            if other_height is not None:
                return chain, min(height, other_height)
        return None, -1

    def median_time_past(self, height):
        '''Returns the median time past at height.'''
        timestamp = header_timestamp
        raw_header = self.raw_header_at_height
        timestamps = [timestamp(raw_header(h))for h in range(height, max(-1, height - 11), -1)]
        return sorted(timestamps)[len(timestamps) // 2]

    def unpersisted_headers(self, cursor_height):
        if self.first_height - 1 <= cursor_height <= self.height:
            start = cursor_height - (self.first_height - 1)
        else:
            raise ValueError(f'invalid cursor height {cursor_height:,d}')
        return self._raw_headers[start * 80:]

    def block_locator(self):
        '''Returns a block locator: a list of block hashes starting from the chain tip back
        to the genesis block, that become increasingly sparse.'''
        def block_heights(height, stop=0, step=-1):
            while height > stop:
                yield height
                height += step
                step += step
            yield stop

        return [self.header_hash_at_height(height) for height in block_heights(self.height)]

    def desc(self):
        return f'tip={self.tip()} log2_chainwork={round(log2_work(self.chainwork), 8)}'

    def __lt__(self, other):
        return self.first_height < other.first_height


class Headers:
    '''A collection of block headers arranged into chains.  Each header header belongs to
    precisely one chain.  Each chain has a parent chain which it forked from, except one
    chain whose parent is None.

    connect() adds one header to the collection and returns the chain the header lies on.

    Headers can be looked up by height on a given chain.  They can be looked up by hash in
    which case the header and its chain are returned as a pair.

    Deserialized "Header" objects that are returned always have their hash and height set
    in addition to the standard header attributes such as nonce and timestamp.
    '''

    def __init__(self, network):
        # mainnet, testnet etc.
        self.network = network
        # Map from chain to block hash
        self.tips = {}
        # Map from block hash to (chain, height) pair
        self.hashes = {}
        # Connect the genesis block
        self.connect(network.genesis_header)

    def raw_header_at_height(self, chain, height):
        return chain.raw_header_at_height(height)

    def header_at_height(self, chain, height):
        return chain.header_at_height(height)

    def lookup(self, hdr_hash):
        # Looks up a header by its hash.
        # Returns a (chain, height) pair if found, otherwise (None, -1) is returned.
        return self.hashes.get(hdr_hash, (None, -1))

    def connect(self, raw_header, check_work=True):
        '''Connect a header to the set of headers.  Optionally performs expensive proof-of-work
        checks if check_work is True.  Returns the chain it lies on.
        '''
        hashes = self.hashes
        tips = self.tips

        hdr_hash = header_hash(raw_header)
        prev_hash = raw_header[4:36]
        chain, height = hashes.get(prev_hash, (None, -1))
        height += 1

        if not chain:
            if raw_header != self.network.genesis_header:
                raise MissingHeader(f'previous header {hash_to_hex_str(prev_hash)} not present')
            # Handle duplicate genesis block
            if self.hashes:
                chain, _ = hashes[hdr_hash]
                return chain
            chain = Chain(None, height)
        elif tips[chain] != prev_hash:
            # Silently ignore duplicate headers
            duplicate, _ = hashes.get(hdr_hash, (None, -1))
            if duplicate:
                return duplicate
            # Form a new chain
            chain = Chain(chain, height)

        if check_work:
            header = deserialized_header(raw_header, height)
            network = self.network
            # Testnet uses the timestamp; mainnet does not.
            required_bits = network.required_bits(network, chain, height, header.timestamp)
            if header.bits != required_bits:
                raise IncorrectBits(header, required_bits)
            if header.hash_value() > header.target():
                raise InsufficientPoW(header)

        chain.append(raw_header)
        hashes[hdr_hash] = (chain, height)
        tips[chain] = hdr_hash
        return chain

    def required_bits(self, chain, height, timestamp=None):
        # Testnet uses the timestamp; mainnet does not.
        return self.network.required_bits(self.network, chain, height, timestamp)

    def __len__(self):
        '''The number of headers stored.'''
        return len(self.hashes)

    def chains(self):
        '''Return an iterable of chains in arbitrary order.'''
        return self.tips.keys()

    def chain_count(self):
        '''The number of chains.'''
        return len(self.tips)

    def longest_chain(self):
        '''The longest chain by proof-of-work.'''
        longest = None
        for chain in self.tips:
            if longest is None or chain.chainwork > longest.chainwork:
                longest = chain
        return longest

    def block_locator(self):
        '''Return a block locator for the longest chain.'''
        return self.longest_chain().block_locator()

    #
    # Persistence
    #

    # Example of intended use (supposing headers are persisted to a file):
    #
    #  # Initially read in headers and record persisted state in a cursor
    #  with open(file_name, 'rb') as f:
    #      raw_headers = f.read()
    #  headers = Headers(network)
    #  cursor = headers.connect_many(raw_headers)
    #
    #  After headers are connect()-ed when provided by a source, persist them:
    #
    #  # Open file for appending
    #  with open(file_name, 'ab') as f:
    #      f.write(headers.unpersisted_headers(cursor))
    #  # Update cursor
    #  cursor = headers.cursor()

    def connect_many(self, raw_headers, check_work=False):

        '''Connect many headers.  Return a cursor.'''
        connect = self.connect
        for raw_header in chunks(raw_headers, 80):
            connect(raw_header, check_work)
        return self.cursor()

    def cursor(self):
        '''A cursor which contains all chains and their heights.'''
        return {chain: chain.height for chain in self.tips}

    def unpersisted_headers(self, cursor):
        '''Return a concatenation of all headers added since the cursor.'''
        return b''.join(
            chain.unpersisted_headers(cursor.get(chain, chain.first_height - 1))
            for chain in sorted(self.chains())
        )


##########
#
#  Specifics of Bitcoin mainnet and its test networks
#
##########


class Network:

    def __init__(self, *, name, full_name, magic_hex, genesis_header_hex, required_bits,
                 default_port, seeds,
                 BIP65_height, BIP66_height, CSV_height, UAHF_height, DAA_height,
                 genesis_height, P2PKH_verbyte, P2SH_verbyte, WIF_byte,
                 xpub_verbytes_hex, xprv_verbytes_hex, cashaddr_prefix):
        self.name = name
        self.full_name = full_name
        self.magic = bytes.fromhex(magic_hex)
        self.genesis_header = bytes.fromhex(genesis_header_hex)
        assert len(self.genesis_header) == 80
        self.genesis_bits = header_bits(self.genesis_header)
        self.max_target = bits_to_target(self.genesis_bits)
        # Signature:  def required_bits(self, headers, chain, height, timestamp=None)
        self.required_bits = required_bits
        self.default_port = default_port
        self.seeds = seeds
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


def _required_bits_fortnightly(network, chain, height):
    '''Bitcoin's original DAA.'''
    if height == 0:
        return network.genesis_bits
    prev = chain.header_at_height(height - 1)
    if height % 2016:
        return prev.bits
    prior = chain.header_at_height(height - 2016)

    # Off-by-one with prev.timestamp.  Constrain the actual time.
    period = prev.timestamp - prior.timestamp
    target_period = 2016 * 600
    adj_period = min(max(period, target_period // 4), target_period * 4)

    prior_target = bits_to_target(prev.bits)
    new_target = (prior_target * adj_period) // target_period
    return target_to_bits(min(new_target, network.max_target))


def _required_bits_DAA(network, chain, height):
    '''BCH's shoddy difficulty adjustment algorithm.  He was warned, he shrugged.'''
    def median_prior_header(ref_height):
        '''Select the median of the 3 prior headers, for a curious definition of median.'''
        def maybe_swap(m, n):
            if prev3[m].timestamp > prev3[n].timestamp:
                prev3[m], prev3[n] = prev3[n], prev3[m]

        nonlocal header_at_height
        prev3 = [header_at_height(h) for h in range(ref_height - 3, ref_height)]
        maybe_swap(0, 2)
        maybe_swap(0, 1)
        maybe_swap(1, 2)
        return prev3[1]

    header_at_height = chain.header_at_height
    start = median_prior_header(height - 144)
    end = median_prior_header(height)

    period_work = chain.chainwork_range(start.height + 1, end.height + 1)
    period_time = min(max(end.timestamp - start.timestamp, 43200), 172800)

    Wn = (period_work * 600) // period_time
    new_target = (1 << 256) // Wn - 1
    return target_to_bits(min(new_target, network.max_target))


def _required_bits_EDA(network, chain, height):
    '''The less said the better.'''
    bits = _required_bits_fortnightly(network, chain, height)
    if height % 2016 == 0:
        return bits

    mtp_diff = (chain.median_time_past(height - 1) - chain.median_time_past(height - 7))
    if mtp_diff < 12 * 3600:
        return bits

    # Increase target by 25% (reducing difficulty by 20%).
    new_target = bits_to_target(bits)
    new_target += new_target >> 2
    return target_to_bits(min(new_target, network.max_target))


def required_bits_mainnet(network, chain, height, _timestamp=None):
    # Unlike testnet, required_bits is not a function of the timestamp
    if height < 478558:
        return _required_bits_fortnightly(network, chain, height)
    elif height <= 504031:
        return _required_bits_EDA(network, chain, height)
    else:
        return _required_bits_DAA(network, chain, height)


def _required_bits_testnet(network, chain, height, timestamp, daa_height, has_daa_minpow):
    def prior_non_special_bits():
        genesis_bits = network.genesis_bits
        raw_header = chain.raw_header_at_height
        for test_height in range(height - 1, -1, -1):
            bits = header_bits(raw_header(test_height))
            if test_height % 2016 == 0 or bits != genesis_bits:
                return bits
        # impossible to fall through here

    if height == 0:
        return network.genesis_bits

    prior_raw_header = chain.raw_header_at_height(height - 1)
    prior_timestamp = header_timestamp(prior_raw_header)
    is_slow = (timestamp - prior_timestamp) > 20 * 60

    if height <= daa_height:
        # Note: testnet did not use the EDA
        if height % 2016 == 0:
            return _required_bits_fortnightly(network, chain, height)
        if is_slow:
            return network.genesis_bits
        return prior_non_special_bits()
    else:
        if has_daa_minpow and is_slow:
            return network.genesis_bits
        return _required_bits_DAA(network, chain, height)


def required_bits_testnet(network, chain, height, timestamp):
    return _required_bits_testnet(network, chain, height, timestamp, 1188697, True)


def required_bits_scaling_testnet(network, chain, height, timestamp):
    # The `fPowAllowMinDifficultyBlocks` setting is disabled on STN, so we no longer
    # check it and adjust min pow after the DAA height.
    return _required_bits_testnet(network, chain, height, timestamp, 2200, False)


def required_bits_regtest(network, _chain, _height, _timestamp):
    # Regtest has no retargeting.
    return network.genesis_bits


Bitcoin = Network(
    name='mainnet',
    full_name='Bitcoin mainnet',
    magic_hex='e3e1f3e8',
    genesis_header_hex='01000000000000000000000000000000000000000000000000000000000000000000000'
    '03ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c',
    required_bits=required_bits_mainnet,
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
    required_bits=required_bits_scaling_testnet,
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
    required_bits=required_bits_testnet,
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
    required_bits=required_bits_regtest,
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


all_networks = (Bitcoin, BitcoinTestnet, BitcoinScalingTestnet, BitcoinRegtest)
networks_by_name = {network.name: network for network in all_networks}
