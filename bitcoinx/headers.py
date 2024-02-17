# Copyright (c) 2024 Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.


from dataclasses import dataclass
import math
import sqlite3

from .base58 import base58_encode_check
from .errors import InsufficientPoW, IncorrectBits, MissingHeader
from .hashes import hash_to_hex_str, hash_to_value, double_sha256 as header_hash
from .misc import chunks, le_bytes_to_int, int_to_le_bytes
from .packing import pack_byte, pack_header, unpack_header, unpack_le_uint32
from .work import bits_to_target, target_to_bits, bits_to_work


__all__ = (
    'Chain', 'Header', 'Headers', 'SimpleHeader',
    'bits_to_difficulty', 'deserialized_header', 'header_bits', 'header_hash',
    'header_prev_hash', 'header_timestamp', 'header_work', 'log2_work',
    # Networks
    'Bitcoin', 'BitcoinTestnet', 'BitcoinScalingTestnet', 'BitcoinRegtest',
    'Network', 'all_networks', 'networks_by_name',
)


def blob_literal(raw):
    return f"x'{raw.hex()}'"

#
# Raw header operations
#


def bits_to_difficulty(bits):
    return Bitcoin.max_target / bits_to_target(bits)


def deserialized_header(raw, height):
    '''Returns a deserialized header object.'''
    return Header(*unpack_header(raw), header_hash(raw), raw, height)


def header_bits(raw_header):
    bits, = unpack_le_uint32(raw_header[72:76])
    return bits


def header_prev_hash(raw_header):
    return raw_header[4:36]


def header_timestamp(raw_header):
    timestamp, = unpack_le_uint32(raw_header[68:72])
    return timestamp


def header_work(raw_header):
    return bits_to_work(header_bits(raw_header))


def log2_work(work):
    return math.log(work, 2)


@dataclass
class SimpleHeader:
    '''Standard header information, along with its hash.'''
    version: int
    prev_hash: bytes
    merkle_root: bytes
    timestamp: int
    bits: int
    nonce: int
    hash: bytes

    def __hash__(self):
        return le_bytes_to_int(self.hash[:4])

    def to_bytes(self):
        return pack_header(self.version, self.prev_hash, self.merkle_root,
                           self.timestamp, self.bits, self.nonce)

    @classmethod
    def from_bytes(cls, raw):
        return cls(*unpack_header(raw), header_hash(raw))

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
        hths = hash_to_hex_str
        return (f'SimpleHeader(version=0x{self.version:x}, prev_hash={hths(self.prev_hash)}, '
                f'merkle_root={hths(self.merkle_root)}, timestamp={self.timestamp}, '
                f'bits=0x{self.bits}, nonce={self.nonce}, hash={hths(self.hash)})')


@dataclass
class Header(SimpleHeader):
    '''SimpleHeader with extra metadata from the database.'''
    height: int
    chain_id: int
    le_work: bytes

    def __hash__(self):
        return le_bytes_to_int(self.hash[1:5])

    def chain_work(self):
        return le_bytes_to_int(self.le_work)

    def __str__(self):
        hths = hash_to_hex_str
        return (f'Header(version=0x{self.version:x}, prev_hash={hths(self.prev_hash)}, '
                f'merkle_root={hths(self.merkle_root)}, timestamp={self.timestamp}, '
                f'bits=0x{self.bits}, nonce={self.nonce}, hash={hths(self.hash)}, '
                f'height={self.height} chain_work={self.chain_work():x})')


@dataclass
class Chain:
    '''A header chain and its tip.'''
    chain_id: int
    tip: Header

    def chain_work(self):
        return self.tip.chain_work()

    def __hash__(self):
        return self.chain_id


class Headers:

    def __init__(self, conn, schema):
        self.conn = conn
        self.schema = schema
        self.required_bits = {
            Bitcoin: self.required_bits_mainnet,
            BitcoinTestnet: self.required_bits_testnet,
            BitcoinScalingTestnet: self.required_bits_scaling_testnet,
            BitcoinRegtest: self.required_bits_regtest,
        }

    def has_tables(self):
        try:
            self.conn.execute('SELECT 1 FROM Headers')
            return True
        except sqlite3.OperationalError:
            return False

    def create_tables(self):
        '''Create the Header table for this network.'''
        with self.conn:
            self.conn.execute(f'''
              CREATE TABLE {self.schema}.Headers (
                hdr_id       INTEGER PRIMARY KEY,
                prev_hdr_id  INTEGER REFERENCES Headers(hdr_id),
                height       INTEGER NOT NULL,
                chain_id     INTEGER NOT NULL,
                chain_work   BLOB NOT NULL,
                hash         BLOB UNIQUE NOT NULL,      -- unique therefore indexed
                merkle_root  BLOB UNIQUE NOT NULL,      -- unique therefore indexed
                version      INTEGER NOT NULL,
                timestamp    INTEGER NOT NULL,
                bits         INTEGER NOT NULL,
                nonce        INTEGER NOT NULL
              );
            ''')

            self.conn.execute(f'CREATE INDEX {self.schema}.HeightIdx on Headers(height);')

            # This veiw cleans up prev_hash and merkle_root for pesky cases
            self.conn.execute(f'''
              CREATE VIEW {self.schema}.HeadersView
                  (hdr_id, prev_hash, height, chain_id, chain_work, hash, merkle_root, version,
                  timestamp, bits, nonce)
                AS SELECT hdr_id, iif(
                      prev_hdr_id ISNULL,
                      zeroblob(32),
                      (SELECT hash from Headers where hdr_id=H1.prev_hdr_id)
                    ), height, chain_id, chain_work, hash, substr(H1.merkle_root, 1, 32),
                    version, timestamp, bits, nonce
                  FROM Headers H1''')

            self.conn.execute(f'''
              CREATE TABLE {self.schema}.Chains (
                chain_id         INTEGER PRIMARY KEY,
                parent_chain_id  INTEGER REFERENCES Chains(chain_id),
                base_hdr_id      INTEGER NOT NULL,
                tip_hdr_id       INTEGER NOT NULL
              );
            ''')

            # A view that adds base_height and tip_height.
            self.conn.execute(f'''
              CREATE VIEW {self.schema}.ChainsView
                  (chain_id, parent_chain_id, base_hdr_id, tip_hdr_id, base_height, tip_height)
                AS SELECT chain_id, parent_chain_id, base_hdr_id, tip_hdr_id,
                    (SELECT height from Headers WHERE hdr_id=base_hdr_id),
                    (SELECT height from Headers WHERE hdr_id=tip_hdr_id)
                  FROM Chains;''')

            # A view to easily obtain ancestor chains
            self.conn.execute(f'''
              CREATE VIEW {self.schema}.AncestorsView(chain_id, anc_chain_id, branch_height)
                AS WITH RECURSIVE
                  Ancestors(chain_id, anc_chain_id, branch_height) AS (
                    SELECT chain_id, chain_id, tip_height FROM ChainsView
                    UNION ALL
                    SELECT A.chain_id, CV.parent_chain_id, CV.base_height - 1
                      FROM ChainsView CV, Ancestors A
                      WHERE CV.chain_id=A.anc_chain_id AND CV.parent_chain_id NOT NULL
                  )
                SELECT chain_id, anc_chain_id, branch_height from Ancestors;
            ''')

            self.conn.execute(f'''
              CREATE TRIGGER {self.schema}.update_chains AFTER INSERT ON Headers
              FOR EACH ROW
                BEGIN
                  -- Insert new chain if one is formed
                  INSERT INTO Chains(chain_id, parent_chain_id, base_hdr_id, tip_hdr_id)
                    SELECT new.chain_id, (SELECT chain_id FROM Headers
                                          WHERE hdr_id=new.prev_hdr_id), new.hdr_id, new.hdr_id
                    WHERE NOT EXISTS(SELECT 1 FROM Chains WHERE chain_id=new.chain_id);

                  -- Set new chain tip
                  UPDATE Chains SET tip_hdr_id=new.hdr_id WHERE chain_id=new.chain_id;
                END;
            ''')

    def insert_genesis_header(self, raw_header):
        gh = SimpleHeader.from_bytes(raw_header)
        if gh.prev_hash != bytes(32):
            raise ValueError('not a genesis header')

        merkle_root = gh.merkle_root
        count = self.conn.execute('SELECT count(hdr_id) from Headers WHERE merkle_root=?',
                                  (gh.merkle_root, )).fetchone()[0]
        if count:
            merkle_root += bytes(count)

        with self.conn:
            # Determine a chain ID to give the new
            chain_id = self.conn.execute('SELECT max(chain_id) + 1 FROM Chains').fetchone()[0]
            chain_id = chain_id or 1
            chain_work = int_to_le_bytes(bits_to_work(gh.bits))

            self.conn.execute('''
              INSERT INTO Headers (prev_hdr_id, height, chain_id, chain_work, hash, merkle_root,
                                   version, timestamp, bits, nonce)
                VALUES (NULL, 0, ?, ?, ?, ?, ?, ?, ?, ?);
            ''', (chain_id, chain_work, gh.hash, merkle_root, gh.version, gh.timestamp,
                  gh.bits, gh.nonce))

    def insert_headers(self, raw_headers, network):
        '''Insert headers into the Headers table.

        raw_headers can either be a sequence of raw headers, or a concatenated sequence of
        raw headers.  Proof of work is checked unless network is None.'''
        def headers(raw_headers):
            if isinstance(raw_headers, (bytes, bytearray)):
                raw_headers = chunks(raw_headers, 80)
            for raw_header in raw_headers:
                yield SimpleHeader.from_bytes(raw_header)

        # Use a new chain ID if another header with the same prev_hdr_id exists
        calc_chain_id = '''
          iif(
            EXISTS(SELECT 1 FROM Headers WHERE height=H.height + 1 AND prev_hdr_id=H.hdr_id),
            (SELECT 1 + max(chain_id) FROM Chains),
            chain_id)'''

        execute = self.conn.execute
        for header in headers(raw_headers):
            row = execute('SELECT hdr_id, chain_id, height, chain_work FROM Headers WHERE hash=?',
                          (header.prev_hash, )).fetchone()
            if not row:
                raise MissingHeader(f'no header with hash {hash_to_hex_str(header.prev_hash)}')
            prev_hdr_id, chain_id, height, chain_work = row

            if network:
                header.height = height + 1
                header.chain_id = chain_id
                bits = self.required_bits[network](header)
                if header.bits != bits:
                    raise IncorrectBits(header, bits)
                if header.hash_value() > header.target():
                    raise InsufficientPoW(header)

            chain_work = int_to_le_bytes(le_bytes_to_int(chain_work) + bits_to_work(header.bits))

            execute(f'''INSERT OR IGNORE INTO Headers(prev_hdr_id, height, chain_id, chain_work,
                hash, merkle_root, version, timestamp, bits, nonce)
              SELECT ?, height + 1, {calc_chain_id}, ?, ?, ?, ?, ?, ?, ?
                FROM Headers H WHERE hash=?''',
                    (prev_hdr_id, chain_work, header.hash, header.merkle_root, header.version,
                     header.timestamp, header.bits, header.nonce, header.prev_hash))

    def _query_headers(self, where_clause, params, is_multi):
        result = self.conn.execute(
            f'''SELECT version, prev_hash, merkle_root, timestamp, bits, nonce, hash, height,
                       chain_id, chain_work FROM HeadersView WHERE {where_clause}''',
            params).fetchall()

        if is_multi:
            return [Header(*row) for row in result]
        else:
            return Header(*(result[0])) if result else None

    def _chains(self, tip_hdr_id_query):
        tips = self._query_headers(f'hdr_id IN ({tip_hdr_id_query})', (), True)
        return [Chain(tip.chain_id, tip) for tip in tips]

    def header_from_hash(self, block_hash):
        '''Look up the block hash and return the block header.'''
        return self._query_headers('hash=?', (block_hash, ), False)

    def header_from_merkle_root(self, merkle_root):
        '''Look up the merkle root and return the block header.'''
        return self._query_headers('merkle_root=?', (merkle_root, ), False)

    def chains(self):
        '''Return all chains.'''
        return self._chains('SELECT tip_hdr_id FROM Chains')

    def chains_containing(self, header):
        '''Return all chains containing the given header.'''
        return self._chains(f'''SELECT tip_hdr_id FROM Chains C, AncestorsView AV
                                  WHERE AV.anc_chain_id={header.chain_id}
                                    AND AV.branch_height >= {header.height}
                                    AND C.chain_id=AV.chain_id''')

    def longest_chain(self, header):
        '''Return the longest chain containing the given header.'''
        chains = self.chains_containing(header)
        if not chains:
            raise MissingHeader('no chains contain the header')
        longest, max_work = None, -1
        for chain in chains:
            chain_work = chain.chain_work()
            if chain_work > max_work:
                longest, max_work = chain, chain_work
        return longest

    def _header_at_height(self, chain_id, height):
        where_clause = f'''height={height} AND chain_id=(
            SELECT chain_id FROM (
                SELECT ChainsView.chain_id, ChainsView.base_height
                  FROM ChainsView, AncestorsView
                  WHERE ChainsView.chain_id=AncestorsView.anc_chain_id
                    AND {height} BETWEEN base_height AND tip_height
                    AND AncestorsView.chain_id={chain_id}
             ) ORDER BY base_height DESC LIMIT 1)'''
        return self._query_headers(where_clause, (), False)

    def header_at_height(self, chain, height):
        '''Return the header on chain at height.'''
        if not 0 <= height <= chain.tip.height:
            raise MissingHeader(f'no header at height {height:,d}; '
                                f'chain tip height is {chain.tip.height:,d}')
        return self._header_at_height(chain.chain_id, height)

    def median_time_past(self, prev_hash):
        '''Return the MTP of a header that would be chained onto a header with hash prev_hash.
        MTP is the median of the timestamps of the 11 blocks up to and including prev_hash.
        '''
        cursor = self.conn.execute(f'''
          WITH RECURSIVE HdrIds(hdr_id) AS (
            SELECT hdr_id FROM Headers WHERE hash={blob_literal(prev_hash)}
            UNION ALL
            SELECT prev_hdr_id FROM Headers, HdrIds where Headers.hdr_id=HdrIds.hdr_id LIMIT 11
          )
          SELECT timestamp FROM Headers WHERE hdr_id IN HdrIds
        ''')

        timestamps = [row[0] for row in cursor]
        if not timestamps:
            raise MissingHeader(f'no header with hash {hash_to_hex_str(prev_hash)} found')

        return sorted(timestamps)[len(timestamps) // 2]

    def block_locator(self, chain):
        '''Returns a block locator for the chain.  A block locator is a list of block hashes
        starting from the chain tip back to the genesis block, that become increasingly
        sparse.
        '''
        def block_heights(height, stop=0, step=-1):
            while height > stop:
                yield height
                height += step
                step += step
            yield stop

        return [self.header_at_height(chain, height).hash
                for height in block_heights(chain.tip.height)]

    def required_bits_mainnet(self, header):
        # Unlike testnet, required_bits is not a function of the timestamp
        if header.height < 478558:
            return self._required_bits_fortnightly(Bitcoin, header)
        elif header.height <= 504031:
            return self._required_bits_EDA(Bitcoin, header)
        else:
            return self._required_bits_DAA(Bitcoin, header)

    def _required_bits_fortnightly(self, network, header):
        '''Bitcoin's original DAA.'''
        prev = self._header_at_height(header.chain_id, header.height - 1)
        if header.height % 2016:
            return prev.bits
        prior = self._header_at_height(header.chain_id, header.height - 2016)

        # Off-by-one with prev.timestamp.  Constrain the actual time.
        period = prev.timestamp - prior.timestamp
        target_period = 2016 * 600
        adj_period = min(max(period, target_period // 4), target_period * 4)

        prior_target = bits_to_target(prev.bits)
        new_target = (prior_target * adj_period) // target_period
        return target_to_bits(min(new_target, network.max_target))

    def _required_bits_EDA(self, network, header):
        '''The less said the better.'''
        bits = self._required_bits_fortnightly(network, header)
        if header.height % 2016 == 0:
            return bits

        prior_hash = self._header_at_height(header.chain_id, header.height - 7).hash
        mtp_diff = self.median_time_past(header.prev_hash) - self.median_time_past(prior_hash)
        if mtp_diff < 12 * 3600:
            return bits

        # Increase target by 25% (reducing difficulty by 20%).
        new_target = bits_to_target(bits)
        new_target += new_target >> 2
        return target_to_bits(min(new_target, network.max_target))

    def _required_bits_DAA(self, network, header):
        '''BCH's shoddy difficulty adjustment algorithm.  He was warned, he shrugged.'''
        def median_prior_header(chain_id, ref_height):
            '''Select the median of the 3 prior headers, for a curious definition of median.'''
            def maybe_swap(m, n):
                if prev3[m].timestamp > prev3[n].timestamp:
                    prev3[m], prev3[n] = prev3[n], prev3[m]

            prev3 = [self._header_at_height(chain_id, height)
                     for height in range(ref_height - 3, ref_height)]
            maybe_swap(0, 2)
            maybe_swap(0, 1)
            maybe_swap(1, 2)
            return prev3[1]

        start = median_prior_header(header.chain_id, header.height - 144)
        end = median_prior_header(header.chain_id, header.height)

        period_work = end.chain_work() - start.chain_work()
        period_time = min(max(end.timestamp - start.timestamp, 43200), 172800)

        Wn = (period_work * 600) // period_time
        new_target = (1 << 256) // Wn - 1
        return target_to_bits(min(new_target, network.max_target))

    def _required_bits_testnet(self, network, header, daa_height, has_daa_minpow):
        def prior_non_special_bits(genesis_bits):
            for test_height in range(header.height - 1, -1, -1):
                bits = self._header_at_height(header.chain_id, test_height).bits
                if test_height % 2016 == 0 or bits != genesis_bits:
                    return bits
            # impossible to fall through here

        prior = self._header_at_height(header.chain_id, header.height - 1)
        is_slow = (header.timestamp - prior.timestamp) > 20 * 60

        if header.height <= daa_height:
            # Note: testnet did not use the EDA
            if header.height % 2016 == 0:
                return self._required_bits_fortnightly(network, header)
            if is_slow:
                return network.genesis_bits
            return prior_non_special_bits(network.genesis_bits)
        else:
            if has_daa_minpow and is_slow:
                return network.genesis_bits
            return self._required_bits_DAA(network, header)

    def required_bits_testnet(self, network, header):
        return self._required_bits_testnet(network, header, 1188697, True)

    def required_bits_scaling_testnet(self, network, header):
        # The `fPowAllowMinDifficultyBlocks` setting is disabled on STN, so we no longer
        # check it and adjust min pow after the DAA height.
        return self._required_bits_testnet(network, header, 2200, False)

    def required_bits_regtest(self, network, _header):
        # Regtest has no retargeting.
        return network.genesis_bits


##########
#
#  Specifics of Bitcoin mainnet and its test networks
#
##########


class Network:

    def __init__(self, *, name, full_name, magic_hex, genesis_header_hex, default_port, seeds,
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

    def to_address(self, hash160):
        '''Return a P2PKH address string.'''
        return base58_encode_check(pack_byte(self.P2PKH_verbyte) + hash160)

    def to_P2SH_address(self, hash160):
        '''Return a P2SH address string.'''
        return base58_encode_check(pack_byte(self.P2SH_verbyte) + hash160)


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


all_networks = (Bitcoin, BitcoinTestnet, BitcoinScalingTestnet, BitcoinRegtest)
networks_by_name = {network.name: network for network in all_networks}
