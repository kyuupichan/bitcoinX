# Copyright (c) 2024 Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.


from dataclasses import dataclass
import logging

import asqlite3

from .base58 import base58_encode_check
from .errors import InsufficientPoW, IncorrectBits, MissingHeader
from .hashes import hash_to_hex_str, hash_to_value, double_sha256 as header_hash
from .misc import le_bytes_to_int, int_to_le_bytes, cachedproperty
from .packing import pack_byte, pack_header, unpack_le_uint32, unpack_le_int32
from .work import bits_to_target, target_to_bits, bits_to_work


__all__ = (
    'Chain', 'Header', 'Headers', 'SimpleHeader', 'bits_to_difficulty', 'header_hash',
    # Networks
    'Bitcoin', 'BitcoinTestnet', 'BitcoinScalingTestnet', 'BitcoinRegtest',
    'Network', 'all_networks', 'networks_by_name',
)


def blob_literal(raw):
    return f"x'{raw.hex()}'"


def bits_to_difficulty(bits):
    return Bitcoin.max_target / bits_to_target(bits)


@dataclass
class SimpleHeader:
    '''A trivial wrapper of a raw header.'''
    raw: bytes

    def __hash__(self):
        return le_bytes_to_int(self.hash[:4])

    @property
    def version(self):
        result, = unpack_le_int32(self.raw[:4])
        return result

    @property
    def prev_hash(self):
        return self.raw[4:36]

    @property
    def merkle_root(self):
        return self.raw[36:68]

    @property
    def timestamp(self):
        result, = unpack_le_uint32(self.raw[68:72])
        return result

    @property
    def bits(self):
        result, = unpack_le_uint32(self.raw[72:76])
        return result

    @property
    def nonce(self):
        result, = unpack_le_uint32(self.raw[76:80])
        return result

    @cachedproperty
    def hash(self):
        return header_hash(self.raw)

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

    @staticmethod
    def are_headers_chained(headers):
        prev_hash = None
        for header in headers:
            if header.prev_hash != prev_hash and prev_hash is not None:
                return False
            prev_hash = header.hash
        return True


@dataclass
class Header(SimpleHeader):
    '''SimpleHeader with extra metadata from the database.'''
    height: int
    chain_id: int
    le_work: bytes

    def __eq__(self, other):
        return isinstance(other, (Header, SimpleHeader)) and self.hash == other.hash

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

    CREATE_HEADERS_TABLE = '''
      CREATE TABLE $S.Headers (
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
      );'''
    CREATE_HEIGHT_INDEX = '''
      CREATE INDEX $S.HeightIdx on Headers(height);'''
    CREATE_HEADERS_VIEW = '''
      CREATE VIEW $S.HeadersView(hdr_id, height, chain_id, chain_work, hash, version,
                                       prev_hash, merkle_root, timestamp, bits, nonce)
        AS SELECT hdr_id, height, chain_id, chain_work, hash, version, iif(
          prev_hdr_id ISNULL,
          zeroblob(32),
          (SELECT hash from Headers where hdr_id=H.prev_hdr_id)
        ), merkle_root, timestamp, bits, nonce
        FROM Headers H;'''
    CREATE_CHAINS_TABLE = '''
      CREATE TABLE $S.Chains (
        chain_id         INTEGER PRIMARY KEY,
        parent_chain_id  INTEGER REFERENCES Chains(chain_id),
        base_hdr_id      INTEGER NOT NULL,
        tip_hdr_id       INTEGER NOT NULL
      );'''
    CREATE_CHAINS_VIEW = '''
      CREATE VIEW $S.ChainsView(chain_id, parent_chain_id, base_hdr_id,
                                      tip_hdr_id, base_height, tip_height)
        AS SELECT chain_id, parent_chain_id, base_hdr_id, tip_hdr_id,
            (SELECT height from Headers WHERE hdr_id=base_hdr_id),
            (SELECT height from Headers WHERE hdr_id=tip_hdr_id)
          FROM Chains;'''
    CREATE_ANCESTORS_VIEW = '''
      CREATE VIEW $S.AncestorsView(chain_id, anc_chain_id, branch_height)
        AS WITH RECURSIVE
          Ancestors(chain_id, anc_chain_id, branch_height) AS (
            SELECT chain_id, chain_id, tip_height FROM ChainsView
            UNION ALL
            SELECT A.chain_id, CV.parent_chain_id, CV.base_height - 1
              FROM ChainsView CV, Ancestors A
              WHERE CV.chain_id=A.anc_chain_id AND CV.parent_chain_id NOT NULL
          )
        SELECT chain_id, anc_chain_id, branch_height from Ancestors;'''
    CREATE_HEADERS_TRIGGER = '''
      CREATE TRIGGER $S.UpdateChains AFTER INSERT ON Headers
      FOR EACH ROW
        BEGIN
          -- Insert new chain if one is formed
          INSERT INTO Chains(chain_id, parent_chain_id, base_hdr_id, tip_hdr_id)
            SELECT new.chain_id, (SELECT chain_id FROM Headers
                                  WHERE hdr_id=new.prev_hdr_id), new.hdr_id, new.hdr_id
            WHERE NOT EXISTS(SELECT 1 FROM Chains WHERE chain_id=new.chain_id);

          -- Set new chain tip
          UPDATE Chains SET tip_hdr_id=new.hdr_id WHERE chain_id=new.chain_id;
        END;'''
    INSERT_GENESIS = '''
      INSERT INTO $S.Headers(prev_hdr_id, height, chain_id, chain_work, hash,
                                   merkle_root, version, timestamp, bits, nonce)
        VALUES (NULL, 0, 1, ?, ?, ?, ?, ?, ?, ?);'''

    def __init__(self, conn, schema, network):
        self.conn = conn
        self.schema = schema
        self.network = network
        self.genesis_header = None    # An instance of Header

    def fixup_sql(self, sql):
        return sql.replace('$S', self.schema)

    async def initialize(self):
        '''If the database is new, create the tables and views needed, and insert the genesis
        block.  On return
        '''
        try:
            self.genesis_header = await self.header_from_hash(self.network.genesis_header.hash)
            logging.info('database tables found')
            return
        except asqlite3.OperationalError:
            pass

        gh = self.network.genesis_header

        # Create the tables and insert the genesis header
        async with self.conn:
            for sql in (self.CREATE_HEADERS_TABLE, self.CREATE_HEIGHT_INDEX,
                        self.CREATE_HEADERS_VIEW, self.CREATE_CHAINS_TABLE,
                        # A view that adds base_height and tip_height, and one to easily
                        # obtain ancestor chains
                        self.CREATE_CHAINS_VIEW, self.CREATE_ANCESTORS_VIEW,
                        self.CREATE_HEADERS_TRIGGER):
                await self.conn.execute(self.fixup_sql(sql))
            logging.info('database tables and views created')

            await self.conn.execute(self.fixup_sql(self.INSERT_GENESIS),
                                    (int_to_le_bytes(gh.work()), gh.hash, gh.merkle_root,
                                     gh.version, gh.timestamp, gh.bits, gh.nonce))
            logging.info('{self.network} genesis header {gh.hex_str()} inserted')

        self.genesis_header = await self.header_from_hash(gh.hash)

    async def insert_headers(self, simple_headers, *, check_work=True):
        '''Insert headers into the Headers table.

        simple_headers is a sequence of SimpleHeader objects.  Proof of work is checked
        if check_work is True.
        '''
        prev_header_sql = self.fixup_sql(
            'SELECT hdr_id, chain_id, height, chain_work FROM $S.Headers WHERE hash=?')
        # Use a new chain ID if another header with the same prev_hdr_id exists
        calc_chain_id = '''
          iif(
            EXISTS(SELECT 1 FROM $S.Headers WHERE height=H.height + 1
                                                         AND prev_hdr_id=H.hdr_id),
            (SELECT 1 + max(chain_id) FROM $S.Chains),
            chain_id)'''
        insert_header_sql = self.fixup_sql(f'''
          INSERT OR IGNORE INTO $S.Headers(prev_hdr_id, height, chain_id,
                chain_work, hash, merkle_root, version, timestamp, bits, nonce)
            SELECT ?, height + 1, {calc_chain_id}, ?, ?, ?, ?, ?, ?, ?
                FROM $S.Headers H WHERE hash=?''')

        execute = self.conn.execute
        required_bits = self.network.required_bits
        for header in simple_headers:
            cursor = await execute(prev_header_sql, (header.prev_hash, ))
            row = await cursor.fetchone()
            if not row:
                if header.hash == self.genesis_header.hash:
                    continue
                raise MissingHeader(f'no header with hash {hash_to_hex_str(header.prev_hash)}')
            prev_hdr_id, chain_id, height, chain_work = row

            if check_work:
                header.height = height + 1
                header.chain_id = chain_id
                bits = await required_bits(self, header)
                if header.bits != bits:
                    raise IncorrectBits(header, bits)
                if header.hash_value() > header.target():
                    raise InsufficientPoW(header)

            chain_work = int_to_le_bytes(le_bytes_to_int(chain_work) + bits_to_work(header.bits))
            await execute(insert_header_sql,
                          (prev_hdr_id, chain_work, header.hash, header.merkle_root,
                           header.version, header.timestamp, header.bits, header.nonce,
                           header.prev_hash))

    async def _query_headers(self, where_clause, params, is_multi):
        sql = f'''SELECT version, prev_hash, merkle_root, timestamp, bits, nonce, height,
                  chain_id, chain_work FROM $S.HeadersView WHERE {where_clause};'''
        cursor = await self.conn.execute(self.fixup_sql(sql), params)

        def row_to_header(row):
            return Header(pack_header(*row[:6]), *row[6:])

        if is_multi:
            return [row_to_header(row) async for row in cursor]

        async for row in cursor:
            return row_to_header(row)
        return None

    async def header_from_hash(self, block_hash):
        '''Look up the block hash and return the block header.'''
        return await self._query_headers('hash=?', (block_hash, ), False)

    async def header_from_merkle_root(self, merkle_root):
        '''Look up the merkle root and return the block header.'''
        return await self._query_headers('merkle_root=?', (merkle_root, ), False)

    async def _chains(self, tip_hdr_id_query, params=()):
        tips = await self._query_headers(f'hdr_id IN ({tip_hdr_id_query})', params, True)
        return [Chain(tip.chain_id, tip) for tip in tips]

    async def chains(self, block_hash=None):
        '''Return all chains containing the given block.  All chains if block_hash is None.'''
        block_hash = block_hash or self.genesis_header.hash
        return await self._chains('''
           SELECT tip_hdr_id
             FROM $S.AncestorsView AV, $S.Headers H, $S.Chains C
               WHERE H.hash=? AND H.chain_id=AV.anc_chain_id AND AV.chain_id=C.chain_id
                 AND AV.branch_height >= H.height''', (block_hash, ))

    async def longest_chain(self, block_hash=None):
        '''Return the longest chain containing the given header.'''
        chains = await self.chains(block_hash)
        if not chains:
            raise MissingHeader('no chains contain the header')
        longest, max_work = None, -1
        for chain in chains:
            chain_work = chain.chain_work()
            if chain_work > max_work:
                longest, max_work = chain, chain_work
        return longest

    async def _header_at_height(self, chain_id, height):
        where_clause = f'''height={height} AND chain_id=(
            SELECT chain_id FROM (
                SELECT ChainsView.chain_id, ChainsView.base_height
                  FROM $S.ChainsView, $S.AncestorsView
                  WHERE ChainsView.chain_id=AncestorsView.anc_chain_id
                    AND {height} BETWEEN base_height AND tip_height
                    AND AncestorsView.chain_id={chain_id}
             ) ORDER BY base_height DESC LIMIT 1)'''
        return await self._query_headers(where_clause, (), False)

    async def header_at_height(self, chain, height):
        '''Return the header on chain at height, or None.'''
        return await self._header_at_height(chain.chain_id, height)

    async def median_time_past(self, prev_hash):
        '''Return the MTP of a header that would be chained onto a header with hash prev_hash.
        MTP is the median of the timestamps of the 11 blocks up to and including prev_hash.
        '''
        cursor = await self.conn.execute(self.fixup_sql(f'''
          WITH RECURSIVE HdrIds(hdr_id) AS (
            SELECT hdr_id FROM $S.Headers WHERE hash={blob_literal(prev_hash)}
            UNION ALL
            SELECT prev_hdr_id FROM $S.Headers, HdrIds where Headers.hdr_id=HdrIds.hdr_id LIMIT 11
          )
          SELECT timestamp FROM $S.Headers WHERE hdr_id IN HdrIds
        '''))

        timestamps = [row[0] async for row in cursor]
        if not timestamps:
            raise MissingHeader(f'no header with hash {hash_to_hex_str(prev_hash)} found')

        return sorted(timestamps)[len(timestamps) // 2]


##########
#
#  Specifics of Bitcoin mainnet and its test networks
#
##########


class Network:

    def __init__(self, *, name, full_name, magic_hex, genesis_header_hex, required_bits,
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

        # Signature: async def required_bits(headers, header):
        self.required_bits = required_bits
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


async def required_bits_mainnet(headers, header):
    # Unlike testnet, required_bits is not a function of the timestamp
    if header.height < 478558:
        return await _required_bits_fortnightly(headers, header)
    elif header.height <= 504031:
        return await _required_bits_EDA(headers, header)
    else:
        return await _required_bits_DAA(headers, header)


async def _required_bits_fortnightly(headers, header):
    '''Bitcoin's original DAA.'''
    if header.height == 0:
        return headers.genesis_header.bits

    prev = await headers._header_at_height(header.chain_id, header.height - 1)
    if header.height % 2016:
        return prev.bits
    prior = await headers._header_at_height(header.chain_id, header.height - 2016)

    # Off-by-one with prev.timestamp.  Constrain the actual time.
    period = prev.timestamp - prior.timestamp
    target_period = 2016 * 600
    adj_period = min(max(period, target_period // 4), target_period * 4)

    prior_target = bits_to_target(prev.bits)
    new_target = (prior_target * adj_period) // target_period
    return target_to_bits(min(new_target, headers.network.max_target))


async def _required_bits_EDA(headers, header):
    '''The less said the better.'''
    bits = await _required_bits_fortnightly(headers, header)
    if header.height % 2016 == 0:
        return bits

    earlier = await headers._header_at_height(header.chain_id, header.height - 7)
    mtp_diff = (await headers.median_time_past(header.prev_hash)
                - await headers.median_time_past(earlier.hash))
    if mtp_diff < 12 * 3600:
        return bits

    # Increase target by 25% (reducing difficulty by 20%).
    new_target = bits_to_target(bits)
    new_target += new_target >> 2
    return target_to_bits(min(new_target, headers.network.max_target))


async def _required_bits_DAA(headers, header):
    '''BCH's shoddy difficulty adjustment algorithm.  He was warned, he shrugged.'''
    async def median_prior_header(chain_id, ref_height):
        '''Select the median of the 3 prior headers, for a curious definition of median.'''
        def maybe_swap(m, n):
            if prev3[m].timestamp > prev3[n].timestamp:
                prev3[m], prev3[n] = prev3[n], prev3[m]

        prev3 = [await headers._header_at_height(chain_id, height)
                 for height in range(ref_height - 3, ref_height)]
        maybe_swap(0, 2)
        maybe_swap(0, 1)
        maybe_swap(1, 2)
        return prev3[1]

    start = await median_prior_header(header.chain_id, header.height - 144)
    end = await median_prior_header(header.chain_id, header.height)

    period_work = end.chain_work() - start.chain_work()
    period_time = min(max(end.timestamp - start.timestamp, 43200), 172800)

    Wn = (period_work * 600) // period_time
    new_target = (1 << 256) // Wn - 1
    return target_to_bits(min(new_target, headers.network.max_target))


async def _required_bits_testnet(headers, header):
    async def prior_non_special_bits(genesis_bits):
        for test_height in range(header.height - 1, -1, -1):
            bits = (await headers._header_at_height(header.chain_id, test_height)).bits
            if test_height % 2016 == 0 or bits != genesis_bits:
                return bits
        # impossible to fall through here

    if header.height == 0:
        return headers.genesis_header.bits

    prior = await headers._header_at_height(header.chain_id, header.height - 1)
    is_slow = (header.timestamp - prior.timestamp) > 20 * 60

    if header.height <= headers.network.DAA_height:
        # Note: testnet did not use the EDA
        if header.height % 2016 == 0:
            return await _required_bits_fortnightly(headers, header)
        if is_slow:
            return headers.genesis_header.bits
        return await prior_non_special_bits(headers.genesis_header.bits)
    else:
        has_DAA_minpow = headers.network is BitcoinTestnet
        if is_slow and has_DAA_minpow:
            return headers.genesis_header.bits
        return await _required_bits_DAA(headers, header)


async def required_bits_testnet(headers, header):
    return await _required_bits_testnet(headers, header)


async def required_bits_STN(headers, header):
    # The `fPowAllowMinDifficultyBlocks` setting is disabled on STN, so we no longer
    # check it and adjust min pow after the DAA height.
    return await _required_bits_testnet(headers, header)


async def required_bits_regtest(headers, _header):
    # Regtest has no retargeting.
    return headers.genesis_header.bits


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
    required_bits=required_bits_STN,
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
