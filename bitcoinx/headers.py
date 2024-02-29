# Copyright (c) 2024 Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.


from collections import defaultdict
from dataclasses import dataclass

import asqlite3

from .errors import MissingHeader, HeadersNotSequential
from .hashes import hash_to_hex_str, hash_to_value, double_sha256 as header_hash
from .misc import le_bytes_to_int, int_to_le_bytes, cachedproperty, prefixed_logger
from .packing import pack_header, unpack_le_uint32, unpack_le_int32
from .work import bits_to_target, bits_to_work, bits_to_difficulty, PoWChecker


__all__ = (
    'Chain', 'Header', 'Headers', 'SimpleHeader', 'header_hash',
)


def blob_literal(raw):
    return f"x'{raw.hex()}'"


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
        self.logger = prefixed_logger('Headers', str(network))
        self.genesis_header = None    # An instance of Header
        self.pow_checker = PoWChecker(network)
        # Map from chain_id to a map from height to header object
        self.cache_by_chain = defaultdict(dict)
        # Map from new chain ID to (prev_chain_id, new_id_first_height) pairs
        self.chain_info = {}

    def fixup_sql(self, sql):
        return sql.replace('$S', self.schema)

    async def initialize(self):
        '''If the database is new, create the tables and views needed, and insert the genesis
        block.  On return
        '''
        try:
            self.genesis_header = await self.header_from_hash(self.network.genesis_header.hash)
            count = len(await self.chains())
            s = '' if count == 1 else 's'
            self.logger.info(f'found {count:,d} chain{s} to height {await self.height()}')
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

            await self.conn.execute(self.fixup_sql(self.INSERT_GENESIS),
                                    (int_to_le_bytes(gh.work()), gh.hash, gh.merkle_root,
                                     gh.version, gh.timestamp, gh.bits, gh.nonce))

        self.genesis_header = await self.header_from_hash(gh.hash)
        self.logger.info('database tables created')

    async def _db_header_at_height(self, chain_id, height):
        where_clause = f'''height={height} AND chain_id=(
            SELECT chain_id FROM (
                SELECT ChainsView.chain_id, ChainsView.base_height
                  FROM $S.ChainsView, $S.AncestorsView
                  WHERE ChainsView.chain_id=AncestorsView.anc_chain_id
                    AND {height} BETWEEN base_height AND tip_height
                    AND AncestorsView.chain_id={chain_id}
             ) ORDER BY base_height DESC LIMIT 1)'''
        return await self._query_headers(where_clause, (), False)

    async def header_at_height_cached(self, chain_id, height):
        '''Return the header on chain_id at height, or None.'''
        # See if an ancestor chain is more likely in the cache
        while True:
            entry = self.chain_info.get(chain_id)
            if not entry:
                break
            prior_chain_id, first_height = entry
            if height >= first_height:
                break
            chain_id = prior_chain_id

        cache = self.cache_by_chain[chain_id]
        header = cache.get(height)
        if not header:
            # Fall back to the DB
            header = await self._db_header_at_height(chain_id, height)
            if header is not None:
                cache[height] = header
        return header

    async def header_at_height(self, chain, height):
        '''Return the header on chain at height, or None.'''
        return await self.header_at_height_cached(chain.chain_id, height)

    def shrink(self, cache):
        tip_height = max(cache)
        old_height = tip_height - 150
        old_heights = [height for height in cache if height < old_height]
        fort_height = tip_height - tip_height % 2016
        try:
            old_heights.remove(fort_height)
        except ValueError:
            pass
        for height in old_heights:
            del cache[height]

    async def insert_headers(self, headers, *, check_work=True):
        '''Insert headers into the Headers table, and returns the number of new headers actually
        added.

        headers is a sequence of SimpleHeader objects which must form a chain.  Proof of
        work is checked if check_work is True.
        '''
        if not SimpleHeader.are_headers_chained(headers):
            raise HeadersNotSequential('headers do not form a chain')

        execute = self.conn.execute
        exists_sql = self.fixup_sql('SELECT hdr_id from $S.Headers WHERE hash=?;')

        # Find the first header not in the DB
        for n, header in enumerate(headers):
            cursor = await execute(exists_sql, (header.hash, ))
            if not await cursor.fetchone():
                headers = headers[n:]
                break
        if not headers:
            return 0

        # If the headers connect they all have the same chain ID, which is that of the
        # prior header if it is a tip, otherwise we need a new chain ID.
        prior_header_sql = self.fixup_sql('''SELECT hdr_id, height, chain_work, chain_id,
            iif(EXISTS(SELECT 1 FROM $S.HeadersView WHERE prev_hash=?),
                (SELECT 1 + max(chain_id) FROM $S.Chains), chain_id)
          FROM $S.Headers WHERE hash=?;''')
        cursor = await execute(prior_header_sql, (headers[0].prev_hash, headers[0].prev_hash))
        result = await cursor.fetchone()
        if not result:
            raise MissingHeader(f'no header with hash {hash_to_hex_str(header.prev_hash)}')
        prev_hdr_id, height, le_work, prev_chain_id, chain_id = result

        # Tell the cache about new chains so that the pow checker doesn't make us query
        # the DB for a chain ID we have not yet inserted...
        if prev_chain_id != chain_id:
            # first_height is the height of the first block of the new chain.
            self.chain_info[chain_id] = (prev_chain_id, height + 1)

        insert_header_sql = self.fixup_sql('''
          INSERT OR IGNORE INTO $S.Headers(prev_hdr_id, height, chain_id,
                chain_work, hash, merkle_root, version, timestamp, bits, nonce)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);''')

        try:
            cache = self.cache_by_chain[chain_id]
            for header in headers:
                height += 1
                le_work = int_to_le_bytes(le_bytes_to_int(le_work) + bits_to_work(header.bits))

                # Convert from SimpleHeader to a full Header.  The PowChecker needs a full
                # Header; for the same reason it is what goes in the cache.  If it passes
                # the PoW check, add the header to the cache
                header = Header(header.raw, height, chain_id, le_work)
                if check_work:
                    await self.pow_checker.check(self, header)
                cache[height] = header

                cursor = await execute(insert_header_sql,
                                       (prev_hdr_id, height, chain_id, le_work, header.hash,
                                        header.merkle_root, header.version, header.timestamp,
                                        header.bits, header.nonce))
                assert cursor.lastrowid != prev_hdr_id
                prev_hdr_id = cursor.lastrowid
        finally:
            if len(cache) >= 200:
                self.shrink(cache)
            await self.conn.commit()

        return len(headers)

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

    async def tip(self):
        '''Returns the tip of the longest chain.'''
        return (await self.longest_chain()).tip

    async def height(self):
        '''Returns the height of the longest chain.'''
        return (await self.tip()).height

    async def median_time_past_from_height(self, chain_id, height):
        '''Return the median of the timestamps of the (up to) 11 prior headers.'''
        timestamps = [(await self.header_at_height_cached(chain_id, height)).timestamp
                      for height in range(max(0, height - 11), height)]
        return sorted(timestamps)[len(timestamps) // 2]

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
