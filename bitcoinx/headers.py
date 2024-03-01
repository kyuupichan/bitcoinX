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

    # Queries to create a new database
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
      CREATE INDEX $S.HeightIdx ON Headers(height);'''
    CREATE_HEADERS_VIEW = '''
      CREATE VIEW $S.HeadersView(hdr_id, height, chain_id, chain_work, hash, version,
                                       prev_hash, merkle_root, timestamp, bits, nonce)
        AS SELECT hdr_id, height, chain_id, chain_work, hash, version, iif(
          prev_hdr_id ISNULL,
          zeroblob(32),
          (SELECT hash FROM Headers WHERE hdr_id=H.prev_hdr_id)
        ), merkle_root, timestamp, bits, nonce
        FROM Headers H;'''
    CREATE_CHAINS_TABLE = '''
      CREATE TABLE $S.Chains (
        chain_id         INTEGER PRIMARY KEY,
        parent_chain_id  INTEGER REFERENCES Chains(chain_id),
        base_hdr_id      INTEGER NOT NULL,
        tip_hdr_id       INTEGER NOT NULL
      );'''
    CREATE_INVALID_HEADERS_TABLE = '''
      CREATE TABLE $S.InvalidHeaders(
        hdr_id INTEGER PRIMARY KEY REFERENCES Headers(hdr_id)
      );'''
    CREATE_CHAINS_VIEW = '''
      CREATE VIEW $S.ChainsView(chain_id, parent_chain_id, base_hdr_id,
                                      tip_hdr_id, base_height, tip_height)
        AS SELECT chain_id, parent_chain_id, base_hdr_id, tip_hdr_id,
            (SELECT height FROM Headers WHERE hdr_id=base_hdr_id),
            (SELECT height FROM Headers WHERE hdr_id=tip_hdr_id)
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
        SELECT chain_id, anc_chain_id, branch_height FROM Ancestors;'''
    INSERT_GENESIS = '''
      INSERT INTO $S.Headers(prev_hdr_id, height, chain_id, chain_work, hash,
                                   merkle_root, version, timestamp, bits, nonce)
        VALUES (NULL, 0, 1, ?, ?, ?, ?, ?, ?, ?);'''
    # queries for insert_chain()
    HASH_EXISTS_SQL = 'SELECT hdr_id FROM $S.Headers WHERE hash=?;'
    PREV_HEADER_SQL = '''
        SELECT hdr_id, height + 1, chain_work, chain_id,
            iif(EXISTS(SELECT 1 FROM $S.HeadersView WHERE prev_hash=?),
                (SELECT 1 + max(chain_id) FROM $S.Chains), chain_id)
          FROM $S.Headers WHERE hash=?;'''
    INSERT_HEADER_SQL = '''
          INSERT INTO $S.Headers(prev_hdr_id, height, chain_id,
                chain_work, hash, merkle_root, version, timestamp, bits, nonce)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);'''
    INSERT_CHAIN_SQL = '''
       INSERT INTO $S.Chains(chain_id, parent_chain_id, base_hdr_id, tip_hdr_id)
         VALUES (?, ?, ?, ?);'''
    UPDATE_CHAIN_TIP_SQL = 'UPDATE $S.Chains SET tip_hdr_id=? WHERE chain_id=?;'
    # other queries
    MTP_SQL = '''
      WITH RECURSIVE Timestamps(ts, hdr_id) AS (
        SELECT timestamp, prev_hdr_id FROM $S.Headers WHERE chain_id=? AND height=?
        UNION ALL
        SELECT timestamp, prev_hdr_id FROM $S.Headers, Timestamps
           WHERE Headers.hdr_id=Timestamps.hdr_id LIMIT 11
      )
      SELECT ts FROM Timestamps ORDER BY ts;'''

    def __init__(self, conn, schema, network):
        self.conn = conn
        self.schema = schema
        self.network = network
        self.logger = prefixed_logger('Headers', str(network))
        self.genesis_header = None    # An instance of Header
        self.pow_checker = PoWChecker(network)
        # Map from chain_id to a map from height to header object
        self.cache_by_chain = defaultdict(dict)
        # Map from new chain ID to (parent_chain_id, new_id_first_height) pairs
        self.chain_info = {}
        self.hash_exists_sql = self.fixup_sql(self.HASH_EXISTS_SQL)
        self.prev_header_sql = self.fixup_sql(self.PREV_HEADER_SQL)
        self.insert_header_sql = self.fixup_sql(self.INSERT_HEADER_SQL)
        self.insert_chain_sql = self.fixup_sql(self.INSERT_CHAIN_SQL)
        self.update_chain_tip_sql = self.fixup_sql(self.UPDATE_CHAIN_TIP_SQL)
        self.mtp_sql = self.fixup_sql(self.MTP_SQL)

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
        execute = self.conn.execute

        # Create the tables and insert the genesis header
        async with self.conn:
            for sql in (self.CREATE_HEADERS_TABLE, self.CREATE_HEIGHT_INDEX,
                        self.CREATE_HEADERS_VIEW, self.CREATE_CHAINS_TABLE,
                        self.CREATE_INVALID_HEADERS_TABLE,
                        # A view that adds base_height and tip_height, and one to easily
                        # obtain ancestor chains
                        self.CREATE_CHAINS_VIEW, self.CREATE_ANCESTORS_VIEW):
                await execute(self.fixup_sql(sql))

            cursor = await self.conn.execute(
                self.fixup_sql(self.INSERT_GENESIS),
                (int_to_le_bytes(gh.work()), gh.hash, gh.merkle_root,
                 gh.version, gh.timestamp, gh.bits, gh.nonce))
            await execute(self.insert_chain_sql, (1, None, cursor.lastrowid, cursor.lastrowid))

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

    async def insert_header_chain(self, headers, *, check_work=True):
        '''Insert a chain of SimpleHeader objects into the Headers table.  Headers already in the
        table they are ignored.

        If the headers do not form a chain, raise a HeadersNotSequential exception.  If
        check_work is True then check proof of work before inserting each header, and
        raise an IncorrectBits or InsufficientPoW exception on failure.  In such a case,
        any valid headers already inserted remain.

        Return a pair (inserted_count, tip).  If inserted_count is zero then tip is None,
        otherwise it is the last header in the chain.
        '''
        if not SimpleHeader.are_headers_chained(headers):
            raise HeadersNotSequential('headers do not form a chain')

        # Find the first header not in the DB; this will generally be the first one
        execute = self.conn.execute
        for n, header in enumerate(headers):
            cursor = await execute(self.hash_exists_sql, (header.hash, ))
            if not await cursor.fetchone():
                if n:
                    headers = headers[n:]
                break
        if not headers:
            return 0, None

        # If the headers connect they all have the same chain ID, which is that of the
        # prior header if it is a tip, otherwise we need a new chain ID.
        prev_hash = headers[0].prev_hash
        cursor = await execute(self.prev_header_sql, (prev_hash, prev_hash))
        result = await cursor.fetchone()
        if not result:
            raise MissingHeader(f'no header with hash {hash_to_hex_str(prev_hash)}')
        tip_hdr_id, start_height, le_work, parent_chain_id, chain_id = result

        create_new_chain = parent_chain_id != chain_id
        if create_new_chain:
            # Tell the cache about new chains so that the pow checker doesn't make us
            # query the DB for a chain ID we have not yet inserted.  It also makes header
            # lookup for new chains more efficient by deferring to the parent.
            self.chain_info[chain_id] = (parent_chain_id, start_height)

        # We have some headers.  Our guarantee is that, on return, all headers (with valid
        # pow if check_work) will be committed to the DB with a consistent cache.  If a
        # new chain is formed, it will be in the Chains table if and only if there is at
        # least one good header.
        count = 0
        cache = self.cache_by_chain[chain_id]
        await execute('BEGIN TRANSACTION')
        try:
            for height, header in enumerate(headers, start=start_height):
                le_work = int_to_le_bytes(le_bytes_to_int(le_work) + bits_to_work(header.bits))

                # Convert from SimpleHeader to a full Header as needed by PowChecker and
                # cache.  If it passes the PoW check add it to the cache
                header = Header(header.raw, height, chain_id, le_work)
                if check_work:
                    await self.pow_checker.check(self, header)

                cursor = await execute(self.insert_header_sql,
                                       (tip_hdr_id, height, chain_id, le_work, header.hash,
                                        header.merkle_root, header.version, header.timestamp,
                                        header.bits, header.nonce))
                count += 1
                cache[height] = header
                tip_hdr_id = cursor.lastrowid
                if create_new_chain:
                    await execute(self.insert_chain_sql, (chain_id, parent_chain_id, tip_hdr_id,
                                                          tip_hdr_id))
                    create_new_chain = False
        finally:
            if count:
                await execute(self.update_chain_tip_sql, (tip_hdr_id, chain_id))
            await self.conn.commit()
            if create_new_chain:
                del self.chain_info[chain_id]
            if len(cache) >= 200:
                self.shrink(cache)

        return count, header

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

    async def median_time_past(self, chain_id, height):
        '''Return the median of the timestamps of the specified header and its 10 prior headers
        (if they exist).

        If you want to find the median time past OF a given header you must pass one less
        than its height to this function.
        '''
        # Timings show that this sqlite query more than twice as fast as using the block
        # cache.  It seems to be slightly faster to take the middle entry in Python.
        cursor = await self.conn.execute(self.mtp_sql, (chain_id, height))
        timestamps = await cursor.fetchall()   # These are already sorted
        if not timestamps:
            raise MissingHeader(f'no header found at height {height:,d} on chain {chain_id}')
        mtp, = timestamps[len(timestamps) // 2]
        return mtp
