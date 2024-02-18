import asyncio
import dataclasses
import os
import random
import asqlite3

import pytest
from bitcoinx import (
    Bitcoin, BitcoinTestnet, header_hash, pack_header, MissingHeader, InsufficientPoW,
    bits_to_work, Headers, SimpleHeader, all_networks
)
from bitcoinx.misc import chunks

from .utils import read_file


def run_test_with_headers(test_func, network=Bitcoin):
    async def run():
        async with asqlite3.connect(':memory:') as conn:
            # Create two copies of the tables with different schemas, to ensure the code
            # always queries with the appropriate schema
            headers1 = Headers(conn, 'main', BitcoinTestnet)
            await headers1.initialize()
            await conn.execute("ATTACH ':memory:' as second")
            headers = Headers(conn, 'second', network)
            await headers.initialize()
            await test_func(headers)

    asyncio.run(run())


class TestSimpleHeader:

    def test_eq(self):
        assert (SimpleHeader.from_bytes(Bitcoin.genesis_header) !=
                SimpleHeader.from_bytes(BitcoinTestnet.genesis_header))

    def test_hash(self):
        assert len({
            SimpleHeader.from_bytes(Bitcoin.genesis_header),
            SimpleHeader.from_bytes(BitcoinTestnet.genesis_header)
        }) == 2

    @pytest.mark.parametrize('network', all_networks)
    def test_to_bytes(self, network):
        raw = SimpleHeader.from_bytes(network.genesis_header).to_bytes()
        assert raw == network.genesis_header


def same_headers(simple, detailed):
    return all(getattr(simple, field.name) == getattr(detailed, field.name)
               for field in dataclasses.fields(SimpleHeader))


def create_random_header(prev_header):
    version = random.randrange(0, 10)
    merkle_root = os.urandom(32)
    timestamp = prev_header.timestamp + random.randrange(-300, 900)
    bits = prev_header.bits
    nonce = random.randrange(0, 1 << 32)
    raw_header = pack_header(version, prev_header.hash, merkle_root, timestamp, bits, nonce)
    return SimpleHeader.from_bytes(raw_header)


def create_random_branch(prev_header, length):
    branch = []
    for _ in range(length):
        header = create_random_header(prev_header)
        branch.append(header)
        prev_header = header
    return branch


def create_random_tree(base_header, branch_count=10, max_branch_length=10):
    headers = [base_header]
    tree = []
    for _ in range(branch_count):
        branch_header = random.choice(headers)
        branch_length = random.randrange(1, max_branch_length + 1)
        branch = create_random_branch(branch_header, branch_length)
        tree.append((branch_header, branch))
        # To form a branch, a branch must be based on other than a tip
        headers.extend(branch[:-1])

    return tree


async def insert_tree(headers, tree):
    for _, branch in tree:
        await headers.insert_headers(b''.join(header.to_bytes() for header in branch),
                                     check_work=False)


COLNAMES = ('prev_hdr_id', 'height', 'chain_id', 'chain_work', 'hash', 'merkle_root', 'version',
            'timestamp', 'bits', 'nonce')


class TestHeaders:

    COMMON_KEYS = ('hash', 'merkle_root', 'version', 'timestamp', 'bits', 'nonce')

    def test_headers(self):
        async def test(headers):
            assert not headers.conn.in_transaction

        run_test_with_headers(test, Bitcoin)

    @pytest.mark.parametrize('network', all_networks)
    def test_genesis_header(self, network):
        async def test(headers):
            header = SimpleHeader.from_bytes(network.genesis_header)
            header2 = await headers.header_from_hash(header.hash)
            assert same_headers(header, header2)

        run_test_with_headers(test, network)

    @pytest.mark.parametrize('network', all_networks)
    def test_genesis_merkle_root(self, network):
        async def test(headers):
            # Only test for Bitcoin, as Testnet genesis merkle root is identical
            header = SimpleHeader.from_bytes(network.genesis_header)
            header2 = await headers.header_from_merkle_root(header.merkle_root)
            assert same_headers(header, header2)

        run_test_with_headers(test, network)

    @pytest.mark.parametrize('network', all_networks)
    def test_genesis_chains(self, network):
        async def test(headers):
            cursor = await headers.conn.cursor()
            cursor.row_factory = asqlite3.Row
            await cursor.execute('SELECT * FROM Chains')
            row = await cursor.fetchone()
            assert row['parent_chain_id'] is None
            assert row['base_hdr_id'] == row['tip_hdr_id']
            assert row['base_hdr_id'] == 1
            assert await cursor.fetchone() is None

            genesis = await headers.header_from_hash(network.genesis_hash)
            chains = await headers.chains()
            assert len(chains) == 1
            chain = chains[0]
            assert chain.tip == genesis == await headers.header_at_height(chain, 0)

        run_test_with_headers(test, network)

    @pytest.mark.parametrize('colname', ('hash', 'merkle_root'))
    def test_unique_columns(self, colname):
        async def test(headers):
            header = SimpleHeader.from_bytes(Bitcoin.genesis_header)
            blob_literal = f"x'{getattr(header, colname).hex()}'"
            columns, values = self.columns_and_values(colname, blob_literal)
            with pytest.raises(asqlite3.IntegrityError) as e:
                await headers.conn.execute(headers.fixup_sql(
                    f'INSERT INTO $S.Headers({columns}) VALUES ({values});'))
            assert f'UNIQUE constraint failed: Headers.{colname}' == str(e.value)

        run_test_with_headers(test)

    @staticmethod
    def columns_and_values(colname, value):
        columns = ', '.join(COLNAMES)
        values = [0] * len(COLNAMES)
        if colname:
            values[COLNAMES.index(colname)] = value
        values = ', '.join(str(value) for value in values)
        return columns, values

    @pytest.mark.parametrize('colname', COLNAMES[1:])
    def test_null_insertions(self, colname):
        async def test(headers):
            columns, values = self.columns_and_values(colname, 'NULL')
            with pytest.raises(asqlite3.IntegrityError) as e:
                await headers.conn.execute(f'INSERT INTO Headers({columns}) VALUES ({values});')
            assert 'NOT NULL constraint failed' in str(e.value)

        run_test_with_headers(test)

    # Tests that test_null_insertions() logic works
    def test_no_null_insertions(self):
        async def test(headers):
            columns, values = self.columns_and_values(None, None)
            await headers.conn.execute(f'INSERT INTO Headers({columns}) VALUES ({values});')

        run_test_with_headers(test)

    @staticmethod
    async def insert_first_headers(headers, count):
        raw_headers = read_file('mainnet-headers-2016.raw', count * 80)[80:]
        await headers.insert_headers(raw_headers)
        return raw_headers

    def test_insert_headers(self):
        async def test(headers):
            assert not headers.conn.in_transaction
            raw_headers = await self.insert_first_headers(headers, 10)
            cursor = await headers.conn.cursor()
            cursor.row_factory = asqlite3.Row
            await cursor.execute('SELECT * from Headers WHERE height ORDER BY height')
            result = await cursor.fetchall()
            for row, (height, raw_header) in zip(result,
                                                 enumerate(chunks(raw_headers, 80), start=1)):
                header = SimpleHeader.from_bytes(raw_header)
                for attrib in self.COMMON_KEYS:
                    assert row[attrib] == getattr(header, attrib)
                assert row['height'] == height

            chains = await headers.chains()
            assert len(chains) == 1
            chain = chains[0]
            assert chain.tip.hash == header_hash(raw_headers[-80:])

        network = Bitcoin
        run_test_with_headers(test, network)

    def test_insert_headers_bad(self):
        async def test(headers):
            genesis_header = await headers.header_from_hash(Bitcoin.genesis_hash)
            branch = create_random_branch(genesis_header, 4)
            raw_headers = [bytearray(header.to_bytes()) for header in branch]
            # muck up prev_hash
            raw_headers[2][7] ^= 1
            with pytest.raises(MissingHeader):
                await headers.insert_headers(raw_headers, check_work=False)

        run_test_with_headers(test)

    def test_insert_existing_headers(self):
        async def test(headers):
            genesis_header = await headers.header_from_hash(Bitcoin.genesis_hash)
            N = 5
            branch = create_random_branch(genesis_header, N)
            await headers.insert_headers([header.to_bytes() for header in branch[:N - 1]],
                                         check_work=False)
            chain = await headers.longest_chain()
            assert chain.tip.height == 4
            await headers.insert_headers([header.to_bytes() for header in branch],
                                         check_work=False)
            assert chain.tip.height == 4

        run_test_with_headers(test)

    def test_header_from_hash(self):
        async def test(headers):
            raw_headers = await self.insert_first_headers(headers, 10)
            for raw_header in chunks(raw_headers, 80):
                header = SimpleHeader.from_bytes(raw_header)
                header2 = await headers.header_from_hash(header.hash)
                assert same_headers(header, header2)

        run_test_with_headers(test)

    def test_header_from_hash_fail(self):
        async def test(headers):
            assert await headers.header_from_hash(b'a' * 32) is None

        run_test_with_headers(test)

    def test_header_from_merkle_root(self):
        async def test(headers):
            raw_headers = await self.insert_first_headers(headers, 10)
            for raw_header in chunks(raw_headers, 80):
                header = SimpleHeader.from_bytes(raw_header)
                header2 = await headers.header_from_merkle_root(header.merkle_root)
                assert same_headers(header, header2)

        run_test_with_headers(test)

    def test_header_from_merkle_root_fail(self):
        async def test(headers):
            assert await headers.header_from_merkle_root(b'a' * 32) is None

        run_test_with_headers(test)

    def test_headers_height_1(self):
        async def test(headers):
            genesis_header = await headers.header_from_hash(Bitcoin.genesis_hash)
            header1 = create_random_header(genesis_header)
            await headers.insert_headers(header1.to_bytes(), check_work=False)
            header1 = await headers.header_from_hash(header1.hash)
            assert header1.chain_id == genesis_header.chain_id

            header2 = create_random_header(genesis_header)
            await headers.insert_headers(header2.to_bytes(), check_work=False)
            header2 = await headers.header_from_hash(header2.hash)
            assert header2.chain_id != genesis_header.chain_id

        run_test_with_headers(test)

    @staticmethod
    async def insert_random_tree(headers, *args):
        genesis_header = await headers.header_from_hash(Bitcoin.genesis_hash)
        tree = create_random_tree(genesis_header, *args)
        await insert_tree(headers, tree)
        return tree, genesis_header

    def test_tree_chain_ids(self):
        async def test(headers):
            tree, genesis_header = await self.insert_random_tree(headers)

            chain_ids = []
            for _, branch in tree:
                db_headers = [await headers.header_from_hash(header.hash) for header in branch]
                assert all(header.chain_id == db_headers[0].chain_id for header in db_headers)
                chain_ids.append(db_headers[0].chain_id)

            assert len(set(chain_ids)) == len(tree)
            assert chain_ids[0] == genesis_header.chain_id

        run_test_with_headers(test)

    @staticmethod
    def full_chains_of_tree(tree, genesis_header):
        # Map from tip hash to a List of headers from genesis
        chains = {}

        # Laboriously build all header chains from the branches
        for branch_header, branch in tree:
            prefix = None
            if branch_header == genesis_header:
                prefix = [genesis_header]
            else:
                for chain in chains.values():
                    try:
                        idx = chain.index(branch_header)
                    except ValueError:
                        continue
                    prefix = chain[:idx + 1]
                    break

            assert prefix
            chain = prefix + branch
            chains[chain[-1].hash] = chain

        return chains

    def test_tree_chains(self):
        async def test(headers):
            tree, genesis_header = await self.insert_random_tree(headers)

            chains = await headers.chains()
            full_chains = self.full_chains_of_tree(tree, genesis_header)
            assert len(chains) == len(tree)

            chains = {chain.tip.hash: chain for chain in chains}
            for branch_header, branch in tree:
                tip_hash = branch[-1].hash
                branch_height = full_chains[tip_hash].index(branch_header)
                chain = chains[tip_hash]

                # Now check all headers in the branch match
                for height, header in enumerate(branch, start=branch_height + 1):
                    db_header = await headers.header_at_height(chain, height)
                    assert same_headers(header, db_header)

                assert same_headers(branch[-1], chain.tip)

        run_test_with_headers(test)

    def test_header_at_height(self):
        async def test(headers):
            tree, genesis_header = await self.insert_random_tree(headers)

            chains = await headers.chains()
            full_chains = self.full_chains_of_tree(tree, genesis_header)
            assert len(chains) == len(full_chains)

            for chain in chains:
                full_chain = full_chains[chain.tip.hash]

                assert chain.tip.height + 1 == len(full_chain)

                for height in range(chain.tip.height + 1):
                    # Compare hashes as chain_id is not set for the tree
                    assert ((await headers.header_at_height(chain, height)).hash
                            == full_chain[height].hash)

        run_test_with_headers(test)

    def test_chain_work(self):
        async def test(headers):
            tree, genesis_header = await self.insert_random_tree(headers)

            all_hashes = set(header.hash for _, branch in tree for header in branch)
            all_hashes.add(genesis_header.hash)
            all_headers = [await headers.header_from_hash(hash) for hash in all_hashes]
            all_headers = {header.hash: header for header in all_headers}
            for header in all_headers.values():
                if header.hash == genesis_header.hash:
                    prev_work = 0
                else:
                    prev_work = all_headers[header.prev_hash].chain_work()
                assert header.chain_work() == prev_work + bits_to_work(header.bits)

            # Check longest_chain()
            chains = await headers.chains()
            longest = await headers.longest_chain()
            assert longest in chains
            assert all(chain.chain_work() <= longest.chain_work() for chain in chains)

        run_test_with_headers(test)

    async def check_tree(self, headers, genesis_header, tree):
        chains = await headers.chains()

        all_headers = [header for _, branch in tree for header in branch]
        for header in all_headers:
            header = await headers.header_from_hash(header.hash)
            chains_with_header = set()
            for chain in chains:
                if (chain.tip.height >= header.height and
                        await headers.header_at_height(chain, header.height) == header):
                    chains_with_header.add(chain)
            assert set(await headers.chains(header.hash)) == set(chains_with_header)

    def test_chains(self):
        async def test(headers):
            tree, genesis_header = await self.insert_random_tree(headers)
            await self.check_tree(headers, genesis_header, tree)

        run_test_with_headers(test)

    def test_chains_manual(self):
        async def test(headers):
            genesis_header = await headers.header_from_hash(Bitcoin.genesis_hash)
            # Create a tree like so:
            #              / H5    chain_2
            #         / H3 - H4    chain_1
            # genesis - H1 - H2    chain_0
            #              \ H6    chain_3
            H1, H2 = create_random_branch(genesis_header, 2)
            H3, H4 = create_random_branch(genesis_header, 2)
            H5, = create_random_branch(H3, 1)
            H6, = create_random_branch(H1, 1)

            H = (H1, H2, H3, H4, H5, H6)
            await headers.insert_headers(b''.join(h.to_bytes() for h in H), check_work=False)

            # This ensures chain_id is set
            H1, H2, H3, H4, H5, H6 = [await headers.header_from_hash(h.hash) for h in H]

            chains = {chain.tip.hash: chain for chain in await headers.chains()}
            chain_0 = chains[H2.hash]
            chain_1 = chains[H4.hash]
            chain_2 = chains[H5.hash]
            chain_3 = chains[H6.hash]

            assert set(await headers.chains()) == {chain_0, chain_1, chain_2, chain_3}
            assert set(await headers.chains(H1.hash)) == {chain_0, chain_3}
            assert set(await headers.chains(H2.hash)) == {chain_0}
            assert set(await headers.chains(H3.hash)) == {chain_1, chain_2}
            assert set(await headers.chains(H4.hash)) == {chain_1}
            assert set(await headers.chains(H5.hash)) == {chain_2}
            assert set(await headers.chains(H6.hash)) == {chain_3}

        run_test_with_headers(test)

    def test_median_time_past(self):
        async def test(headers):
            count = 100
            genesis_header = await headers.header_from_hash(Bitcoin.genesis_hash)
            branch = create_random_branch(genesis_header, count)
            await insert_tree(headers, [(None, branch)])

            cheaders = [genesis_header]
            cheaders.extend(branch)
            timestamps = [header.timestamp for header in cheaders]

            check_mtps = []
            for height, header in enumerate(cheaders, start=1):
                past_timestamps = timestamps[max(0, height - 11): height]
                mtp = sorted(past_timestamps)[len(past_timestamps) // 2]
                check_mtps.append(mtp)

            mtps = [await headers.median_time_past(prev_header.hash) for prev_header in cheaders]
            assert mtps == check_mtps

        run_test_with_headers(test)

    def test_median_time_past_missing(self):
        async def test(headers):
            with pytest.raises(MissingHeader):
                await headers.median_time_past(bytes(32))

        run_test_with_headers(test)

    def test_block_locator(self):
        async def test(headers):
            count = 100
            genesis_header = await headers.header_from_hash(Bitcoin.genesis_hash)
            branch = create_random_branch(genesis_header, count)
            await insert_tree(headers, [(None, branch)])
            locator = await headers.block_locator()
            assert len(locator) == 8
            for loc_pos in range(7):
                assert locator[loc_pos] == branch[-(1 << loc_pos)].hash
            assert locator[-1] == genesis_header.hash

        run_test_with_headers(test)

    @pytest.mark.parametrize('network', all_networks)
    def test_block_locator_empty_headers(self, network):
        async def test(headers):
            assert await headers.block_locator() == [network.genesis_hash]

        run_test_with_headers(test, network)

    def test_target_checked(self):
        async def test(headers):
            header = create_random_header(SimpleHeader.from_bytes(network.genesis_header))
            with pytest.raises(InsufficientPoW):
                await headers.insert_headers(header.to_bytes())

        network = Bitcoin
        run_test_with_headers(test, network)
