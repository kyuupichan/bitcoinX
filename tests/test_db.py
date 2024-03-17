import dataclasses
import logging

import asqlite3

import pytest
from bitcoinx import (
    Bitcoin, MissingHeader, InsufficientPoW, IncorrectBits, HeadersNotSequential,
    bits_to_work, SimpleHeader, all_networks,
)

from .utils import (
    run_test_with_db, create_random_branch, insert_tree, create_random_tree,
    create_random_header, first_mainnet_headers, in_caplog,
)


def same_headers(simple, detailed):
    return all(getattr(simple, field.name) == getattr(detailed, field.name)
               for field in dataclasses.fields(SimpleHeader))


COLNAMES = ('prev_hdr_id', 'height', 'chain_id', 'chain_work', 'hash', 'merkle_root', 'version',
            'timestamp', 'bits', 'nonce')


class TestDB:

    COMMON_KEYS = ('hash', 'merkle_root', 'version', 'timestamp', 'bits', 'nonce')

    def test_headers(self):
        async def test(db):
            assert not db.conn.in_transaction

        run_test_with_db(test, Bitcoin)

    def test_double_init(self, caplog):
        async def test(db):
            await db.initialize()

        with caplog.at_level(logging.INFO):
            run_test_with_db(test, Bitcoin)
        assert in_caplog(caplog, 'found 1 chain to height 0')

    @pytest.mark.parametrize('network', all_networks)
    def test_genesis_header(self, network):
        async def test(db):
            header = network.genesis_header
            header2 = await db.header_from_hash(header.hash)
            assert same_headers(header, header2)
            await self.check_tip_and_height(db)

        run_test_with_db(test, network)

    @pytest.mark.parametrize('network', all_networks)
    def test_genesis_merkle_root(self, network):
        async def test(db):
            # Only test for Bitcoin, as Testnet genesis merkle root is identical
            header = network.genesis_header
            header2 = await db.header_from_merkle_root(header.merkle_root)
            assert same_headers(header, header2)

        run_test_with_db(test, network)

    @pytest.mark.parametrize('network', all_networks)
    def test_genesis_chains(self, network):
        async def test(db):
            cursor = await db.conn.cursor()
            cursor.row_factory = asqlite3.Row
            await cursor.execute('SELECT * FROM Chains')
            row = await cursor.fetchone()
            assert row['parent_chain_id'] is None
            assert row['base_hdr_id'] == row['tip_hdr_id']
            assert row['base_hdr_id'] == 1
            assert await cursor.fetchone() is None

            chains = await db.chains()
            assert len(chains) == 1
            chain = chains[0]
            assert chain.tip == db.genesis_header == await db.header_at_height(chain, 0)

        run_test_with_db(test, network)

    @pytest.mark.parametrize('colname', ('hash', 'merkle_root'))
    def test_unique_columns(self, colname):
        async def test(db):
            header = Bitcoin.genesis_header
            colnames = ', '.join(COLNAMES)
            questions = ', '.join('?' * len(COLNAMES))
            values = [0] * len(COLNAMES)
            values[COLNAMES.index(colname)] = getattr(header, colname)
            with pytest.raises(asqlite3.IntegrityError) as e:
                await db.conn.execute(
                    f'INSERT INTO Headers({colnames}) VALUES ({questions});', values)
            # An sqlite3 module bug with Python before 3.11 (I think) sometimes gives an
            # error string of "not an error".  Googling shows a few cases online.
            assert str(e.value) in ('not and error',
                                    f'UNIQUE constraint failed: Headers.{colname}')

        run_test_with_db(test)

    @pytest.mark.parametrize('colname', COLNAMES)
    def test_null_insertions(self, colname):
        async def test(db):
            with pytest.raises(asqlite3.IntegrityError) as e:
                await db.conn.execute(f'INSERT INTO Headers({colname}) VALUES (NULL);')
            assert 'NOT NULL constraint failed' in str(e.value)

        if colname != 'prev_hdr_id':
            run_test_with_db(test)

    @staticmethod
    async def insert_first_headers(db, count):
        simple_headers = first_mainnet_headers(count)
        inserted_count, tip = await db.insert_header_chain(simple_headers)
        assert inserted_count == count - 1
        assert tip.hash == simple_headers[-1].hash
        return simple_headers

    def test_insert_header_chain(self):
        async def test(db):
            assert not db.conn.in_transaction
            simple_headers = await self.insert_first_headers(db, 10)
            cursor = await db.conn.cursor()
            cursor.row_factory = asqlite3.Row
            await cursor.execute('SELECT * from Headers ORDER BY height')
            result = await cursor.fetchall()
            assert len(result) == len(simple_headers)
            for row, (height, header) in zip(result, enumerate(simple_headers)):
                for attrib in self.COMMON_KEYS:
                    assert row[attrib] == getattr(header, attrib)
                assert row['height'] == height

            chains = await db.chains()
            assert len(chains) == 1
            chain = chains[0]
            assert chain.tip.hash == simple_headers[-1].hash

        network = Bitcoin
        run_test_with_db(test, network)

    def test_insert_header_chain_empty(self):
        async def test(db):
            assert await db.insert_header_chain([]) == (0, None)
        run_test_with_db(test, Bitcoin)

    def test_insert_header_chain_commits(self):
        async def test(db):
            mainnet_headers = first_mainnet_headers(6)
            await db.insert_header_chain(mainnet_headers)
            assert await db.height() == 5
            await db.conn.rollback()
            assert await db.height() == 5

        run_test_with_db(test)

    def test_insert_header_chain_commits_successes(self):
        async def test(db):
            mainnet_headers = first_mainnet_headers(6)
            mainnet_headers.append(create_random_header(mainnet_headers[-1]))
            try:
                await db.insert_header_chain(mainnet_headers)
            except InsufficientPoW:
                pass
            assert await db.height() == 5
            await db.conn.rollback()
            assert await db.height() == 5

        run_test_with_db(test)

    def test_insert_header_chain_not_a_chain(self):
        async def test(db):
            branch = create_random_branch(db.genesis_header, 4)
            branch.append(branch[0])
            with pytest.raises(HeadersNotSequential):
                await db.insert_header_chain(branch)

        run_test_with_db(test)

    def test_insert_header_chain_not_connecting(self):
        async def test(db):
            header = create_random_header(db.genesis_header)
            branch = create_random_branch(header, 4)
            with pytest.raises(MissingHeader):
                await db.insert_header_chain(branch)

        run_test_with_db(test)

    def test_insert_existing_headers(self):
        async def test(db):
            simples = first_mainnet_headers(10)
            count, tip = await db.insert_header_chain(simples[:5])
            assert count == 4
            assert tip.hash == simples[4].hash
            chain = await db.longest_chain()
            assert chain.tip == tip
            count, tip = await db.insert_header_chain(simples[2:])
            assert count == 5
            assert tip.hash == simples[-1].hash
            chain = await db.longest_chain()
            assert chain.tip.height == 9

        run_test_with_db(test)

    def test_insert_new_branch_checking_work(self):
        async def test(db):
            branch = create_random_branch(network.genesis_header, 4)
            simples = first_mainnet_headers(10)
            await db.insert_header_chain(branch, check_work=False)
            count, tip = await db.insert_header_chain(simples)
            assert count == 9

        network = Bitcoin
        run_test_with_db(test, network)

    def test_insert_new_branch_checking_work_fail(self):
        async def test(db):
            mainnet_headers = first_mainnet_headers(10)
            await db.insert_header_chain(mainnet_headers)
            branch = create_random_branch(network.genesis_header, 4)
            chain_info = db.chain_info.copy()
            with pytest.raises(InsufficientPoW):
                await db.insert_header_chain(branch)
            # Check the new chain info item was removed
            assert db.chain_info == chain_info

        network = Bitcoin
        run_test_with_db(test, network)

    def test_header_from_hash(self):
        async def test(db):
            for header in await self.insert_first_headers(db, 10):
                header2 = await db.header_from_hash(header.hash)
                assert same_headers(header, header2)

        run_test_with_db(test)

    def test_header_from_hash_fail(self):
        async def test(db):
            assert await db.header_from_hash(b'a' * 32) is None

        run_test_with_db(test)

    def test_header_from_merkle_root(self):
        async def test(db):
            for header in await self.insert_first_headers(db, 10):
                header2 = await db.header_from_merkle_root(header.merkle_root)
                assert same_headers(header, header2)

        run_test_with_db(test)

    def test_header_from_merkle_root_fail(self):
        async def test(db):
            assert await db.header_from_merkle_root(b'a' * 32) is None

        run_test_with_db(test)

    def test_headers_height_1(self):
        async def test(db):
            header1 = create_random_header(db.genesis_header)
            count, tip = await db.insert_header_chain([header1], check_work=False)
            assert count == 1
            header1 = await db.header_from_hash(header1.hash)
            assert header1.chain_id == db.genesis_header.chain_id

            header2 = create_random_header(db.genesis_header)
            count, tip = await db.insert_header_chain([header2], check_work=False)
            assert count == 1
            header2 = await db.header_from_hash(header2.hash)
            assert header2.chain_id != db.genesis_header.chain_id

        run_test_with_db(test)

    @staticmethod
    async def insert_random_tree(db, *args):
        genesis_header = db.genesis_header
        tree = create_random_tree(genesis_header, *args)
        await insert_tree(db, tree)
        return tree, genesis_header

    def test_tree_chain_ids(self):
        async def test(db):
            tree, genesis_header = await self.insert_random_tree(db)

            chain_ids = []
            for _, branch in tree:
                db_headers = [await db.header_from_hash(header.hash) for header in branch]
                assert all(header.chain_id == db_headers[0].chain_id for header in db_headers)
                chain_ids.append(db_headers[0].chain_id)

            assert len(set(chain_ids)) == len(tree)
            assert chain_ids[0] == genesis_header.chain_id

        run_test_with_db(test)

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
        async def test(db):
            tree, genesis_header = await self.insert_random_tree(db)

            chains = await db.chains()
            full_chains = self.full_chains_of_tree(tree, genesis_header)
            assert len(chains) == len(tree)

            chains = {chain.tip.hash: chain for chain in chains}
            for branch_header, branch in tree:
                tip_hash = branch[-1].hash
                branch_height = full_chains[tip_hash].index(branch_header)
                chain = chains[tip_hash]

                # Now check all headers in the branch match
                for height, header in enumerate(branch, start=branch_height + 1):
                    db_header = await db.header_at_height(chain, height)
                    assert same_headers(header, db_header)

                assert same_headers(branch[-1], chain.tip)

        run_test_with_db(test)

    def test_header_at_height(self):
        async def test(db):
            tree, genesis_header = await self.insert_random_tree(db)

            chains = await db.chains()
            full_chains = self.full_chains_of_tree(tree, genesis_header)
            assert len(chains) == len(full_chains)

            for chain in chains:
                full_chain = full_chains[chain.tip.hash]

                assert chain.tip.height + 1 == len(full_chain)

                for height in range(chain.tip.height + 1):
                    # Compare hashes as chain_id is not set for the tree
                    assert ((await db.header_at_height(chain, height)).hash
                            == full_chain[height].hash)

            await self.check_tip_and_height(db)

        run_test_with_db(test)

    def test_header_at_height_bad(self):
        async def test(db):
            chain = await db.longest_chain()
            assert await db.header_at_height(chain, -1) is None
            assert await db.header_at_height(chain, 2) is None

        run_test_with_db(test)

    def test_longest_chain_bad_header(self):
        async def test(db):
            with pytest.raises(MissingHeader) as e:
                await db.longest_chain(bytes(32))
            assert str(e.value) == 'no chains contain the header'

        network = Bitcoin
        run_test_with_db(test, network)

    def test_chain_work(self):
        async def test(db):
            tree, genesis_header = await self.insert_random_tree(db)

            all_hashes = set(header.hash for _, branch in tree for header in branch)
            all_hashes.add(genesis_header.hash)
            all_headers = [await db.header_from_hash(hash) for hash in all_hashes]
            all_headers = {header.hash: header for header in all_headers}
            for header in all_headers.values():
                if header.hash == genesis_header.hash:
                    prev_work = 0
                else:
                    prev_work = all_headers[header.prev_hash].chain_work()
                assert header.chain_work() == prev_work + bits_to_work(header.bits)

            # Check longest_chain()
            chains = await db.chains()
            longest = await db.longest_chain()
            assert longest in chains
            assert all(chain.chain_work() <= longest.chain_work() for chain in chains)

            await self.check_tip_and_height(db)

        run_test_with_db(test)

    async def check_tree(self, db, genesis_header, tree):
        chains = await db.chains()

        all_headers = [header for _, branch in tree for header in branch]
        for header in all_headers:
            header = await db.header_from_hash(header.hash)
            chains_with_header = set()
            for chain in chains:
                if (chain.tip.height >= header.height and
                        await db.header_at_height(chain, header.height) == header):
                    chains_with_header.add(chain)
            assert set(await db.chains(header.hash)) == set(chains_with_header)

    def test_chains(self):
        async def test(db):
            tree, genesis_header = await self.insert_random_tree(db)
            await self.check_tree(db, genesis_header, tree)
            await self.check_tip_and_height(db)

        run_test_with_db(test)

    async def check_tip_and_height(self, db):
        chain = await db.longest_chain()
        assert await db.tip() == chain.tip
        assert await db.height() == chain.tip.height

    def test_chains_manual(self):
        async def test(db):
            # Create a tree like so:
            #              / H5    chain_2
            #         / H3 - H4    chain_1
            # genesis - H1 - H2    chain_0
            #              \ H6    chain_3
            B1 = create_random_branch(db.genesis_header, 2)
            B2 = create_random_branch(db.genesis_header, 2)
            B3 = create_random_branch(B2[0], 1)
            B4 = create_random_branch(B1[0], 1)

            for B in (B1, B2, B3, B4):
                count, tip = await db.insert_header_chain(B, check_work=False)
                assert count == len(B)
                assert tip.hash == B[-1].hash

            # This ensures chain_id is set
            H1, H2, H3, H4, H5, H6 = [await db.header_from_hash(h.hash)
                                      for h in B1 + B2 + B3 + B4]

            chains = {chain.tip.hash: chain for chain in await db.chains()}
            chain_0 = chains[H2.hash]
            chain_1 = chains[H4.hash]
            chain_2 = chains[H5.hash]
            chain_3 = chains[H6.hash]

            assert set(await db.chains()) == {chain_0, chain_1, chain_2, chain_3}
            assert set(await db.chains(H1.hash)) == {chain_0, chain_3}
            assert set(await db.chains(H2.hash)) == {chain_0}
            assert set(await db.chains(H3.hash)) == {chain_1, chain_2}
            assert set(await db.chains(H4.hash)) == {chain_1}
            assert set(await db.chains(H5.hash)) == {chain_2}
            assert set(await db.chains(H6.hash)) == {chain_3}

            await self.check_tip_and_height(db)

        run_test_with_db(test)

    def test_median_time_past(self):
        async def test(db):
            count = 100
            branch = create_random_branch(db.genesis_header, count)
            await insert_tree(db, [(None, branch)])

            cheaders = [db.genesis_header]
            cheaders.extend(branch)
            timestamps = [header.timestamp for header in cheaders]

            check_mtps = []
            for height, header in enumerate(cheaders, start=1):
                past_timestamps = timestamps[max(0, height - 11): height]
                mtp = sorted(past_timestamps)[len(past_timestamps) // 2]
                check_mtps.append(mtp)

            mtps = [await db.median_time_past(1, height) for height in range(len(cheaders))]
            assert mtps == check_mtps

        run_test_with_db(test)

    @pytest.mark.parametrize('chain_id, height', ((1, -1), (1, 10), (0, 0)))
    def test_median_time_past_missing(self, chain_id, height):
        async def test(db):
            with pytest.raises(MissingHeader):
                await db.median_time_past(chain_id, height)

        run_test_with_db(test)

    def test_target_checked(self):
        async def test(db):
            simples = first_mainnet_headers(2)
            header = SimpleHeader(b'0' + simples[1].raw[1:])
            with pytest.raises(InsufficientPoW) as e:
                await db.insert_header_chain([header])
            assert str(e.value) == (
                'header f300000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d61900000000'
                '00982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff'
                '001d01e36299 hash value exceeds its target')

        network = Bitcoin
        run_test_with_db(test, network)

    def test_bits_checked(self):
        async def test(db):
            simples = first_mainnet_headers(2)
            raw = bytearray(simples[1].raw)
            raw[72] ^= 0xf
            header = SimpleHeader(raw)
            with pytest.raises(IncorrectBits) as e:
                await db.insert_header_chain([header])
            assert str(e.value) == 'header requires bits 486604799 but has 486604784'

        network = Bitcoin
        run_test_with_db(test, network)
