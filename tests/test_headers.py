import dataclasses
import logging

import asqlite3

import pytest
from bitcoinx import (
    Bitcoin, BitcoinTestnet, MissingHeader, InsufficientPoW, IncorrectBits, HeadersNotSequential,
    bits_to_work, SimpleHeader, Header, all_networks, int_to_le_bytes,
)

from .utils import (
    run_test_with_headers, create_random_branch, insert_tree, create_random_tree,
    create_random_header, first_mainnet_headers, in_caplog,
)


class TestSimpleHeader:

    def test_eq(self):
        assert Bitcoin.genesis_header != BitcoinTestnet.genesis_header

    def test_hashable(self):
        assert len({Bitcoin.genesis_header, BitcoinTestnet.genesis_header}) == 2

    def test_str(self):
        assert str(Bitcoin.genesis_header) == (
            'SimpleHeader(version=0x1, prev_hash=000000000000000000000000000000000000000000000'
            '0000000000000000000, merkle_root=4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77a'
            'b2127b7afdeda33b, timestamp=1231006505, bits=0x486604799, nonce=2083236893, hash='
            '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f)'
        )

    def test_are_headers_chained_good(self):
        branch = create_random_branch(Bitcoin.genesis_header, 10)
        assert SimpleHeader.are_headers_chained(branch) is True

    def test_are_headers_chained_not(self):
        branch = create_random_branch(Bitcoin.genesis_header, 10)
        branch.append(create_random_header(Bitcoin.genesis_header))
        assert SimpleHeader.are_headers_chained(branch) is False


class TestHeader:

    @staticmethod
    def genesis():
        simple = Bitcoin.genesis_header
        return Header(simple.raw, 0, 1, int_to_le_bytes(simple.work()))

    def test_eq(self):
        assert Bitcoin.genesis_header == self.genesis()

    def test_hashable(self):
        assert len({self.genesis(), self.genesis()}) == 1

    def test_str(self):
        assert str(self.genesis()) == (
            'Header(version=0x1, prev_hash=000000000000000000000000000000000000000000000000000000'
            '0000000000, merkle_root=4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afded'
            'a33b, timestamp=1231006505, bits=0x486604799, nonce=2083236893, hash=000000000019d66'
            '89c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f, height=0 chain_work=100010001)'
        )


def same_headers(simple, detailed):
    return all(getattr(simple, field.name) == getattr(detailed, field.name)
               for field in dataclasses.fields(SimpleHeader))


COLNAMES = ('prev_hdr_id', 'height', 'chain_id', 'chain_work', 'hash', 'merkle_root', 'version',
            'timestamp', 'bits', 'nonce')


class TestHeaders:

    COMMON_KEYS = ('hash', 'merkle_root', 'version', 'timestamp', 'bits', 'nonce')

    def test_headers(self):
        async def test(headers):
            assert not headers.conn.in_transaction

        run_test_with_headers(test, Bitcoin)

    def test_double_init(self, caplog):
        async def test(headers):
            await headers.initialize()

        with caplog.at_level(logging.INFO):
            run_test_with_headers(test, Bitcoin)
        assert in_caplog(caplog, 'found 1 chain to height 0')

    @pytest.mark.parametrize('network', all_networks)
    def test_genesis_header(self, network):
        async def test(headers):
            header = network.genesis_header
            header2 = await headers.header_from_hash(header.hash)
            assert same_headers(header, header2)
            await self.check_tip_and_height(headers)

        run_test_with_headers(test, network)

    @pytest.mark.parametrize('network', all_networks)
    def test_genesis_merkle_root(self, network):
        async def test(headers):
            # Only test for Bitcoin, as Testnet genesis merkle root is identical
            header = network.genesis_header
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

            chains = await headers.chains()
            assert len(chains) == 1
            chain = chains[0]
            assert chain.tip == headers.genesis_header == await headers.header_at_height(chain, 0)

        run_test_with_headers(test, network)

    @pytest.mark.parametrize('colname', ('hash', 'merkle_root'))
    def test_unique_columns(self, colname):
        async def test(headers):
            header = Bitcoin.genesis_header
            colnames = ', '.join(COLNAMES)
            questions = ', '.join('?' * len(COLNAMES))
            values = [0] * len(COLNAMES)
            values[COLNAMES.index(colname)] = getattr(header, colname)
            with pytest.raises(asqlite3.IntegrityError) as e:
                await headers.conn.execute(headers.fixup_sql(
                    f'INSERT INTO $S.Headers({colnames}) VALUES ({questions});'), values)
            # An sqlite3 module bug with Python before 3.11 (I think) sometimes gives an
            # error string of "not an error".  Googling shows a few cases online.
            assert str(e.value) in ('not and error',
                                    f'UNIQUE constraint failed: Headers.{colname}')

        run_test_with_headers(test)

    @pytest.mark.parametrize('colname', COLNAMES)
    def test_null_insertions(self, colname):
        async def test(headers):
            with pytest.raises(asqlite3.IntegrityError) as e:
                await headers.conn.execute(headers.fixup_sql(
                    f'INSERT INTO $S.Headers({colname}) VALUES (NULL);'))
            assert 'NOT NULL constraint failed' in str(e.value)

        if colname != 'prev_hdr_id':
            run_test_with_headers(test)

    @staticmethod
    async def insert_first_headers(headers, count):
        simple_headers = first_mainnet_headers(count)
        assert await headers.insert_headers(simple_headers) == count - 1
        return simple_headers

    def test_insert_headers(self):
        async def test(headers):
            assert not headers.conn.in_transaction
            simple_headers = await self.insert_first_headers(headers, 10)
            cursor = await headers.conn.cursor()
            cursor.row_factory = asqlite3.Row
            await cursor.execute(f'SELECT * from {headers.schema}.Headers ORDER BY height')
            result = await cursor.fetchall()
            assert len(result) == len(simple_headers)
            for row, (height, header) in zip(result, enumerate(simple_headers)):
                for attrib in self.COMMON_KEYS:
                    assert row[attrib] == getattr(header, attrib)
                assert row['height'] == height

            chains = await headers.chains()
            assert len(chains) == 1
            chain = chains[0]
            assert chain.tip.hash == simple_headers[-1].hash

        network = Bitcoin
        run_test_with_headers(test, network)

    def test_insert_headers_empty(self):
        async def test(headers):
            assert await headers.insert_headers([]) == 0
        run_test_with_headers(test, Bitcoin)

    def test_insert_headers_commits(self):
        async def test(headers):
            mainnet_headers = first_mainnet_headers(6)
            await headers.insert_headers(mainnet_headers)
            assert await headers.height() == 5
            await headers.conn.rollback()
            assert await headers.height() == 5

        run_test_with_headers(test)

    def test_insert_headers_commits_successes(self):
        async def test(headers):
            mainnet_headers = first_mainnet_headers(6)
            mainnet_headers.append(create_random_header(mainnet_headers[-1]))
            try:
                await headers.insert_headers(mainnet_headers)
            except InsufficientPoW:
                pass
            assert await headers.height() == 5
            await headers.conn.rollback()
            assert await headers.height() == 5

        run_test_with_headers(test)

    def test_insert_headers_not_a_chain(self):
        async def test(headers):
            branch = create_random_branch(headers.genesis_header, 4)
            branch.append(branch[0])
            with pytest.raises(HeadersNotSequential):
                await headers.insert_headers(branch)

        run_test_with_headers(test)

    def test_insert_headers_not_connecting(self):
        async def test(headers):
            header = create_random_header(headers.genesis_header)
            branch = create_random_branch(header, 4)
            with pytest.raises(MissingHeader):
                await headers.insert_headers(branch)

        run_test_with_headers(test)

    def test_insert_existing_headers(self):
        async def test(headers):
            simples = first_mainnet_headers(10)
            count = await headers.insert_headers(simples[:5])
            assert count == 4
            chain = await headers.longest_chain()
            assert chain.tip.height == 4
            count = await headers.insert_headers(simples[2:])
            assert count == 5
            chain = await headers.longest_chain()
            assert chain.tip.height == 9

        run_test_with_headers(test)

    def test_insert_new_branch_checking_work(self):
        async def test(headers):
            branch = create_random_branch(network.genesis_header, 4)
            simples = first_mainnet_headers(10)
            count = await headers.insert_headers(branch, check_work=False)
            count = await headers.insert_headers(simples)
            assert count == 9

        network = Bitcoin
        run_test_with_headers(test, network)

    def test_header_from_hash(self):
        async def test(headers):
            for header in await self.insert_first_headers(headers, 10):
                header2 = await headers.header_from_hash(header.hash)
                assert same_headers(header, header2)

        run_test_with_headers(test)

    def test_header_from_hash_fail(self):
        async def test(headers):
            assert await headers.header_from_hash(b'a' * 32) is None

        run_test_with_headers(test)

    def test_header_from_merkle_root(self):
        async def test(headers):
            for header in await self.insert_first_headers(headers, 10):
                header2 = await headers.header_from_merkle_root(header.merkle_root)
                assert same_headers(header, header2)

        run_test_with_headers(test)

    def test_header_from_merkle_root_fail(self):
        async def test(headers):
            assert await headers.header_from_merkle_root(b'a' * 32) is None

        run_test_with_headers(test)

    def test_headers_height_1(self):
        async def test(headers):
            header1 = create_random_header(headers.genesis_header)
            assert await headers.insert_headers([header1], check_work=False) == 1
            header1 = await headers.header_from_hash(header1.hash)
            assert header1.chain_id == headers.genesis_header.chain_id

            header2 = create_random_header(headers.genesis_header)
            assert await headers.insert_headers([header2], check_work=False) == 1
            header2 = await headers.header_from_hash(header2.hash)
            assert header2.chain_id != headers.genesis_header.chain_id

        run_test_with_headers(test)

    @staticmethod
    async def insert_random_tree(headers, *args):
        genesis_header = headers.genesis_header
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

            await self.check_tip_and_height(headers)

        run_test_with_headers(test)

    def test_header_at_height_bad(self):
        async def test(headers):
            chain = await headers.longest_chain()
            assert await headers.header_at_height(chain, -1) is None
            assert await headers.header_at_height(chain, 2) is None

        run_test_with_headers(test)

    def test_longest_chain_bad_header(self):
        async def test(headers):
            with pytest.raises(MissingHeader) as e:
                await headers.longest_chain(bytes(32))
            assert str(e.value) == 'no chains contain the header'

        network = Bitcoin
        run_test_with_headers(test, network)

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

            await self.check_tip_and_height(headers)

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
            await self.check_tip_and_height(headers)

        run_test_with_headers(test)

    async def check_tip_and_height(self, headers):
        chain = await headers.longest_chain()
        assert await headers.tip() == chain.tip
        assert await headers.height() == chain.tip.height

    def test_chains_manual(self):
        async def test(headers):
            # Create a tree like so:
            #              / H5    chain_2
            #         / H3 - H4    chain_1
            # genesis - H1 - H2    chain_0
            #              \ H6    chain_3
            B1 = create_random_branch(headers.genesis_header, 2)
            B2 = create_random_branch(headers.genesis_header, 2)
            B3 = create_random_branch(B2[0], 1)
            B4 = create_random_branch(B1[0], 1)

            for B in (B1, B2, B3, B4):
                assert await headers.insert_headers(B, check_work=False) == len(B)

            # This ensures chain_id is set
            H1, H2, H3, H4, H5, H6 = [await headers.header_from_hash(h.hash)
                                      for h in B1 + B2 + B3 + B4]

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

            await self.check_tip_and_height(headers)

        run_test_with_headers(test)

    def test_median_time_past(self):
        async def test(headers):
            count = 100
            branch = create_random_branch(headers.genesis_header, count)
            await insert_tree(headers, [(None, branch)])

            cheaders = [headers.genesis_header]
            cheaders.extend(branch)
            timestamps = [header.timestamp for header in cheaders]

            check_mtps = []
            for height, header in enumerate(cheaders, start=1):
                past_timestamps = timestamps[max(0, height - 11): height]
                mtp = sorted(past_timestamps)[len(past_timestamps) // 2]
                check_mtps.append(mtp)

            mtps = [await headers.median_time_past(1, height) for height in range(len(cheaders))]
            assert mtps == check_mtps

        run_test_with_headers(test)

    @pytest.mark.parametrize('chain_id, height', ((1, -1), (1, 10), (0, 0)))
    def test_median_time_past_missing(self, chain_id, height):
        async def test(headers):
            with pytest.raises(MissingHeader):
                await headers.median_time_past(chain_id, height)

        run_test_with_headers(test)

    def test_target_checked(self):
        async def test(headers):
            simples = first_mainnet_headers(2)
            header = SimpleHeader(b'0' + simples[1].raw[1:])
            with pytest.raises(InsufficientPoW) as e:
                await headers.insert_headers([header])
            assert str(e.value) == (
                'header f300000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d61900000000'
                '00982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff'
                '001d01e36299 hash value exceeds its target')

        network = Bitcoin
        run_test_with_headers(test, network)

    def test_bits_checked(self):
        async def test(headers):
            simples = first_mainnet_headers(2)
            raw = bytearray(simples[1].raw)
            raw[72] ^= 0xf
            header = SimpleHeader(raw)
            with pytest.raises(IncorrectBits) as e:
                await headers.insert_headers([header])
            assert str(e.value) == 'header requires bits 486604799 but has 486604784'

        network = Bitcoin
        run_test_with_headers(test, network)


class TestNetwork:

    @pytest.mark.parametrize('network', all_networks)
    def test_str(self, network):
        assert str(network) == network.name
