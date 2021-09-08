from os import urandom, path
import pickle
import random

import pytest

from bitcoinx import (
    Bitcoin, BitcoinTestnet, pack_le_uint32, double_sha256, hex_str_to_hash, IncorrectBits,
    InsufficientPoW,
)
from bitcoinx.chain import _HeaderStorage, Chain, Headers, CheckPoint, MissingHeader


some_good_bits = [486604799, 472518933, 453281356, 436956491]
empty_header = bytes(80)

genesis_checkpoint = CheckPoint(Bitcoin.genesis_header, 0, 0)
bsv_raw_header = bytes.fromhex(
    '000000203b0bc2a72e7313ac216e3c63314b8aec4be35374d66d2e0200000000000000009d14e99d'
    '7799f2d8b62b3c745aa94514da4c831193bd057a916e1f45183600b5d001f95b11fd02180d32952e'
)
bsv_checkpoint = CheckPoint(bsv_raw_header, height=557957, prev_work=0xd54c44dbdc491c25d097bf)


def random_header(prev_hash=None, height=-1, good_bits=None):
    good_bits = good_bits or some_good_bits
    raw_header = bytearray(urandom(80))
    raw_header[72:76] = pack_le_uint32(random.choice(good_bits))
    if prev_hash:
        raw_header[4:36] = prev_hash
    return Bitcoin.deserialized_header(bytes(raw_header), height)


def storage_filename(tmpdir):
    return path.join(tmpdir, 'hs')


def create_or_open_storage(tmpdir, checkpoint=None):
    checkpoint = checkpoint or genesis_checkpoint
    hs = _HeaderStorage(storage_filename(tmpdir))
    hs.open_or_create(checkpoint)
    return hs


def create_headers(tmpdir, checkpoint=None, coin=Bitcoin):
    checkpoint = checkpoint or genesis_checkpoint
    return Headers(coin, storage_filename(tmpdir), checkpoint)


def create_chain(headers_obj, count, prior=None, good_bits=None):
    checkpoint_hash = double_sha256(headers_obj.checkpoint.raw_header)
    checkpoint, chain = headers_obj.lookup(checkpoint_hash)

    prior = prior or checkpoint
    orig_prior = prior

    prior_len = len(headers_obj)

    new_headers = []
    for n in range(count):
        new_header = random_header(prior.hash, orig_prior.height + n + 1, good_bits)
        new_headers.append(new_header)
        header_index = headers_obj._storage.append(new_header.raw)
        chain = headers_obj._read_header(header_index)
        prior = new_header

    assert len(headers_obj) == prior_len + count
    assert chain.tip.hash == prior.hash

    return new_headers, chain


class TestChain:

    def test_chain(self):
        N = 10
        headers = []
        for n in range(N * 2):
            headers.append(random_header())
        indices = list(range(N * 2))
        random.shuffle(indices)

        genesis = random_header()
        genesis.height = 0
        base = Chain(None, genesis, 0, 0)
        assert base.height == 0

        for n, (header, index) in enumerate(zip(headers, indices)):
            if n < N:
                base.append(header, index)

        # Test all public attributes and methods
        assert base.parent is None
        assert base.first_height == 0
        assert base.height == N
        assert base.tip == headers[N - 1]
        assert base.work == genesis.work() + sum(header.work() for header in headers[:N])
        assert base.desc()

        for height in range(1, N + 1):
            assert base.header_index(height) == indices[height - 1]

        for n in -1, N + 1:
            with pytest.raises(MissingHeader):
                base.header_index(n)

        assert base.parent_heights() == {base: base.height}
        assert base.common_chain_and_height(base) == (base, base.height)

        # Build a fork chain
        common_height = 5
        work = sum(header.work() for header in headers[:common_height + 1])
        for n, (header, index) in enumerate(zip(headers, indices)):
            if n == N:
                header.height = common_height + 1
                fork = Chain(base, header, index, work)
            elif n > N:
                fork.append(header, index)

        # Test all public attributes and methods
        assert fork.parent is base
        assert fork.first_height == common_height + 1
        assert fork.height == common_height + N
        assert fork.tip == headers[-1]
        assert fork.work == work + sum(header.work() for header in headers[N:])

        for height in range(1, fork.height + 1):
            if height <= common_height:
                assert fork.header_index(height) == indices[height - 1]
            else:
                assert fork.header_index(height) == indices[N + (height - 1 - common_height)]

        for n in -1, fork.height + 1:
            with pytest.raises(MissingHeader):
                fork.header_index(n)

        assert fork.parent_heights() == {fork: fork.height, base: common_height}
        assert fork.common_chain_and_height(fork) == (fork, fork.height)
        assert fork.common_chain_and_height(base) == (base, common_height)
        assert base.common_chain_and_height(fork) == (base, common_height)

    def test_from_checkpoint(self):
        header = Bitcoin.deserialized_header(bsv_checkpoint.raw_header, bsv_checkpoint.height)
        chain = Chain.from_checkpoint(Bitcoin, bsv_checkpoint)
        assert chain.height == bsv_checkpoint.height
        assert chain.tip == header
        assert chain.work == bsv_checkpoint.prev_work + header.work() == 0xd54c9a84f54e93d3d87015
        assert chain.parent is None
        assert chain._header_indices[-1] == bsv_checkpoint.height


class TestHeaderStorage:

    def test_new(self, tmpdir):
        hs = create_or_open_storage(tmpdir)
        assert len(hs) == 1
        assert hs[0] == Bitcoin.genesis_header

    def test_bad_dir(self):
        with pytest.raises(FileNotFoundError):
            create_or_open_storage('no_such_dir')

    def test_open_short(self, tmpdir):
        hs = create_or_open_storage(tmpdir)
        hs[0]
        hs.close()
        hs = create_or_open_storage(tmpdir, bsv_checkpoint)
        assert len(hs) == bsv_checkpoint.height + 1
        with pytest.raises(MissingHeader):
            hs[0]

    def test_open_mismatch(self, tmpdir):
        checkpoint = CheckPoint(urandom(80), 5, 0)
        hs = create_or_open_storage(tmpdir, checkpoint)
        hs.append(urandom(80))
        assert hs[checkpoint.height] == checkpoint.raw_header
        assert len(hs) == checkpoint.height + 2
        hs[checkpoint.height + 1]
        hs.close()

        checkpoint2 = CheckPoint(urandom(80), checkpoint.height, 0)
        hs = create_or_open_storage(tmpdir, checkpoint2)
        assert len(hs) == checkpoint.height + 1
        assert hs[checkpoint.height] == checkpoint2.raw_header
        with pytest.raises(MissingHeader):
            hs[checkpoint.height + 1]

    def test_getitem(self, tmpdir):
        # This also tests append()
        hs = create_or_open_storage(tmpdir)
        raw_header = urandom(80)
        hs.append(raw_header)
        with pytest.raises(TypeError):
            hs['a']
        assert len(hs) == 2
        with pytest.raises(MissingHeader):
            hs[2]
        assert hs[1] == raw_header
        assert hs[0] == Bitcoin.genesis_header
        assert hs[-1] == raw_header
        assert hs[-2] == Bitcoin.genesis_header
        with pytest.raises(MissingHeader):
            hs[-3]

        assert hs[1:2] == [raw_header]
        assert hs[0:1] == [Bitcoin.genesis_header]
        assert hs[0:2] == [Bitcoin.genesis_header, raw_header]
        assert hs[-1:] == [raw_header]
        assert hs[-2:] == [Bitcoin.genesis_header, raw_header]
        assert hs[1::-1] == [raw_header, Bitcoin.genesis_header]

    def test_setitem(self, tmpdir):
        hs = create_or_open_storage(tmpdir, bsv_checkpoint)
        with pytest.raises(TypeError):
            hs['a'] = empty_header
        with pytest.raises(TypeError):
            hs[1:2] = empty_header
        hs[0] = Bitcoin.genesis_header
        hs[1] = empty_header
        hs[bsv_checkpoint.height] = bsv_checkpoint.raw_header
        with pytest.raises(TypeError):
            hs[1] = bytes(85)
        with pytest.raises(TypeError):
            hs[1] = 'f' * 80

    def test_hole(self, tmpdir):
        hs = create_or_open_storage(tmpdir, bsv_checkpoint)
        N = random.randrange(1000)
        raw_header = urandom(80)
        hs[N] = raw_header
        assert len(hs) == bsv_checkpoint.height + 1
        for index in range(N):
            with pytest.raises(MissingHeader):
                hs[index]
        assert hs[N] == raw_header
        with pytest.raises(MissingHeader):
            hs[N + 1]
        assert hs[bsv_checkpoint.height] == bsv_checkpoint.raw_header

    def test_flush(self, tmpdir):
        # flush is likely needed on some OSes and not others.  It doesn't appear to be
        # needed on a Mac.
        hs = create_or_open_storage(tmpdir)
        raw_header = urandom(80)
        hs.append(raw_header)
        hs.flush()
        with open(hs.filename, 'rb') as f:
            assert f.read(8) == bytes([8, 0, 0, 0, 2, 0, 0, 0])

    def test_close(self, tmpdir):
        hs = create_or_open_storage(tmpdir)
        raw_header = urandom(80)
        hs.append(raw_header)
        hs.close()
        with pytest.raises(ValueError):
            hs[1]
        with open(hs.filename, 'rb') as f:
            assert f.read(8) == bytes([8, 0, 0, 0, 2, 0, 0, 0])


class TestHeaders:

    def test_constructor(self, tmpdir):
        headers = create_headers(tmpdir)
        assert headers.coin is Bitcoin
        assert len(headers) == len(headers._storage)
        assert len(headers.chains()) == 1
        chain = headers.chains()[0]
        assert chain.tip.height == 0
        assert chain.tip.prev_hash == bytes(32)
        assert chain.work == chain.tip.work()

    def test_flush(self, tmpdir):
        headers = create_headers(tmpdir)
        headers.flush()

    def test_lookup(self, tmpdir):
        headers = create_headers(tmpdir, bsv_checkpoint)
        assert len(headers) == bsv_checkpoint.height + 1

        checkpoint_hash = double_sha256(bsv_checkpoint.raw_header)
        for clear_cache in (False, True):
            if clear_cache:
                headers._cache.clear()
            header, chain = headers.lookup(checkpoint_hash)
            assert header.hash == checkpoint_hash
            assert header.height == bsv_checkpoint.height
            assert chain.tip.raw == header.raw

        # Test header_index for chain with hole
        assert chain.header_index(0) == 0
        with pytest.raises(MissingHeader):
            headers.lookup(header.prev_hash)

        # Lookup fake header but which triggers a loop because of a fake match
        fake_hash = bytes(headers._short_hashes[:4])
        with pytest.raises(MissingHeader):
            headers.lookup(fake_hash)

    def test_set_one(self, tmpdir):
        headers = create_headers(tmpdir, bsv_checkpoint)
        assert len(headers) == bsv_checkpoint.height + 1

        chain = headers.chains()[0]
        header = headers.header_at_height(chain, bsv_checkpoint.height)
        assert header.raw == bsv_checkpoint.raw_header

        height = 10
        header = random_header()
        with pytest.raises(MissingHeader):
            headers.header_at_height(chain, height)
        headers.set_one(height, header.raw)
        assert headers.header_at_height(chain, height).raw == header.raw

        with pytest.raises(ValueError):
            headers.set_one(bsv_checkpoint.height + 1, empty_header)

    def test_chainwork_to_height(self, tmpdir):
        headers_obj = create_headers(tmpdir, bsv_checkpoint)

        checkpoint_hash = double_sha256(bsv_checkpoint.raw_header)
        cp_header, chain = headers_obj.lookup(checkpoint_hash)

        # Test chainwork_to_height
        chainwork = bsv_checkpoint.prev_work + cp_header.work()
        assert headers_obj.chainwork_to_height(chain, bsv_checkpoint.height) == chainwork
        with pytest.raises(MissingHeader):
            headers_obj.chainwork_to_height(chain, 0)

        count = 10
        new_headers, chain = create_chain(headers_obj, count)
        for new_header in new_headers:
            chainwork += new_header.work()
            assert headers_obj.chainwork_to_height(chain, new_header.height) == chainwork

    def test_create_single_chain_and_reload(self, tmpdir):
        headers_obj = create_headers(tmpdir, bsv_checkpoint)

        checkpoint_hash = double_sha256(bsv_checkpoint.raw_header)
        prior, chain = headers_obj.lookup(checkpoint_hash)

        count = 10
        new_headers, chain = create_chain(headers_obj, count)
        assert chain.height == bsv_checkpoint.height + count
        headers_obj._storage.close()

        headers_obj = create_headers(tmpdir, bsv_checkpoint)
        chains = headers_obj.chains()
        assert len(chains) == 1
        chain = chains[0]
        for n, new_header in enumerate(new_headers):
            header = headers_obj.raw_header_at_height(chain, bsv_checkpoint.height + n + 1)
            assert header == new_header.raw

        # Test adding a non-connecting header
        prior_len = len(headers_obj)
        new_header = random_header()
        with pytest.raises(MissingHeader):
            headers_obj.connect(new_header.raw)
        assert len(headers_obj) == prior_len

    def test_create_two_chains_and_reload(self, tmpdir):
        headers_obj = create_headers(tmpdir, bsv_checkpoint)

        checkpoint_hash = double_sha256(bsv_checkpoint.raw_header)
        prior, chain = headers_obj.lookup(checkpoint_hash)

        good_bits = [some_good_bits[0]]
        count = 10
        chain1_headers, chain1 = create_chain(headers_obj, count, good_bits=good_bits)
        fork_point = chain1_headers[0]
        chain2_headers, chain2 = create_chain(headers_obj, count, fork_point, good_bits=good_bits)
        assert headers_obj.longest_chain() is chain2

        assert chain1 is not chain2
        assert headers_obj.chain_count() == 2
        assert (headers_obj.chainwork_to_height(chain1, fork_point.height) ==
                headers_obj.chainwork_to_height(chain2, fork_point.height))

        chain3_headers, chain3 = create_chain(headers_obj, count, chain1.tip)
        chain4_headers, chain4 = create_chain(headers_obj, count, chain2.tip)
        assert chain3 is chain1
        assert chain4 is chain2
        assert headers_obj.chain_count() == 2
        headers_obj._storage.close()

        headers_obj = create_headers(tmpdir, bsv_checkpoint)
        assert headers_obj.chain_count() == 2
        chain5, chain6 = headers_obj.chains()
        assert chain5.work == chain1.work
        assert chain6.work == chain2.work
        assert chain5.tip.hash == chain1.tip.hash
        assert chain6.tip.hash == chain6.tip.hash

    def test_connect(self, tmpdir):
        testnet_genesis_checkpoint = CheckPoint(BitcoinTestnet.genesis_header, 0, 0)
        headers_obj = create_headers(tmpdir, testnet_genesis_checkpoint)

        header1 = bytes.fromhex(
            '0100000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000bac8b0fa'
            '927c0ac8234287e33c5f74d38d354820e24756ad709d7038fc5f31f020e7494dffff001d03e4b672'
        )
        header2 = bytes.fromhex(
            '0100000006128e87be8b1b4dea47a7247d5528d2702c96826c7a648497e773b800000000e241352e'
            '3bec0a95a6217e10c3abb54adfa05abb12c126695595580fb92e222032e7494dffff001d00d23534'
        )

        # Test cache-clearing
        headers_obj.max_cache_size = 1

        # Test they connect
        headers_obj.connect(header1)
        headers_obj.connect(header2)

        # Test re-adding is OK
        headers_obj.connect(header1)

        # Test bad bits raises
        bad_header = bytearray(header1)
        bad_header[72:76] = pack_le_uint32(472518933)
        with pytest.raises(IncorrectBits) as e:
            headers_obj.connect(bad_header)
        assert str(e.value).endswith('requires bits 0x486604799')

        # Test insufficient PoW raises
        bad_header = bytearray(header1)
        bad_header[0] = 2
        with pytest.raises(InsufficientPoW) as e:
            headers_obj.connect(bad_header)
        assert 'exceeds its target' in str(e.value)

    def test_pickle(self, tmpdir):
        testnet_genesis_checkpoint = CheckPoint(BitcoinTestnet.genesis_header, 0, 0)
        headers_obj = create_headers(tmpdir, testnet_genesis_checkpoint)

        header1 = bytes.fromhex(
            '0100000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000bac8b0fa'
            '927c0ac8234287e33c5f74d38d354820e24756ad709d7038fc5f31f020e7494dffff001d03e4b672'
        )
        header2 = bytes.fromhex(
            '0100000006128e87be8b1b4dea47a7247d5528d2702c96826c7a648497e773b800000000e241352e'
            '3bec0a95a6217e10c3abb54adfa05abb12c126695595580fb92e222032e7494dffff001d00d23534'
        )

        headers_obj.connect(header1)
        headers_obj.connect(header2)

        pickle_bytes = pickle.dumps(headers_obj)

        headers_obj2 = pickle.loads(pickle_bytes)
        assert headers_obj._short_hashes == headers_obj2._short_hashes
        assert headers_obj._heights == headers_obj2._heights
        assert headers_obj._chain_indices == headers_obj2._chain_indices
        assert len(headers_obj._chains) == len(headers_obj2._chains)

        # Chain objects cannot be directly compared, so we need to do the legwork.
        # This goes beyond what is needed here as it might be reused for a wider variety of
        # cases if necessary.
        for i in range(len(headers_obj._chains)):
            original_chain = headers_obj._chains[i]
            unpickled_chain = headers_obj2._chains[i]
            assert original_chain.tip == unpickled_chain.tip
            assert original_chain.work == unpickled_chain.work
            assert original_chain.first_height == unpickled_chain.first_height
            assert original_chain._header_indices == unpickled_chain._header_indices
            if original_chain.parent is None:
                assert unpickled_chain.parent is None
            else:
                assert unpickled_chain.parent is not None
                original_index = headers_obj._chains.index(original_chain.parent)
                unpickled_index = headers_obj2._chains.index(unpickled_chain.parent)
                assert original_index == unpickled_index

        header_1_hash_hex = '00000000b873e79784647a6c82962c70d228557d24a747ea4d1b8bbe878e1206'
        header_1_hash = hex_str_to_hash(header_1_hash_hex)

        headers_obj2.common_setup(headers_obj.coin, storage_filename(tmpdir),
            testnet_genesis_checkpoint)

        original_header, original_chain = headers_obj.lookup(header_1_hash)
        unpickled_header, unpickled_chain = headers_obj2.lookup(header_1_hash)
        assert original_header == unpickled_header

        header_2_hash_hex = '000000006c02c8ea6e4ff69651f7fcde348fb9d557a06e6957b65552002a7820'
        header_2_hash = hex_str_to_hash(header_2_hash_hex)

        original_header, original_chain = headers_obj.lookup(header_2_hash)
        unpickled_header, unpickled_chain = headers_obj2.lookup(header_2_hash)
        assert original_header == unpickled_header
