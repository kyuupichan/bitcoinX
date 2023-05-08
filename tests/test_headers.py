import copy
import math
import random
from os import urandom, path

import pytest

from bitcoinx.errors import MissingHeader, IncorrectBits, InsufficientPoW
from bitcoinx.headers import *

from bitcoinx import pack_le_uint32, double_sha256, hex_str_to_hash


some_good_bits = [486604799, 472518933, 453281356, 436956491]


def random_raw_header(prev_hash=None, good_bits=None):
    good_bits = good_bits or some_good_bits
    raw_header = bytearray(urandom(80))
    raw_header[72:76] = pack_le_uint32(random.choice(good_bits))
    if prev_hash:
        raw_header[4:36] = prev_hash
    return bytes(raw_header)


class TestChainAndHeaders:

    @classmethod
    def setup_class(cls):
        cls.N = 10
        cls.common_height = cls.N // 2

        cls.base_headers = []
        cls.fork_headers = []
        cls.headers = Headers(Bitcoin)

        for n in range(cls.N):
            raw_header = Bitcoin.genesis_header if n == 0 else random_raw_header(prev_hash)
            cls.base_headers.append(raw_header)
            cls.headers.connect(raw_header, False)
            prev_hash = header_hash(raw_header)

        cls.base_chain = list(cls.headers.tips)[0]

        prev_hash = header_hash(cls.base_headers[cls.common_height])
        for n in range(cls.N):
            raw_header = random_raw_header(prev_hash)
            cls.fork_headers.append(raw_header)
            cls.headers.connect(raw_header, False)
            prev_hash = header_hash(raw_header)

        chains = set(cls.headers.tips)
        chains.remove(cls.base_chain)
        cls.fork_chain = chains.pop()

    def test_parent(self):
        assert self.base_chain.parent is None
        assert self.fork_chain.parent is self.base_chain

    def test_first_height(self):
        assert self.base_chain.first_height == 0
        assert self.fork_chain.first_height == self.common_height + 1

    def test_height(self):
        assert self.base_chain.height == self.N - 1
        assert self.fork_chain.height == self.N + self.common_height

    def test_chainwork(self):
        assert self.base_chain.chainwork == sum(header_work(header)
                                                for header in self.base_headers)
        common_work = sum(header_work(self.base_headers[n]) for n in range(self.common_height + 1))
        fork_work = sum(header_work(header) for header in self.fork_headers)
        assert self.fork_chain.chainwork == common_work + fork_work

    def test_tip(self):
        assert self.base_chain.tip() == deserialized_header(self.base_headers[-1], self.N - 1)
        assert self.fork_chain.tip() == deserialized_header(self.fork_headers[-1],
                                                            self.common_height + self.N)
    def test_raw_header_at_height(self):
        for n in range(self.base_chain.height + 1):
            raw_header = self.base_chain.raw_header_at_height(n)
            assert isinstance(raw_header, bytes)
            assert raw_header == self.base_headers[n]

        for n in range(self.fork_chain.height + 1):
            raw_header = self.fork_chain.raw_header_at_height(n)
            assert isinstance(raw_header, bytes)
            if n <= self.common_height:
                assert raw_header == self.base_headers[n]
            else:
                assert raw_header == self.fork_headers[n - self.common_height - 1]

    def test_raw_header_missing(self):
        with pytest.raises(MissingHeader):
            self.base_chain.raw_header_at_height(-1)
        with pytest.raises(MissingHeader):
            self.base_chain.raw_header_at_height(self.N * 2)

    def test_header_at_height(self):
        for n in range(self.base_chain.height + 1):
            assert self.base_chain.header_at_height(n) == deserialized_header(
                self.base_headers[n], n)
        for n in range(self.fork_chain.height + 1):
            header = self.fork_chain.header_at_height(n)
            raw_header = self.fork_chain.raw_header_at_height(n)
            assert header == deserialized_header(raw_header, n)

    def test_header_missing(self):
        with pytest.raises(MissingHeader):
            self.base_chain.header_at_height(-1)
        with pytest.raises(MissingHeader):
            self.base_chain.header_at_height(self.N * 2)

    def test_chainwork_at_height(self):
        for n in range(self.base_chain.height + 1):
            assert self.base_chain.chainwork_at_height(n) == sum(
                header_work(self.base_headers[i]) for i in range(n + 1))
        for n in range(self.fork_chain.height + 1):
            fork_chainwork = self.fork_chain.chainwork_at_height(n)
            if n <= self.common_height:
                assert fork_chainwork == self.base_chain.chainwork_at_height(n)
            else:
                assert fork_chainwork == (
                    self.base_chain.chainwork_at_height(self.common_height) +
                    sum(header_work(self.fork_headers[i]) for i in range(n - self.common_height))
                )

    def test_chainwork_missing(self):
        with pytest.raises(MissingHeader):
            self.fork_chain.chainwork_at_height(-1)
        with pytest.raises(MissingHeader):
            self.fork_chain.chainwork_at_height(self.fork_chain.height + 1)

    def test_desc(self):
        assert self.base_chain.desc()
        assert self.fork_chain.desc()

    def test_parent_chains(self):
        assert self.base_chain.parent_chains() == [self.base_chain]
        assert self.fork_chain.parent_chains() == [self.fork_chain, self.base_chain]

    def test_common_chain_and_height(self):
        assert self.fork_chain.common_chain_and_height(self.fork_chain) == (
            self.fork_chain, self.fork_chain.height)
        assert self.fork_chain.common_chain_and_height(self.base_chain) == (
            self.base_chain, self.common_height)
        assert self.base_chain.common_chain_and_height(self.fork_chain) == (
            self.base_chain, self.common_height)
        other_chain = Chain(None, 0)
        assert self.base_chain.common_chain_and_height(other_chain) == (None, -1)

    def test_unpersisted_headers(self):
        for chain, headers in ((self.base_chain, self.base_headers),
                               (self.fork_chain, self.fork_headers)):
            for height in range(chain.first_height - 1, chain.height + 1):
                start = height - (chain.first_height - 1)
                assert chain.unpersisted_headers(height) == b''.join(
                    headers[i] for i in range(start, len(headers)))

    def test_unpersisted_headers_fails(self):
        with pytest.raises(ValueError):
            self.base_chain.unpersisted_headers(-2)
        with pytest.raises(ValueError):
            self.base_chain.unpersisted_headers(self.base_chain.height + 1)

    def test_lt(self):
        assert self.base_chain < self.fork_chain
        assert not (self.fork_chain < self.base_chain)

    # Headers

    def test_headers_len(self):
        assert len(self.headers) == self.N * 2

    def test_lookup(self):
        for height, header in enumerate(self.base_headers):
            hash = header_hash(header)
            assert self.headers.lookup(hash) == (self.base_chain, height)

        for height, header in enumerate(self.fork_headers, start=self.common_height + 1):
            hash = header_hash(header)
            assert self.headers.lookup(hash) == (self.fork_chain, height)

    def test_failed_lookup(self):
        assert self.headers.lookup(bytes(32)) == (None, -1)

    def test_connect_missing(self):
        header = random_raw_header(bytes(32))
        with pytest.raises(MissingHeader):
            self.headers.connect(header)

    def test_connect_duplicate(self):
        for n in range(0, self.N):
            assert self.headers.connect(self.base_headers[n]) == self.base_chain

    def test_incorrect_bits(self):
        prev_hash = header_hash(Bitcoin.genesis_header)
        header = random_raw_header(prev_hash, [436956491])
        with pytest.raises(IncorrectBits):
            self.headers.connect(header)

    def test_header_hash_at_height(self):
        for chain in self.headers.chains():
            for height in range(chain.height):
                assert (chain.header_hash_at_height(height) ==
                        header_hash(chain.raw_header_at_height(height)))

    def test_insufficient_pow(self):
        prev_hash = header_hash(Bitcoin.genesis_header)
        header = random_raw_header(prev_hash, [header_bits(Bitcoin.genesis_header)])
        with pytest.raises(InsufficientPoW):
            self.headers.connect(header)

    def test_chain_count(self):
        assert self.headers.chain_count() == 2

    def test_longest_chain(self):
        assert all(self.headers.longest_chain().chainwork >= chain.chainwork
                   for chain in self.headers.chains())

    def test_cursor(self):
        assert self.headers.cursor() == {chain: chain.height for chain in self.headers.chains()}

    def test_persistence(self):
        cursor = {}
        raw_headers = self.headers.unpersisted_headers(cursor)
        assert len(raw_headers) == 80 * len(self.headers)

        new_headers = Headers(self.headers.network)
        cursor = new_headers.connect_many(raw_headers)
        assert cursor == new_headers.cursor()
        assert len(new_headers) == len(self.headers)

        new_chains_by_tip = {hash: chain for chain, hash in new_headers.tips.items()}
        for chain in self.headers.chains():
            new_chain = new_chains_by_tip[self.headers.tips[chain]]
            assert chain.first_height == new_chain.first_height
            assert chain._raw_headers == new_chain._raw_headers
            assert chain.chainwork == new_chain.chainwork
            for height in range(chain.height + 1):
                assert chain.raw_header_at_height(height) == new_chain.raw_header_at_height(height)

    def test_persistence_sorting(self):
        # Add a new fork at height 1 than the fork chain
        headers = copy.copy(self.headers)
        raw_header = random_raw_header(header_hash(headers.network.genesis_header))
        chain = headers.connect(raw_header, check_work=False)
        assert headers.chain_count() == 3
        assert chain.first_height == 1

        # Check unpersisted headers are topologically sorted
        raw_headers = headers.unpersisted_headers({})
        assert raw_headers == (b''.join(self.base_headers)
                               + raw_header
                               + b''.join(self.fork_headers))

        # Add a new fork after the base of the fork fork chain
        raw_header2 = random_raw_header(header_hash(self.fork_headers[0]))
        chain = headers.connect(raw_header2, check_work=False)
        assert headers.chain_count() == 4
        assert chain.first_height == self.fork_chain.first_height + 1

        # Check unpersisted headers are topologically sorted
        raw_headers = headers.unpersisted_headers({})
        assert raw_headers == (b''.join(self.base_headers)
                               + raw_header
                               + b''.join(self.fork_headers)
                               + raw_header2)

    def test_block_locator(self):
        for chain in (self.base_chain, self.fork_chain):
            locator = chain.block_locator()
            log2h = math.log(chain.height + 1, 2)
            assert log2h <= len(locator) <= log2h + 2

            heights = [self.headers.lookup(header_hash)[1] for header_hash in locator]
            for n, height in enumerate(heights):
                assert chain.header_hash_at_height(height) == locator[n]
            assert sorted(heights) == list(reversed(heights))

        assert self.headers.block_locator() == self.headers.longest_chain().block_locator()

    @pytest.mark.parametrize('network', all_networks)
    def test_block_locator_empty_headers(self, network):
        headers = Headers(network)
        assert headers.block_locator() == [header_hash(network.genesis_header)]
