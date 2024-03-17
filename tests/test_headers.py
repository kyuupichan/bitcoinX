from bitcoinx import (
    Bitcoin, BitcoinTestnet, SimpleHeader, Header, int_to_le_bytes,
)

from .utils import (
    create_random_branch, create_random_header,
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
