import pytest

from bitcoinx import (
    hex_str_to_hash, bits_to_work, bits_to_target, hash_to_value, hash_to_hex_str,
)
from bitcoinx.coin import *

header_400k = (
    b'\x04\x00\x00\x009\xfa\x82\x18Hx\x1f\x02z.m\xfa\xbb\xf6\xbd\xa9 \xd9'
    b'\xaea\xb64\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\xec\xaeSj0@B\xe3'
    b'\x15K\xe0\xe3\xe9\xa8"\x0eUh\xc3C:\x9a\xb4\x9a\xc4\xcb\xb7O\x8d\xf8'
    b'\xe8\xb0\xcc*\xcfV\x9f\xb9\x06\x18\x06e,\''
)

@pytest.mark.parametrize("raw_header,header_hash,version,prev_hash,"
                         "merkle_root,timestamp,bits,nonce", (
    (
        Bitcoin.genesis_header,
        '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f',
        1,
        '0000000000000000000000000000000000000000000000000000000000000000',
        '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b',
        1231006505,
        486604799,
        2083236893
    ),
    (
        header_400k,
        '000000000000000004ec466ce4732fe6f1ed1cddc2ed4b328fff5224276e3f6f',
        4,
        '0000000000000000030034b661aed920a9bdf6bbfa6d2e7a021f78481882fa39',
        'b0e8f88d4fb7cbc49ab49a3a43c368550e22a8e9e3e04b15e34240306a53aeec',
        1456417484,
        403093919,
        657220870
    ),
))
def test_Bitcoin(raw_header, header_hash, version, prev_hash, merkle_root,
                 timestamp, bits, nonce):
    header_hash = hex_str_to_hash(header_hash)
    prev_hash = hex_str_to_hash(prev_hash)
    merkle_root = hex_str_to_hash(merkle_root)

    assert Bitcoin.header_hash(raw_header) == header_hash
    assert Bitcoin.header_prev_hash(raw_header) == prev_hash
    assert Bitcoin.header_work(raw_header) == bits_to_work(bits)
    assert Bitcoin.header_timestamp(raw_header) == timestamp

    header = Bitcoin.deserialized_header(raw_header, 0)
    assert header.version == version
    assert header.prev_hash == prev_hash
    assert header.merkle_root == merkle_root
    assert header.timestamp == timestamp
    assert header.bits == bits
    assert header.nonce == nonce
    assert header.raw == raw_header
    assert header.hash == header_hash
    assert header.height == 0
    assert header.work() == Bitcoin.header_work(raw_header)
    assert header.target() == bits_to_target(bits)
    assert header.hash_value() == hash_to_value(header_hash)
    assert header.hex_str() == hash_to_hex_str(header_hash)
    assert 'height=0' in str(header)


def test_from_WIF_byte():
    for coin in all_coins:
        if coin in (BitcoinScalingTestnet, BitcoinRegtest):
            # Testnet has the same identifiers as scaling testnet, as the latter is dumbed down.
            assert Coin.from_WIF_byte(coin.WIF_byte) is BitcoinTestnet
        else:
            assert Coin.from_WIF_byte(coin.WIF_byte) is coin
    with pytest.raises(ValueError):
        Coin.from_WIF_byte(0x01)


def test_lookup_xver_bytes():
    for coin in all_coins:
        if coin in (BitcoinScalingTestnet, BitcoinRegtest):
            # Testnet has the same identifiers as scaling testnet, as the latter is dumbed down.
            assert Coin.lookup_xver_bytes(coin.xpub_verbytes) == (BitcoinTestnet, True)
            assert Coin.lookup_xver_bytes(coin.xprv_verbytes) == (BitcoinTestnet, False)
        else:
            assert Coin.lookup_xver_bytes(coin.xpub_verbytes) == (coin, True)
            assert Coin.lookup_xver_bytes(coin.xprv_verbytes) == (coin, False)
    with pytest.raises(ValueError):
        Coin.lookup_xver_bytes(bytes.fromhex("043587ff"))


def test_P2SH_verbyte():
    assert Bitcoin.P2SH_verbyte == 0x05
    assert BitcoinTestnet.P2SH_verbyte == BitcoinScalingTestnet.P2SH_verbyte == 0xc4
