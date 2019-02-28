import array
import io
import os

import pytest

from bitcoinx import (
    CheckPoint, Bitcoin, BitcoinTestnet, Headers,
    unpack_le_uint16, unpack_le_uint32, pack_le_uint32,
)
from bitcoinx.work import *

from .test_chain import create_headers


data_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


@pytest.mark.parametrize("bits,answer", (
    (0x00000000, 0x0),
    (0x03123456, 0x123456),
    (0x04123456, 0x12345600),
    (0x05009234, 0x92340000),
    (0x20123456,
     0x1234560000000000000000000000000000000000000000000000000000000000),
))
def test_bits_to_target(bits, answer):
    assert bits_to_target(bits) == answer
    assert target_to_bits(answer) == bits


@pytest.mark.parametrize("bits", (
    0x00123456, 0x01123456, 0x02123456,
    0x01003456, 0x02000056, 0x03000000, 0x04000000, 0x01fedcba, 0x04923456,
    0x00923456, 0x01803456, 0x02800056, 0x03800000, 0x04800000))
def test_bits_to_target_invalid(bits):
    with pytest.raises(ValueError) as e:
        bits_to_target(bits)
    assert 'invalid' in str(e.value)


@pytest.mark.parametrize("bits", (0xff123456, 0x21010000))
def test_bits_to_target_overflow(bits):
    with pytest.raises(ValueError) as e:
        bits_to_target(bits)
    assert 'out of range' in str(e.value)


@pytest.mark.parametrize("target,answer,canonical_target", (
    (
        0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
        0x2100ffff,
        0xffff000000000000000000000000000000000000000000000000000000000000
    ),
    (
        0x8000000000000000000000000000000000000000000000000000000000000000,
        0x21008000,
        0x8000000000000000000000000000000000000000000000000000000000000000,
    ),
    (
        0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
        0x207fffff,
        0x7fffff0000000000000000000000000000000000000000000000000000000000
    ),
    # Ensure we don't generate bits with sign bit set
    (0x80, 0x2008000, 0x80),
))
def test_target_to_bits(target, answer, canonical_target):
    assert target_to_bits(target) == answer
    assert bits_to_target(answer) == canonical_target


@pytest.mark.parametrize("target", (-1, 1 << 256))
def test_target_to_bits_out_of_range(target):
    with pytest.raises(ValueError) as e:
        target_to_bits(target)
    assert 'out of range' in str(e.value)


@pytest.mark.parametrize("bits,answer", (
    (0x00000000, 1 << 256),
    (0x207fffff, 2),
    (0x200fffff, 16),
    (0x1731d97c, 24251489930719369683417),
))
def test_bits_to_work(bits, answer):
    assert bits_to_work(bits) == answer


def setup_headers(tmpdir, headers_file):
    with open(os.path.join(data_dir, headers_file), 'rb') as f:
        raw_headers = f.read()

    last_height, = unpack_le_uint32(raw_headers[-84:-80])
    last_raw = raw_headers[-80:]
    checkpoint = CheckPoint(last_raw, last_height, 0)
    headers = create_headers(tmpdir, checkpoint)
    for offset in range(0, len(raw_headers), 84):
        height, = unpack_le_uint32(raw_headers[offset: offset + 4])
        raw_header = raw_headers[offset + 4: offset + 84]
        headers.set_one(height, raw_header)
    return headers


def test_mainnet_2016_headers(tmpdir):
    # Mainnet headers 0, 2015, 2016, 4031, 4032, ... 4249808
    headers = setup_headers(tmpdir, 'mainnet-headers-2016')

    chain = headers.chains()[0]
    for height in range(0, len(headers), 2016):
        header = headers.header_at_height(chain, height)
        assert headers.required_bits(chain, height, None) == header.bits
        assert headers.required_bits(chain, height + 1, None) == header.bits

    assert header.difficulty() == 860_221_984_436.2223

    bounded_bits = 403011440
    # Test // 4 is lower bound for the last one
    raw_header = bytearray(headers.raw_header_at_height(chain, height - 2016))
    timestamp = Bitcoin.header_timestamp(raw_header)
    # Add 8 weeks and a 14 seconds; the minimum to trigger it
    raw_header[68:72] = pack_le_uint32(timestamp + 4 * 2016 * 600 + 14)
    headers.set_one(height - 1, raw_header)
    assert headers.required_bits(chain, height, ) == bounded_bits


def setup_compressed_headers(tmpdir, headers_file, ts_offset, coin):
    with open(os.path.join(data_dir, headers_file), 'rb') as f:
        raw_data = f.read()

    all_times = array.array('I')
    all_bits = array.array('I')
    read = io.BytesIO(raw_data).read

    first_height, = unpack_le_uint32(read(4))
    header_count, = unpack_le_uint32(read(4))

    # Timestamps
    first_time, = unpack_le_uint32(read(4))
    all_times.append(first_time)
    for n in range(1, header_count):
        diff, = unpack_le_uint16(read(2))
        all_times.append(all_times[-1] + diff - ts_offset)
    # Bits
    while True:
        raw = read(4)
        if not raw:
            break
        bits, = unpack_le_uint32(raw)
        if bits < 2016 * 2:
            count = bits
            bits, = unpack_le_uint32(read(4))
            all_bits.extend(array.array('I', [bits]) * count)
        else:
            all_bits.append(bits)

    assert len(all_times) == header_count
    assert len(all_bits) == header_count

    raw_header = bytearray(80)
    raw_header[0] = 1

    checkpoint = CheckPoint(raw_header, first_height + header_count - 1, 0)
    headers = create_headers(tmpdir, checkpoint, coin=coin)

    for height, (bits, timestamp) in enumerate(zip(all_bits, all_times), start=first_height):
        raw_header[68:72] = pack_le_uint32(timestamp)
        raw_header[72:76] = pack_le_uint32(bits)
        headers.set_one(height, raw_header)

    return headers


def test_mainnet_EDA_and_DAA(tmpdir):
    # Mainnet bits and timestamps from height 478400 to 564528 inclusive
    headers = setup_compressed_headers(tmpdir, 'mainnet-headers-compressed', 300, Bitcoin)

    EDA_height = 478558
    chain = headers.chains()[0]
    for height in range(EDA_height - 3, len(headers)):
        header = headers.header_at_height(chain, height)
        required_bits = headers.required_bits(chain, height, None)
        assert headers.required_bits(chain, height, None) == header.bits


def test_testnet_fortnightly(tmpdir):
    # Testnet bits and timestamps from height 52416 to 56454 inclusive
    headers = setup_compressed_headers(tmpdir, 'testnet-headers-52416', 3600, BitcoinTestnet)

    first_height = 52417   # Avoid need to know timestamp 2016 blocks prior
    chain = headers.chains()[0]
    prior_timestamp = 0
    for height in range(first_height, len(headers)):
        header = headers.header_at_height(chain, height)
        required_bits = headers.required_bits(chain, height, header.timestamp)
        assert required_bits == header.bits
        prior_timestamp = header.timestamp
