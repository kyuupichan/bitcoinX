import array
import asyncio
import gzip
import io
import os
import random
import time

import asqlite3
import pytest


from bitcoinx import (
    Bitcoin, BitcoinTestnet, Headers, BitcoinScalingTestnet, BitcoinRegtest,
    unpack_le_uint16, unpack_le_uint32, pack_le_uint32, merkle_root,
    Header, header_hash, SimpleHeader,
    bits_to_target, target_to_bits, grind_header, bits_to_work, int_to_le_bytes,
)

from .utils import read_file, data_dir_path


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


def read_sparse_headers(headers_file):
    # File is a sequence of 84-bytes in the form height:raw_header. height is le_uint32
    # encoded.  Headers are part of a single chain
    raw_data = read_file(headers_file)

    # last_height, = unpack_le_uint32(raw_data[-84:-80])
    # last_raw = raw_data[-80:]
    raw_headers = {}
    for offset in range(0, len(raw_data), 84):
        height, = unpack_le_uint32(raw_data[offset: offset + 4])
        raw_headers[height] = raw_data[offset + 4: offset + 84]

    return raw_headers


def read_compressed_headers(headers_file, ts_offset):
    # Compressed headers just store bits and timestamps...
    raw_data = read_file(headers_file)

    all_times = array.array('I')
    all_bits = array.array('I')
    read = io.BytesIO(raw_data).read

    first_height, = unpack_le_uint32(read(4))
    header_count, = unpack_le_uint32(read(4))

    # Timestamps
    first_time, = unpack_le_uint32(read(4))
    all_times.append(first_time)
    for _ in range(1, header_count):
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
    prev_hash = bytes(32)

    raw_headers = {}
    for height, (bits, timestamp) in enumerate(zip(all_bits, all_times), start=first_height):
        raw_header[4:36] = prev_hash
        raw_header[68:72] = pack_le_uint32(timestamp)
        raw_header[72:76] = pack_le_uint32(bits)
        raw_headers[height] = raw_header.copy()
        prev_hash = header_hash(raw_header)

    return raw_headers


def read_gzipped_headers(headers_file):
    raw_headers = {}
    with gzip.open(data_dir_path(headers_file), 'rb') as f:
        first_height = unpack_le_uint32(f.read(4))[0]
        header_count = unpack_le_uint32(f.read(4))[0]

        for height in range(first_height, header_count):
            raw_headers[height] = f.read(80)

    return raw_headers


async def override_headers(headers, raw_headers):
    Headers = {}

    cum_work = 0
    for height in sorted(raw_headers):
        header = SimpleHeader(bytes(raw_headers[height]))
        cum_work += header.work()
        Headers[height] = Header(header.raw, height, 1, int_to_le_bytes(cum_work))

    # Ugly hHack for missing header in 2nd testnet case
    if min(Headers) == 1155850:
        Headers[1155168] = Headers[1155850]

    Headers_by_hash = {header.hash: header for header in Headers.values()}

    async def header_at_height(_chain_id, height):
        return Headers[height]

    async def median_time_past(prev_hash):
        height = Headers_by_hash[prev_hash].height + 1
        timestamps = [Headers[height].timestamp for height in range(height - 11, height)]
        return sorted(timestamps)[len(timestamps) // 2]

    headers.median_time_past = median_time_past
    headers.header_at_height_cached = header_at_height


async def check_bits(headers, raw_headers, first_height=None):
    chain_id = None
    first_height = first_height or min(raw_headers)
    required_bits = headers.pow_checker.required_bits
    for height in range(first_height, max(raw_headers)):
        header = await headers.header_at_height_cached(chain_id, height)
        req_bits = await required_bits(headers, header)
        assert req_bits == header.bits


def test_mainnet_2016_headers():
    # Mainnet headers 0, 2015, 2016, 4031, 4032, ... 4249808
    async def test(headers):
        chain_id = None
        raw_headers = read_sparse_headers('mainnet-headers-2016')
        await override_headers(headers, raw_headers)

        required_bits = headers.pow_checker.required_bits
        for height in range(0, max(raw_headers) + 1, 2016):
            header = await headers.header_at_height_cached(chain_id, height)
            assert await required_bits(headers, header) == header.bits

        assert header.difficulty() == 860_221_984_436.2223

        bounded_bits = 403011440
        # Test // 4 is lower bound for the last one
        prev_header = await headers.header_at_height_cached(chain_id, height - 1)
        prior_header = await headers.header_at_height_cached(chain_id, height - 2016)
        # Add 8 weeks and a 14 seconds; the minimum to trigger it
        prev_header.raw = b''.join((
            prev_header.raw[:68],
            pack_le_uint32(prior_header.timestamp + 4 * 2016 * 600 + 14),
            prev_header.raw[72:]
        ))
        assert await required_bits(headers, header) == bounded_bits

    run_test_with_headers(test, Bitcoin)


def test_mainnet_EDA_and_DAA():
    # Mainnet bits and timestamps from height 478400 to 564528 inclusive
    async def test(headers):
        raw_headers = read_compressed_headers('mainnet-headers-compressed', 300)
        await override_headers(headers, raw_headers)
        EDA_height = 478558
        await check_bits(headers, raw_headers, EDA_height - 3)

    run_test_with_headers(test, Bitcoin)


@pytest.mark.parametrize("filename, first_height", (
    ('testnet-headers-52416', 52417),
    ('testnet-headers-1155850', 1155851),
    ('testnet-headers-1175328', 1175329),
))
def test_testnet(filename, first_height):
    async def test(headers):
        raw_headers = read_compressed_headers(filename, 3600)
        await override_headers(headers, raw_headers)
        await check_bits(headers, raw_headers, first_height)

    run_test_with_headers(test, BitcoinTestnet)


def test_scalingtestnet():
    async def test(headers):
        raw_headers = read_gzipped_headers("stnheaders.gz")
        await override_headers(headers, raw_headers)
        await check_bits(headers, raw_headers)

    run_test_with_headers(test, BitcoinScalingTestnet)


def test_regtest():
    async def test(headers):
        required_bits = headers.pow_checker.required_bits
        assert (await required_bits(None, None) == headers.genesis_header.bits)

    run_test_with_headers(test, BitcoinRegtest)


def run_test_with_headers(test_func, network):
    async def run():
        async with asqlite3.connect(':memory:') as conn:
            headers = Headers(conn, 'main', network)
            await headers.initialize()
            await test_func(headers)

    asyncio.run(run())


def test_grind_header():
    target = 1 << 252
    bits = target_to_bits(target)
    version = 4
    prev_hash = os.urandom(32)
    tx_hashes = [os.urandom(32) for _ in range(random.randrange(1, 9))]
    tx_merkle_root = merkle_root(tx_hashes)
    timestamp = int(time.time())

    raw = grind_header(version, prev_hash, tx_merkle_root, timestamp, bits)
    header = SimpleHeader(raw)

    assert header.version == version
    assert header.prev_hash == prev_hash
    assert header.merkle_root == tx_merkle_root
    assert header.timestamp == timestamp
    assert header.bits == bits
    assert header.hash_value() <= target


def test_grind_header_fail():
    bits = target_to_bits(256)
    version = 4
    prev_hash = os.urandom(32)
    root = os.urandom(32)
    timestamp = int(time.time())

    assert grind_header(version, prev_hash, root, timestamp, bits, max_tries=10) is None
