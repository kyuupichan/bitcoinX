from os import urandom
import random

import pytest

from bitcoinx import Bitcoin, pack_le_uint32
from bitcoinx.chain import *


good_bits = [486604799, 472518933, 453281356, 436956491]


def test_Chain():
    base = Chain(None, -1, 0)
    assert base.height == -1

    N = 10
    headers = []
    for n in range(N * 2):
        raw_header = bytearray(urandom(80))
        raw_header[72:76] = pack_le_uint32(random.choice(good_bits))
        headers.append(Bitcoin.deserialized_header(raw_header))
    indices = list(range(N * 2))
    random.shuffle(indices)

    for n, (header, index) in enumerate(zip(headers, indices)):
        if n < N:
            base._add_header(header, index)

    # Test public attributes
    assert base.height == N - 1
    assert base.work == sum(header.work() for header in headers[:N])
    assert base.tip == headers[N - 1]

    for n in range(base.height + 1):
        assert base._header_idx(n) == indices[n]

    for n in -1, N:
        with pytest.raises(MissingHeader):
            base._header_idx(n)

    # Build a fork chain
    common_height = 5
    work = sum(header.work() for header in headers[:common_height + 1])
    fork = Chain(base, common_height, work)
    for n, (header, index) in enumerate(zip(headers, indices)):
        if n >= N:
            fork._add_header(header, index)

    # Test public attributes
    assert fork.height == common_height + N
    assert fork.work == work + sum(header.work() for header in headers[N:])
    assert fork.tip == headers[-1]

    for n in range(fork.height + 1):
        if n <= common_height:
            assert fork._header_idx(n) == indices[n]
        else:
            assert fork._header_idx(n) == indices[N + (n - 1 - common_height)]

    for n in -1, 2 * N:
        with pytest.raises(MissingHeader):
            base._header_idx(n)
