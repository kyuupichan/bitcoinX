import io
from os.path import join

import pytest

from bitcoinx.misc import *
from bitcoinx.misc import map_file


def test_be_bytes_to_int():
    assert be_bytes_to_int(bytes([2, 3])) == 515


def test_le_bytes_to_int():
    assert le_bytes_to_int(bytes([2, 3])) == 770


def test_int_to_be_bytes():
    assert int_to_be_bytes(0) == b''
    assert int_to_be_bytes(515) == bytes([2, 3])
    assert int_to_be_bytes(515, 4) == bytes([0, 0, 2, 3])


def test_int_to_le_bytes():
    assert int_to_le_bytes(0) == b''
    assert int_to_le_bytes(770) == bytes([2, 3])
    assert int_to_le_bytes(770, 4) == bytes([2, 3, 0, 0])


def test_map_file_basic(tmpdir):
    file_name = join(tmpdir, 'file')
    data = b'abcd'
    data2 = b'efgh'
    with open(file_name, 'wb+') as f:
        f.write(data)
    mmap = map_file(file_name)
    assert len(mmap) == len(data)
    assert mmap[:] == data
    mmap[:] = data2
    mmap.close()
    with open(file_name, 'rb+') as f:
        assert f.read() == data2


def test_map_file_expand(tmpdir):
    file_name = join(tmpdir, 'file')
    data = b'abcd'
    data2 = b'efgh'
    with open(file_name, 'wb+') as f:
        f.write(data)
    mmap = map_file(file_name, 10000)
    assert len(mmap) == 10000
    assert mmap[:4] == data
    assert mmap[-4:] == bytes(4)
    mmap[-4:] = data2
    mmap.close()
    with open(file_name, 'rb+') as f:
        assert f.read(4) == data
        f.seek(-4, io.SEEK_END)
        assert f.read(4) == data2
