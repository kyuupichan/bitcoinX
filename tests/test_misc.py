# import pytest

from bitcoinx.misc import *


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
