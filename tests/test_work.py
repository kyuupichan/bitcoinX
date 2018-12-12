import pytest

from bitcoinx.work import *


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
