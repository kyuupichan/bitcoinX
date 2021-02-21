import os

import pytest

from bitcoinx.base58 import *

b58_chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


@pytest.mark.parametrize("value,answer", (
    (b'\0', '1'),
    (b'\0\0\0\0123456', '11129kECtd'),
    (b'Bitcoin', '3WyEDWjcVB'),
    (b'0123456789', '3i37NcgooY8f1S'),
    (bytes.fromhex('000111d38e5fc9071ffcd20b4a763cc9ae4f252bb4e48fd66a835e252'
                   'ada93ff480d6dd43dc62a641155a5'), b58_chars),
))
def test_base58_encoding(value, answer):
    assert base58_encode(value) == answer
    assert base58_decode(answer) == value


@pytest.mark.parametrize("value,c", enumerate(b58_chars))
def test_char_value(value, c):
    assert base58_decode(c) == bytes([value])


@pytest.mark.parametrize("c", set(chr(n) for n in range(256)) - set(b58_chars))
def test_bad_values(c):
    with pytest.raises(Base58Error):
        base58_decode(c)


def test_base58_decode():
    with pytest.raises(TypeError):
        base58_decode(b'foo')
    with pytest.raises(Base58Error):
        base58_decode('')


def test_base58_encode():
    with pytest.raises(TypeError):
        base58_encode('foo')
    assert base58_encode(b'') == ''


@pytest.mark.parametrize("value,answer", (
    (b'', '3QJmnh'),
    (b'foo', '4t9WKfuAB8'),
))
def test_base58_encoding_checked(value, answer):
    assert base58_encode_check(value) == answer
    assert base58_decode_check(answer) == value


def test_base58_decode_check():
    with pytest.raises(TypeError):
        base58_decode_check(b'foo')
    with pytest.raises(Base58Error):
        base58_decode_check('4t9WKfuAB9')
    with pytest.raises(Base58Error):
        base58_decode_check('4t9')


def test_base58_encode_check():
    with pytest.raises(TypeError):
        base58_encode_check('foo')


@pytest.mark.parametrize("key,value", (
    ('', False),                                 # Incorrect length
    ('Se8PHsmtYGZkpciL1cWVh7W', False),          # Incorrect length
    ('W8ZcbzkX9TSoJ54SRV9tXR', False),           # Does not begin with S
    ('SQiH93YO37ZF9rSnWjMg3Z1IO1zHHo', False),   # Not Base58
    ('S8sv8WF3zptsD2rMHsSc9D', False),           # Bad sha256 when suffixed with '?'
    ('SZEfg4eYxCJoqzumUqP34g', True),            # Good length 22
    ('S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy', True),    # Good length 30
))
def test_is_minikey(key, value):
    assert is_minikey(key) == value
