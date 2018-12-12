import pytest

from bitcoinx.hashes import *

cases = [
    (sha1, b'sha1',
     b'AZ\xb4\n\xe9\xb7\xccNf\xd6v\x9c\xb2\xc0\x81\x06\xe8);H'),
    (sha256, b'sha256',
     b'][\t\xf6\xdc\xb2\xd5:_\xff\xc6\x0cJ\xc0\xd5_\xab\xdfU`i\xd6c\x15E\xf4*\xa6\xe3P\x0f.'),
    (ripemd160, b'ripemd160',
     b'\x903\x91\xa1\xc0I\x9e\xc8\xdf\xb5\x1aSK\xa5VW\xf9|W\xd5'),
    (double_sha256, b'double_sha256',
     b'ksn\x8e\xb7\xb9\x0f\xf6\xd9\xad\x88\xd9#\xa1\xbcU(j1Bx\xce\xd5;s\xectL\xe7\xc5\xb4\x00'),
    (hash160, b'hash160',
     b'\xb7\xe2\xbdh(\x82\xa8\xbd\xfc\x10\x03\x00\xdc\xcbX\xb7\xe62\x18>'),
]

def test_hash_funcs():
    for func, case, result in cases:
        assert func(case) == result

def test_hash_to_hex_str():
    assert hash_to_hex_str(b'1234567890abcd') == '6463626130393837363534333231'


def test_hex_str_to_hash():
    assert hex_str_to_hash('6463626130393837363534333231') == b'1234567890abcd'
