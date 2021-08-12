import hashlib
from os import urandom

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


def test_hmac_sha512():
    key = b'foo'
    msg = b'bar'
    assert hmac_sha512(key, msg) == hmac_digest(key, msg, hashlib.sha512)


def test_merkle_root_empty():
    with pytest.raises(ValueError):
        merkle_root([])


def test_merkle_root_one():
    tx_hash = urandom(32)
    assert merkle_root([tx_hash]) == tx_hash
    assert merkle_root((tx_hash, )) == tx_hash


def test_merkle_root_two():
    hashes = [urandom(32), urandom(32)]
    assert merkle_root(hashes) == double_sha256(hashes[0] + hashes[1])


@pytest.mark.parametrize('tx_hashes, answer', (
    (('54247e57e4a1efdc9957c1546b77ff76d8c4007644f6ee2b4298659876712bfe',
      '7a840ee6cd354ed3c78eba768e8156ed7447f50969edadb0a2067699c776e5c6',
      'bd16637297daef8681158bf1117bfab39baaa4dd645349ff91553d06afc9a473'),
     '5160d7f550c185a0d533df7fbf0939a51adca07cc5befa5bb1e6e0f2ad2d7913'
    ),
    (('097f13a44278f01683518344cd84b109bf518b200c39c75f5925a17a067a2305',
      '06627c4a7ebed8ffc388352c32707a7d6a1d5ab774afa17849542cce5f402fad',
      '26e86e63729d2632006590615aefc43fd74a838b7641781979cb470e1fb470eb',
      '2f2d0469d02c962187be2202b06dc0c3c7ac5918be4b7f894d37cdd878cecbf3',
      '4e9c66a6c6ea6dab0219b39247fedc41834500558ccd8ae74ae1f34c81c70921',
      '6edcb74713e7279b5396a0ac17eb7a1d132791fdeff274e689d52155c4347018',
      'd562389baba0c9447f0a568e893d9934fc0dcda50cd52f0a9502dadeacd1b32c'),
     '5a0ac89d9427e27f31d8e9531e9e0aedc467ed9b2bd2a50d840ee20e48107e4d'
    ),
    (('0682e258c5ec43c4511482c9554d0bd473a660a53444eb2b78611870edbc90ae',
      '33402582ec79b44fe90c2e302c44ab3d550d5020ccb95cb0fcdbc4020b72cbbe',
      '8836e5dc968478d11fc7dd8d469a77fc4524eae7b9b0cf62f6b22c921731c43b',
      '913c36738a034568a33f641d3653d40706358124cf7e0d1c1c4893eac6bb4162'),
     '6a3aa0a0357eb7c169c688773f88f849d4dd1cca76792a84e5d90119a3527510',
    ),
))
def test_merkle_root(tx_hashes, answer):
    answer = hex_str_to_hash(answer)
    # Test a generator is accepted
    assert merkle_root(hex_str_to_hash(tx_hash) for tx_hash in tx_hashes) == answer
    # Test a tuple is accepted
    assert merkle_root(tuple(hex_str_to_hash(tx_hash) for tx_hash in tx_hashes)) == answer
