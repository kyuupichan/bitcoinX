import json
import os

import pytest

from bitcoinx import BIP32PrivateKey, Bitcoin
from bitcoinx.mnemonic import *
from bitcoinx.mnemonic import _mnemonic_from_entropy


data_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

def read_wordlist(filename):
    with open(os.path.join(data_dir, filename)) as f:
        text = f.read()
    return bip39_text_to_wordlist(text)

english_wordlist = read_wordlist('english.txt')


@pytest.mark.parametrize("text,answer", (
    ('cat dog', 'cat dog'),
    (' 　cat 　dog  ', 'cat dog'),
    ('　やきとり　きぎ　', 'やきとり きき\u3099'),
    (' élève ', 'e\u0301le\u0300ve' ),
    ('e\u0301le\u0300ve', 'e\u0301le\u0300ve' ),
))
def test_bip39_normalize_mnemonic(text, answer):
    assert bip39_normalize_mnemonic(text) == answer


@pytest.mark.parametrize("mnemonic,passphrase,answer", (
    ('cat dog', 'secret', '97e3e08653c3d414715f0cc66450c45d4c5058c9bdd66511faef508a0bbcf00'
     'c482b7aaf85a8f0bd0a5f554a6f643c4f8f9d6148b4db877e6f0d3b38d756b032'),
    ('satoshi', 'nakamoto', '4fe51b817226a539176db8a90404a271cf1ab258dbac34e5b2a054f5a4b42'
     '67fe0d2f2521bd6420cd35694a6b43942698554d492182e1c04ca59d6b8775da09e'),
), ids=['cat dog', 'satoshi']
)
def test_bip39_mnemonic_to_seed(mnemonic, passphrase, answer):
    assert bip39_mnemonic_to_seed(mnemonic, passphrase).hex() == answer


@pytest.mark.parametrize("text, result", (
    ('# A wordlist\n\r\n cat \r\ndog\n\n', ['cat', 'dog']),
    ('élève', ['e\u0301le\u0300ve']),
))
def test_bip39_text_to_wordlist(text, result):
    assert bip39_text_to_wordlist(text, check=False) == result


def test_bip39_text_to_wordlist_space():
    with pytest.raises(SyntaxError) as e:
        bip39_text_to_wordlist('cat dog', check=False)
    assert 'contain whitespace' in str(e.value)


def test_bip39_text_to_wordlist_count():
    with pytest.raises(SyntaxError) as e:
        bip39_text_to_wordlist('cat')
    assert '2048' in str(e.value)


@pytest.mark.parametrize("bits", (128, 160, 192, 224, 256))
def test_bip39_generate_mnemonic(bits):
    mnemonic = bip39_generate_mnemonic(english_wordlist, bits)
    assert isinstance(mnemonic, str)
    words = mnemonic.split()
    assert len(words) == (bits + bits // 32) // 11
    assert bip39_is_valid_mnemonic(mnemonic, english_wordlist)


def test_bip39_generate_mnemonic_count():
    with pytest.raises(ValueError) as e:
        bip39_generate_mnemonic(['foo'], 128)
    assert 'wordlist' in str(e.value)


def test_bip39_generate_mnemonic_bits():
    with pytest.raises(ValueError) as e:
        bip39_generate_mnemonic(['foo'] * 2048, 140)
    assert 'invalid number' in str(e.value)


def bip39_test_vectors():
    with open('tests/data/bip39_vectors.json') as f:
        text = f.read()
    tests = json.loads(text)
    return tests['english']


@pytest.mark.parametrize("entropy_hex, mnemonic, seed_hex, xprv", bip39_test_vectors())
def test_bip39_test_vectors(entropy_hex, mnemonic, seed_hex, xprv):
    assert mnemonic == _mnemonic_from_entropy(bytes.fromhex(entropy_hex), english_wordlist)
    seed = bip39_mnemonic_to_seed(mnemonic, 'TREZOR')
    assert seed.hex() == seed_hex
    assert BIP32PrivateKey.from_seed(seed, Bitcoin).to_extended_key_string() == xprv


def test_bip39_is_valid_mnemonic_bad_list():
    with pytest.raises(ValueError) as e:
        bip39_is_valid_mnemonic('', ['foo'])
    assert '2048 words' in str(e.value)


def test_bip39_is_valid_mnemonic_bad_words():
    words = [english_wordlist[n] for n in range(12)]
    words[2] = 'baz'
    words[8] = 'Trump'
    mnemonic = ' '.join(words)
    with pytest.raises(BIP39BadWords) as e:
        bip39_is_valid_mnemonic(mnemonic, english_wordlist)
    assert e.value.args[0] == ['baz', 'Trump']


def test_bip39_is_valid_mnemonic_bad_length():
    words = [english_wordlist[n] for n in range(11)]
    mnemonic = ' '.join(words)
    assert not bip39_is_valid_mnemonic(mnemonic, english_wordlist)
