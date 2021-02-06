# Copyright (c) 2021, Neil Booth
#
# All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

'''BIP39 implementation.

BIP39 is wordlist independent; it just operates on text.  Wordlists are a GUI /
user-friendliness feature.

It is not possible to derive the mnemonic from the seed, so a wallet must store the
mnemonic a user supplied if it wants to be able to display it later.

BIP39 sucks; don't use it for new development.
'''

__all__ = ('bip39_mnemonic_to_seed', 'bip39_normalize_mnemonic', 'bip39_is_valid_mnemonic',
           'bip39_text_to_wordlist', 'bip39_generate_mnemonic', 'BIP39BadWords')


from hashlib import pbkdf2_hmac
from os import urandom
from unicodedata import normalize

from .hashes import sha256
from .misc import int_to_be_bytes, be_bytes_to_int


class BIP39BadWords(Exception):
    pass


def _normalize_text(text):
    '''Return the normalized text. No elimination of leading or trailing whitespace is
    done, nor is whitespace collapsed.
    '''
    return normalize('NFKD', text)


def bip39_normalize_mnemonic(text):
    '''Return the normalized mnemonic. Leading and trailing whitespace is removed and
    whitespace is collapsed to a single space.
    '''
    return ' '.join(_normalize_text(text).split())


def bip39_mnemonic_to_seed(mnemonic, passphrase):
    '''Return a 512-bit seed generated from the mnemonic.  The validity of the mnemonic is not
    checked.
    '''
    mnemonic = bip39_normalize_mnemonic(mnemonic).encode()
    passphrase = _normalize_text(passphrase).encode()
    return pbkdf2_hmac('sha512', mnemonic, b'mnemonic' + passphrase, iterations=2048)


def bip39_is_valid_mnemonic(mnemonic, wordlist):
    '''Return true if the mnemonic is valid, i.e., has a correct number of words and that the
    checksum is good.  Wordlist order is significant, and the wordlist is assumed
    normalized.

    Raises: ValueError if the wordlist does not contain 2048 words.
    Raises: BIP39BadWords if the mnemonic contains words not in the wordlist.  The first exception
    argument is a list of the bad words.
    '''
    if len(wordlist) != 2048:
        raise ValueError('wordlist must contain 2048 words')
    words = bip39_normalize_mnemonic(mnemonic).split()

    m_len = len(words)
    if m_len not in {12, 15, 18, 21, 24}:
        return False

    def safe_index(word):
        try:
            return wordlist.index(word)
        except ValueError:
            return None

    parts = [safe_index(word) for word in words]
    bad_words = [word for part, word in zip(parts, words) if part is None]
    if bad_words:
        raise BIP39BadWords(bad_words)

    entropy = 0
    mult = 1
    for part in reversed(parts):
        entropy += part * mult
        mult *= 2048

    ent_bytes = 4 * m_len // 3
    cs_bits = m_len // 3
    cs_mod = 1 << cs_bits

    checksum = entropy % cs_mod
    entropy = int_to_be_bytes(entropy // cs_mod, size=ent_bytes)

    expected_checksum = be_bytes_to_int(sha256(entropy)) >> (256 - cs_bits)

    return expected_checksum == checksum


# This function is split out for testing purposes
def _mnemonic_from_entropy(entropy, wordlist):
    size = len(entropy)
    cs_bits = size // 4
    checksum = be_bytes_to_int(sha256(entropy)) >> (256 - cs_bits)
    entropy_cs = be_bytes_to_int(entropy) * (1 << cs_bits) + checksum

    m_len = 3 * size // 4
    parts = []
    for _ in range(m_len):
        entropy_cs, part = divmod(entropy_cs, 2048)
        parts.append(part)

    return ' '.join(wordlist[part] for part in reversed(parts))


def bip39_generate_mnemonic(wordlist, bits=128):
    '''Return a bip39 mnemonic with bits (128, 160, 192, 224 or 256) entropy.  The mnemonic is
    a space-separated list of words of length (bits + bits // 32) // 11.

    The wordlist is assumed normalized and must have 2048 words.

    Raises: ValueError if the wordlist does not contain 2048 words or bits is invalid.
    '''
    if len(wordlist) != 2048:
        raise ValueError(f'wordlist contains {len(wordlist)} words')

    if bits not in {128, 160, 192, 224, 256}:
        raise ValueError(f'invalid number of entropy bits: {bits}')

    entropy = urandom(bits // 8)

    return _mnemonic_from_entropy(entropy, wordlist)


def bip39_text_to_wordlist(text, check=True):
    '''Convert text to a normalized bip39 wordlist.  Every line is assumed to be a word unless
    it starts with a '#' character or is empty.  Leading and trailing whitespace in lines
    is not significant.

    Raises: SyntaxError if any word contains a space, or if check is True and there are not
    2048 words.
    '''
    text = _normalize_text(text)
    lines = [line.strip() for line in text.split('\n')]
    words = [line for line in lines if line and not line.startswith('#')]
    if any(' ' in word for word in words):
        raise SyntaxError('some words contain whitespace')
    if check and len(words) != 2048:
        raise SyntaxError('text must contain 2048 words')
    return words
