# Copyright (c) 2021, Neil Booth
#
# All rights reserved.
#
# Licensed under the the Open BSV License version 3; see LICENCE for details.
#

'''Mnemonic handling functionality.

Includes a BIP39 implementation and Electrum-style seed support.

BIP39 is wordlist independent; it just operates on text.  Wordlists are a GUI /
user-friendliness feature.

It is not possible to derive the mnemonic from the seed, so a wallet must store the
mnemonic a user supplied if it wants to be able to display it later.

BIP39 sucks; don't use it for new development.
'''

__all__ = ('BIP39Mnemonic', 'ElectrumMnemonic', 'Wordlists', )


from math import ceil, log

from hashlib import pbkdf2_hmac
from os import urandom
from unicodedata import normalize, combining, east_asian_width

from .hashes import sha256, hmac_sha512
from .misc import int_to_be_bytes, be_bytes_to_int, chunks, data_file_path


class Wordlists:
    '''Validate, read and cache word lists.'''

    cache = {}

    @classmethod
    def _text_to_wordlist(cls, text, expected_count):
        '''Convert text to a normalized bip39 wordlist.  Every line is assumed to be a word unless
        it starts with a '#' character or is empty.  Leading and trailing whitespace in
        lines is not significant, and words are converted to lower case.

        Raises: SyntaxError if any word contains a space, or if check is True and there
        are not 2048 words.
        '''
        text = _normalize_text(text)
        lines = [line.strip() for line in text.split('\n')]
        words = [line.lower() for line in lines if line and not line.startswith('#')]
        if any(' ' in word for word in words):
            raise SyntaxError('some words contain whitespace')
        if expected_count is not None and len(words) != expected_count:
            raise SyntaxError(f'text should contain {expected_count} words')
        return words

    @classmethod
    def _read_wordlist(cls, filename, expected_count):
        with open(data_file_path(filename), encoding='utf-8') as f:
            text = f.read()
        return cls._text_to_wordlist(text, expected_count)

    @classmethod
    def _cached_wordlist(cls, filename, expected_count):
        result = cls.cache.get(filename)
        if not result:
            result = cls.cache[filename] = cls._read_wordlist(filename, expected_count)
        return result

    @classmethod
    def original_electrum_wordlist(cls):
        return cls._cached_wordlist('electrum_old.txt', 1626)

    @classmethod
    def bip39_wordlist(cls, filename):
        return cls._cached_wordlist(filename, 2048)


class BIP39Mnemonic:
    '''BIP39 mnemonic support.'''

    class BadWords(Exception):
        pass

    # This function is split out for testing purposes
    @classmethod
    def _from_entropy(cls, entropy, wordlist):
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

    @classmethod
    def generate(cls, wordlist, bits=128):
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

        return cls._from_entropy(entropy, wordlist)

    @classmethod
    def normalize(cls, mnemonic):
        '''Return the normalized mnemonic. Leading and trailing whitespace is removed, whitespace
        is collapsed to a single space, and the mnemonic is converted to lower case.
        '''
        return ' '.join(_normalize_text(mnemonic).split()).lower()

    @classmethod
    def to_seed(cls, mnemonic, passphrase):
        '''Return a 512-bit seed generated from the mnemonic.  The validity of the mnemonic is not
        checked.
        '''
        mnemonic = cls.normalize(mnemonic).encode()
        passphrase = _normalize_text(passphrase).encode()
        return pbkdf2_hmac('sha512', mnemonic, b'mnemonic' + passphrase, iterations=2048)

    @classmethod
    def is_valid(cls, mnemonic, wordlist):
        '''Return true if the mnemonic is valid, i.e., has a correct number of words and that the
        checksum is good.  Wordlist order is significant, and the wordlist is assumed
        normalized.

        Raises ValueError if the wordlist does not contain 2048 words.  Raises
        BIP39.BadWords if the mnemonic contains words not in the wordlist.  The first
        exception argument is a list of the bad words.
        '''
        if len(wordlist) != 2048:
            raise ValueError('wordlist must contain 2048 words')
        words = cls.normalize(mnemonic).split()

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
            raise cls.BadWords(bad_words)

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


class ElectrumMnemonic:
    '''Electrum mnemonic support.'''

    @classmethod
    def generate_new(cls, wordlist, *, prefix='01', bits=132, skip_old=True):
        '''Return a new electrum mnemonic from the wordlist with the given bits of entropy.

        The wordlist can be of arbitrary length and have arbitrary words.
        '''
        if bits < 132:
            raise ValueError(f'insufficient bits to generate a mnemonic: {bits}')

        wordlist_size = len(wordlist)
        if wordlist_size < 2048:
            raise ValueError('wordlist is too short')

        word_count = ceil(bits / log(wordlist_size, 2))
        entropy, delta = _random_integer(word_count, wordlist_size)

        while True:
            mnemonic = cls._from_entropy(entropy, wordlist)
            if cls.is_valid_new(mnemonic, prefix):
                # There is a chance of about 1 in 35,000 it is also a valid old seed
                if not (skip_old and cls.is_valid_old(mnemonic)):
                    return mnemonic
            entropy += delta

    @classmethod
    def generate_old_seed(cls, *, word_count=12):
        '''Return an old electrum seed.  The result is a hex string which is how Electrum used to
        store the seed.

        When converted to a user-facing mnemonic with hex_seed_to_old() it will have the given
        number of words (12 or 24).
        '''
        if word_count not in {12, 24}:
            raise ValueError('word count must be 12 or 24')
        return urandom(word_count * 4 // 3).hex()

    @classmethod
    def normalize_new(cls, mnemonic):
        '''Return the normalized mnemonic. Leading and trailing whitespace is removed, whitespace
        is collapsed to a single space, and the mnemonic is converted to lower case.
        '''
        return ' '.join(_normalize_text(mnemonic).split()).lower()

    @classmethod
    def is_valid_new(cls, mnemonic, prefix):
        '''Return True if mnemonic is a valid new-style mnemonic for the given prefix.'''
        mnemonic = cls.normalize_new(mnemonic)
        hmac = hmac_sha512(b'Seed version', mnemonic.encode())
        return hmac.hex().startswith(prefix)

    @classmethod
    def passphrase_mangler(cls, passphrase):
        '''An Electrum-compatible passphrase mangler.  IMO this is a really bad idea.'''
        # Ugh, this normalizes whitespace, lower-cases, and strips leading and trailing.
        passphrase = cls.normalize_new(passphrase)
        # Ugh, this totally changes the meaning of words and introduces collisions
        passphrase = ''.join(c for c in passphrase if not combining(c))
        # Ugh, remove spaces between CJK words.  why exactly?
        return ''.join(c for i, c in enumerate(passphrase) if not
                       (c == ' ' and east_asian_width(passphrase[i - 1]) == 'W'
                        and east_asian_width(passphrase[i + 1]) == 'W'))

    @classmethod
    def new_to_seed(cls, mnemonic, passphrase, compatible=False):
        '''Return a 512-bit seed generated from the new-style mnemonic and passphrase.  The
        validity of the mnemonic is not checked.

        To be compatible with Electrum passphrase mangling in a bad way, pass compatible=True.
        '''
        mnemonic = cls.normalize_new(mnemonic).encode()
        passphrase_mangler = cls.passphrase_mangler if compatible else _normalize_text
        passphrase = passphrase_mangler(passphrase).encode()
        return pbkdf2_hmac('sha512', mnemonic, b'electrum' + passphrase, iterations=2048)

    @classmethod
    def normalize_old(cls, mnemonic):
        return ' '.join(mnemonic.lower().split())

    @classmethod
    def is_valid_old(cls, mnemonic):
        '''Return True if mnemonic is a valid old-style mnemonic.'''
        try:
            cls.old_to_hex_seed(mnemonic)
            return True
        except ValueError:
            pass

        # Check if it's hex of length 32 or 64.
        try:
            return len(bytes.fromhex(mnemonic)) in {16, 32}
        except ValueError:
            return False

    @classmethod
    def old_to_hex_seed(cls, mnemonic):
        mnemonic = cls.normalize_old(mnemonic)
        words = mnemonic.split()
        if len(words) not in {12, 24}:
            raise ValueError('invalid length mnemonic')
        wordlist = Wordlists.original_electrum_wordlist()
        indices = [wordlist.index(word) for word in words]

        def parts():
            n = len(wordlist)
            for pos in range(0, len(words), 3):
                i1, i2, i3 = indices[pos: pos+3]
                part = i1 + n * (((i2 - i1) % n) + n * ((i3 - i2) % n))
                if part >= 4294967296:
                    raise ValueError('mnemonic is not valid')
                yield part

        return ''.join(f'{part:08x}' for part in parts())

    @classmethod
    def hex_seed_to_old(cls, hex_seed):
        if len(hex_seed) not in {32, 64}:
            raise ValueError('hex seed has invalid length')

        def indices(hex_seed, n):
            for chunk in chunks(hex_seed, 8):
                value = int(chunk, 16)
                value, i1 = divmod(value, n)
                i3, i2 = divmod(value, n)
                i2 = (i2 + i1) % n
                i3 = (i3 + i2) % n
                yield i1
                yield i2
                yield i3

        wordlist = Wordlists.original_electrum_wordlist()
        return ' '.join(wordlist[index] for index in indices(hex_seed, len(wordlist)))

    @classmethod
    def _from_entropy(cls, entropy, wordlist):
        '''Covert entropy to a mnemonic.

        Note: this repeats until entropy is exhausted; it is not fixed-length.  The first
        word represents the least significant bits of the entropy, so this is a
        little-endian encoding.
        '''
        def words(entropy, wordlist):
            count = len(wordlist)
            while entropy:
                entropy, rem = divmod(entropy, count)
                yield wordlist[rem]

        return ' '.join(words(entropy, wordlist))


def _normalize_text(text):
    '''Return the normalized text. No elimination of leading or trailing whitespace is
    done, nor is whitespace collapsed.
    '''
    return normalize('NFKD', text)


def _random_integer(word_count, wordlist_size):
    '''Return a random integer sufficient to encode word_count words from a wordlist
    of size wordlist_size.'''

    bits = ceil(word_count * log(wordlist_size, 2)) + 16
    size = (bits + 7) // 8
    # Because of the unfortunate encoding Electrum uses, the most sigificant word cannot have
    # index 0.
    modulus = wordlist_size ** word_count
    min_value = modulus // wordlist_size + 1

    while True:
        value = be_bytes_to_int(urandom(size)) % modulus
        if value <= min_value:
            continue
        delta = 1 if value < (min_value + modulus) // 2 else -1
        return value, delta
