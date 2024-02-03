import json

import pytest

from bitcoinx import BIP32PrivateKey, Bitcoin, int_to_be_bytes
from bitcoinx.mnemonic import *
import bitcoinx.mnemonic

from .utils import Replace_os_urandom


english_wordlist = Wordlists.bip39_wordlist('english.txt')


def bip39_test_vectors():
    with open('tests/data/bip39_vectors.json') as f:
        text = f.read()
    tests = json.loads(text)
    return tests['english']


class TestWordlists:

    @pytest.mark.parametrize("text, result", (
        ('# A wordlist\n\r\n CAT \r\ndog\n\n', ['cat', 'dog']),
        ('élèvE', ['e\u0301le\u0300ve']),
    ))
    def test_text_to_wordlist(self, text, result):
        assert Wordlists._text_to_wordlist(text, None) == result

    def test_text_to_wordlist_space(self):
        with pytest.raises(SyntaxError) as e:
            Wordlists._text_to_wordlist('cat dog', None)
        assert 'contain whitespace' in str(e.value)

    def test_bip39_text_to_wordlist_count(self):
        with pytest.raises(SyntaxError) as e:
            Wordlists._text_to_wordlist('cat', 2048)
        assert '2048' in str(e.value)


class TestBIP39Mnemonic:

    @pytest.mark.parametrize("text,answer", (
        ('cat Dog', 'cat dog'),
        (' 　cat 　dog  ', 'cat dog'),
        ('　やきとり　きぎ　', 'やきとり きき\u3099'),
        (' élève ', 'e\u0301le\u0300ve'),
        ('e\u0301le\u0300ve', 'e\u0301le\u0300ve'),
    ))
    def test_normalize(self, text, answer):
        assert BIP39Mnemonic.normalize(text) == answer

    @pytest.mark.parametrize("mnemonic,passphrase,answer", (
        (' cat DOG ', 'secret', '97e3e08653c3d414715f0cc66450c45d4c5058c9bdd66511faef508a0bbcf00'
         'c482b7aaf85a8f0bd0a5f554a6f643c4f8f9d6148b4db877e6f0d3b38d756b032'),
        ('satoshi', ' nakamoto ', '4b6953dc0adb93323476bc7fcfdc5efaa687ec2535408ca85ec26d11dc793'
         '0d9a16095617880eb9699dd873a8b1532316bcde513f99ef572d8068926cabecf4e'),
        ('satoshi', ' NAKAMOTO ', 'b76966c0d7e5355e381cfc98fc354c8a9d956880f62da82874cd0516371ce'
         'bafccd79d00bc6cfc072a1bbbf4a71d5541f15cab0a4b9b2040e145ee55387b7a05'),
    ), ids=['cat dog', 'satoshi', 'NAKAMOTO']
    )
    def test_to_seed(self, mnemonic, passphrase, answer):
        assert BIP39Mnemonic.to_seed(mnemonic, passphrase).hex() == answer

    @pytest.mark.parametrize("bits", (128, 160, 192, 224, 256))
    def test_generate(self, bits):
        mnemonic = BIP39Mnemonic.generate(english_wordlist, bits)
        assert isinstance(mnemonic, str)
        words = mnemonic.split()
        assert len(words) == (bits + bits // 32) // 11
        assert BIP39Mnemonic.is_valid(mnemonic, english_wordlist)

    def test_generate_count(self):
        with pytest.raises(ValueError) as e:
            BIP39Mnemonic.generate(['foo'], 128)
        assert 'wordlist' in str(e.value)

    def test_generate_bits(self):
        with pytest.raises(ValueError) as e:
            BIP39Mnemonic.generate(['foo'] * 2048, 140)
        assert 'invalid number' in str(e.value)

    @pytest.mark.parametrize("entropy_hex, mnemonic, seed_hex, xprv", bip39_test_vectors())
    def test_bip39_test_vectors(self, entropy_hex, mnemonic, seed_hex, xprv):
        entropy = bytes.fromhex(entropy_hex)
        assert mnemonic == ' '.join(BIP39Mnemonic._words_from_entropy(entropy, english_wordlist))
        seed = BIP39Mnemonic.to_seed(mnemonic, 'TREZOR')
        assert seed.hex() == seed_hex
        assert BIP32PrivateKey.from_seed(seed).to_extended_key_string(Bitcoin) == xprv

    def test_is_valid_bad_list(self):
        with pytest.raises(ValueError) as e:
            BIP39Mnemonic.is_valid('', ['foo'])
        assert '2048 words' in str(e.value)

    def test_is_valid_bad_words(self):
        words = [english_wordlist[n] for n in range(12)]
        words[2] = 'baz'
        words[8] = 'Trump'
        mnemonic = ' '.join(words)
        with pytest.raises(BIP39Mnemonic.BadWords) as e:
            BIP39Mnemonic.is_valid(mnemonic, english_wordlist)
        assert e.value.args[0] == ['baz', 'trump']

    def test_is_valid_bad_length(self):
        words = [english_wordlist[n] for n in range(11)]
        mnemonic = ' '.join(words)
        assert not BIP39Mnemonic.is_valid(mnemonic, english_wordlist)


def one_entropy(entropy):
    return [int_to_be_bytes(entropy, 19)]


class TestElectrumMnemonic:

    # This mnemonic is a valid old and new Electrum mnemonic
    VALID_OLD_NEW = 'skin help erase offer twenty mystery noise minute wish upset sentence claim'
    # This mnemonic is a valid BIP39 and new Electrum mnemonic
    VALID_BIP39_NEW = 'balance ethics sign doctor text cattle damp force short sting coast tonight'

    @pytest.mark.parametrize("bits, prefix, _execution_count", (
        (bits, prefix, n)
        for bits in (132, 264)
        for prefix in ('01', '02')
        for n in range(10))
    )
    def test_generate_new(self, bits, prefix, _execution_count):
        mnemonic = ElectrumMnemonic.generate_new(english_wordlist, prefix=prefix, bits=bits)
        assert ElectrumMnemonic.is_valid_new(mnemonic, prefix)

    def mnemonic_to_entropy(self, mnemonic, wordlist):
        words = mnemonic.split()
        entropy = 0
        count = len(wordlist)
        for word in reversed(words):
            entropy = entropy * count + wordlist.index(word)
        return entropy

    def test_valid_old(self):
        wordlist = english_wordlist
        entropy = self.mnemonic_to_entropy(self.VALID_OLD_NEW, wordlist)
        prefix = '01'
        mnemonic = ' '.join(ElectrumMnemonic._words_from_entropy(entropy, wordlist))
        assert ElectrumMnemonic.is_valid_old(mnemonic)
        assert ElectrumMnemonic.is_valid_new(mnemonic, prefix)

        # Test we generate if not skip_old
        with Replace_os_urandom(one_entropy(entropy)):
            m =  ElectrumMnemonic.generate_new(wordlist, bits=132, prefix=prefix, skip_old=False)
        assert m == mnemonic

        # Test we don't generate it with skip_old
        with Replace_os_urandom(one_entropy(entropy)), pytest.raises(EOFError):
            ElectrumMnemonic.generate_new(wordlist, bits=132, prefix=prefix, skip_old=True)

    def test_valid_bip39(self):
        wordlist = english_wordlist
        entropy = self.mnemonic_to_entropy(self.VALID_BIP39_NEW, wordlist)
        prefix = '01'
        mnemonic = ' '.join(ElectrumMnemonic._words_from_entropy(entropy, wordlist))
        assert ElectrumMnemonic.is_valid_new(mnemonic, prefix)
        assert BIP39Mnemonic.is_valid(mnemonic, wordlist)

        # Test we generate if not skip_BIP39
        with Replace_os_urandom(one_entropy(entropy)):
            m =  ElectrumMnemonic.generate_new(wordlist, bits=132, prefix=prefix, skip_bip39=False)
        assert m == mnemonic

        # Test we don't generate it with skip_BIP39
        with Replace_os_urandom(one_entropy(entropy)), pytest.raises(EOFError):
            ElectrumMnemonic.generate_new(wordlist, bits=132, prefix=prefix, skip_bip39=True)

    def test_skip_short_mnemonic(self):
        wordlist = english_wordlist
        entropy = 500
        prefix = '01'
        with Replace_os_urandom(one_entropy(entropy)), pytest.raises(EOFError):
            ElectrumMnemonic.generate_new(wordlist, bits=132, prefix=prefix)

    @pytest.mark.parametrize("text,answer", (
        ('caT dog', 'cat dog'),
        (' 　cat 　dOg  ', 'cat dog'),
        ('　やきとり　きぎ　', 'やきとり きき\u3099'),
        (' élève ', 'e\u0301le\u0300ve'),
        ('e\u0301le\u0300ve', 'e\u0301le\u0300ve'),
    ))
    def test_normalize_new(self, text, answer):
        assert ElectrumMnemonic.normalize_new(text) == answer

    @pytest.mark.parametrize("mnemonic, passphrase, sane, electrum", (
        ('foo bar', 'none',
         '6cea46eb1b30006263e74a977ee932c9ea16fef2b7fb8dea4585a855245d3747'
         '2ec75213f7533152568a3fcdb32960fc8b201e7c156962701fe24873c117f9a8',
         '6cea46eb1b30006263e74a977ee932c9ea16fef2b7fb8dea4585a855245d3747'
         '2ec75213f7533152568a3fcdb32960fc8b201e7c156962701fe24873c117f9a8'),
        (' foo BAR ', 'NONE',
         '854e1c995c9cae464403ec161981cae33912d1bf42835233d2f2b8abed7dd658'
         '2c8b7cec2d4c4d1b2d1432c9a04afa93e36715e5c8cfb1237ea846d0a7c1305c',
         '6cea46eb1b30006263e74a977ee932c9ea16fef2b7fb8dea4585a855245d3747'
         '2ec75213f7533152568a3fcdb32960fc8b201e7c156962701fe24873c117f9a8'),
        (' foo BAR ', ' NONE ',
         'c676e45e5b3baae832c642b754f086fc644779f588bd60173df17b6fe651c47c'
         '5d1185f599c58c05e125d499cbd59ff7cd0df754cdd5169a3625199b94b56c23',
         '6cea46eb1b30006263e74a977ee932c9ea16fef2b7fb8dea4585a855245d3747'
         '2ec75213f7533152568a3fcdb32960fc8b201e7c156962701fe24873c117f9a8'),
        (' 東南 dog ', ' extension やきとり　きぎ ',
         '0cd87aaee689bf8935af9fb44b8fb1b69cad74b8ecd8ef079468c6244883539c'
         '9f912180f4f2b841df42269099fc482ef0fdbad7c9b0ee96ea0d6b1b63732165',
         '066b52821f12dc1b40b687d811f9e8c9bf723ef8e1fb7e89c23ce624472e77ce'
         '969760b2f7b697958fc0b484ea58ea4f7b93dfc25996b82b29ee94b3c0956802'),
    ))
    def test_new_to_seed(self, mnemonic, passphrase, sane, electrum):
        assert ElectrumMnemonic.new_to_seed(mnemonic, passphrase).hex() == sane
        assert ElectrumMnemonic.new_to_seed(mnemonic, passphrase, False).hex() == sane
        assert ElectrumMnemonic.new_to_seed(mnemonic, passphrase, True).hex() == electrum

    def test_generate_new_bits(self):
        with pytest.raises(ValueError) as e:
            ElectrumMnemonic.generate_new(english_wordlist, bits=128)
        assert 'insufficient bits' in str(e.value)

    def test_generate_new_wordlist(self):
        with pytest.raises(ValueError) as e:
            ElectrumMnemonic.generate_new(['bar'] * 2000)
        assert 'too short' in str(e.value)

    @pytest.mark.parametrize("word_count, _execution_count", (
        (word_count, n)
        for word_count in (12, 24)
        for n in range(10))
    )
    def test_generate_old_seed(self, word_count, _execution_count):
        hex_seed = ElectrumMnemonic.generate_old_seed(word_count=word_count)
        mnemonic = ElectrumMnemonic.hex_seed_to_old(hex_seed)
        assert len(mnemonic.split()) == word_count
        assert ElectrumMnemonic.is_valid_old(mnemonic)
        assert ElectrumMnemonic.old_to_hex_seed(mnemonic) == hex_seed

    def test_generate_old_seed_word_count(self):
        with pytest.raises(ValueError) as e:
            ElectrumMnemonic.generate_old_seed(word_count=20)
        assert 'word count' in str(e.value)

    @pytest.mark.parametrize("hex_seed,result", (
        ('43e79bb152d4256c9a6818ee8c34228c', True),
        ('43e79bb152d4256c9a6818ee8c34228cde', False),
        ('b29f20a1214a1e7748059e0f5e699b9ff5dabf2741873ba350b8de4fcc8d3cde', True),
        ('b29f20a1214a1e7748059e0f5e699b9ff5dabf2741873ba350b8de4fcc8d3c', False),
    ))
    def test_is_valid_old_hex(self, hex_seed, result):
        assert ElectrumMnemonic.is_valid_old(hex_seed) is result

    @pytest.mark.parametrize("n", (5, 11, 13, 16, 20, 23, 25))
    def test_old_to_hex_seed_bad(self, n):
        with pytest.raises(ValueError) as e:
            ElectrumMnemonic.old_to_hex_seed(' '.join(['like'] * n))
        assert 'invalid length' in str(e.value)

    @pytest.mark.parametrize("n", (15, 20, 24, 33))
    def test_hex_seed_to_old_bad(self, n):
        with pytest.raises(ValueError) as e:
            ElectrumMnemonic.hex_seed_to_old('ab' * n)
        assert 'invalid length' in str(e.value)

    @pytest.mark.parametrize("mnemonic", (
        # These happen to be valid new and old seeds.
        'happy ceiling STOLEN wheel slam mix listen gain mask vast autumn truck',
        'secret thing tomorrow victim figure six bought woman salty iron warn midnight',
        'salt funny cold again iGnore look led dirt forever marry blur dry',
        'pair feed suit sure inside rough bid behind sudden planet dumb special',
    ))
    def test_unlucky_mnemonics(self, mnemonic):
        assert ElectrumMnemonic.is_valid_new(mnemonic, '01')
        assert ElectrumMnemonic.is_valid_old(mnemonic)

    def test_old_to_hex_seed_bad_3149(self):
        # See https://github.com/spesmilo/electrum/issues/3149
        m = 'hurry idiot prefer sunset mention mist jaw inhale impossible kingdom rare squeeze'
        with pytest.raises(ValueError):
            ElectrumMnemonic.old_to_hex_seed(m)
