import os

from base64 import b64decode, b64encode
import pytest

from bitcoinx.consts import CURVE_ORDER, SIGNED_MESSAGE_PREFIX
from bitcoinx.errors import DecryptionError, InvalidSignature
from bitcoinx.keys import *
from bitcoinx.hashes import sha256, sha512, _sha256, hmac_digest, hash160, double_sha256
from bitcoinx.misc import int_to_be_bytes
from bitcoinx import Bitcoin, BitcoinTestnet
from bitcoinx import pack_byte, base58_encode_check, Address, pack_varbytes


one = bytes(31) + bytes([1])
global_privkey = PrivateKey.from_random()


WIF_tests = [
    (Bitcoin, "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
     "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d", False),
    (Bitcoin, "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617",
     "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d", True),
    (Bitcoin, "5HpHgWkLaovGWySEFpng1XQ6pdG1TzNWR7SrETvfTRVdKHNXZh8",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", False),
    (Bitcoin, "KwDidQJHSE67VJ6MWRvbBKAxhD3F48DvqRT6JRqrjd7MHLBjGF7V",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", True),
    (BitcoinTestnet, "91gGn1HgSap6CbU12F6z3pJri26xzp7Ay1VW6NHCoEayNXwRpu2",
     "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d", False),
    (BitcoinTestnet, "cMzLdeGd5vEqxB8B6VFQoRopQ3sLAAvEzDAoQgvX54xwofSWj1fx",
     "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d", True),
]


def test_constants():
    assert CURVE_ORDER == \
        115792089237316195423570985008687907852837564279074904382605163141518161494337
    assert SIGNED_MESSAGE_PREFIX == pack_varbytes('Bitcoin Signed Message:\n'.encode())


class TestPrivateKey:

    @pytest.mark.parametrize("bad_key", (
        1,
        'g',
    ))
    def test_bad_type(self, bad_key):
        with pytest.raises(TypeError):
            PrivateKey(bad_key)

    @pytest.mark.parametrize("bad_key", (
        int_to_be_bytes(CURVE_ORDER),
        int_to_be_bytes(CURVE_ORDER + 1),
        b'',
        bytes(30) + bytes([1]),
        bytes(32),
    ))
    def test_bad_value(self, bad_key):
        with pytest.raises(ValueError):
            PrivateKey(bad_key)

    @pytest.mark.parametrize("good_key", (
        one,
        bytes(31) + bytes([1]),
        int_to_be_bytes(CURVE_ORDER - 1),
    ))
    def test_good(self, good_key):
        p = PrivateKey(good_key)

    def test_constructor(self):
        secret = os.urandom(32)
        p1 = PrivateKey(secret, True, Bitcoin)
        p2 = PrivateKey(secret, network=BitcoinTestnet, compressed=False)
        assert p1.to_bytes() is secret and p2.to_bytes() is secret
        assert p1 == p2
        assert p1.network() is Bitcoin and p2.network() is BitcoinTestnet
        assert p1.is_compressed()
        assert not p2.is_compressed()
        p3 = PrivateKey(secret)
        assert p3.network() is Bitcoin
        assert p3.is_compressed()

    def test_from_arbitrary_bytes(self):
        p = PrivateKey.from_arbitrary_bytes(b'BitcoinSV')
        assert p._secret == bytes(23) + b'BitcoinSV'
        p = PrivateKey.from_arbitrary_bytes(double_sha256(b'a') + double_sha256(b'b'))
        assert p.to_hex() == '6d2611b247da5cfe25f82673fb52d1739635bedfd3f1c2aa0bc5b10c044f18e9'
        with pytest.raises(ValueError):
            PrivateKey.from_arbitrary_bytes(bytes(46))
        with pytest.raises(ValueError):
            PrivateKey.from_arbitrary_bytes(int_to_be_bytes(CURVE_ORDER) * 10)

    def test_eq(self):
        secret = os.urandom(32)
        p1 = PrivateKey(secret)
        p2 = PrivateKey(bytes(secret))
        assert p1 is not p2
        assert p1 == p2
        p2 = PrivateKey(os.urandom(32))
        assert p1 != p2
        # Non-PrivateKeys
        assert p1 != 0
        assert p1 != 'foo'

    def test_hashable(self):
        secret = os.urandom(32)
        p1 = PrivateKey(secret, True, Bitcoin)
        p2 = PrivateKey(secret, False, BitcoinTestnet)
        assert len({p1, p2}) == 1

    def test_public_key(self):
        secret = os.urandom(32)
        for network in (Bitcoin, BitcoinTestnet):
            for compressed in (False, True):
                p = PrivateKey(secret, compressed, network)
                P = p.public_key
                assert P.network() is network
                assert P.is_compressed() is compressed

    def test_public_key_bad(self):
        # Force coverage with a fake condition
        priv = PrivateKey.from_random()
        priv._secret = bytes(32)
        with pytest.raises(RuntimeError):
            priv.public_key

    def test_to_int(self):
        secret = os.urandom(32)
        p = PrivateKey(secret)
        assert p.to_int() == int.from_bytes(secret, 'big')

    def test_to_bytes(self):
        secret = os.urandom(32)
        p = PrivateKey(secret)
        assert p.to_bytes() == secret

    @pytest.mark.parametrize("value", [1, 283758232, 1 << 31, ])
    def test_from_int(self, value):
        p = PrivateKey.from_int(value)
        assert p.to_int() == value
        assert p.network() is Bitcoin
        assert p.is_compressed()

    @pytest.mark.parametrize("value", [0, 0x0, 00])
    def test_from_int_bad(self, value):
        with pytest.raises(ValueError):
            PrivateKey.from_int(value)

    @pytest.mark.parametrize("value", [-1, 1 << 256])
    def test_from_int_overflow(self, value):
        with pytest.raises(OverflowError):
            PrivateKey.from_int(value)

    def test_to_hex(self):
        secret = os.urandom(32)
        p = PrivateKey(secret)
        assert p.to_hex() == secret.hex()

    @pytest.mark.parametrize("value", [1, 283758232, 1 << 31, ])
    def test_from_hex(self, value):
        hex_str = hex(value)[2:]  # Drop 0x
        if len(hex_str) < 64:
            hex_str = '0' * (64 - len(hex_str)) + hex_str
        p = PrivateKey.from_hex(hex_str)
        assert p.to_int() == value
        assert p.network() is Bitcoin
        assert p.is_compressed()

    @pytest.mark.parametrize("hex_str", ['', '00', '2345', '  ' + '11' * 30 + '  '])
    def test_from_hex_bad(self, hex_str):
        with pytest.raises(ValueError):
            PrivateKey.from_hex(hex_str)

    def test_from_text(self):
        priv = PrivateKey.from_random()
        # Hex
        priv2 = PrivateKey.from_text(priv.to_hex())
        assert priv2 == priv
        # Minikey
        assert (PrivateKey.from_text('SZEfg4eYxCJoqzumUqP34g')
                == PrivateKey.from_minikey('SZEfg4eYxCJoqzumUqP34g'))
        # WIF
        assert (PrivateKey.from_text('KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617')
                == PrivateKey.from_WIF('KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617'))

    @pytest.mark.parametrize("text", ['01' * 31, 'SZEfg4eYxCJoqzumUqP34',
                                      'wdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617'])
    def test_from_text_bad(self, text):
        with pytest.raises(ValueError):
            PrivateKey.from_text(text)

    def test_from_random(self):
        secret = int_to_be_bytes(39823453, 32)
        values = [secret, int_to_be_bytes(0, 32), int_to_be_bytes(CURVE_ORDER, 32)]

        def source(size):
            assert size == 32
            return values.pop()

        p = PrivateKey.from_random(source=source)
        assert p.to_bytes() == secret
        assert p.network() is Bitcoin
        assert p.is_compressed()

    @pytest.mark.parametrize("minikey", ['SZEfg4eYxCJoqzumUqP34g',
                                         'S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy'])
    def test_from_minikey(self, minikey):
        p = PrivateKey.from_minikey(minikey)
        assert p._secret == sha256(minikey.encode())
        assert p.network() is Bitcoin
        assert not p.is_compressed()

    @pytest.mark.parametrize("minikey", ['SZEfg4eYxCJoqzumUqP34h',
                                         'S6c56bnXQiBjk9mqSYE7ykVQ7NzrRz'])
    def test_from_minikey_bad(self, minikey):
        with pytest.raises(ValueError):
            PrivateKey.from_minikey(minikey)

    @pytest.mark.parametrize("network,WIF,hex_str,compressed", WIF_tests)
    def test_from_WIF(self, network, WIF, hex_str, compressed):
        p = PrivateKey.from_WIF(WIF)
        assert p.to_hex() == hex_str
        assert p.network() is network
        assert p._compressed == compressed
        assert len(p.public_key.to_bytes()) == (33 if compressed else 65)
        assert p.to_WIF() == WIF

    def test_from_WIF_bad(self):
        with pytest.raises(TypeError):
            PrivateKey.from_WIF(b'6')
        with pytest.raises(TypeError):
            PrivateKey.from_WIF(1)
        with pytest.raises(ValueError):
            PrivateKey.from_WIF('4t9WKfuAB8')

    @pytest.mark.parametrize("value", list(range(256)))
    def test_from_WIF_bad_suffix_byte(self, value):
        payload = pack_byte(Bitcoin.WIF_byte) + global_privkey.to_bytes() + pack_byte(value)
        WIF = base58_encode_check(payload)
        if value == 0x01:
            PrivateKey.from_WIF(WIF)
        else:
            with pytest.raises(ValueError):
                PrivateKey.from_WIF(WIF)

    @pytest.mark.parametrize("network,WIF,hex_str,compressed", WIF_tests)
    def test_to_WIF(self, network, WIF, hex_str, compressed):
        p = PrivateKey.from_hex(hex_str)
        assert p.to_WIF(network=network, compressed=compressed) == WIF

    def test_to_WIF_no_args(self):
        p = PrivateKey.from_random()
        assert p.to_WIF() == p.to_WIF(network=Bitcoin, compressed=True)

    def test_add_one(self):
        p1 = PrivateKey.from_random()
        p2 = p1.add(one)
        assert p2.to_int() == p1.to_int() + 1

    def test_subtract_one(self):
        p1 = PrivateKey.from_random()
        p2 = p1.add(int_to_be_bytes(CURVE_ORDER - 1))
        assert p1.to_int() - 1 == p2.to_int()

    def test_add(self):
        p1 = PrivateKey.from_random()
        p2 = PrivateKey.from_random()
        p2_int = p2.to_int()
        result = (p1.to_int() + p2_int) % CURVE_ORDER
        p3 = p2.add(p1._secret)
        assert p3.to_int() == result
        assert p2.to_int() == p2_int

    @pytest.mark.parametrize("network,WIF,hex_str,compressed", WIF_tests)
    def test_add_preserves_attributes(self, network, WIF, hex_str, compressed):
        p = PrivateKey.from_WIF(WIF).add(one)
        assert p.network() is network
        assert p.is_compressed() is compressed

    def test_add_bad(self):
        p1 = PrivateKey.from_random()
        with pytest.raises(ValueError):
            p1.add(int_to_be_bytes(CURVE_ORDER - p1.to_int()))
        with pytest.raises(ValueError):
            p1.add(int_to_be_bytes(CURVE_ORDER))
        with pytest.raises(ValueError):
            p1.add(int_to_be_bytes(CURVE_ORDER + 1))
        with pytest.raises(ValueError):
            p1.add(bytes(33))
        with pytest.raises(ValueError):
            p1.add(b'1' * 31)
        with pytest.raises(TypeError):
            p1.add('')

    def test_mult_one(self):
        p1 = PrivateKey.from_random()
        value = p1.to_int()
        p2 = p1.multiply(one)
        assert p2.to_int() == value

    def test_mult(self):
        p1 = PrivateKey.from_random()
        p2 = PrivateKey.from_random()
        p2_int = p2.to_int()
        result = (p1.to_int() * p2_int) % CURVE_ORDER
        p3 = p2.multiply(p1._secret)
        assert p3.to_int() == result
        assert p2.to_int() == p2_int

    @pytest.mark.parametrize("network,WIF,hex_str,compressed", WIF_tests)
    def test_mult_preserves_attributes(self, network, WIF, hex_str, compressed):
        p = PrivateKey.from_WIF(WIF).multiply(one)
        assert p.network() is network
        assert p.is_compressed() is compressed

    def test_mult_bad(self):
        p1 = PrivateKey.from_random()
        with pytest.raises(ValueError):
            p1.multiply(bytes(32))
        with pytest.raises(ValueError):
            p1.multiply(int_to_be_bytes(CURVE_ORDER))
        with pytest.raises(ValueError):
            p1.multiply(int_to_be_bytes(CURVE_ORDER + 1))
        with pytest.raises(ValueError):
            p1.add(bytes(33))
        with pytest.raises(ValueError):
            p1.add(b'1' * 31)
        with pytest.raises(TypeError):
            p1.add('')

    def test_sign(self):
        p = PrivateKey(bytes(range(32)))
        msg = b'BitcoinSV'
        result = p.sign(msg)
        assert result.hex() == (
            '3045022100914038d25ac6d195fa8e9b25c6c22a1cb711fde4a11fe305175b52fc77a12'
            '04002202575b92f63cc6b08893cbd6791d41259129c7d9d5162258c19836976871f63bd'
        )
        assert p.sign(msg, hasher=sha256) == result
        assert p.sign(sha256(msg), hasher=None) == result

    def test_sign_bad_privkey(self):
        p = PrivateKey(bytes(range(32)))
        p._secret = bytes(32)
        msg = b'BitcoinSV'
        with pytest.raises(ValueError):
            p.sign(msg)

    def test_sign_bad_hasher(self):
        p = PrivateKey(bytes(range(32)))
        msg = b'BitcoinSV'

        def bad_hasher(data):
            return sha256(data)[:31]

        with pytest.raises(ValueError):
            p.sign(msg, hasher=bad_hasher)

    def test_sign_string(self):
        p = PrivateKey(bytes(range(32)))
        msg = 'BitcoinSV'
        with pytest.raises(TypeError):
            p.sign(msg)

    def test_sign_recoverable(self):
        p = PrivateKey(bytes(range(32)))
        msg = b'BitcoinSV'
        result = p.sign_recoverable(msg)
        assert result.hex() == (
            '914038d25ac6d195fa8e9b25c6c22a1cb711fde4a11fe305175b52fc77a12040'
            '2575b92f63cc6b08893cbd6791d41259129c7d9d5162258c19836976871f63bd01'
        )
        assert p.sign_recoverable(msg, hasher=sha256) == result
        assert p.sign_recoverable(sha256(msg), hasher=None) == result

    def test_sign_recoverable_bad_privkey(self):
        p = PrivateKey(bytes(range(32)))
        p._secret = bytes(32)
        msg = b'BitcoinSV'
        with pytest.raises(ValueError):
            p.sign_recoverable(msg)

    def test_sign_recoverable_bad_hasher(self):
        p = PrivateKey(bytes(range(32)))
        msg = b'BitcoinSV'

        def bad_hasher(data):
            return sha256(data)[:31]

        with pytest.raises(ValueError):
            p.sign_recoverable(msg, hasher=bad_hasher)

    def test_sign_recoverable_string(self):
        p = PrivateKey(bytes(range(32)))
        msg = 'BitcoinSV'
        with pytest.raises(TypeError):
            p.sign_recoverable(msg)

    @pytest.mark.parametrize("msg", (b'BitcoinSV', 'BitcoinSV'))
    def test_sign_message_and_to_base64(self, msg):
        secret = 'L4n6D5GnWkASz8RoNwnxvLXsLrn8ZqUMcjF3Th2Uas476qusFKYf'
        priv = PrivateKey.from_WIF(secret)
        priv._compressed = True
        msg_sig = priv.sign_message(msg)
        for encoded_sig in (b64encode(msg_sig).decode(), priv.sign_message_to_base64(msg)):
            assert encoded_sig == ('IIccCk2FG2xufHJmSqnrnOo/b6gPw+A+EpVAJEqfSqV0Nu'
                                   'LXYiio6UZfvY/vmuI6jyNj/REuTFxxkhBM+zWA7jE=')

        priv._compressed = False
        msg_sig = priv.sign_message(msg)
        assert b64encode(msg_sig) == (b'HIccCk2FG2xufHJmSqnrnOo/b6gPw+A+EpVAJEqfSqV0Nu'
                                      b'LXYiio6UZfvY/vmuI6jyNj/REuTFxxkhBM+zWA7jE=')

    def test_sign_message_hash(self):
        priv = PrivateKey.from_random()
        # Not a hash, a message
        priv.sign_message(bytes(32))
        # We don't permit signing message hashes directly
        with pytest.raises(ValueError):
            priv.sign_message(bytes(32), hasher=None)

    def test_sign_message_long(self):
        secret = 'L4n6D5GnWkASz8RoNwnxvLXsLrn8ZqUMcjF3Th2Uas476qusFKYf'
        priv = PrivateKey.from_WIF(secret)
        P = priv.public_key
        msg = (
            'A purely peer-to-peer version of electronic cash would allow online payments to be se'
            'nt directly from one party to another without going through a financial institution. '
            'Digital signatures provide part of the solution, but the main benefits are lost if '
            'a trusted third party is still required to prevent double-spending.'
        )
        msg_sig = priv.sign_message(msg)
        assert b64encode(msg_sig).decode() == (
            'H7iIlcANsbiKmCGgMus8GIw8AYjQs+uzUQX1z/bFyv8aeJlGBM'
            '1rG4B7SvE0vDDT1q2T6wSElIp6wysKJKOH7RQ='
        )

    def test_ecdh_shared_secret(self):
        p1 = PrivateKey.from_random()
        p2 = PrivateKey.from_random()
        ecdh_secret = p1.ecdh_shared_secret(p2.public_key)
        assert ecdh_secret == p2.ecdh_shared_secret(p1.public_key)
        assert p1.shared_secret(p2.public_key, bytes(32), None) == ecdh_secret

    def test_shared_secret(self):
        p = PrivateKey(bytes(range(32)))
        p2 = PrivateKey(bytes(range(1, 33)))
        msg = b'BitcoinSV'
        P = p.shared_secret(p2.public_key, msg)
        assert P.to_hex() == '034339a901d8526c4d733c8ea7c861f1a6324f37f6b86f838725820e0c5fc19570'
        assert P == p.shared_secret(p2.public_key, msg, sha256)
        assert P == p.shared_secret(p2.public_key, sha256(msg), hasher=None)

    def test_shared_secret_is_shared(self):
        ours = PrivateKey.from_random()
        theirs = PrivateKey.from_random()

        msg = b'BitcoinSV'
        our_P = ours.shared_secret(theirs.public_key, msg)
        their_P = theirs.shared_secret(ours.public_key, msg)

        assert our_P == their_P

    def test_decrypt_message_fails(self):
        priv = PrivateKey(bytes(range(32)))
        P = priv.public_key
        msg = b'BitcoinSV'
        enc_msg = P.encrypt_message(msg)

        with pytest.raises(DecryptionError) as e:
            priv.decrypt_message(b64encode(enc_msg).decode() + '%')
        assert 'invalid base64' in str(e.value)

        with pytest.raises(DecryptionError) as e:
            priv.decrypt_message(bytes(84))
        assert 'too short' in str(e.value)

        with pytest.raises(DecryptionError) as e:
            priv.decrypt_message(enc_msg, magic=b'Z')
        assert 'bad magic' in str(e.value)

        # Bad pubkey first byte
        enc_msg2 = bytearray(enc_msg)
        enc_msg2[4] ^= 2
        with pytest.raises(DecryptionError) as e:
            priv.decrypt_message(bytes(enc_msg2))
        assert 'invalid ephemeral public key' in str(e.value)

        # Bad padding.  Triggering this is work...
        ephemeral_pubkey = PublicKey.from_bytes(enc_msg[4: 37])
        key = sha512(priv.ecdh_shared_secret(ephemeral_pubkey).to_bytes())
        iv, key_e, key_m = key[0:16], key[16:32], key[32:]

        encrypted_data = bytearray(enc_msg[:-32])
        encrypted_data[-1] ^= 1    # Bad padding
        enc_msg = bytes(encrypted_data) + hmac_digest(key_m, encrypted_data, _sha256)
        with pytest.raises(DecryptionError) as e:
            priv.decrypt_message(enc_msg)
        assert 'padding' in str(e.value)

        enc_msg = bytes.fromhex(
            '4249453102e5cde5b5924d745958ba05c87d6d8930c6314481fbdefa02d8f4bafc8a2e1dee7d9c3e9d704'
            '8d72c63fc3e7b76f7f0d0b99c9b75ac78af43442e5926ea9fbaab1d4d32d71a4237e432bc2bbf7808fcd3'
        )
        with pytest.raises(DecryptionError) as e:
            priv.decrypt_message(enc_msg)
        assert 'inconsistent padding bytes' in str(e.value)

        # A valid encrypted message but for the wrong key; should give hmac mismatch
        enc_msg = P.add(one).encrypt_message(msg)
        with pytest.raises(DecryptionError) as e:
            priv.decrypt_message(enc_msg)
        assert 'bad HMAC' in str(e.value)

    def test_str(self):
        p = PrivateKey.from_random()
        assert str(p) == sha256(p.to_bytes()).hex()


class TestPublicKey:

    @pytest.mark.parametrize("bad_key", (
        1,
        bytes.fromhex('036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2'),
        'g',
    ))
    def test_bad_type(self, bad_key):
        with pytest.raises(TypeError):
            PublicKey(bad_key, True)

    def test_good(self):
        pub = PrivateKey.from_random().public_key
        PublicKey(pub._public_key, False)

    def test_eq(self):
        secret = os.urandom(32)
        priv = PrivateKey(secret)
        pub1 = priv.public_key
        pub2 = PublicKey(pub1._public_key, False)
        assert pub1 is not pub2
        assert pub1 == pub2
        assert PrivateKey.from_random().public_key != pub1
        # Other types
        assert pub1 != 0
        assert pub1 != 'foo'

    def test_public_key(self):
        pub = PrivateKey.from_random().public_key
        assert pub.public_key is pub

    def test_hashable(self):
        secret = os.urandom(32)
        p1 = PrivateKey(secret, True, Bitcoin)
        p2 = PrivateKey(secret, False, BitcoinTestnet)
        pub1 = p1.public_key
        pub2 = p2.public_key
        assert pub1.is_compressed() != pub2.is_compressed()
        assert pub1.network() != pub2.network()
        assert len({pub1, pub2}) == 1

    def test_to_bytes(self):
        priv = PrivateKey(bytes(range(32)))
        pub = priv.public_key
        assert pub.to_bytes().hex() == pub.to_bytes(compressed=True).hex() == (
            '036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2'
        )

        assert pub.to_bytes(compressed=False).hex() == (
            '046d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e'
            '2487e6222a6664e079c8edf7518defd562dbeda1e7593dfd7f0be285880a24dab'
        )

    def test_from_bytes(self):
        priv = PrivateKey.from_random()
        for compressed in (False, True):
            pub = PublicKey.from_bytes(priv.public_key.to_bytes(compressed=compressed))
            assert pub == priv.public_key
            assert pub.network() is Bitcoin
            assert pub.is_compressed() is compressed

    def test_from_bytes_bad(self):
        priv = PrivateKey(bytes(range(32)))
        pub = priv.public_key
        data = pub.to_bytes(compressed=False)[:-1] + bytes(1)
        with pytest.raises(ValueError):
            PublicKey.from_bytes(data)

    def test_to_hex(self):
        priv = PrivateKey(bytes(range(32)))
        pub = priv.public_key
        assert pub.to_hex() == pub.to_hex(compressed=True) == (
            '036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2'
        )

        assert pub.to_hex(compressed=False) == (
            '046d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e'
            '2487e6222a6664e079c8edf7518defd562dbeda1e7593dfd7f0be285880a24dab'
        )

    def test_from_hex(self):
        priv = PrivateKey(bytes(range(32)))
        pub = priv.public_key

        assert pub == PublicKey.from_hex(
            '046d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2'
            '487e6222a6664e079c8edf7518defd562dbeda1e7593dfd7f0be285880a24dab'
        )

        assert pub == PublicKey.from_hex(
            '036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2'
        )

    def test_from_hex_bad(self):
        with pytest.raises(ValueError):
            PublicKey.from_hex(
                '046d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2'
                '487e6222a6664e079c8edf7518defd562dbeda1e7593dfd7f0be285880a24daa'
            )

    def test_to_point(self):
        priv = PrivateKey(bytes(range(32)))
        pub = priv.public_key

        assert pub.to_point() == (
            49494098513335428077054975730806467664514612540321453185917289738417036617954,
            32789825133461354718917898111687295334475538855588308840542926904654395755947
        )

    def test_from_point(self):
        priv = PrivateKey(bytes(range(32)))
        pub = priv.public_key

        x = 49494098513335428077054975730806467664514612540321453185917289738417036617954
        y = 32789825133461354718917898111687295334475538855588308840542926904654395755947

        assert PublicKey.from_point(x, y) == pub

    def test_from_point_bad(self):
        x = 49494098513335428077054975730806467664514612540321453185917289738417036617954
        y = 32789825133461354718917898111687295334475538855588308840542926904654395755948
        with pytest.raises(ValueError):
            PublicKey.from_point(x, y)

    def test_to_address(self):
        priv = PrivateKey(bytes(range(32)))
        pub = priv.public_key

        assert pub.to_address() == Address.from_string('16ZbRYV2f1NNuNQ9FDYyUMC2d1cjGS2G3L',
                                                       Bitcoin)
        assert pub.to_address(compressed=False) == Address.from_string(
            '1G9f5Kdd5A8MeBN8jduUNfcAXUVvtFxVhP', Bitcoin)

        assert pub.to_address(network=Bitcoin) == Address.from_string(
            '16ZbRYV2f1NNuNQ9FDYyUMC2d1cjGS2G3L', Bitcoin)
        assert pub.to_address(network=Bitcoin, compressed=False) == Address.from_string(
            '1G9f5Kdd5A8MeBN8jduUNfcAXUVvtFxVhP', Bitcoin)

        assert pub.to_address(network=BitcoinTestnet, compressed=True) == Address.from_string(
            'mm5Yiba1U2odgUskxnXMJGQMV1DSAXVPib', BitcoinTestnet)
        assert pub.to_address(network=BitcoinTestnet, compressed=False) == Address.from_string(
            'mvfcNNibtBZcRHqkTCsrCapVPU6dpCoKjp', BitcoinTestnet)

    def test_add(self):
        priv = PrivateKey.from_random()
        value = os.urandom(32)

        P = priv.public_key
        priv2 = priv.add(value)
        P2 = P.add(value)
        assert P2 == priv2.public_key
        assert P == priv.public_key

    @pytest.mark.parametrize("network,WIF,hex_str,compressed", WIF_tests)
    def test_add_preserves_attributes(self, network, WIF, hex_str, compressed):
        P = PrivateKey.from_WIF(WIF).public_key.add(one)
        assert P.network() is network
        assert P.is_compressed() is compressed

    def test_add_bad(self):
        priv = PrivateKey.from_random()
        P = priv.public_key

        value = int_to_be_bytes(CURVE_ORDER - priv.to_int())
        with pytest.raises(ValueError):
            P.add(value)
        with pytest.raises(ValueError):
            P.add(bytes(33))
        with pytest.raises(ValueError):
            P.add(b'1' * 31)
        with pytest.raises(TypeError):
            P.add('')

    def test_multiply(self):
        priv = PrivateKey.from_random()
        value = os.urandom(32)
        priv2 = priv.multiply(value)

        P = priv.public_key
        P2 = P.multiply(value)
        assert P2 == priv2.public_key
        assert P == priv.public_key

    @pytest.mark.parametrize("network,WIF,hex_str,compressed", WIF_tests)
    def test_multiply_preserves_attributes(self, network, WIF, hex_str, compressed):
        P = PrivateKey.from_WIF(WIF).public_key.multiply(one)
        assert P.network() is network
        assert P.is_compressed() is compressed

    def test_multiply_bad(self):
        priv = PrivateKey.from_random()
        P = priv.public_key

        with pytest.raises(ValueError):
            P.multiply(bytes(32))
        with pytest.raises(ValueError):
            P.multiply(bytes(33))
        with pytest.raises(ValueError):
            P.multiply(b'1' * 31)
        with pytest.raises(TypeError):
            P.multiply('')

    def test_combine_keys_none(self):
        with pytest.raises(ValueError):
            PublicKey.combine_keys([])

    def test_combine_keys_self(self):
        priv = PrivateKey.from_random()
        P = priv.public_key
        P2 = PublicKey.combine_keys([P])
        assert P is not P2
        assert P == P2

        priv2 = priv.add(priv._secret)
        assert PublicKey.combine_keys([P, P]) == priv2.public_key

    @pytest.mark.parametrize("compressed,network", (
        (True, Bitcoin), (False, Bitcoin), (True, BitcoinTestnet), (False, BitcoinTestnet),
    ))
    def test_combine_keys(self, compressed, network):
        priv_keys = [PrivateKey.from_random() for n in range(5)]
        priv_keys[0]._compressed = compressed
        priv_keys[0]._network = network
        pub_keys = [priv_key.public_key for priv_key in priv_keys]

        pk = priv_keys[0]
        for n in range(1, len(priv_keys)):
            pk = pk.add(priv_keys[n]._secret)
        combined = PublicKey.combine_keys(pub_keys)
        assert pk.public_key == combined
        assert combined.network() is network
        assert combined.is_compressed() is compressed

    def test_combine_keys_bad(self):
        priv = PrivateKey.from_random()
        priv2 = PrivateKey(int_to_be_bytes(CURVE_ORDER - priv.to_int(), size=32))
        with pytest.raises(ValueError):
            PublicKey.combine_keys([priv.public_key, priv2.public_key])

    def test_combine_keys_bad_intermediate(self):
        priv = PrivateKey.from_random()
        priv2 = PrivateKey(int_to_be_bytes(CURVE_ORDER - priv.to_int(), size=32))
        # But combining with bad intermediate result but good final is fine
        P = PublicKey.combine_keys([priv.public_key, priv2.public_key, priv.public_key])
        assert P == priv.public_key

    def test_verify_der_signature(self):
        priv = PrivateKey.from_random()
        message = b'BitcoinSV'
        sig = priv.sign(message)

        P = priv.public_key
        assert P.verify_der_signature(sig, message)
        assert P.verify_der_signature(sig, message, sha256)
        assert P.verify_der_signature(sig, sha256(message), None)
        assert not P.verify_der_signature(sig, message[:-1])

    def test_verify_der_signature_bad(self):
        priv = PrivateKey.from_random()
        message = b'BitcoinSV'
        sig_der = priv.sign(message)
        sig_rec = priv.sign_recoverable(message)

        P = priv.public_key
        with pytest.raises(InvalidSignature):
            P.verify_der_signature(sig_rec, message)

        for n in (0, 10, 20, 30, 40):
            bad_der = bytearray(sig_der)
            bad_der[n] ^= 0x10
            try:
                assert not P.verify_der_signature(bytes(bad_der), message)
            except InvalidSignature:
                pass

    def test_verify_recoverable_signature(self):
        priv = PrivateKey.from_random()
        message = b'BitcoinSV'
        sig = priv.sign_recoverable(message)

        P = priv.public_key
        assert P.verify_recoverable_signature(sig, message)
        assert P.verify_recoverable_signature(sig, message, sha256)
        assert P.verify_recoverable_signature(sig, sha256(message), None)
        assert not P.verify_recoverable_signature(sig, message[:-1])

    def test_verify_recoverable_signature_bad(self):
        priv = PrivateKey.from_random()
        message = b'BitcoinSV'
        sig = priv.sign(message)

        P = priv.public_key
        # Bad recid
        bad_sig = bytes([0x01]) * 64 + bytes([4])
        with pytest.raises(InvalidSignature):
            P.verify_recoverable_signature(bad_sig, message)
        # Overflow
        bad_sig = bytes([0xff]) * 64 + bytes([1])
        with pytest.raises(InvalidSignature):
            P.verify_recoverable_signature(bad_sig, message)
        # Invalid sig
        bad_sig = bytes([sig[0] ^ 1]) + sig[1:]
        with pytest.raises(InvalidSignature):
            P.verify_recoverable_signature(bad_sig, message)

    def test_from_recoverable_signature(self):
        priv = PrivateKey.from_random()
        message = b'BitcoinSV'
        rec_sig = priv.sign_recoverable(message)
        pub = PublicKey.from_recoverable_signature(rec_sig, message)

        assert priv.public_key == pub
        assert pub.network() is Bitcoin

    def test_from_recoverable_signature_bad(self):
        message = b'BitcoinSV'
        with pytest.raises(InvalidSignature):
            PublicKey.from_recoverable_signature(b'1' * 64, message)

    def test_from_recoverable_signature_bad_r(self):
        priv = PrivateKey.from_random()
        message = b'BitcoinSV'
        rec_sig = priv.sign_recoverable(message)
        bad_sig = bytes(32) + rec_sig[32:]
        with pytest.raises(InvalidSignature):
            PublicKey.from_recoverable_signature(bad_sig, message)

    def test_from_signed_message(self):
        priv = PrivateKey.from_random()
        P = priv.public_key
        msg = b'BitcoinSV'

        msg_sig = priv.sign_message(msg)
        P2 = PublicKey.from_signed_message(msg_sig, msg)
        assert P == P2
        assert P2.network() is Bitcoin

    def test_from_signed_message_base64(self):
        priv = PrivateKey.from_random()
        message = b'BitcoinSV'
        message_sig = priv.sign_message(message)
        P1 = PublicKey.from_signed_message(message_sig, message)
        P2 = PublicKey.from_signed_message(b64encode(message_sig).decode(), message)
        assert P1 == P2 == priv.public_key
        with pytest.raises(InvalidSignature):
            PublicKey.from_signed_message('abcd%', message)

    def test_from_signed_message_no_hasher(self):
        priv = PrivateKey.from_random()
        message = bytes(32)
        message_sig = priv.sign_message(message)

        PublicKey.from_signed_message(message_sig, message)
        with pytest.raises(ValueError):
            PublicKey.from_signed_message(message_sig, message, None)

    @pytest.mark.parametrize("msg", (
        b'BitcoinSV', 'BitcoinSV',
        # Test longer messages are prefix-encoded correctly
        b'BitcoinSV * 100',
    ))
    def test_verify_message(self, msg):
        priv = PrivateKey.from_random()
        P = priv.public_key
        address_comp = P.to_address()
        address_uncomp = P.to_address(compressed=False)
        assert address_comp != address_uncomp
        base_msg = b'BitcoinSV'

        msg_sig = priv.sign_message(msg)
        msg_sig2 = bytearray(msg_sig)
        msg_sig2[3] ^= 79
        msg_sig2 = bytes(msg_sig2)

        assert P.verify_message(msg_sig, msg)
        assert PublicKey.verify_message_and_address(msg_sig, msg, address_comp)
        assert PublicKey.verify_message_and_address(msg_sig, msg, address_uncomp)

        msg_sig = priv.sign_message_to_base64(msg)
        assert P.verify_message(msg_sig, msg)
        assert PublicKey.verify_message_and_address(msg_sig, msg, address_comp)
        assert PublicKey.verify_message_and_address(msg_sig, msg, address_uncomp)

        assert not PublicKey.verify_message_and_address(msg_sig, msg,
                                                        '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')

        assert not P.verify_message(msg_sig2, msg)
        assert not PublicKey.verify_message_and_address(msg_sig2, msg, address_comp)
        assert not PublicKey.verify_message_and_address(msg_sig2, msg, address_uncomp)

    def test_verify_message_no_hasher(self):
        priv = PrivateKey.from_random()
        message = bytes(32)
        message_sig = priv.sign_message(message)

        priv.public_key.verify_message(message_sig, message)
        with pytest.raises(ValueError):
            priv.public_key.verify_message(message_sig, message, hasher=None)

    def test_verify_message_sig_base64(self):
        priv = PrivateKey.from_random()
        P = priv.public_key
        message = bytes(32)
        message_sig = priv.sign_message(message)
        P.verify_message(message_sig, message)
        P.verify_message(b64encode(message_sig).decode(), message)
        with pytest.raises(InvalidSignature):
            P.verify_message('abcd%', message)

    def test_verify_message_and_address_coin(self):
        priv = PrivateKey.from_random()
        P = priv.public_key
        msg = b'BitcoinSV'
        msg_sig = priv.sign_message(msg)

        assert P.verify_message_and_address(msg_sig, msg, P.to_address(network=Bitcoin))
        assert P.verify_message_and_address(msg_sig, msg, P.to_address(network=BitcoinTestnet))

    def test_verify_message_and_address_bad(self):
        priv1 = PrivateKey.from_random()
        priv2 = PrivateKey.from_random()
        P1, P2 = priv1.public_key, priv2.public_key
        msg = b'BitcoinSV'
        msg_sig = priv1.sign_message(msg)

        assert P1.verify_message_and_address(msg_sig, msg, P1.to_address())
        assert not P1.verify_message_and_address(msg_sig, msg, P2.to_address())
        assert not P1.verify_message_and_address(msg_sig[:-1], msg, P1.to_address())

        with pytest.raises(TypeError):
            P1.verify_message_and_address(msg_sig, msg, b'foobar')

    @pytest.mark.parametrize("hasher", (double_sha256, sha256))
    def test_verify_message_and_address_hasher(self, hasher):
        priv = PrivateKey.from_random()
        P = priv.public_key
        msg = b'BitcoinSV'
        msg_sig = priv.sign_message(msg, hasher=hasher)

        assert P.verify_message_and_address(msg_sig, msg, P.to_address(), hasher=hasher)

    def test_verify_message_bad(self):
        priv = PrivateKey.from_random()
        P = priv.public_key
        msg = b'BitcoinSV'
        msg_sig = priv.sign_message(msg)

        with pytest.raises(InvalidSignature):
            P.verify_message(b'bar', msg)
        with pytest.raises(InvalidSignature):
            P.verify_message(msg_sig[:-1], msg)
        msg_sig = bytearray(msg_sig)
        for n in (26, 35):
            msg_sig[0] = n
            with pytest.raises(InvalidSignature):
                P.verify_message(bytes(msg_sig), msg)

    def test_encrypt_message_and_to_base64(self):
        bmsg = b'BitcoinSV'
        # Test both compressed and uncompressed pubkeys
        for msg in (bmsg, bmsg.decode()):
            for compressed in (False, True):
                priv = PrivateKey.from_random()
                priv._compressed = compressed
                P = priv.public_key
                enc_msg = P.encrypt_message(msg)
                assert isinstance(enc_msg, bytes)
                assert priv.decrypt_message(enc_msg) == bmsg
                # This tests the default magic of both functions is b'BIE1'
                assert priv.decrypt_message(enc_msg, magic=b'BIE1') == bmsg

                # Now base64
                enc_msg = P.encrypt_message_to_base64(msg)
                assert isinstance(enc_msg, str)
                assert priv.decrypt_message(enc_msg) == bmsg
                # This tests the default magic of both functions is b'BIE1'
                assert priv.decrypt_message(enc_msg, magic=b'BIE1') == bmsg

    def test_encrypt_message_magic(self):
        priv = PrivateKey.from_random()
        P = priv.public_key
        msg = b'BitcoinSV'
        for magic in (b'Z', b'ABCDEFG'):
            enc_msg = P.encrypt_message(msg, magic)
            assert priv.decrypt_message(enc_msg, magic) == msg
            enc_msg = P.encrypt_message_to_base64(msg, magic)
            assert priv.decrypt_message(enc_msg, magic) == msg

    def test_str(self):
        P = PrivateKey.from_random().public_key
        assert str(P) == P.to_hex()

    def test_P2PK_script(self):
        P = PrivateKey.from_random().public_key
        script_c = P.P2PK_script()
        script_u = P.complement().P2PK_script()
        assert script_c == bytes([33]) + P.to_bytes(compressed=True) + bytes([0xac])
        assert script_u == bytes([65]) + P.to_bytes(compressed=False) + bytes([0xac])
        assert script_c == P.P2PK_script()

    def test_P2PKH_script(self):
        P = PrivateKey.from_random().public_key
        script_c = P.P2PKH_script()
        script_u = P.complement().P2PKH_script()
        assert script_c == b''.join((bytes([0x76, 0xa9, 20]),
                                     hash160(P.to_bytes(compressed=True)),
                                     bytes([0x88, 0xac])))
        assert script_u == b''.join((bytes([0x76, 0xa9, 20]),
                                     hash160(P.to_bytes(compressed=False)),
                                     bytes([0x88, 0xac])))
        assert script_c == P.P2PKH_script()

    def test_hash160(self):
        # From block 1
        P = PublicKey.from_hex(
            '0496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379'
            '515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858ee')
        assert P.hash160().hex() == '119b098e2e980a229e139a9ed01a469e518e6f26'
        assert P.hash160(compressed=True).hex() == 'f4d294debc9799f1b6e0d15cd696b207ce6df0f9'
        assert P.hash160(compressed=False).hex() == '119b098e2e980a229e139a9ed01a469e518e6f26'

    def test_complement(self):
        P = PublicKey.from_hex(
            '0496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379'
            '515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858ee')
        P._network = BitcoinTestnet
        C = P.complement()
        assert C.hash160().hex() == 'f4d294debc9799f1b6e0d15cd696b207ce6df0f9'
        assert C == P
        assert C is not P
        assert C.network() is BitcoinTestnet
