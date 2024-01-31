import pytest

from bitcoinx.bip32 import *
from bitcoinx import (
    Bitcoin, BitcoinTestnet, Base58Error, base58_decode_check, base58_encode_check, PrivateKey,
    Address, BIP32_HARDENED,
)

HARDENED = 1 << 31
MXPRV = 'xprv9s21ZrQH143K2gMVrSwwojnXigqHgm1khKZGTCm7K8w4PmuDEUru' \
        'dk11ZBxhGPUiUeVcrfGLoZmt8rFNRDLp18jmKMcVma89z7PJd2Vn7R9'
MXPRV_TESTNET = 'tprv8ZgxMBicQKsPdVb2X1oSyPQX2pFVvH3m2sUPKdBZo7RYBNeJDrCf' \
                '9VNTUN8MGks2r62Prkt6xvMgbho7YRgkpC1MqzpoRvrCuD8j4nCxQgV'
MPRIVKEY = bytes.fromhex('3bf4bf48d230ea94015f101bc3b0ffc917243f4b02e58252e5b341db87264500')
MXPUB = 'xpub661MyMwAqRbcFARxxUUxAsjGGifn6Djc4YUsFbAisUU3GaEMn2BA' \
        'BYKVQTHrDtwvSfgY2bK8aFGyCNmB52SKjkFGP18sSRTNn1sCeez7Utd'
MXPUB_TESTNET = 'tpubD6NzVbkrYhZ4WxcpQfU3No4dbqmS5cEfcB5Ac9DsDPDw1ru4rF2FKyzK' \
                'eVNdkPuAEaDSeAq17M71tZFnTtHZdBhZSbtB7x7cMyTcQiWF5J8'


mpubkey, net1 = bip32_key_from_string(MXPUB)
mpubkey_testnet, net2 = bip32_key_from_string(MXPUB_TESTNET)
mprivkey, net3 = bip32_key_from_string(MXPRV)
mprivkey_testnet, net4 = bip32_key_from_string(MXPRV_TESTNET)


def test_bip32_key_from_string():
    assert net1 is net3 is Bitcoin
    assert net2 is net4 is BitcoinTestnet


def test_hardened():
    assert BIP32_HARDENED == HARDENED


def test_bip32_key_from_string_bad():
    # Tests the failure modes of from_extended_key.
    with pytest.raises(Base58Error):
        bip32_key_from_string('')
    with pytest.raises(ValueError):
        bip32_key_from_string('1Po1oWkD2LmodfkBYiAktwh76vkF93LKnh')
    with pytest.raises(TypeError):
        bip32_key_from_string(b'')
    with pytest.raises(Base58Error):
        bip32_key_from_string(bytes(78).decode())
    # Invalid prefix byte
    raw = base58_decode_check(MXPRV)
    bad_string = base58_encode_check(raw[:45] + b'\1' + raw[46:])
    with pytest.raises(ValueError):
        bip32_key_from_string(bad_string)


class TestBIP32Derivation:

    def test_repr(self):
        d = mpubkey.derivation()
        assert repr(d) == (
            'BIP32Derivation(chain_code=bytes.fromhex("3e568392600d17b322a67fafc09330f71edc12699ce'
            '4c02c611a04ec1619ae4b"), n=0, depth=0, parent_fingerprint=bytes.fromhex("00000000"))'
        )


class TestBIP32PublicKey:

    def test_public_key(self):
        assert mpubkey.public_key is mpubkey

    def test_from_to_extended_key_string(self):
        d = mpubkey.derivation()
        assert d.n == 0
        assert d.depth == 0
        assert d.parent_fingerprint == bytes(4)
        assert d.chain_code == (
            b'>V\x83\x92`\r\x17\xb3"\xa6\x7f\xaf\xc0\x930\xf7\x1e\xdc\x12i'
            b'\x9c\xe4\xc0,a\x1a\x04\xec\x16\x19\xaeK'
        )
        x, _y = mpubkey.to_point()
        assert x == 44977109961578369385937116592536468905742111247230478021459394832226142714624

    def test_extended_key(self):
        assert mpubkey.to_extended_key_string(Bitcoin) == MXPUB
        assert mpubkey_testnet.to_extended_key_string(BitcoinTestnet) == MXPUB_TESTNET
        chg_master = mpubkey.child(1)
        chg5 = chg_master.child(5)
        assert chg5.to_address(network=Bitcoin) == Address.from_string(
            '1BsEFqGtcZnVBbPeimcfAFTitQdTLvUXeX', Bitcoin)
        assert chg5.to_extended_key_string(Bitcoin) == (
            'xpub6AzPNZ1SAS7zmSnj6gakQ6tAKPzRVdQzieL3eCnoeT3A89nJaJKuUYW'
            'oZuYp8xWhCs1gF9yXAwGg7zKYhvCfhk9jrb1bULhLkQCwtB1Nnn1'
        )

        ext_key_base58 = chg5.to_extended_key_string(Bitcoin)
        assert ext_key_base58 == (
            'xpub6AzPNZ1SAS7zmSnj6gakQ6tAKPzRVdQzieL3eCnoeT3A89nJaJKu'
            'UYWoZuYp8xWhCs1gF9yXAwGg7zKYhvCfhk9jrb1bULhLkQCwtB1Nnn1'
        )

        # Check can recreate
        dup, network = bip32_key_from_string(ext_key_base58)
        d = dup.derivation()
        assert network is Bitcoin
        assert d == chg5.derivation()
        assert dup.to_point() == chg5.to_point()

    def test_child(self):
        '''Test child derivations agree with Electrum.'''
        rec_master = mpubkey.child(0)
        assert rec_master.to_address(Bitcoin).to_string() == '18zW4D1Vxx9jVPGzsFzgXj8KrSLHt7w2cg'
        chg_master = mpubkey.child(1)
        assert chg_master.to_address(Bitcoin).to_string() == '1G8YpbkZd7bySHjpdQK3kMcHhc6BvHr5xy'
        rec0 = rec_master.child(0)
        assert rec0.to_address(Bitcoin).to_string() == '13nASW7rdE2dnSycrAP9VePhRmaLg9ziaw'
        rec19 = rec_master.child(19)
        assert rec19.to_address(Bitcoin).to_string() == '15QrXnPQ8aS8yCpA5tJkyvXfXpw8F8k3fB'
        chg0 = chg_master.child(0)
        assert chg0.to_address(Bitcoin).to_string() == '1L6fNSVhWjuMKNDigA99CweGEWtcqqhzDj'

        with pytest.raises(ValueError):
            mpubkey.child(-1)
        with pytest.raises(ValueError):
            mpubkey.child(1 << 31)
        # OK
        mpubkey.child((1 << 31) - 1)

    def test_child_safe(self):
        '''Test child derivations agree with Electrum.'''
        rec_master = mpubkey.child_safe(0)
        assert rec_master.to_address(Bitcoin).to_string() == '18zW4D1Vxx9jVPGzsFzgXj8KrSLHt7w2cg'
        chg_master = mpubkey.child_safe(1)
        assert chg_master.to_address(Bitcoin).to_string() == '1G8YpbkZd7bySHjpdQK3kMcHhc6BvHr5xy'
        rec0 = rec_master.child_safe(0)
        assert rec0.to_address(Bitcoin).to_string() == '13nASW7rdE2dnSycrAP9VePhRmaLg9ziaw'
        rec19 = rec_master.child_safe(19)
        assert rec19.to_address(Bitcoin).to_string() == '15QrXnPQ8aS8yCpA5tJkyvXfXpw8F8k3fB'
        chg0 = chg_master.child_safe(0)
        assert chg0.to_address(Bitcoin).to_string() == '1L6fNSVhWjuMKNDigA99CweGEWtcqqhzDj'

        with pytest.raises(ValueError):
            mpubkey.child_safe(-1)
        with pytest.raises(ValueError):
            mpubkey.child_safe(1 << 31)
        # OK
        mpubkey.child_safe((1 << 31) - 1)

    def test_child_safe_is_safe(self):
        pub = BIP32PrivateKey.from_random().public_key
        bad_n = 666

        def bad_child(self, n):
            if n == bad_n:
                return BIP32PublicKey.from_hex('04' + 'ff' * 64)
            else:
                return saved_child(self, n)

        # monkey-patching fun
        saved_child = BIP32PublicKey.child
        BIP32PublicKey.child = bad_child
        with pytest.raises(ValueError):
            child = pub.child(bad_n)
        child = pub.child_safe(bad_n)
        assert child.derivation().n == bad_n + 1
        for wrap_n in ((1 << 31) - 1, (1 << 32) - 1):
            bad_n = wrap_n
            with pytest.raises(ValueError):
                pub.child_safe(bad_n)
        BIP32PublicKey.child = saved_child

    def test_address(self):
        assert mpubkey.to_address(network=Bitcoin) == Address.from_string(
            '1ENCpq6mbb1KYcaodGG7eTpSpYvPnDjFmU', Bitcoin)

    def test_identifier(self):
        assert mpubkey.identifier() == bytes.fromhex('929c3db8d6e7eb52905464851ca70c8a456087dd')

    def test_fingerprint(self):
        assert mpubkey.fingerprint() == b'\x92\x9c=\xb8'

    def test_to_bytes(self):
        assert mpubkey.to_bytes() == bytes.fromhex(
            '026370246118a7c218fd557496ebb2b0862d59c6486e88f83e07fd12ce8a88fb00')

    def test_str(self):
        assert str(mpubkey) == MXPUB

    def test_repr(self):
        assert repr(mpubkey) == f'BIP32PublicKey("{MXPUB}")'


class TestPrivKey:

    def test_from_to_extended_key_string(self):
        d = mprivkey.derivation()
        assert d == mpubkey.derivation()
        assert mprivkey.public_key == mpubkey

    def test_to_int(self):
        assert mprivkey.to_int() == \
            27118888947022743980605817563635166434451957861641813930891160184742578898176

    def test_from_random(self):
        p = BIP32PrivateKey.from_random()
        assert isinstance(p, BIP32PrivateKey)

        values = [bytes(range(64)), bytes(64)]

        def source(size):
            assert size == 64
            return values.pop()

        p = BIP32PrivateKey.from_random(source=source)
        assert p.to_extended_key_string(Bitcoin) == (
            'xprv9s21ZrQH143K2NukZg6wLLhBGTfK6twkq4qMuqCpX2uq3udoAx4'
            'cKXFmyQrGAMn8TNyjNJThnPHL321QCxRxZpg7QQAvQFb7kePtCLcSrq3'
        )

    def test_identifier(self):
        assert mprivkey.identifier() == mpubkey.identifier()

    def test_fingerprint(self):
        assert mprivkey.fingerprint() == mpubkey.fingerprint()

    def test_parent_fingerprint(self):
        assert mprivkey.derivation().parent_fingerprint == bytes(4)
        child = mprivkey.child(0)
        assert child.derivation().parent_fingerprint == mprivkey.fingerprint()

    def test_extended_key(self):
        assert mprivkey.to_extended_key_string(Bitcoin) == MXPRV
        assert mprivkey_testnet.to_extended_key_string(BitcoinTestnet) == MXPRV_TESTNET
        chg_master = mprivkey.child(1)
        chg5 = chg_master.child(5)
        assert chg5.to_WIF(network=Bitcoin) == \
            'L5kTYMuajTGWdYiMoD4V8k6LS4Bg3HFMA5UGTfxG9Wh7UKu9CHFC'
        ext_key_base58 = chg5.to_extended_key_string(Bitcoin)
        assert ext_key_base58 == (
            'xprv9x12y3UYL4ZhYxiFzf3k2xwRmN9w6Ah9MRQSqpPC67WBFMTA2m1evkCKi'
            'dz7UYBa5i8QwxmU9Ju7giqEmcPRXKXwzgAJwssNeZNQLPT3LAY'
        )
        assert chg5.to_extended_key_string(Bitcoin) == chg5.to_extended_key_string(Bitcoin)

        # Check can recreate
        dup, network = bip32_key_from_string(ext_key_base58)
        d = dup.derivation()
        assert network is Bitcoin
        assert dup.derivation() == chg5.derivation()
        assert d.n == 5
        assert d.depth == 2
        assert dup.public_key == chg5.public_key

    def test_child(self):
        '''Test child derivations agree with Electrum.'''
        # Also tests WIF, address
        rec_master = mprivkey.child(0)
        assert rec_master.public_key.to_address(Bitcoin) == Address.from_string(
            '18zW4D1Vxx9jVPGzsFzgXj8KrSLHt7w2cg', Bitcoin)
        chg_master = mprivkey.child(1)
        assert chg_master.public_key.to_address(Bitcoin) == Address.from_string(
            '1G8YpbkZd7bySHjpdQK3kMcHhc6BvHr5xy', Bitcoin)
        rec0 = rec_master.child(0)
        assert rec0.to_WIF(Bitcoin) == 'L2M6WWMdu3YfWxvLGF76HZgHCA6idwVQx5QL91vfdqeZi8XAgWkz'
        rec19 = rec_master.child(19)
        assert rec19.to_WIF(Bitcoin) == 'KwMHa1fynU2J2iBGCuBZxumM2qDXHe5tVPU9VecNGQv3UCqnET7X'
        chg0 = chg_master.child(0)
        assert chg0.to_WIF(Bitcoin) == 'L4J1esD4rYuBHXwjg72yi7Rw4G3iF2yUHt7LN9trpC3snCppUbq8'

        with pytest.raises(ValueError):
            mprivkey.child(-1)
        with pytest.raises(ValueError):
            mprivkey.child(1 << 32)
        # OK
        mprivkey.child((1 << 32) - 1)

    def test_child_safe(self):
        '''Test child derivations agree with Electrum.'''
        # Also tests WIF, address
        rec_master = mprivkey.child_safe(0)
        assert rec_master.public_key.to_address(Bitcoin) == Address.from_string(
            '18zW4D1Vxx9jVPGzsFzgXj8KrSLHt7w2cg', Bitcoin)
        chg_master = mprivkey.child_safe(1)
        assert chg_master.public_key.to_address(Bitcoin) == Address.from_string(
            '1G8YpbkZd7bySHjpdQK3kMcHhc6BvHr5xy', Bitcoin)
        rec0 = rec_master.child_safe(0)
        assert rec0.to_WIF(Bitcoin) == 'L2M6WWMdu3YfWxvLGF76HZgHCA6idwVQx5QL91vfdqeZi8XAgWkz'
        rec19 = rec_master.child_safe(19)
        assert rec19.to_WIF(Bitcoin) == 'KwMHa1fynU2J2iBGCuBZxumM2qDXHe5tVPU9VecNGQv3UCqnET7X'
        chg0 = chg_master.child_safe(0)
        assert chg0.to_WIF(Bitcoin) == 'L4J1esD4rYuBHXwjg72yi7Rw4G3iF2yUHt7LN9trpC3snCppUbq8'

        with pytest.raises(ValueError):
            mprivkey.child_safe(-1)
        with pytest.raises(ValueError):
            mprivkey.child_safe(1 << 32)
        # OK
        mprivkey.child_safe((1 << 32) - 1)

    def test_child_safe_is_safe(self):
        priv = BIP32PrivateKey.from_random()
        bad_n = 666

        def bad_child(self, n):
            if n == bad_n:
                return PrivateKey(bytes(32))
            else:
                return saved_child(self, n)

        # monkey-patching fun
        saved_child = BIP32PrivateKey.child
        BIP32PrivateKey.child = bad_child
        with pytest.raises(ValueError):
            child = priv.child(bad_n)
        child = priv.child_safe(bad_n)
        assert child.derivation().n == bad_n + 1
        for wrap_n in ((1 << 31) - 1, (1 << 32) - 1):
            bad_n = wrap_n
            with pytest.raises(ValueError):
                priv.child_safe(bad_n)
        BIP32PrivateKey.child = saved_child

    def test_str(self):
        assert str(mprivkey) == str(PrivateKey(mprivkey._secret))

    def test_repr(self):
        assert repr(mprivkey) == f'BIP32PrivateKey("{str(mprivkey)}")'

    def test_from_seed(self):
        seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

        # Chain m
        m = BIP32PrivateKey.from_seed(seed)
        assert m.to_extended_key_string(Bitcoin) == (
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqj"
            "iChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        )


class TestVectors():
    '''These are from the BIP32 document.'''

    def test_vector1(self):
        seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

        # Chain m
        m = BIP32PrivateKey.from_seed(seed)
        xprv = m.to_extended_key_string(Bitcoin)
        assert xprv == ("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChk"
                        "VvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
        xpub = m.public_key.to_extended_key_string(Bitcoin)
        assert xpub == ("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY"
                        "2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")

        # Chain m/0H
        m1 = m.child(0 + HARDENED)
        xprv = m1.to_extended_key_string(Bitcoin)
        assert xprv == ("xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4c"
                        "V1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7")
        xpub = m1.public_key.to_extended_key_string(Bitcoin)
        assert xpub == ("xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEj"
                        "WgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw")

        # Chain m/0H/1
        m2 = m1.child(1)
        xprv = m2.to_extended_key_string(Bitcoin)
        assert xprv == ("xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLn"
                        "vSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs")
        xpub = m2.public_key.to_extended_key_string(Bitcoin)
        assert xpub == ("xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3"
                        "UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ")

        # Chain m/0H/1/2H
        m3 = m2.child(2 + HARDENED)
        xprv = m3.to_extended_key_string(Bitcoin)
        assert xprv == ("xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBD"
                        "ptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM")
        xpub = m3.public_key.to_extended_key_string(Bitcoin)
        assert xpub == ("xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VU"
                        "NgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5")

        # Chain m/0H/1/2H/2
        m4 = m3.child(2)
        xprv = m4.to_extended_key_string(Bitcoin)
        assert xprv == ("xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb"
                        "2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334")
        xpub = m4.public_key.to_extended_key_string(Bitcoin)
        assert xpub == ("xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBq"
                        "aGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV")

        # Chain m/0H/1/2H/2/1000000000
        m5 = m4.child(1000000000)
        xprv = m5.to_extended_key_string(Bitcoin)
        assert xprv == ("xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8"
                        "FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76")
        xpub = m5.public_key.to_extended_key_string(Bitcoin)
        assert xpub == ("xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FS"
                        "VqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy")

    def test_vector2(self):
        seed = bytes.fromhex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5"
                             "a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")
        # Chain m
        m = BIP32PrivateKey.from_seed(seed)
        xprv = m.to_extended_key_string(Bitcoin)
        assert xprv == ("xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtAL"
                        "Gdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U")
        xpub = m.public_key.to_extended_key_string(Bitcoin)
        assert xpub == ("xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUa"
                        "pSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB")

        # Chain m/0
        m1 = m.child(0)
        xprv = m1.to_extended_key_string(Bitcoin)
        assert xprv == ("xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9W"
                        "QRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt")
        xpub = m1.public_key.to_extended_key_string(Bitcoin)
        assert xpub == ("xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9Lg"
                        "peyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH")

        # Chain m/0H/2147483647H
        m2 = m1.child(2147483647 + HARDENED)
        xprv = m2.to_extended_key_string(Bitcoin)
        assert xprv == ("xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vid"
                        "YEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9")
        xpub = m2.public_key.to_extended_key_string(Bitcoin)
        assert xpub == ("xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyB"
                        "LZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a")

        # Chain m/0H/2147483647H/1
        m3 = m2.child(1)
        xprv = m3.to_extended_key_string(Bitcoin)
        xpub = m3.public_key.to_extended_key_string(Bitcoin)
        assert xprv == ("xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYT"
                        "RXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef")
        assert xpub == ("xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5m"
                        "g5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon")

        # Chain m/0/2147483647H/1/2147483646H
        m4 = m3.child(2147483646 + HARDENED)
        xprv = m4.to_extended_key_string(Bitcoin)
        xpub = m4.public_key.to_extended_key_string(Bitcoin)
        assert xprv == ("xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS"
                        "3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc")
        assert xpub == ("xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhg"
                        "bmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL")

        # Chain m/0/2147483647H/1/2147483646H/2
        m5 = m4.child(2)
        xprv = m5.to_extended_key_string(Bitcoin)
        xpub = m5.public_key.to_extended_key_string(Bitcoin)
        assert xprv == ("xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrK"
                        "CEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j")
        assert xpub == ("xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPd"
                        "SnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt")

    def test_vector3(self):
        seed = bytes.fromhex("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acb"
                             "a45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be")

        # Chain m
        m = BIP32PrivateKey.from_seed(seed)
        xprv = m.to_extended_key_string(Bitcoin)
        xpub = m.public_key.to_extended_key_string(Bitcoin)
        assert xprv == ("xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJ"
                        "Du7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6")
        assert xpub == ("xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiY"
                        "mhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13")

        # Chain m/0H
        m1 = m.child(0 + HARDENED)
        xprv = m1.to_extended_key_string(Bitcoin)
        xpub = m1.public_key.to_extended_key_string(Bitcoin)
        assert xprv == ("xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2"
                        "qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L")
        assert xpub == ("xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQr"
                        "ADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y")


derivation_tests = (
    ("m", []),
    ("m/0", [0]),
    ("m/1'", [0x80000001]),
    ("m/1/2/3'/4/5/6", [1, 2, 0x80000003, 4, 5, 6]),
    ("m/2147483647/2", [0x07fffffff, 2]),
    ("m/2147483647'/255'", [0xffffffff, 0x800000ff]),
)


@pytest.mark.parametrize("chain_str,derivation", derivation_tests)
def test_bip32_decompose_chain_string(chain_str, derivation):
    assert bip32_decompose_chain_string(chain_str) == derivation
    assert bip32_is_valid_chain_string(chain_str)


@pytest.mark.parametrize("chain_str,derivation", derivation_tests)
def test_bip32_build_chain_string(chain_str, derivation):
    assert bip32_build_chain_string(derivation) == chain_str
    assert bip32_build_chain_string(x for x in derivation) == chain_str
    bip32_validate_derivation(derivation)


@pytest.mark.parametrize("bad_arg,exc", (
    (1, TypeError),
    (b'm/0', TypeError),
    ('s/1', ValueError),
    ("m/", ValueError),
    ("mm", ValueError),
    ("mm/1", ValueError),
    ("m/1//2", ValueError),
    ("m/1''", ValueError),
    ("m/-1/2", ValueError),
    ("m/2147483648/2", ValueError),
    ("m/0xab/2", ValueError),
    ("m/1/2/3/", ValueError),
    ("m/1/2/2147483648'", ValueError),
))
def test_bip32_decompose_chain_string_bad(bad_arg, exc):
    with pytest.raises(exc):
        bip32_decompose_chain_string(bad_arg)
    if exc is ValueError:
        assert not bip32_is_valid_chain_string(bad_arg)


@pytest.mark.parametrize("derivation,exc", (
    (1, TypeError),
    ([1, 2, 'z'], TypeError),
    ([-1], ValueError),
    ([1, 1 << 32], ValueError),
))
def test_bip32_validate_derivation_bad(derivation, exc):
    with pytest.raises(exc):
        bip32_validate_derivation(derivation)
