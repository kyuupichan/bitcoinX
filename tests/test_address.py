import os

import pytest

from bitcoinx import (
    Bitcoin, BitcoinTestnet, BitcoinScalingTestnet, int_to_be_bytes, PrivateKey, PublicKey,
    Script, pack_byte, push_int, push_item,
    OP_RETURN, OP_CHECKMULTISIG, OP_0, OP_1, OP_DROP, OP_2DROP, OP_NOP, OP_CHECKSIG,
    hash160, classify_output_script
)
from bitcoinx.address import *


class TestAddress:

    @pytest.mark.parametrize("string,kind,network,equal", (
        ('1111111111111111111114oLvT2', P2PKH_Address, Bitcoin, P2PKH_Address(bytes(20), Bitcoin)),
        ('mfWxJ45yp2SFn7UciZyNpvDKrzbi36LaVX', P2PKH_Address, BitcoinTestnet,
         P2PKH_Address(int_to_be_bytes(1, 20), network=BitcoinTestnet)),
        ('31h1vYVSYuKP6AhS86fbRdMw9XHieotbST', P2SH_Address, Bitcoin,
         P2SH_Address(bytes(20), Bitcoin)),
        ('2MsFDzHRUAMpjHxKyoEHU3aMCMsVtXMsfu8', P2SH_Address, BitcoinTestnet,
         P2SH_Address(int_to_be_bytes(1, 20), network=BitcoinTestnet)),
    ))
    def test_from_string(self, string, kind, network, equal):
        address = Address.from_string(string, network)
        assert isinstance(address, kind)
        assert address.network() is network
        assert address == equal

    def test_from_string_network(self):
        assert Address.from_string('1111111111111111111114oLvT2', Bitcoin).to_string() == \
            '1111111111111111111114oLvT2'
        assert Address.from_string('mfWxJ45yp2SFn7UciZyNpvDKrzbi36LaVX', BitcoinTestnet) \
                      .to_string() == 'mfWxJ45yp2SFn7UciZyNpvDKrzbi36LaVX'
        assert Address.from_string(
            'mfWxJ45yp2SFn7UciZyNpvDKrzbi36LaVX',
            BitcoinScalingTestnet).to_string() == 'mfWxJ45yp2SFn7UciZyNpvDKrzbi36LaVX'
        with pytest.raises(ValueError):
            Address.from_string('1111111111111111111114oLvT2', BitcoinTestnet)
        with pytest.raises(ValueError):
            Address.from_string('mfWxJ45yp2SFn7UciZyNpvDKrzbi36LaVX', Bitcoin)

    def test_from_string_bad(self):
        # Too short
        with pytest.raises(ValueError):
            Address.from_string('111111111111111111117K4nzc', Bitcoin)
        # Unknown version byte
        with pytest.raises(ValueError):
            Address.from_string('mm5Yiba1U2odgUskxnXMJGQMV1DSAXVPib', Bitcoin)

    @pytest.mark.parametrize("string,kind,network,equal", (
        ('qp7sl3kxvswe33zmm4mmm2chc22asud3j5g5p6g6u9', P2PKH_Address, Bitcoin,
         '1CQGN9WnzdYeFhT2YDS4xkm94PVzwFByC8'),
        ('pqcnpyfktqzkm9su04empn3ju8e2k4j74q2zzn7h0f', P2SH_Address, Bitcoin,
         '36B7DTHvi58L3rq9Ni3jRVxBkeJa3R5EC1'),
        ('PQCNPYFKTQZKM9SU04EMPN3JU8E2K4J74Q2ZZN7H0F', P2SH_Address, Bitcoin,
         '36B7DTHvi58L3rq9Ni3jRVxBkeJa3R5EC1'),
    ))
    def test_cashaddr(self, string, kind, network, equal):
        address = Address.from_string(string, network)
        assert isinstance(address, kind)
        assert address.network() is network
        assert address.to_string() == equal

    def test_cashaddr_bad(self):
        with pytest.raises(ValueError):
            Address.from_string('bitcoinCash:isamaurysbitcoinandtherealbcash', Bitcoin)
        with pytest.raises(ValueError):
            Address.from_string('bcash:qp7sl3kxvswe33zmm4mmm2chc22asud3j5g5p6g6u9', Bitcoin)
        with pytest.raises(ValueError):
            Address.from_string('zvqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqxhap8z55',
                                Bitcoin)
        with pytest.raises(ValueError):
            Address.from_string('qp7sl3kxvswe33zmm4mmm2chc22asud3j5g5p6g6u9', BitcoinTestnet)


class TestP2PKH_Address:

    def test_constructor(self):
        address = P2PKH_Address(bytes(20), Bitcoin)
        assert address.to_string() == '1111111111111111111114oLvT2'
        assert str(address) == address.to_string()

    def test_constructor_bad(self):
        with pytest.raises(TypeError):
            P2PKH_Address(bytes(20))   # pylint:disable=no-value-for-parameter
        with pytest.raises(TypeError):
            P2PKH_Address(bytearray(20), Bitcoin)
        with pytest.raises(ValueError):
            P2PKH_Address(bytes(21), Bitcoin)
        with pytest.raises(ValueError):
            P2PKH_Address(bytes(19), Bitcoin)

    def test_network(self):
        address = P2PKH_Address(bytes(20), BitcoinTestnet)
        assert address.network() is BitcoinTestnet

    def test_hash160(self):
        data = os.urandom(20)
        assert P2PKH_Address(data, Bitcoin).hash160() is data

    def test_to_string(self):
        address = P2PKH_Address(int_to_be_bytes(1, 20), Bitcoin)
        assert address.to_string() == '11111111111111111111BZbvjr'
        address = P2PKH_Address(int_to_be_bytes(1, 20), BitcoinTestnet)
        assert address.to_string() == 'mfWxJ45yp2SFn7UciZyNpvDKrzbi36LaVX'

    def test_to_script_bytes(self):
        address = P2PKH_Address(bytes.fromhex('d63cc1e3b6009e31d03bd5f8046cbe0f7e37e8c0'), Bitcoin)
        assert address.to_string() == '1LXnPYpHTwQeWfBVnQZ4yDP23b57NwoyrP'
        raw = address.to_script_bytes()
        assert isinstance(raw, bytes)
        assert raw.hex() == '76a914d63cc1e3b6009e31d03bd5f8046cbe0f7e37e8c088ac'

    def test_to_script(self):
        address = P2PKH_Address(bytes.fromhex('d63cc1e3b6009e31d03bd5f8046cbe0f7e37e8c0'), Bitcoin)
        S = address.to_script()
        assert isinstance(S, Script)
        assert S == address.to_script_bytes()
        assert isinstance(classify_output_script(S, Bitcoin), P2PKH_Address)

    def test_hashable(self):
        {P2PKH_Address(bytes(20), Bitcoin)}

    def test_eq(self):
        address = P2PKH_Address(int_to_be_bytes(1, 20), Bitcoin)
        assert address == P2PKH_Address(int_to_be_bytes(1, 20), Bitcoin)
        assert address == P2PKH_Address(int_to_be_bytes(1, 20), BitcoinTestnet)
        assert address != '11111111111111111111BZbvjr'
        assert address != P2SH_Address(int_to_be_bytes(1, 20), Bitcoin)


class TestP2SH_Address:

    def test_constructor(self):
        address = P2SH_Address(bytes(20), Bitcoin)
        assert address.to_string() == '31h1vYVSYuKP6AhS86fbRdMw9XHieotbST'

    def test_constructor_bad(self):
        with pytest.raises(TypeError):
            P2SH_Address(bytes(20))  # pylint:disable=no-value-for-parameter
        with pytest.raises(TypeError):
            P2SH_Address(bytearray(20), Bitcoin)
        with pytest.raises(ValueError):
            P2SH_Address(bytes(21), Bitcoin)
        with pytest.raises(ValueError):
            P2SH_Address(bytes(19), Bitcoin)

    def test_network(self):
        address = P2SH_Address(bytes(20), BitcoinTestnet)
        assert address.network() is BitcoinTestnet

    def test_hash160(self):
        data = os.urandom(20)
        assert P2SH_Address(data, Bitcoin).hash160() is data

    def test_to_string(self):
        address = P2SH_Address(int_to_be_bytes(1, 20), Bitcoin)
        assert address.to_string() == '31h1vYVSYuKP6AhS86fbRdMw9XHiiQ93Mb'
        address = P2SH_Address(int_to_be_bytes(1, 20), BitcoinTestnet)
        assert address.to_string() == '2MsFDzHRUAMpjHxKyoEHU3aMCMsVtXMsfu8'

    def test_to_script_bytes(self):
        address = P2SH_Address(bytes.fromhex('ca9f1c4998bf46f66af34d949d8a8f189b6675b5'), Bitcoin)
        assert address.to_string() == '3LAP2V4pNJhZ11gwAFUZsDnvXDcyeeaQM5'
        raw = address.to_script_bytes()
        assert isinstance(raw, bytes)
        assert raw.hex() == 'a914ca9f1c4998bf46f66af34d949d8a8f189b6675b587'

    def test_to_script(self):
        address = P2SH_Address(bytes.fromhex('ca9f1c4998bf46f66af34d949d8a8f189b6675b5'), Bitcoin)
        S = address.to_script()
        assert isinstance(S, Script)
        assert S == address.to_script_bytes()
        assert isinstance(classify_output_script(S, Bitcoin), P2SH_Address)

    def test_hashable(self):
        {P2SH_Address(bytes(20), Bitcoin)}

    def test_eq(self):
        address = P2SH_Address(int_to_be_bytes(1, 20), Bitcoin)
        assert address == P2SH_Address(int_to_be_bytes(1, 20), Bitcoin)
        assert address != '31h1vYVSYuKP6AhS86fbRdMw9XHiiQ93Mb'
        assert address != P2PKH_Address(int_to_be_bytes(1, 20), Bitcoin)


class TestP2PK_Output:

    def test_constructor_bad(self):
        with pytest.raises(ValueError):
            P2PK_Output(b'', Bitcoin)

    def test_constructor_hex(self):
        h = '0363f75554e05e05a04551e59d78d78965ec6789f42199f7cbaa9fa4bd2df0a4b4'
        p = P2PK_Output(h, Bitcoin)
        assert p.public_key.to_hex() == h

    def test_eq(self):
        p = PrivateKey.from_random().public_key
        assert P2PK_Output(p, Bitcoin) == P2PK_Output(p, Bitcoin)
        assert P2PK_Output(p, Bitcoin) != p

    def test_hashable(self):
        p = PrivateKey.from_random().public_key
        {P2PK_Output(p, Bitcoin)}

    def test_hash160(self):
        pubkey_hex = '0363f75554e05e05a04551e59d78d78965ec6789f42199f7cbaa9fa4bd2df0a4b4'
        pubkey = PublicKey.from_hex(pubkey_hex)
        output = P2PK_Output(pubkey, Bitcoin)
        assert output.hash160() == hash160(bytes.fromhex(pubkey_hex))

    def test_to_script_bytes(self):
        pubkey_hex = '0363f75554e05e05a04551e59d78d78965ec6789f42199f7cbaa9fa4bd2df0a4b4'
        pubkey = PublicKey.from_hex(pubkey_hex)
        output = P2PK_Output(pubkey, Bitcoin)
        raw = output.to_script_bytes()
        assert isinstance(raw, bytes)
        assert raw == push_item(bytes.fromhex(pubkey_hex)) + pack_byte(OP_CHECKSIG)

    def test_to_script(self):
        pubkey_hex = '0363f75554e05e05a04551e59d78d78965ec6789f42199f7cbaa9fa4bd2df0a4b4'
        pubkey = PublicKey.from_hex(pubkey_hex)
        output = P2PK_Output(pubkey, Bitcoin)
        S = output.to_script()
        assert isinstance(S, Script)
        assert S == output.to_script_bytes()
        assert isinstance(classify_output_script(S, Bitcoin), P2PK_Output)

    def test_to_address_compressed(self):
        pubkey_hex = '036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2'
        pubkey = PublicKey.from_hex(pubkey_hex)
        output = P2PK_Output(pubkey, Bitcoin)
        address = output.to_address()
        assert isinstance(address, P2PKH_Address)
        assert address.to_string() == '16ZbRYV2f1NNuNQ9FDYyUMC2d1cjGS2G3L'

    def test_to_address_uncompressed(self):
        pubkey_hex = (
            '046d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e'
            '2487e6222a6664e079c8edf7518defd562dbeda1e7593dfd7f0be285880a24dab'
        )
        pubkey = PublicKey.from_hex(pubkey_hex)
        output = P2PK_Output(pubkey, Bitcoin, compressed=False)
        address = output.to_address()
        assert isinstance(address, P2PKH_Address)
        assert address.to_string() == '1G9f5Kdd5A8MeBN8jduUNfcAXUVvtFxVhP'


MS_PUBKEYS = [PrivateKey.from_random().public_key for n in range(5)]
multisig_scriptsig = (
    '004830450221009a8f3f87228213a66525137b59bb9884c5a6fce43128f0eaf81082c50b99c07b022030a2a4'
    '5a7b75b9d691370afc0e790ad17d971cfccb3da9c236e9aaa316973d0c41483045022100928b6b9b5e0d063f'
    'ff02d74a7fcc2fcc2ea5a9a1d4cf4e241302979fe0b976d102203f4aeac2959cf4f91742720c0c77b66c4883'
    '34d56e45486aecf46599af1f204941'
)
p2sh_multisig_scriptsig = (
    '004830450221009a8f3f87228213a66525137b59bb9884c5a6fce43128f0eaf81082c50b99c07b022030a2a4'
    '5a7b75b9d691370afc0e790ad17d971cfccb3da9c236e9aaa316973d0c41483045022100928b6b9b5e0d063f'
    'ff02d74a7fcc2fcc2ea5a9a1d4cf4e241302979fe0b976d102203f4aeac2959cf4f91742720c0c77b66c4883'
    '34d56e45486aecf46599af1f204941475221022812701688bc76ef3610b46c8e97f4b385241d5ed6eab6269b'
    '8af5f9bfd5a89c2103fa0879c543ac97f34daffdaeed808f3500811aa5070e4a1f7e2daed3dd22ef2052ae'
)


class TestP2MultiSig_Output:

    @pytest.mark.parametrize("threshold, count", [
        (m + 1, n + 1) for n in range(len(MS_PUBKEYS)) for m in range(n)
    ])
    def test_to_script_bytes(self, threshold, count):
        output = P2MultiSig_Output(MS_PUBKEYS[:count], threshold)
        assert output.public_key_count() == count
        raw = output.to_script_bytes()
        assert isinstance(raw, bytes)
        assert raw == b''.join((
            push_int(threshold),
            b''.join(push_item(public_key.to_bytes()) for public_key in MS_PUBKEYS[:count]),
            push_int(count),
            pack_byte(OP_CHECKMULTISIG),
        ))
        S = output.to_script()
        assert isinstance(S, Script)
        assert S == raw

    def test_constructor_copies(self):
        public_keys = list(MS_PUBKEYS[:2])
        script = P2MultiSig_Output(public_keys, 2)
        assert script.public_keys is not public_keys

    def test_eq(self):
        assert P2MultiSig_Output(MS_PUBKEYS[:1], 1) != P2MultiSig_Output(MS_PUBKEYS[:2], 1)
        assert P2MultiSig_Output(MS_PUBKEYS[:2], 1) != P2MultiSig_Output(MS_PUBKEYS[:2], 2)
        assert P2MultiSig_Output(MS_PUBKEYS[:2], 2) == P2MultiSig_Output(MS_PUBKEYS[:2], 2)

    def test_hashable(self):
        {P2MultiSig_Output(MS_PUBKEYS, 1)}

    def test_constructor_bad(self):
        with pytest.raises(ValueError):
            P2MultiSig_Output(MS_PUBKEYS + [b''], 2)
        with pytest.raises(ValueError):
            P2MultiSig_Output(MS_PUBKEYS, 0)
        with pytest.raises(ValueError):
            P2MultiSig_Output(MS_PUBKEYS, len(MS_PUBKEYS) + 1)

    @pytest.mark.parametrize("threshold, count", [
        (m + 1, n + 1) for n in range(len(MS_PUBKEYS)) for m in range(n)
    ])
    def test_from_template(self, threshold, count):
        good_output = P2MultiSig_Output(MS_PUBKEYS[:count], threshold)
        public_keys = [public_key.to_bytes() for public_key in MS_PUBKEYS[:count]]
        output = P2MultiSig_Output.from_template(pack_byte(threshold), *public_keys,
                                                 pack_byte(count))
        assert list(output.public_keys) == [(public_key, True)
                                            for public_key in MS_PUBKEYS[:count]]
        assert output.threshold == threshold
        assert output == good_output

    def test_hash160(self):
        output = P2MultiSig_Output(MS_PUBKEYS, 1)
        assert output.hash160() == hash160(output.to_script_bytes())

    def test_from_template_bad(self):
        public_keys = [PrivateKey.from_random().public_key.to_bytes() for n in range(2)]
        with pytest.raises(ValueError):
            P2MultiSig_Output.from_template(pack_byte(1), *public_keys, pack_byte(1))
        with pytest.raises(ValueError):
            P2MultiSig_Output.from_template(pack_byte(1), *public_keys, pack_byte(3))


MS_SIGS = [bytes.fromhex(sig_hex) for sig_hex in (
    '30450221009a8f3f87228213a66525137b59bb9884c5a6fce43128f0eaf81082c50b99c07'
    'b022030a2a45a7b75b9d691370afc0e790ad17d971cfccb3da9c236e9aaa316973d0c41',
    '3045022100928b6b9b5e0d063fff02d74a7fcc2fcc2ea5a9a1d4cf4e241302979fe0b976'
    'd102203f4aeac2959cf4f91742720c0c77b66c488334d56e45486aecf46599af1f204941',
)]


class TestOP_RETURN_Output:

    def test_eq(self):
        assert OP_RETURN_Output() == OP_RETURN_Output()
        assert OP_RETURN_Output() != 2

    def test_hashable(self):
        {OP_RETURN_Output()}

    def test_to_script_bytes(self):
        raw = OP_RETURN_Output().to_script_bytes()
        assert isinstance(raw, bytes)
        assert raw == bytes([OP_RETURN])

    def test_to_script(self):
        S = OP_RETURN_Output().to_script()
        assert isinstance(S, Script)
        assert S == bytes([OP_RETURN])

    def test_from_template(self):
        output = OP_RETURN_Output.from_template(b'', b'bab')
        assert output == OP_RETURN_Output()


class TestUnknown_Output:

    def test_eq(self):
        a = Unknown_Output()
        assert a != Unknown_Output()
        assert a == a

    def test_hashable(self):
        {Unknown_Output()}

    def test_to_script_bytes(self):
        with pytest.raises(RuntimeError):
            Unknown_Output().to_script_bytes()

    def test_to_script(self):
        with pytest.raises(RuntimeError):
            Unknown_Output().to_script()


class TestClassification:

    def test_P2PKH(self):
        script_hex = '76a914a6dbba870185ab6689f386a40522ae6cb5c7b61a88ac'
        s = Script.from_hex(script_hex)
        sc = classify_output_script(s, Bitcoin)
        assert isinstance(sc, P2PKH_Address)

        prefix = push_item(b'foobar') + pack_byte(OP_DROP) + pack_byte(OP_NOP)
        s2 = Script.from_hex(prefix.hex() + script_hex)
        sc2 = classify_output_script(s2, Bitcoin)
        assert s2 != s
        assert isinstance(sc2, P2PKH_Address)

    def test_P2SH(self):
        script_hex = 'a9143e4501f9f212cb6813b3815edbc7013d6a3f0f1087'
        s = Script.from_hex(script_hex)
        sc = classify_output_script(s, Bitcoin)
        assert isinstance(sc, P2SH_Address)

        suffix = push_item(b'foobar') + pack_byte(OP_DROP) + pack_byte(OP_NOP)
        s2 = Script.from_hex(script_hex + suffix.hex())
        sc2 = classify_output_script(s2, Bitcoin)
        assert s2 != s
        assert isinstance(sc2, P2SH_Address)

    def test_P2PK(self):
        script_hex = '210363f75554e05e05a04551e59d78d78965ec6789f42199f7cbaa9fa4bd2df0a4b4ac'
        s = Script.from_hex(script_hex)
        sc = classify_output_script(s, Bitcoin)
        assert isinstance(sc, P2PK_Output)
        assert (sc.public_key.to_hex() ==
                '0363f75554e05e05a04551e59d78d78965ec6789f42199f7cbaa9fa4bd2df0a4b4')

        suffix = push_item(b'foo') + push_item(b'bar') + pack_byte(OP_2DROP)
        s2 = Script.from_hex(script_hex + suffix.hex())
        sc2 = classify_output_script(s2, Bitcoin)
        assert sc2.public_key == sc.public_key
        assert s2 != s
        assert isinstance(sc2, P2PK_Output)

    def test_P2MultiSig(self):
        script_hex = ('5221022812701688bc76ef3610b46c8e97f4b385241d5ed6eab6269b8af5f9bfd5a89c210'
                      '3fa0879c543ac97f34daffdaeed808f3500811aa5070e4a1f7e2daed3dd22ef2052ae')
        s = Script.from_hex(script_hex)
        sc = classify_output_script(s, Bitcoin)
        assert isinstance(sc, P2MultiSig_Output)
        assert len(sc.public_keys) == 2
        assert sc.threshold == 2

        # Confirm suffix fails to match
        s = Script.from_hex(script_hex + 'a0')
        assert isinstance(classify_output_script(s, Bitcoin), Unknown_Output)
        # Confirm prefix fails to match
        s = Script.from_hex('a0' + script_hex)
        assert isinstance(classify_output_script(s, Bitcoin), Unknown_Output)

    def _test_op_return(self, old=False):
        prefix = b'' if old else pack_byte(OP_0)

        s = Script(prefix + pack_byte(OP_RETURN))
        sc = classify_output_script(s, Bitcoin)
        assert isinstance(sc, OP_RETURN_Output)

        s = Script(prefix + pack_byte(OP_RETURN) + push_item(b'BitcoinSV'))
        sc = classify_output_script(s, Bitcoin)
        assert isinstance(sc, OP_RETURN_Output)

        # Truncated OP_RETURN script
        s = Script(prefix + pack_byte(OP_RETURN) + pack_byte(1))
        sc = classify_output_script(s, Bitcoin)
        assert isinstance(sc, OP_RETURN_Output)

    def test_old_OP_RETURN(self):
        self._test_op_return(False)

    def test_new_OP_RETURN(self):
        self._test_op_return(True)

    def test_unknown(self):
        # Modified final pubkey byte; not a curve point
        script_hex = '210363f75554e05e05a04551e59d78d78965ec6789f42199f7cbaa9fa4bd2df0a4b3ac'
        s = Script.from_hex(script_hex)
        sc = classify_output_script(s, Bitcoin)
        assert isinstance(sc, Unknown_Output)

        # Truncated script
        script_hex = '210363f7'
        s = Script.from_hex(script_hex)
        sc = classify_output_script(s, Bitcoin)
        assert isinstance(sc, Unknown_Output)

        # Unknown script
        script_hex = pack_byte(OP_1).hex()
        s = Script.from_hex(script_hex)
        sc = classify_output_script(s, Bitcoin)
        assert isinstance(sc, Unknown_Output)


def test_abstract_methods():
    Address.to_string(None)
