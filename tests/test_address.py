import os

import pytest

from bitcoinx import (
    Bitcoin, BitcoinTestnet, BitcoinScalingTestnet, int_to_be_bytes, PrivateKey, PublicKey,
    Signature, Script, pack_byte, push_int, push_item,
    OP_RETURN, OP_CHECKMULTISIG, OP_0, OP_1, OP_DROP, OP_2DROP, OP_NOP, OP_CHECKSIG,
    hash160
)
from bitcoinx.address import *


class TestAddress:

    @pytest.mark.parametrize("string,kind,coin,equal", (
        ('1111111111111111111114oLvT2', P2PKH_Address, Bitcoin, P2PKH_Address(bytes(20))),
        ('mfWxJ45yp2SFn7UciZyNpvDKrzbi36LaVX', P2PKH_Address, BitcoinTestnet,
         P2PKH_Address(int_to_be_bytes(1, 20), coin=BitcoinTestnet)),
        ('31h1vYVSYuKP6AhS86fbRdMw9XHieotbST', P2SH_Address, Bitcoin, P2SH_Address(bytes(20))),
        ('2MsFDzHRUAMpjHxKyoEHU3aMCMsVtXMsfu8', P2SH_Address, BitcoinTestnet,
         P2SH_Address(int_to_be_bytes(1, 20), coin=BitcoinTestnet)),
    ))
    def test_from_string(self, string, kind, coin, equal):
        address = Address.from_string(string)
        assert isinstance(address, kind)
        assert address.coin() is coin
        assert address == equal

    def test_from_string_coin(self):
        assert Address.from_string('1111111111111111111114oLvT2', coin=Bitcoin).to_string() == \
            '1111111111111111111114oLvT2'
        assert Address.from_string('mfWxJ45yp2SFn7UciZyNpvDKrzbi36LaVX', coin=BitcoinTestnet) \
            .to_string() == 'mfWxJ45yp2SFn7UciZyNpvDKrzbi36LaVX'
        assert Address.from_string('mfWxJ45yp2SFn7UciZyNpvDKrzbi36LaVX',
                                   coin=BitcoinScalingTestnet).to_string() == \
                                   'mfWxJ45yp2SFn7UciZyNpvDKrzbi36LaVX'
        with pytest.raises(ValueError):
            Address.from_string('1111111111111111111114oLvT2', coin=BitcoinTestnet)
        with pytest.raises(ValueError):
            Address.from_string('mfWxJ45yp2SFn7UciZyNpvDKrzbi36LaVX', coin=Bitcoin)


    def test_from_string_bad(self):
        # Too short
        with pytest.raises(ValueError):
            Address.from_string('111111111111111111117K4nzc')
        # Unknown version byte
        with pytest.raises(ValueError):
            Address.from_string('4d3RrygbPdAtMuFnDmzsN8T5fYKVUjFu7m')

    @pytest.mark.parametrize("string,kind,coin,equal", (
        ('qp7sl3kxvswe33zmm4mmm2chc22asud3j5g5p6g6u9', P2PKH_Address, Bitcoin,
         '1CQGN9WnzdYeFhT2YDS4xkm94PVzwFByC8'),
        ('pqcnpyfktqzkm9su04empn3ju8e2k4j74q2zzn7h0f', P2SH_Address, Bitcoin,
         '36B7DTHvi58L3rq9Ni3jRVxBkeJa3R5EC1'),
        ('PQCNPYFKTQZKM9SU04EMPN3JU8E2K4J74Q2ZZN7H0F', P2SH_Address, Bitcoin,
         '36B7DTHvi58L3rq9Ni3jRVxBkeJa3R5EC1'),
    ))
    def test_cashaddr(self, string, kind, coin, equal):
        address = Address.from_string(string)
        assert isinstance(address, kind)
        assert address.coin() is coin
        assert address.to_string() == equal

    def test_cashaddr_bad(self):
        with pytest.raises(ValueError):
            address = Address.from_string('bitcoinCash:isamaurysbitcoinandtherealbcash')
        with pytest.raises(ValueError):
            Address.from_string('bcash:qp7sl3kxvswe33zmm4mmm2chc22asud3j5g5p6g6u9')
        with pytest.raises(ValueError):
            Address.from_string('zvqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqxhap8z55')
        with pytest.raises(ValueError):
            Address.from_string('qp7sl3kxvswe33zmm4mmm2chc22asud3j5g5p6g6u9', coin=BitcoinTestnet)


class TestP2PKH_Address:

    def test_constructor(self):
        address = P2PKH_Address(bytes(20))
        assert address.to_string() == '1111111111111111111114oLvT2'

    def test_constructor_bad(self):
        with pytest.raises(TypeError):
            P2PKH_Address(bytearray(20))
        with pytest.raises(ValueError):
            P2PKH_Address(bytes(21))
        with pytest.raises(ValueError):
            P2PKH_Address(bytes(19))

    def test_coin(self):
        address = P2PKH_Address(bytes(20))
        assert address.coin() is Bitcoin

    def test_hash160(self):
        data = os.urandom(20)
        assert P2PKH_Address(data).hash160() is data

    def test_to_string(self):
        address = P2PKH_Address(int_to_be_bytes(1, 20))
        assert address.to_string() == '11111111111111111111BZbvjr'
        assert address.to_string(coin=BitcoinTestnet) == 'mfWxJ45yp2SFn7UciZyNpvDKrzbi36LaVX'

    def test_to_script_bytes(self):
        address = P2PKH_Address(bytes.fromhex('d63cc1e3b6009e31d03bd5f8046cbe0f7e37e8c0'))
        assert address.to_string() == '1LXnPYpHTwQeWfBVnQZ4yDP23b57NwoyrP'
        raw = address.to_script_bytes()
        assert isinstance(raw, bytes)
        assert raw.hex() == '76a914d63cc1e3b6009e31d03bd5f8046cbe0f7e37e8c088ac'

    def test_to_script(self):
        address = P2PKH_Address(bytes.fromhex('d63cc1e3b6009e31d03bd5f8046cbe0f7e37e8c0'))
        S = address.to_script()
        assert isinstance(S, Script)
        assert S == address.to_script_bytes()
        assert isinstance(classify_output_script(S), P2PKH_Address)

    def test_hashable(self):
        {P2PKH_Address(bytes(20))}

    def test_eq(self):
        address = P2PKH_Address(int_to_be_bytes(1, 20))
        assert address == P2PKH_Address(int_to_be_bytes(1, 20))
        assert address == P2PKH_Address(int_to_be_bytes(1, 20), coin=BitcoinTestnet)
        assert address != '11111111111111111111BZbvjr'
        assert address != P2SH_Address(int_to_be_bytes(1, 20))


class TestP2SH_Address:

    def test_constructor(self):
        address = P2SH_Address(bytes(20))
        assert address.to_string() == '31h1vYVSYuKP6AhS86fbRdMw9XHieotbST'

    def test_constructor_bad(self):
        with pytest.raises(TypeError):
            P2SH_Address(bytearray(20))
        with pytest.raises(ValueError):
            P2SH_Address(bytes(21))
        with pytest.raises(ValueError):
            P2SH_Address(bytes(19))

    def test_coin(self):
        address = P2SH_Address(bytes(20))
        assert address.coin() is Bitcoin

    def test_hash160(self):
        data = os.urandom(20)
        assert P2SH_Address(data).hash160() is data

    def test_to_string(self):
        address = P2SH_Address(int_to_be_bytes(1, 20))
        assert address.to_string() == '31h1vYVSYuKP6AhS86fbRdMw9XHiiQ93Mb'
        assert address.to_string(coin=BitcoinTestnet) == '2MsFDzHRUAMpjHxKyoEHU3aMCMsVtXMsfu8'

    def test_to_script_bytes(self):
        address = P2SH_Address(bytes.fromhex('ca9f1c4998bf46f66af34d949d8a8f189b6675b5'))
        assert address.to_string() == '3LAP2V4pNJhZ11gwAFUZsDnvXDcyeeaQM5'
        raw = address.to_script_bytes()
        assert isinstance(raw, bytes)
        assert raw.hex() == 'a914ca9f1c4998bf46f66af34d949d8a8f189b6675b587'

    def test_to_script(self):
        address = P2SH_Address(bytes.fromhex('ca9f1c4998bf46f66af34d949d8a8f189b6675b5'))
        S = address.to_script()
        assert isinstance(S, Script)
        assert S == address.to_script_bytes()
        assert isinstance(classify_output_script(S), P2SH_Address)

    def test_hashable(self):
        {P2SH_Address(bytes(20))}

    def test_eq(self):
        address = P2SH_Address(int_to_be_bytes(1, 20))
        assert address == P2SH_Address(int_to_be_bytes(1, 20))
        assert address == P2SH_Address(int_to_be_bytes(1, 20), coin=BitcoinTestnet)
        assert address != '31h1vYVSYuKP6AhS86fbRdMw9XHiiQ93Mb'
        assert address != P2PKH_Address(int_to_be_bytes(1, 20))


class TestP2PK_Output:

    def test_constructor_bad(self):
        with pytest.raises(ValueError):
            P2PK_Output(b'')

    def test_eq(self):
        p = PrivateKey.from_random().public_key
        assert P2PK_Output(p) == P2PK_Output(p)
        assert P2PK_Output(p) != p

    def test_hashable(self):
        p = PrivateKey.from_random().public_key
        {P2PK_Output(p)}

    def test_hash160(self):
        pubkey_hex = '0363f75554e05e05a04551e59d78d78965ec6789f42199f7cbaa9fa4bd2df0a4b4'
        pubkey = PublicKey.from_hex(pubkey_hex)
        output = P2PK_Output(pubkey)
        assert output.hash160() == hash160(bytes.fromhex(pubkey_hex))

    def test_to_script_bytes(self):
        pubkey_hex = '0363f75554e05e05a04551e59d78d78965ec6789f42199f7cbaa9fa4bd2df0a4b4'
        pubkey = PublicKey.from_hex(pubkey_hex)
        output = P2PK_Output(pubkey)
        raw = output.to_script_bytes()
        assert isinstance(raw, bytes)
        assert raw == push_item(bytes.fromhex(pubkey_hex)) + pack_byte(OP_CHECKSIG)

    def test_to_script(self):
        pubkey_hex = '0363f75554e05e05a04551e59d78d78965ec6789f42199f7cbaa9fa4bd2df0a4b4'
        pubkey = PublicKey.from_hex(pubkey_hex)
        output = P2PK_Output(pubkey)
        S = output.to_script()
        assert isinstance(S, Script)
        assert S == output.to_script_bytes()
        assert isinstance(classify_output_script(S), P2PK_Output)


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

    @pytest.mark.parametrize("threshold, count",
                             [(m + 1, n + 1) for n in range(len(MS_PUBKEYS)) for m in range(n)]
    )
    def test_to_script_bytes(self, threshold, count):
        output = P2MultiSig_Output(MS_PUBKEYS[:count], threshold)
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

    @pytest.mark.parametrize("threshold, count",
                             [(m + 1, n + 1) for n in range(len(MS_PUBKEYS)) for m in range(n)]
    )
    def test_from_template(self, threshold, count):
        good_output = P2MultiSig_Output(MS_PUBKEYS[:count], threshold)
        public_keys = [public_key.to_bytes() for public_key in MS_PUBKEYS[:count]]
        output = P2MultiSig_Output.from_template(pack_byte(threshold), *public_keys,
                                                 pack_byte(count))
        assert list(output.public_keys) == MS_PUBKEYS[:count]
        assert output.threshold == threshold
        assert output == good_output

    def test_hash160(self):
        output = P2MultiSig_Output(MS_PUBKEYS, 1)
        assert output.hash160() == hash160(output.to_script_bytes())

    def test_from_template_bad(self):
        public_keys = [PrivateKey.from_random().public_key.to_bytes() for n in range(2)]
        with pytest.raises(ValueError):
            script = P2MultiSig_Output.from_template(pack_byte(1), *public_keys, pack_byte(1))
        with pytest.raises(ValueError):
            script = P2MultiSig_Output.from_template(pack_byte(1), *public_keys, pack_byte(3))

MS_SIGS = [bytes.fromhex(sig_hex) for sig_hex in (
    '30450221009a8f3f87228213a66525137b59bb9884c5a6fce43128f0eaf81082c50b99c07b022030a2a45a7b75b9d691370afc0e790ad17d971cfccb3da9c236e9aaa316973d0c41',
    '3045022100928b6b9b5e0d063fff02d74a7fcc2fcc2ea5a9a1d4cf4e241302979fe0b976d102203f4aeac2959cf4f91742720c0c77b66c488334d56e45486aecf46599af1f204941',
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


class TestP2PK_Input:

    @pytest.mark.parametrize("signature", MS_SIGS)
    def test_constructor(self, signature):
        input = P2PK_Input(signature)
        raw = input.to_script_bytes()
        assert isinstance(raw, bytes)
        assert raw == push_item(signature)
        S = input.to_script()
        assert isinstance(S, Script)
        assert S == raw

    def test_is_complete(self):
        assert P2PK_Input(MS_SIGS[0]).is_complete()
        assert not P2PK_Input(Signature.MISSING).is_complete()

    @pytest.mark.parametrize("signature", list(MS_SIGS) + [Signature.MISSING])
    def test_counts(self, signature):
        input = P2PK_Input(signature)
        assert input.signatures_required() == 1
        assert input.signatures_present() == int(signature != Signature.MISSING)


class TestUnknown_Input:

    def test_counts(self):
        assert Unknown_Input().signatures_required() == 0
        assert Unknown_Input().signatures_present() == 0
        assert Unknown_Input().is_complete()

    def test_to_script_bytes(self):
        with pytest.raises(RuntimeError):
            Unknown_Input().to_script_bytes()

    def test_to_script(self):
        with pytest.raises(RuntimeError):
            Unknown_Input().to_script()


SIG_PUBKEY_PAIRS = [
    (bytes.fromhex('304402206f840c84939bb711e9805dc10ced562fa70ea0f7dcc36b5f44c209b2ac29fc9b'
                   '022042b810f40adc6cb3f186d82394c3b0296d1fcb0211d2d6d20febbd1d515675f101'),
     PublicKey.from_hex('040bf47f1c24d1b5a597312422091a324a3d57d0123c9ba853ac9dc1eb81d954bc056'
                        'a18a33d9e7cefd2bf10434ec3f1a39d3c3ede6f2bb3cf21730df38fa0a05d'), ),
]


class TestP2PKH_Input:

    @pytest.mark.parametrize("sig, public_key", SIG_PUBKEY_PAIRS)
    def test_constructor(self, sig, public_key):
        input = P2PKH_Input(sig, public_key)
        raw = input.to_script_bytes()
        assert isinstance(raw, bytes)
        assert raw == push_item(sig) + push_item(public_key.to_bytes())
        S = input.to_script()
        assert isinstance(S, Script)
        assert S == raw
        assert input.signature.sighash == sig[-1]
        assert input.public_key is public_key

    @pytest.mark.parametrize("sig, public_key", SIG_PUBKEY_PAIRS)
    def test_is_complete(self, sig, public_key):
        assert P2PKH_Input(sig, public_key).is_complete()
        assert not P2PKH_Input(Signature.MISSING, public_key).is_complete()

    @pytest.mark.parametrize("sig, public_key", SIG_PUBKEY_PAIRS)
    def test_counts(self, sig, public_key):
        input = P2PKH_Input(sig, public_key)
        assert input.signatures_required() == 1
        assert input.signatures_present() == 1
        input = P2PKH_Input(Signature.MISSING, public_key)
        assert input.signatures_required() == 1
        assert input.signatures_present() == 0


class TestP2MultiSig_Input:

    def test_constructor_copies(self):
        input = P2MultiSig_Input(MS_SIGS)
        assert input.signatures is not MS_SIGS
        assert input.signatures == MS_SIGS
        raw = input.to_script_bytes()
        assert isinstance(raw, bytes)
        assert raw == pack_byte(OP_0) + b''.join(push_item(signature) for signature in MS_SIGS)
        S = input.to_script()
        assert isinstance(S, Script)
        assert S == raw

    def test_constructor_bad(self):
        with pytest.raises(TypeError):
            P2MultiSig_Input(MS_SIGS[:-1] + [2])
        with pytest.raises(ValueError):
            P2MultiSig_Input([])

    # From_template tested in TestClassification

    def test_from_template_bad(self):
        with pytest.raises(ValueError):
           P2MultiSig_Input.from_template(None)
        with pytest.raises(ValueError):
            P2MultiSig_Input.from_template(None, pack_byte(OP_0))
        with pytest.raises(ValueError):
            P2MultiSig_Input.from_template(None, pack_byte(OP_1), *MS_SIGS)

    @pytest.mark.parametrize("sig, public_key", SIG_PUBKEY_PAIRS)
    def test_counts(self, sig, public_key):
        sig, _pubkey = SIG_PUBKEY_PAIRS[0]
        input = P2MultiSig_Input([sig, sig])
        assert input.signatures_required() == 2
        assert input.signatures_present() == 2
        input = P2MultiSig_Input([sig, Signature.MISSING])
        assert input.signatures_required() == 2
        assert input.signatures_present() == 1
        input = P2MultiSig_Input([Signature.MISSING, sig])
        assert input.signatures_required() == 2
        assert input.signatures_present() == 1
        input = P2MultiSig_Input([Signature.MISSING] * 5)
        assert input.signatures_required() == 5
        assert input.signatures_present() == 0

    def test_is_complete(self):
        sig, _pubkey = SIG_PUBKEY_PAIRS[0]
        assert P2MultiSig_Input([sig]).is_complete()
        assert P2MultiSig_Input([sig, sig]).is_complete()
        assert not P2MultiSig_Input([Signature.MISSING, sig]).is_complete()
        assert not P2MultiSig_Input([sig, Signature.MISSING]).is_complete()


class TestP2SHMultiSig_Input:

    def test_constructor(self):
        good = classify_input_script(Script(bytes.fromhex(p2sh_multisig_scriptsig)))
        P2SHMultiSig_Input(good.p2multisig_input, good.nested_script)

    def test_constructor_bad(self):
        good = classify_input_script(Script(bytes.fromhex(p2sh_multisig_scriptsig)))
        with pytest.raises(TypeError):
            P2SHMultiSig_Input(good.nested_script, good.nested_script)
        with pytest.raises(TypeError):
            P2SHMultiSig_Input(good.p2multisig_input, good.p2multisig_input)
        good.p2multisig_input.signatures *= 2
        with pytest.raises(ValueError):
            P2SHMultiSig_Input(good.p2multisig_input, good.nested_script)

    def test_script(self):
        input = classify_input_script(Script.from_hex(p2sh_multisig_scriptsig))
        raw = input.to_script_bytes()
        assert raw.hex() == p2sh_multisig_scriptsig
        assert isinstance(raw, bytes)
        S = input.to_script()
        assert isinstance(S, Script)
        assert S == raw

    def test_hash160(self):
        input = classify_input_script(Script.from_hex(p2sh_multisig_scriptsig))
        assert input.hash160() == input.nested_script.hash160()
        address = P2SH_Address(input.hash160())
        assert address.to_string() == '3LMZdnYo1w3uUZqmGWFCCv786pz3Br4y45'

    # From_template tested in TestClassification

    def test_from_template_bad(self):
        with pytest.raises(ValueError):
           P2SHMultiSig_Input.from_template(*MS_SIGS[:2])

    def test_is_complete(self):
        good = classify_input_script(Script(bytes.fromhex(p2sh_multisig_scriptsig)))
        assert good.is_complete()
        good.p2multisig_input.signatures[-1] = Signature.MISSING
        assert not good.is_complete()

    def test_counts(self):
        input = classify_input_script(Script(bytes.fromhex(p2sh_multisig_scriptsig)))
        assert input.signatures_required() == 2
        assert input.signatures_present() == 2
        input.p2multisig_input.signatures[-1] = Signature.MISSING
        assert input.signatures_required() == 2
        assert input.signatures_present() == 1


class TestClassification:

    def test_P2PKH(self):
        script_hex = '76a914a6dbba870185ab6689f386a40522ae6cb5c7b61a88ac'
        s = Script.from_hex(script_hex)
        sc = classify_output_script(s)
        assert isinstance(sc, P2PKH_Address)

        prefix = push_item(b'foobar') + pack_byte(OP_DROP) + pack_byte(OP_NOP)
        s2 = Script.from_hex(prefix.hex() + script_hex)
        sc2 = classify_output_script(s2)
        assert s2 != s
        assert isinstance(sc2, P2PKH_Address)

    def test_P2SH(self):
        script_hex = 'a9143e4501f9f212cb6813b3815edbc7013d6a3f0f1087'
        s = Script.from_hex(script_hex)
        sc = classify_output_script(s)
        assert isinstance(sc, P2SH_Address)

        suffix = push_item(b'foobar') + pack_byte(OP_DROP) + pack_byte(OP_NOP)
        s2 = Script.from_hex(script_hex + suffix.hex())
        sc2 = classify_output_script(s2)
        assert s2 != s
        assert isinstance(sc2, P2SH_Address)

    def test_P2PK(self):
        script_hex = '210363f75554e05e05a04551e59d78d78965ec6789f42199f7cbaa9fa4bd2df0a4b4ac'
        s = Script.from_hex(script_hex)
        sc = classify_output_script(s)
        assert isinstance(sc, P2PK_Output)
        assert (sc.public_key.to_hex() ==
                '0363f75554e05e05a04551e59d78d78965ec6789f42199f7cbaa9fa4bd2df0a4b4')

        suffix = push_item(b'foo') + push_item(b'bar') + pack_byte(OP_2DROP)
        s2 = Script.from_hex(script_hex + suffix.hex())
        sc2 = classify_output_script(s2)
        assert sc2.public_key == sc.public_key
        assert s2 != s
        assert isinstance(sc2, P2PK_Output)

    def test_P2MultiSig(self):
        script_hex = ('5221022812701688bc76ef3610b46c8e97f4b385241d5ed6eab6269b8af5f9bfd5a89c210'
                      '3fa0879c543ac97f34daffdaeed808f3500811aa5070e4a1f7e2daed3dd22ef2052ae')
        s = Script.from_hex(script_hex)
        sc = classify_output_script(s)
        assert isinstance(sc, P2MultiSig_Output)
        assert len(sc.public_keys) == 2
        assert sc.threshold == 2

        # Confirm suffix fails to match
        s = Script.from_hex(script_hex + 'a0')
        assert isinstance(classify_output_script(s), Unknown_Output)
        # Confirm prefix fails to match
        s = Script.from_hex('a0' + script_hex)
        assert isinstance(classify_output_script(s), Unknown_Output)

    def test_OP_RETURN(self):
        s = Script(pack_byte(OP_RETURN))
        sc = classify_output_script(s)
        assert isinstance(sc, OP_RETURN_Output)

        s = Script(pack_byte(OP_RETURN) + push_item(b'BitcoinSV'))
        sc = classify_output_script(s)
        assert isinstance(sc, OP_RETURN_Output)

        # Truncated OP_RETURN script
        s = Script(pack_byte(OP_RETURN) + pack_byte(1))
        sc = classify_output_script(s)
        assert isinstance(sc, OP_RETURN_Output)

    def test_unknown(self):
        # Modified final pubkey byte; not a curve point
        script_hex = '210363f75554e05e05a04551e59d78d78965ec6789f42199f7cbaa9fa4bd2df0a4b3ac'
        s = Script.from_hex(script_hex)
        sc = classify_output_script(s)
        assert isinstance(sc, Unknown_Output)

        # Truncated script
        script_hex = '210363f7'
        s = Script.from_hex(script_hex)
        sc = classify_output_script(s)
        assert isinstance(sc, Unknown_Output)

        # Unknown script
        script_hex = pack_byte(OP_1).hex()
        s = Script.from_hex(script_hex)
        sc = classify_output_script(s)
        assert isinstance(sc, Unknown_Output)

    @pytest.mark.parametrize("sig_hex", (
        'ff',
        '304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd4'
        '10220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0941',
    ))
    def test_P2PK_scriptsig(self, sig_hex):
        script = Script(push_item(bytes.fromhex(sig_hex)))
        sc = classify_input_script(script)
        assert isinstance(sc, P2PK_Input)

    @pytest.mark.parametrize("sig_hex", (
        'fe',
        '302402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd4'
        '10220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0941',
    ))
    def test_bad_P2PK_scriptsig(self, sig_hex):
        script = Script(push_item(bytes.fromhex(sig_hex)))
        sc = classify_input_script(script)
        assert isinstance(sc, Unknown_Input)

    @pytest.mark.parametrize("sig_hex,public_key_hex", (
        ('ff',
         '0496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63'
         'c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858ee'),
        ('304402206f840c84939bb711e9805dc10ced562fa70ea0f7dcc36b5f44c209b2ac29fc9b'
         '022042b810f40adc6cb3f186d82394c3b0296d1fcb0211d2d6d20febbd1d515675f141',
         '040bf47f1c24d1b5a597312422091a324a3d57d0123c9ba853ac9dc1eb81d954bc056'
         'a18a33d9e7cefd2bf10434ec3f1a39d3c3ede6f2bb3cf21730df38fa0a05d'),
    ))
    def test_P2PKH_scriptsig(self, sig_hex, public_key_hex):
        script = Script(b''.join(push_item(bytes.fromhex(item))
                                 for item in (sig_hex, public_key_hex)))
        sc = classify_input_script(script)
        assert isinstance(sc, P2PKH_Input)

    @pytest.mark.parametrize("sig_hex, sigs", (
        (multisig_scriptsig,
         [Signature.from_hex(hex_str) for hex_str in (
             '30450221009a8f3f87228213a66525137b59bb9884c5a6fce43128f0eaf81082c50b99c0'
             '7b022030a2a45a7b75b9d691370afc0e790ad17d971cfccb3da9c236e9aaa316973d0c41',
             '3045022100928b6b9b5e0d063fff02d74a7fcc2fcc2ea5a9a1d4cf4e241302979fe0b976'
             'd102203f4aeac2959cf4f91742720c0c77b66c488334d56e45486aecf46599af1f204941',
         )],
        ),
    ))
    def test_P2MultiSig_Input(self, sig_hex, sigs):
        script = Script(bytes.fromhex(sig_hex))
        sc = classify_input_script(script)
        assert isinstance(sc, P2MultiSig_Input)
        assert sc.signatures == sigs

    @pytest.mark.parametrize("sig_hex,sigs,public_keys", (
        (p2sh_multisig_scriptsig,
         [Signature.from_hex(hex_str) for hex_str in (
             '30450221009a8f3f87228213a66525137b59bb9884c5a6fce43128f0eaf81082c50b99c0'
             '7b022030a2a45a7b75b9d691370afc0e790ad17d971cfccb3da9c236e9aaa316973d0c41',
             '3045022100928b6b9b5e0d063fff02d74a7fcc2fcc2ea5a9a1d4cf4e241302979fe0b976'
             'd102203f4aeac2959cf4f91742720c0c77b66c488334d56e45486aecf46599af1f204941',
         )],
         [PublicKey.from_hex(hex_str) for hex_str in (
             '022812701688bc76ef3610b46c8e97f4b385241d5ed6eab6269b8af5f9bfd5a89c',
             '03fa0879c543ac97f34daffdaeed808f3500811aa5070e4a1f7e2daed3dd22ef20',
         )],
        ),
    ))
    def test_P2SHMultiSig_Input(self, sig_hex, sigs, public_keys):
        script = Script(bytes.fromhex(sig_hex))
        sc = classify_input_script(script)
        assert isinstance(sc, P2SHMultiSig_Input)
        assert sc.p2multisig_input.signatures == sigs
        assert list(sc.nested_script.public_keys) == public_keys


def test_abstract_methods():
    from bitcoinx.address import InputBase
    Address.to_string(None)
    Address.to_string(None, coin=Bitcoin)
    InputBase.signatures_required(None)
    InputBase.signatures_present(None)
