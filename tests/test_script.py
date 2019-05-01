import os

import pytest
import random

from bitcoinx.script import *
from bitcoinx import (
    pack_varint, PrivateKey, pack_byte, BitcoinTestnet, PublicKey,
    P2PKH_Script, P2PKH_Address, P2SH_Address, P2PKH_ScriptSig, P2PK_ScriptSig,
    ScriptSignature
)


# Workaround pytest bug: "ValueError: the environment variable is longer than 32767 bytes"
# https://github.com/pytest-dev/pytest/issues/2951
last_id = -1
def parameter_id(v):
    global last_id
    last_id += 1
    return last_id


def test_op_exports():
    assert OP_0 == 0
    assert OP_FALSE is OP_0
    assert OP_PUSHDATA1 == 76
    assert OP_PUSHDATA2 == 77
    assert OP_PUSHDATA4 == 78
    assert OP_1NEGATE == 79
    assert OP_RESERVED == 80
    assert OP_1 == 81
    assert OP_TRUE is OP_1
    assert OP_2 == 82
    assert OP_3 == 83
    assert OP_4 == 84
    assert OP_5 == 85
    assert OP_6 == 86
    assert OP_7 == 87
    assert OP_8 == 88
    assert OP_9 == 89
    assert OP_10 == 90
    assert OP_11 == 91
    assert OP_12 == 92
    assert OP_13 == 93
    assert OP_14 == 94
    assert OP_15 == 95
    assert OP_16 == 96
    assert OP_NOP == 97
    assert OP_VER == 98
    assert OP_IF == 99
    assert OP_NOTIF == 100
    assert OP_VERIF == 101
    assert OP_VERNOTIF == 102
    assert OP_ELSE == 103
    assert OP_ENDIF == 104
    assert OP_VERIFY == 105
    assert OP_RETURN == 106
    assert OP_TOALTSTACK == 107
    assert OP_FROMALTSTACK == 108
    assert OP_2DROP == 109
    assert OP_2DUP == 110
    assert OP_3DUP == 111
    assert OP_2OVER == 112
    assert OP_2ROT == 113
    assert OP_2SWAP == 114
    assert OP_IFDUP == 115
    assert OP_DEPTH == 116
    assert OP_DROP == 117
    assert OP_DUP == 118
    assert OP_NIP == 119
    assert OP_OVER == 120
    assert OP_PICK == 121
    assert OP_ROLL == 122
    assert OP_ROT == 123
    assert OP_SWAP == 124
    assert OP_TUCK == 125
    assert OP_CAT == 126
    assert OP_SPLIT == 127
    assert OP_NUM2BIN == 128
    assert OP_BIN2NUM == 129
    assert OP_SIZE == 130
    assert OP_INVERT == 131
    assert OP_AND == 132
    assert OP_OR == 133
    assert OP_XOR == 134
    assert OP_EQUAL == 135
    assert OP_EQUALVERIFY == 136
    assert OP_RESERVED1 == 137
    assert OP_RESERVED2 == 138
    assert OP_1ADD == 139
    assert OP_1SUB == 140
    assert OP_2MUL == 141
    assert OP_2DIV == 142
    assert OP_NEGATE == 143
    assert OP_ABS == 144
    assert OP_NOT == 145
    assert OP_0NOTEQUAL == 146
    assert OP_ADD == 147
    assert OP_SUB == 148
    assert OP_MUL == 149
    assert OP_DIV == 150
    assert OP_MOD == 151
    assert OP_LSHIFT == 152
    assert OP_RSHIFT == 153
    assert OP_BOOLAND == 154
    assert OP_BOOLOR == 155
    assert OP_NUMEQUAL == 156
    assert OP_NUMEQUALVERIFY == 157
    assert OP_NUMNOTEQUAL == 158
    assert OP_LESSTHAN == 159
    assert OP_GREATERTHAN == 160
    assert OP_LESSTHANOREQUAL == 161
    assert OP_GREATERTHANOREQUAL == 162
    assert OP_MIN == 163
    assert OP_MAX == 164
    assert OP_WITHIN == 165
    assert OP_RIPEMD160 == 166
    assert OP_SHA1 == 167
    assert OP_SHA256 == 168
    assert OP_HASH160 == 169
    assert OP_HASH256 == 170
    assert OP_CODESEPARATOR == 171
    assert OP_CHECKSIG == 172
    assert OP_CHECKSIGVERIFY == 173
    assert OP_CHECKMULTISIG == 174
    assert OP_CHECKMULTISIGVERIFY == 175
    assert OP_NOP1 == 176
    assert OP_CHECKLOCKTIMEVERIFY == 177
    assert OP_NOP2 is OP_CHECKLOCKTIMEVERIFY
    assert OP_CHECKSEQUENCEVERIFY == 178
    assert OP_NOP3 is OP_CHECKSEQUENCEVERIFY
    assert OP_NOP4 == 179
    assert OP_NOP5 == 180
    assert OP_NOP6 == 181
    assert OP_NOP7 == 182
    assert OP_NOP8 == 183
    assert OP_NOP9 == 184
    assert OP_NOP10 == 185


def test_Ops_members():
    # In order to be sure we catch new additions
    assert len(Ops) == 111
    assert len(Ops.__members__) == 115

    assert Ops['OP_0'].value == 0
    assert Ops['OP_FALSE'].value == 0
    assert Ops['OP_PUSHDATA1'].value == 76
    assert Ops['OP_PUSHDATA2'].value == 77
    assert Ops['OP_PUSHDATA4'].value == 78
    assert Ops['OP_1NEGATE'].value == 79
    assert Ops['OP_RESERVED'].value == 80
    assert Ops['OP_1'].value == 81
    assert Ops['OP_TRUE'].value == 81
    assert Ops['OP_2'].value == 82
    assert Ops['OP_3'].value == 83
    assert Ops['OP_4'].value == 84
    assert Ops['OP_5'].value == 85
    assert Ops['OP_6'].value == 86
    assert Ops['OP_7'].value == 87
    assert Ops['OP_8'].value == 88
    assert Ops['OP_9'].value == 89
    assert Ops['OP_10'].value == 90
    assert Ops['OP_11'].value == 91
    assert Ops['OP_12'].value == 92
    assert Ops['OP_13'].value == 93
    assert Ops['OP_14'].value == 94
    assert Ops['OP_15'].value == 95
    assert Ops['OP_16'].value == 96
    assert Ops['OP_NOP'].value == 97
    assert Ops['OP_VER'].value == 98
    assert Ops['OP_IF'].value == 99
    assert Ops['OP_NOTIF'].value == 100
    assert Ops['OP_VERIF'].value == 101
    assert Ops['OP_VERNOTIF'].value == 102
    assert Ops['OP_ELSE'].value == 103
    assert Ops['OP_ENDIF'].value == 104
    assert Ops['OP_VERIFY'].value == 105
    assert Ops['OP_RETURN'].value == 106
    assert Ops['OP_TOALTSTACK'].value == 107
    assert Ops['OP_FROMALTSTACK'].value == 108
    assert Ops['OP_2DROP'].value == 109
    assert Ops['OP_2DUP'].value == 110
    assert Ops['OP_3DUP'].value == 111
    assert Ops['OP_2OVER'].value == 112
    assert Ops['OP_2ROT'].value == 113
    assert Ops['OP_2SWAP'].value == 114
    assert Ops['OP_IFDUP'].value == 115
    assert Ops['OP_DEPTH'].value == 116
    assert Ops['OP_DROP'].value == 117
    assert Ops['OP_DUP'].value == 118
    assert Ops['OP_NIP'].value == 119
    assert Ops['OP_OVER'].value == 120
    assert Ops['OP_PICK'].value == 121
    assert Ops['OP_ROLL'].value == 122
    assert Ops['OP_ROT'].value == 123
    assert Ops['OP_SWAP'].value == 124
    assert Ops['OP_TUCK'].value == 125
    assert Ops['OP_CAT'].value == 126
    assert Ops['OP_SPLIT'].value == 127
    assert Ops['OP_NUM2BIN'].value == 128
    assert Ops['OP_BIN2NUM'].value == 129
    assert Ops['OP_SIZE'].value == 130
    assert Ops['OP_INVERT'].value == 131
    assert Ops['OP_AND'].value == 132
    assert Ops['OP_OR'].value == 133
    assert Ops['OP_XOR'].value == 134
    assert Ops['OP_EQUAL'].value == 135
    assert Ops['OP_EQUALVERIFY'].value == 136
    assert Ops['OP_RESERVED1'].value == 137
    assert Ops['OP_RESERVED2'].value == 138
    assert Ops['OP_1ADD'].value == 139
    assert Ops['OP_1SUB'].value == 140
    assert Ops['OP_2MUL'].value == 141
    assert Ops['OP_2DIV'].value == 142
    assert Ops['OP_NEGATE'].value == 143
    assert Ops['OP_ABS'].value == 144
    assert Ops['OP_NOT'].value == 145
    assert Ops['OP_0NOTEQUAL'].value == 146
    assert Ops['OP_ADD'].value == 147
    assert Ops['OP_SUB'].value == 148
    assert Ops['OP_MUL'].value == 149
    assert Ops['OP_DIV'].value == 150
    assert Ops['OP_MOD'].value == 151
    assert Ops['OP_LSHIFT'].value == 152
    assert Ops['OP_RSHIFT'].value == 153
    assert Ops['OP_BOOLAND'].value == 154
    assert Ops['OP_BOOLOR'].value == 155
    assert Ops['OP_NUMEQUAL'].value == 156
    assert Ops['OP_NUMEQUALVERIFY'].value == 157
    assert Ops['OP_NUMNOTEQUAL'].value == 158
    assert Ops['OP_LESSTHAN'].value == 159
    assert Ops['OP_GREATERTHAN'].value == 160
    assert Ops['OP_LESSTHANOREQUAL'].value == 161
    assert Ops['OP_GREATERTHANOREQUAL'].value == 162
    assert Ops['OP_MIN'].value == 163
    assert Ops['OP_MAX'].value == 164
    assert Ops['OP_WITHIN'].value == 165
    assert Ops['OP_RIPEMD160'].value == 166
    assert Ops['OP_SHA1'].value == 167
    assert Ops['OP_SHA256'].value == 168
    assert Ops['OP_HASH160'].value == 169
    assert Ops['OP_HASH256'].value == 170
    assert Ops['OP_CODESEPARATOR'].value == 171
    assert Ops['OP_CHECKSIG'].value == 172
    assert Ops['OP_CHECKSIGVERIFY'].value == 173
    assert Ops['OP_CHECKMULTISIG'].value == 174
    assert Ops['OP_CHECKMULTISIGVERIFY'].value == 175
    assert Ops['OP_NOP1'].value == 176
    assert Ops['OP_CHECKLOCKTIMEVERIFY'].value == 177
    assert Ops['OP_NOP2'].value == 177
    assert Ops['OP_CHECKSEQUENCEVERIFY'].value == 178
    assert Ops['OP_NOP3'].value == 178
    assert Ops['OP_NOP4'].value == 179
    assert Ops['OP_NOP5'].value == 180
    assert Ops['OP_NOP6'].value == 181
    assert Ops['OP_NOP7'].value == 182
    assert Ops['OP_NOP8'].value == 183
    assert Ops['OP_NOP9'].value == 184
    assert Ops['OP_NOP10'].value == 185


P2PKH_script = PrivateKey.from_random().public_key.P2PKH_script()
assert P2PKH_script._script is None
assert isinstance(P2PKH_script, P2PKH_Script)

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

class TestScript:

    def test_construtor(self):
        assert Script() == b''

    def test_len(self):
        script = b'abcd'
        assert len(Script(script)) == len(script)

    def test_len_does_bytes_conversion(self):
        assert len(P2PKH_script) == 25

    def test_bytes(self):
        script = b'abcd'
        S = Script(script)
        assert bytes(S) == script
        S = Script(None)
        S._default_script = lambda: script
        assert bytes(S) is script

    def test_str(self):
        script = b'abcd'
        S = Script(script)
        assert str(S) == script.hex()

    def test_str_does_bytes_conversion(self):
        str(P2PKH_script)

    def test_hashable(self):
        {P2PKH_script, Script(b'ab')}

    def test_hash(self):
        assert hash(P2PKH_script) == hash(P2PKH_script.to_bytes())

    def test_default_script(self):
        S = Script(None)
        with pytest.raises(NotImplementedError):
            bytes(S)

    @pytest.mark.parametrize("script,item,answer", (
        ('0203', OP_CHECKSIG, '0203ac'),
        ('', OP_HASH160, 'a9'),
        ('ab', 0, 'ab00'),
        ('ab', 1, 'ab51'),
        ('ab', 16, 'ab60'),
        ('ab', 17, 'ab0111'),
        ('ab', -1, 'ab4f'),
        ('ab', -2, 'ab0182'),
        ('', bytearray(b'BitcoinSV'), '09426974636f696e5356'),
        ('', b'', '00'),
        ('8844aa', b'0' * 100, '8844aa4c64' + '30' * 100),
        ('88', Script.from_hex('77'), '8877'),
    ))
    def test_lshift(self, script, item, answer):
        script = Script.from_hex(script)
        script = script << item
        assert script.to_hex() == answer

    @pytest.mark.parametrize("item", ("text", [1, 2], (3, 4), {"a"}))
    def test_lshift_bad(self, item):
        with pytest.raises(TypeError):
            Script(b'') << item

    def test_lshift_does_bytes_conversion(self):
        result = P2PKH_script << OP_CHECKSIG
        raw = P2PKH_script.to_bytes()
        assert not isinstance(result, P2PKH_Script)
        assert result == raw + bytes([OP_CHECKSIG])
        assert P2PKH_script << P2PKH_script == raw * 2

    @pytest.mark.parametrize("items", (
        (OP_EQUALVERIFY, OP_CHECKSIG),
        (b'data', OP_EQUAL, OP_ADD, 45, -1, b'more data'),
    ))
    def test_push_many(self, items):
        script = Script(os.urandom(10))
        result = script.push_many(items)
        answer = script
        for item in items:
            answer = answer << item
        assert result == answer

    def test_push_many_with_iterable(self):
        items = (OP_EQUALVERIFY, OP_CHECKSIG)
        script = Script(b'')
        assert script.push_many(items) == script.push_many(item for item in items)

    def test_push_many_does_bytes_conversion(self):
        raw = P2PKH_script.to_bytes()
        result = P2PKH_script.push_many([OP_CHECKSIG])
        assert not isinstance(result, P2PKH_Script)
        assert result == raw + bytes([OP_CHECKSIG])

    @pytest.mark.parametrize("other", (
        Script(b'abcd'),
        b'abcd',
        bytearray(b'abcd'),
        memoryview(b'abcd'),
        memoryview(bytearray(b'abcd')),
    ))
    def test_eq(self, other):
        assert Script(b'abcd') == other

    @pytest.mark.parametrize("other", (
        "abcd",
        2,
    ))
    def test_not_eq(self, other):
        assert Script(b'abcd') != other

    def test_ops_does_bytes_conversion(self):
        list(P2PKH_script.ops())

    def test_P2PKHK_script(self):
        p = PrivateKey.from_random()
        PC = p.public_key
        PU = PC.complement()
        for P in (PC, PU):
            script = P.P2PKH_script()
            data = P.hash160()
            assert script == (bytes([OP_DUP, OP_HASH160, len(data)]) + data +
                              bytes([OP_EQUALVERIFY, OP_CHECKSIG]))

    @pytest.mark.parametrize("script,asm", (
        # No script
        (pack_byte(OP_0), '0'),
        (pack_byte(OP_1), '1'),
        (pack_byte(OP_2), '2'),
        (pack_byte(OP_3), '3'),
        (pack_byte(OP_4), '4'),
        (pack_byte(OP_5), '5'),
        (pack_byte(OP_6), '6'),
        (pack_byte(OP_7), '7'),
        (pack_byte(OP_8), '8'),
        (pack_byte(OP_9), '9'),
        (pack_byte(OP_10), '10'),
        (pack_byte(OP_11), '11'),
        (pack_byte(OP_12), '12'),
        (pack_byte(OP_13), '13'),
        (pack_byte(OP_14), '14'),
        (pack_byte(OP_15), '15'),
        (pack_byte(OP_16), '16'),
        (pack_byte(OP_1NEGATE), '-1'),
        (bytes([OP_6, OP_1NEGATE]), '6 -1'),
        (bytes([OP_16, 1, 16, 2, 16, 0, OP_PUSHDATA1, 1, 16]), '16 16 16 16'),
        (bytes([1, 17, 2, 17, 0, OP_PUSHDATA1, 1, 17]), '17 17 17'),
        (bytes([1, 128, 1, 127, 1, 128, 1, 255, 2, 127, 0, 2, 128, 0, 2, 255, 0, 2, 0, 1]),
         '0 127 0 -127 127 128 255 256'),
        (bytes([4, 255, 255, 255, 255, 4, 255, 255, 255, 127]), "-2147483647 2147483647"),
        # This has value 1 (if bignums are re-enabled) but shows as hex
        (bytes([5, 1, 0, 0, 0, 0]), '0100000000'),
        (bytes(), ''),
        # This is a truncated script
        (bytes([5, 1, 1, 1, 1]), '[error]'),
        (bytes(range(OP_1NEGATE, 256)),
         "-1 OP_RESERVED 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 OP_NOP OP_VER OP_IF OP_NOTIF "
         "OP_VERIF OP_VERNOTIF OP_ELSE OP_ENDIF OP_VERIFY OP_RETURN OP_TOALTSTACK OP_FROMALTSTACK "
         "OP_2DROP OP_2DUP OP_3DUP OP_2OVER OP_2ROT OP_2SWAP OP_IFDUP OP_DEPTH OP_DROP OP_DUP "
         "OP_NIP OP_OVER OP_PICK OP_ROLL OP_ROT OP_SWAP OP_TUCK OP_CAT OP_SPLIT OP_NUM2BIN "
         "OP_BIN2NUM OP_SIZE OP_INVERT OP_AND OP_OR OP_XOR OP_EQUAL OP_EQUALVERIFY OP_RESERVED1 "
         "OP_RESERVED2 OP_1ADD OP_1SUB OP_2MUL OP_2DIV OP_NEGATE OP_ABS OP_NOT OP_0NOTEQUAL "
         "OP_ADD OP_SUB OP_MUL OP_DIV OP_MOD OP_LSHIFT OP_RSHIFT OP_BOOLAND OP_BOOLOR "
         "OP_NUMEQUAL OP_NUMEQUALVERIFY OP_NUMNOTEQUAL OP_LESSTHAN OP_GREATERTHAN "
         "OP_LESSTHANOREQUAL OP_GREATERTHANOREQUAL OP_MIN OP_MAX OP_WITHIN OP_RIPEMD160 OP_SHA1 "
         "OP_SHA256 OP_HASH160 OP_HASH256 OP_CODESEPARATOR OP_CHECKSIG OP_CHECKSIGVERIFY "
         "OP_CHECKMULTISIG OP_CHECKMULTISIGVERIFY OP_NOP1 OP_CHECKLOCKTIMEVERIFY "
         "OP_CHECKSEQUENCEVERIFY OP_NOP4 OP_NOP5 OP_NOP6 OP_NOP7 OP_NOP8 OP_NOP9 OP_NOP10 "
         + "OP_UNKNOWN " * 69 + "OP_INVALIDOPCODE"),
    ))
    def test_to_asm(self, script, asm):
        assert Script(script).to_asm() == asm

    @pytest.mark.parametrize("op,word", (
        (OP_VERIF, "OP_VERIF"),
        (b'a', "97"),
        (b'\x01a', str(97 * 256 + 1)),
        (b'abcde', "6162636465"),
        (bytes([255, 255, 255, 255]), "-2147483647"),
        (bytes([255, 255, 255, 127]), "2147483647"),
    ))
    def test_op_to_asm_word(self, op, word):
        assert Script.op_to_asm_word(op) == word

    def test_to_bytes(self):
        data = os.urandom(15)
        script = Script(data)
        assert script.to_bytes() == data
        assert script.to_bytes() is data

    def test_to_hex(self):
        data = os.urandom(15)
        script = Script(data)
        assert script.to_hex() == data.hex()

    def test_to_hex_does_bytes_conversion(self):
        P2PKH_script.to_hex()

    def test_from_hex(self):
        data = os.urandom(20)
        script = Script.from_hex(data.hex())
        assert script.to_bytes() == data

    @pytest.mark.parametrize("word,item", (
        ("OP_VERIF", pack_byte(OP_VERIF)),
        ("OP_NOP", pack_byte(OP_NOP)),
        ("OP_0", pack_byte(OP_0)),
        ("97", b'\x01a'),
        ("6162636465", b'\5abcde'),
    ))
    def test_asm_word_to_bytes(self, word, item):
        assert Script.asm_word_to_bytes(word) == item

    @pytest.mark.parametrize("word", (
        "OP_FOO",
        "junk",
    ))
    def test_asm_word_to_btyes_bad(self, word):
        with pytest.raises(ScriptError):
            Script.asm_word_to_bytes(word)

    @pytest.mark.parametrize("asm,script", (
        ("OP_NOP OP_CHECKSIG OP_0 90 ababababab",
         bytes([OP_NOP, OP_CHECKSIG, OP_0, 1, 90, 5, 171, 171, 171, 171, 171])),
    ))
    def test_from_asm(self, asm, script):
        assert Script.from_asm(asm) == script

    @pytest.mark.parametrize("asm", (
        "OP_NOP5 OP_CHECKSIG 0 67 287542 -1 deadbeefdead",
    ))
    def test_asm_both_ways(self, asm):
        script = Script.from_asm(asm)
        assert script.to_asm() == asm

    @pytest.mark.parametrize("script,answer", (
        (Script(), (b'', [])),
        (Script() << OP_IF << OP_ELSE, (bytes([OP_IF, OP_ELSE]), [])),
        (Script() << 10 << OP_IF << b'data', (b'LcL', [pack_byte(10), b'data'])),
        (Script() << OP_NOP << OP_NOP << OP_EQUAL << OP_NOP, (bytes([OP_EQUAL]), [])),
        (Script() << b'foo' << b'bar' << OP_DROP, (b'L', [b'foo'])),
        (Script() << b'foo' << OP_DROP << b'bar' << OP_DROP, (b'', [])),
        (Script() << b'foo' << b'bar' << OP_DROP << OP_DROP, (b'', [])),
        (Script() << b'foo' << b'bar' << OP_2DROP, (b'', [])),
        (Script() << b'foo' << b'bar' << 12 << OP_2DROP, (b'L', [b'foo'])),
        (Script() << b'foo' << b'bar' << OP_NOP << OP_2DROP, (b'', [])),
        (Script() << OP_DROP << b'foo' << b'bar', (b'uLL', [b'foo', b'bar'])),
        (Script() << b'foo' << OP_2DROP << b'bar', (b'LmL', [b'foo', b'bar'])),
        (Script() << OP_IF << OP_DROP, (bytes([OP_IF, OP_DROP]), [])),
        (Script() << OP_IF << b'foo' << OP_2DROP, (bytes([OP_IF, OP_PUSHDATA1, OP_2DROP]),
                                                   [b'foo'])),
        (Script() << b'foo' << OP_IF << OP_2DROP, (bytes([OP_PUSHDATA1, OP_IF, OP_2DROP]),
                                                   [b'foo'])),
        (Script(b'\xff'), (bytes([0xff]), [])),
        (Script(b'\x00'), (b'L', [b''])),
        # A truncated script
        (Script(b'\x01'), (pack_byte(OP_0), [])),
    ))
    def test_to_template(self, script, answer):
        result = script.to_template()
        assert result == answer

    def test_to_template_complex(self):
        N = 10
        # Put some random operations on the stack
        items = [os.urandom(10) for n in range(N)]
        ops = [Ops(x) for x in range(OP_VER, OP_NOP10)]
        ops.remove(OP_DROP)
        ops.remove(OP_2DROP)
        items.extend(random.choice(ops) for n in range(N))
        random.shuffle(items)

        s1 = Script().push_many(items)
        answer = s1.to_template()

        # Now add some random nops at random points
        for n in range(N):
            p = random.randrange(0, 3)
            pos = random.randrange(0, len(items))
            if p == 0:
                items.insert(pos, OP_NOP)
            elif p == 1:
                items.insert(pos, os.urandom(10))
                items.insert(pos + 1, OP_DROP)
            else:
                items.insert(pos, os.urandom(10))
                items.insert(pos + 1, os.urandom(10))
                items.insert(pos + 2, OP_2DROP)

        s2 = Script().push_many(items)
        assert s2.to_template() == answer


class TestP2PK_Script:

    def test_constructor(self):
        p = PrivateKey.from_random()
        PC = p.public_key
        PU = PC.complement()
        for P in (PC, PU):
            script = P2PK_Script(P)
            data = P.to_bytes()
            assert script == bytes([len(data)]) + data + bytes([OP_CHECKSIG])
        script = P2PK_Script(P, b'foobar')
        assert script == b'foobar'

    def test_constructor_bad(self):
        with pytest.raises(TypeError):
            P2PK_Script(bytes.fromhex('036d6caac248af96f6afa7f904f550253a0f3ef3f5a'
                                      'a2fe6838a95b216691468e2'))

    def test_from_template(self):
        p = PrivateKey.from_random()
        PC = p.public_key
        script = P2PK_Script.from_template(b'foobar', PC.to_bytes())
        assert script.public_key == PC
        assert script == b'foobar'


class TestP2PKH_Script:

    def test_constructor(self):
        p = PrivateKey.from_random()
        PC = p.public_key
        script_PC = P2PKH_Script(PC)
        hash160 = PC.hash160()
        script_hash160 = P2PKH_Script(hash160)
        address = P2PKH_Address(hash160)
        script_address = P2PKH_Script(address)
        assert script_PC == script_hash160 == script_address
        assert (script_PC.hash160() == script_hash160.hash160() ==
                script_address.hash160() == hash160)

    def test_constructor_bad(self):
        with pytest.raises(TypeError):
            P2PKH_Script(bytearray(20))
        with pytest.raises(ValueError):
            P2PKH_Script(bytes(21))

    def test_to_address(self):
        hash160 = os.urandom(20)
        assert P2PKH_Script(hash160).to_address() == P2PKH_Address(hash160)
        assert P2PKH_Script(hash160).to_address(coin=BitcoinTestnet) != P2PKH_Address(hash160)
        assert (P2PKH_Script(hash160).to_address(coin=BitcoinTestnet) ==
                P2PKH_Address(hash160, coin=BitcoinTestnet))

    def test_from_template(self):
        p = PrivateKey.from_random()
        PC = p.public_key
        script = P2PKH_Script.from_template(b'foobar', PC.hash160())
        assert script.hash160() == PC.hash160()
        assert script == b'foobar'


class TestP2SH_Script:

    def test_constructor(self):
        hash160 = os.urandom(20)
        script_hash160 = P2SH_Script(hash160)
        address = P2SH_Address(hash160)
        script_address = P2SH_Script(address)
        assert script_hash160 == script_address
        assert script_hash160.hash160() == script_address.hash160() == hash160

    def test_constructor_bad(self):
        with pytest.raises(TypeError):
            P2SH_Script(bytearray(20))
        with pytest.raises(ValueError):
            P2SH_Script(bytes(21))

    def test_to_address(self):
        hash160 = os.urandom(20)
        assert P2SH_Script(hash160).to_address() == P2SH_Address(hash160)
        assert P2SH_Script(hash160).to_address(coin=BitcoinTestnet) != P2SH_Address(hash160)
        assert (P2SH_Script(hash160).to_address(coin=BitcoinTestnet) ==
                P2SH_Address(hash160, coin=BitcoinTestnet))

    def test_from_template(self):
        p = PrivateKey.from_random()
        PC = p.public_key
        script = P2SH_Script.from_template(b'foobar', PC.hash160())
        assert script.hash160() == PC.hash160()
        assert script == b'foobar'


MS_PUBKEYS = [PrivateKey.from_random().public_key for n in range(5)]

class TestP2MultiSig_Script:

    @pytest.mark.parametrize("threshold, count",
                             [(m + 1, n + 1) for n in range(len(MS_PUBKEYS)) for m in range(n)]
    )
    def test_constructor(self, threshold, count):
        script_pk = P2MultiSig_Script(MS_PUBKEYS[:count], threshold)
        assert bytes(script_pk) == b''.join((
            push_int(threshold),
            b''.join(push_item(public_key.to_bytes()) for public_key in MS_PUBKEYS[:count]),
            push_int(count),
            pack_byte(OP_CHECKMULTISIG),
        ))

    def test_constructor_copies(self):
        public_keys = list(MS_PUBKEYS[:2])
        script = P2MultiSig_Script(public_keys, 2)
        assert script.public_keys is not public_keys

    def test_constructor_bad(self):
        with pytest.raises(TypeError):
            P2MultiSig_Script(MS_PUBKEYS + [b''], 2)
        with pytest.raises(ValueError):
            P2MultiSig_Script(MS_PUBKEYS, 0)
        with pytest.raises(ValueError):
            P2MultiSig_Script(MS_PUBKEYS, len(MS_PUBKEYS) + 1)

    @pytest.mark.parametrize("threshold, count",
                             [(m + 1, n + 1) for n in range(len(MS_PUBKEYS)) for m in range(n)]
    )
    def test_from_template(self, threshold, count):
        good_script = P2MultiSig_Script(MS_PUBKEYS[:count], threshold)
        public_keys = [public_key.to_bytes() for public_key in MS_PUBKEYS[:count]]
        script = P2MultiSig_Script.from_template(bytes(good_script), pack_byte(threshold),
                                                 *public_keys, pack_byte(count))
        assert script.public_keys == MS_PUBKEYS[:count]
        assert script.threshold == threshold
        assert script == good_script

    def test_from_template_bad(self):
        public_keys = [PrivateKey.from_random().public_key.to_bytes() for n in range(2)]
        with pytest.raises(ValueError):
            script = P2MultiSig_Script.from_template(pack_byte(1), public_keys, pack_byte(1))
        with pytest.raises(ValueError):
            script = P2MultiSig_Script.from_template(pack_byte(1), public_keys, pack_byte(3))

MS_SIGS = tuple(bytes.fromhex(sig_hex) for sig_hex in (
    '30450221009a8f3f87228213a66525137b59bb9884c5a6fce43128f0eaf81082c50b99c07b022030a2a45a7b75b9d691370afc0e790ad17d971cfccb3da9c236e9aaa316973d0c41',
    '3045022100928b6b9b5e0d063fff02d74a7fcc2fcc2ea5a9a1d4cf4e241302979fe0b976d102203f4aeac2959cf4f91742720c0c77b66c488334d56e45486aecf46599af1f204941'
))


class TestP2PK_ScriptSig:

    def test_constructor(self):
        for sig in MS_SIGS:
            scriptsig = P2PK_ScriptSig(sig)
            assert bytes(scriptsig) == push_item(sig)

    def test_from_template(self):
        sig = MS_SIGS[0]
        assert P2PK_ScriptSig.from_template(None, sig) == P2PK_ScriptSig(sig)

SIG_PUBKEY_PAIRS = [
    (bytes.fromhex('304402206f840c84939bb711e9805dc10ced562fa70ea0f7dcc36b5f44c209b2ac29fc9b'
                   '022042b810f40adc6cb3f186d82394c3b0296d1fcb0211d2d6d20febbd1d515675f101'),
     PublicKey.from_hex('040bf47f1c24d1b5a597312422091a324a3d57d0123c9ba853ac9dc1eb81d954bc056'
                        'a18a33d9e7cefd2bf10434ec3f1a39d3c3ede6f2bb3cf21730df38fa0a05d'), ),
]


class TestP2PKH_ScriptSig:

    @pytest.mark.parametrize("sig, public_key", SIG_PUBKEY_PAIRS)
    def test_constructor(self, sig, public_key):
        scriptsig = P2PKH_ScriptSig(sig, public_key)
        assert bytes(scriptsig) == push_item(sig) + push_item(public_key.to_bytes())
        assert bytes(scriptsig.script_sig) == sig
        assert scriptsig.script_sig.sighash == sig[-1]
        assert scriptsig.public_key == public_key

    @pytest.mark.parametrize("sig, public_key", SIG_PUBKEY_PAIRS)
    def test_from_template(self, sig, public_key):
        assert (P2PKH_ScriptSig.from_template(None, sig, public_key.to_bytes()) ==
                P2PKH_ScriptSig(sig, public_key))


class TestP2MultiSig_ScriptSig:

    def test_constructor_copies(self):
        script_sigs = [ScriptSignature(script_sig) for script_sig in MS_SIGS]
        script = P2MultiSig_ScriptSig(script_sigs)
        assert script.script_sigs is not script_sigs
        assert script.script_sigs == script_sigs

    def test_constructor_bad(self):
        script_sigs = [ScriptSignature(script_sig) for script_sig in MS_SIGS]
        with pytest.raises(TypeError):
            P2MultiSig_ScriptSig(script_sigs[:-1] + [2])
        with pytest.raises(ValueError):
            P2MultiSig_ScriptSig([])

    def test_default_script(self):
        s = classify_script_sig(Script(bytes.fromhex(multisig_scriptsig)))
        assert s._default_script().hex() == multisig_scriptsig

    # From_template tested in classify_script_sig() above

    def test_from_template_bad(self):
        with pytest.raises(ValueError):
           P2MultiSig_ScriptSig.from_template(None)
        with pytest.raises(ValueError):
            P2MultiSig_ScriptSig.from_template(None, pack_byte(OP_0))
        with pytest.raises(ValueError):
            P2MultiSig_ScriptSig.from_template(None, pack_byte(OP_1), *MS_SIGS)


class TestClassification:

    def test_P2PKH(self):
        script_hex = '76a914a6dbba870185ab6689f386a40522ae6cb5c7b61a88ac'
        s = Script.from_hex(script_hex)
        sc = classify_script_pk(s)
        assert s == sc
        assert isinstance(sc, P2PKH_Script)

        prefix = push_item(b'foobar') + pack_byte(OP_DROP) + pack_byte(OP_NOP)
        s2 = Script.from_hex(prefix.hex() + script_hex)
        sc2 = classify_script_pk(s2)
        assert s2 == sc2
        assert s2 != s
        assert isinstance(sc2, P2PKH_Script)

    def test_P2SH(self):
        script_hex = 'a9143e4501f9f212cb6813b3815edbc7013d6a3f0f1087'
        s = Script.from_hex(script_hex)
        sc = classify_script_pk(s)
        assert s == sc
        assert isinstance(sc, P2SH_Script)

        suffix = push_item(b'foobar') + pack_byte(OP_DROP) + pack_byte(OP_NOP)
        s2 = Script.from_hex(script_hex + suffix.hex())
        sc2 = classify_script_pk(s2)
        assert s2 == sc2
        assert s2 != s
        assert isinstance(sc2, P2SH_Script)

    def test_P2PK(self):
        script_hex = '210363f75554e05e05a04551e59d78d78965ec6789f42199f7cbaa9fa4bd2df0a4b4ac'
        s = Script.from_hex(script_hex)
        sc = classify_script_pk(s)
        assert s == sc
        assert isinstance(sc, P2PK_Script)
        assert (sc.public_key.to_hex() ==
                '0363f75554e05e05a04551e59d78d78965ec6789f42199f7cbaa9fa4bd2df0a4b4')

        suffix = push_item(b'foo') + push_item(b'bar') + pack_byte(OP_2DROP)
        s2 = Script.from_hex(script_hex + suffix.hex())
        sc2 = classify_script_pk(s2)
        assert s2 == sc2
        assert sc2.public_key == sc.public_key
        assert s2 != s
        assert isinstance(sc2, P2PK_Script)

    def test_P2MultiSig(self):
        script_hex = ('5221022812701688bc76ef3610b46c8e97f4b385241d5ed6eab6269b8af5f9bfd5a89c210'
                      '3fa0879c543ac97f34daffdaeed808f3500811aa5070e4a1f7e2daed3dd22ef2052ae')
        s = Script.from_hex(script_hex)
        sc = classify_script_pk(s)
        assert isinstance(sc, P2MultiSig_Script)
        assert len(sc.public_keys) == 2
        assert sc.threshold == 2

        # Confirm suffix fails to match
        s = Script.from_hex(script_hex + 'a0')
        assert classify_script_pk(s) is s
        # Confirm prefix fails to match
        s = Script.from_hex('a0' + script_hex)
        assert classify_script_pk(s) is s

    def test_OP_RETURN(self):
        s = Script(pack_byte(OP_RETURN))
        sc = classify_script_pk(s)
        assert sc == s
        assert isinstance(sc, OP_RETURN_Script)

        s = Script(pack_byte(OP_RETURN) + push_item(b'BitcoinSV'))
        sc = classify_script_pk(s)
        assert sc == s
        assert isinstance(sc, OP_RETURN_Script)

        # Truncated OP_RETURN script
        s = Script(pack_byte(OP_RETURN) + pack_byte(1))
        sc = classify_script_pk(s)
        assert sc == s
        assert isinstance(sc, OP_RETURN_Script)

    def test_unknown(self):
        # Modified final pubkey byte; not a curve point
        script_hex = '210363f75554e05e05a04551e59d78d78965ec6789f42199f7cbaa9fa4bd2df0a4b3ac'
        s = Script.from_hex(script_hex)
        sc = classify_script_pk(s)
        assert sc is s

        # Truncated script
        script_hex = '210363f7'
        s = Script.from_hex(script_hex)
        sc = classify_script_pk(s)
        assert sc is s

        # Unknown script
        script_hex = pack_byte(OP_TRUE).hex()
        s = Script.from_hex(script_hex)
        sc = classify_script_pk(s)
        assert sc is s

    @pytest.mark.parametrize("sig_hex", (
        'ff',
        '304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd4'
        '10220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0941',
    ))
    def test_P2PK_scriptsig(self, sig_hex):
        script = Script(push_item(bytes.fromhex(sig_hex)))
        sc = classify_script_sig(script)
        assert isinstance(sc, P2PK_ScriptSig)

    @pytest.mark.parametrize("sig_hex", (
        'fe',
        '302402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd4'
        '10220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0941',
    ))
    def test_bad_P2PK_scriptsig(self, sig_hex):
        script = Script(push_item(bytes.fromhex(sig_hex)))
        sc = classify_script_sig(script)
        assert sc is script

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
        sc = classify_script_sig(script)
        assert isinstance(sc, P2PKH_ScriptSig)

    @pytest.mark.parametrize("sig_hex, sigs", (
        (multisig_scriptsig,
         [ScriptSignature.from_hex(hex_str) for hex_str in (
             '30450221009a8f3f87228213a66525137b59bb9884c5a6fce43128f0eaf81082c50b99c0'
             '7b022030a2a45a7b75b9d691370afc0e790ad17d971cfccb3da9c236e9aaa316973d0c41',
             '3045022100928b6b9b5e0d063fff02d74a7fcc2fcc2ea5a9a1d4cf4e241302979fe0b976'
             'd102203f4aeac2959cf4f91742720c0c77b66c488334d56e45486aecf46599af1f204941',
         )],
        ),
    ))
    def test_P2MultiSig_ScriptSig(self, sig_hex, sigs):
        script = Script(bytes.fromhex(sig_hex))
        sc = classify_script_sig(script)
        assert isinstance(sc, P2MultiSig_ScriptSig)
        assert sc.script_sigs == sigs

    @pytest.mark.parametrize("sig_hex,sigs,public_keys", (
        (p2sh_multisig_scriptsig,
         [ScriptSignature.from_hex(hex_str) for hex_str in (
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
    def test_P2SHMultiSig_ScriptSig(self, sig_hex, sigs, public_keys):
        script = Script(bytes.fromhex(sig_hex))
        sc = classify_script_sig(script)
        assert isinstance(sc, P2SHMultiSig_ScriptSig)
        assert sc.multisig_script_sig.script_sigs == sigs
        assert sc.nested_script.public_keys == public_keys


@pytest.mark.parametrize("item,answer", (
    (b'', pack_byte(OP_0)),
    (b'\x00', bytes([1, 0])),
    (b'\x01', pack_byte(OP_1)),
    (b'\x02', pack_byte(OP_2)),
    (b'\x03', pack_byte(OP_3)),
    (b'\x04', pack_byte(OP_4)),
    (b'\x05', pack_byte(OP_5)),
    (b'\x06', pack_byte(OP_6)),
    (b'\x07', pack_byte(OP_7)),
    (b'\x08', pack_byte(OP_8)),
    (b'\x09', pack_byte(OP_9)),
    (b'\x0a', pack_byte(OP_10)),
    (b'\x0b', pack_byte(OP_11)),
    (b'\x0c', pack_byte(OP_12)),
    (b'\x0d', pack_byte(OP_13)),
    (b'\x0e', pack_byte(OP_14)),
    (b'\x0f', pack_byte(OP_15)),
    (b'\x10', pack_byte(OP_16)),
    (b'\x11', bytes([1, 0x11])),
    (b'\x80', bytes([1, 0x80])),
    (b'\x81', pack_byte(OP_1NEGATE)),
    (b'\x82', bytes([1, 0x82])),
    (b'\xff', bytes([1, 0xff])),
    (b'abcd', bytes([4]) +  b'abcd'),
    (b'a' * 75, bytes([75]) +  b'a' * 75),
    (b'a' * 76, bytes([OP_PUSHDATA1, 76]) +  b'a' * 76),
    (b'a' * 255, bytes([OP_PUSHDATA1, 255]) +  b'a' * 255),
    (b'a' * 256, bytes([OP_PUSHDATA2, 0, 1]) +  b'a' * 256),
    (b'a' * 260, bytes([OP_PUSHDATA2, 4, 1]) +  b'a' * 260),
    (b'a' * 65535, bytes([OP_PUSHDATA2, 0xff, 0xff]) +  b'a' * 65535),
    (b'a' * 65536, bytes([OP_PUSHDATA4, 0, 0, 1, 0]) +  b'a' * 65536),
    (b'a' * 65541, bytes([OP_PUSHDATA4, 5, 0, 1, 0]) +  b'a' * 65541),
), ids=parameter_id)
def test_push_item(item, answer):
    # Also tests push_and_drop_item
    assert push_item(item) == answer
    assert push_and_drop_item(item) == answer + bytes([OP_DROP])


@pytest.mark.parametrize("items,answer", (
    ([b''], pack_byte(OP_0) + pack_byte(OP_DROP)),
    ([b'', b''], pack_byte(OP_0) * 2 + pack_byte(OP_2DROP)),
    ([b'', b'\x04', b''], bytes((OP_0, OP_4, OP_0, OP_2DROP, OP_DROP))),
), ids=parameter_id)
def test_push_and_drop_items(items, answer):
    assert push_and_drop_items(items) == answer


@pytest.mark.parametrize("value,encoding", (
    (-1, pack_byte(OP_1NEGATE)),
    (-2, bytes([1, 0x82])),
    (-127, bytes([1, 0xff])),
    (-128, bytes([2, 128, 0x80])),
    (0, pack_byte(OP_0)),
    (1, pack_byte(OP_1)),
    (2, pack_byte(OP_2)),
    (15, pack_byte(OP_15)),
    (16, pack_byte(OP_16)),
    (17, bytes([1, 17])),
), ids=parameter_id)
def test_push_int(value, encoding):
    assert push_int(value) == encoding


@pytest.mark.parametrize("value,encoding", (
    (-1, b'\x81'),
    (-2, b'\x82'),
    (-127, b'\xff'),
    (-128, b'\x80\x80'),
    (0, b''),
    (1, b'\x01'),
    (2, b'\x02'),
    (16, b'\x10'),
    (127, b'\x7f'),
    (128, b'\x80\x00'),
    (129, b'\x81\x00'),
    (255, b'\xff\x00'),
    (256, b'\x00\x01'),
    (32767, b'\xff\x7f'),
    (32768, b'\x00\x80\x00'),
), ids=parameter_id)
def test_item_to_int(value, encoding):
    assert item_to_int(encoding) == value


@pytest.mark.parametrize("script,ops", (
    (bytes([OP_RESERVED, OP_DUP, OP_NOP, OP_15, OP_HASH160, OP_1NEGATE]) + push_item(b'BitcoinSV'),
     [OP_RESERVED, OP_DUP, OP_NOP, b'\x0f', OP_HASH160, b'\x81', b'BitcoinSV']),
    (b'', []),
    (push_item(b'a' * 80), [b'a' * 80]),
    (push_item(b'a' * 256), [b'a' * 256]),
    (push_item(b'a' * 65536), [b'a' * 65536]),
), ids=parameter_id)
def test_script_ops(script, ops):
    assert list(Script(script).ops()) == ops


@pytest.mark.parametrize("script", (
    push_item(bytes(2))[:-1],
    push_item(bytes(76))[:-1],
    push_item(bytes(80))[:-1],
    push_item(bytes(256))[:-1],
    push_item(bytes(65536))[:-1],
), ids=parameter_id)
def test_script_ops_truncated(script):
    with pytest.raises(TruncatedScriptError):
        list(Script(script).ops())


@pytest.mark.parametrize("script", (
    'hello',
    [b''],
), ids=parameter_id)
def test_script_ops_type_error(script):
    with pytest.raises(TypeError):
        list(Script(script).ops())
