import os
import random

import pytest

from bitcoinx.errors import ImpossibleEncoding
from bitcoinx.consts import JSONFlags
from bitcoinx.script import (
    Script, ScriptError, TruncatedScriptError, Ops, push_item, int_to_item, push_and_drop_item,
    push_and_drop_items, push_int, item_to_int, is_item_minimally_encoded, minimal_push_opcode,
    cast_to_bool,
    OP_0, OP_FALSE, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4, OP_1NEGATE, OP_RESERVED, OP_1,
    OP_TRUE, OP_2, OP_3, OP_4, OP_5, OP_6, OP_7, OP_8, OP_9, OP_10, OP_11, OP_12, OP_13, OP_14,
    OP_15, OP_16, OP_NOP, OP_VER, OP_IF, OP_NOTIF, OP_VERIF, OP_VERNOTIF, OP_ELSE, OP_ENDIF,
    OP_VERIFY, OP_RETURN, OP_TOALTSTACK, OP_FROMALTSTACK, OP_2DROP, OP_2DUP, OP_3DUP, OP_2OVER,
    OP_2ROT, OP_2SWAP, OP_IFDUP, OP_DEPTH, OP_DROP, OP_DUP, OP_NIP, OP_OVER, OP_PICK, OP_ROLL,
    OP_ROT, OP_SWAP, OP_TUCK, OP_CAT, OP_SPLIT, OP_NUM2BIN, OP_BIN2NUM, OP_SIZE, OP_INVERT,
    OP_AND, OP_OR, OP_XOR, OP_EQUAL, OP_EQUALVERIFY, OP_RESERVED1, OP_RESERVED2, OP_1ADD, OP_1SUB,
    OP_2MUL, OP_2DIV, OP_NEGATE, OP_ABS, OP_NOT, OP_0NOTEQUAL, OP_ADD, OP_SUB, OP_MUL, OP_DIV,
    OP_MOD, OP_LSHIFT, OP_RSHIFT, OP_BOOLAND, OP_BOOLOR, OP_NUMEQUAL, OP_NUMEQUALVERIFY,
    OP_NUMNOTEQUAL, OP_LESSTHAN, OP_GREATERTHAN, OP_LESSTHANOREQUAL, OP_GREATERTHANOREQUAL,
    OP_MIN, OP_MAX, OP_WITHIN, OP_RIPEMD160, OP_SHA1, OP_SHA256, OP_HASH160, OP_HASH256,
    OP_CODESEPARATOR, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY,
    OP_NOP1, OP_CHECKLOCKTIMEVERIFY, OP_NOP2, OP_CHECKSEQUENCEVERIFY, OP_NOP3, OP_NOP4, OP_NOP5,
    OP_NOP6, OP_NOP7, OP_NOP8, OP_NOP9, OP_NOP10
)
from bitcoinx import PublicKey, pack_byte, Bitcoin, BitcoinTestnet

from .utils import zeroes, non_zeroes


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


P2PKH_script = PublicKey.from_random().P2PKH_script()


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
        assert bytes(S) is script

    def test_str(self):
        script = b'abcd'
        S = Script(script)
        assert str(S) == script.hex()

    def test_repr(self):
        S = Script(b'abcd')
        assert repr(S) == 'Script<"61626364">'

    def test_str_does_bytes_conversion(self):
        str(P2PKH_script)

    def test_hashable(self):
        {P2PKH_script, Script(b'ab')}

    def test_hash(self):
        assert hash(P2PKH_script) == hash(P2PKH_script.to_bytes())

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
    ), ids=["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"])
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

    def test_P2PKH_script(self):
        P = PublicKey.from_random()
        script = P.P2PKH_script()
        data = P.hash160()
        assert data == P.hash160(compressed=True)
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
    ), ids=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14",
            "15", "16", "-1", "6 -1", "16 16 16 16", "17 17 17", "0...256", "signed 32",
            "1hex", "empty", "many ops"])
    def test_to_asm(self, script, asm):
        assert Script(script).to_asm(False) == asm

    def test_to_asm_extreme(self):
        # Test a messy script full of corner cases; I have comfirmed the result is what
        # bitcoind outputs.  Note how ASM output of the last 2 distinct numbers is the
        # same...
        s = (Script() << OP_1 << OP_1NEGATE << OP_RESERVED << OP_16 << 98 << 65538 <<
             ((1 << 31) - 1) << -2147483647 << (1 << 31) << (1 << 32) <<
             OP_CHECKSIG << Script(b'\xfe\xff') << 1_000_000_010 << 0x1000000010)
        assert s.to_asm(False) == (
            '1 -1 OP_RESERVED 16 98 65538 2147483647 -2147483647 0000008000 0000000001 '
            'OP_CHECKSIG OP_UNKNOWN OP_INVALIDOPCODE 1000000010 1000000010'
        )

    @pytest.mark.parametrize("script, asm", (
        (bytes([OP_DUP, 5, 1, 1, 1, 1]), 'OP_DUP [script error]'),
        (bytes([OP_15, OP_1, OP_HASH160, 2, 2]), '15 1 OP_HASH160 [script error]'),
    ))
    def test_to_asm_truncated(self, script, asm):
        assert Script(script).to_asm(False) == asm
        text = '<wombat>'
        assert Script(script).to_asm(False, text) == asm.replace('[script error]', text)

    @pytest.mark.parametrize("script,network,json,extra", (
        # A P2PK output
        (
            '410494b9d3e76c5b1629ecf97fff95d7a4bbdac87cc26099ada28066c6ff1eb9191223cd89719'
            '4a08d0c2726c5747f1db49e8cf90e75dc3e3550ae9b30086f3cd5aaac', Bitcoin,
            {
                'asm': '0494b9d3e76c5b1629ecf97fff95d7a4bbdac87cc26099ada28066c6ff1eb9191223c'
                'd897194a08d0c2726c5747f1db49e8cf90e75dc3e3550ae9b30086f3cd5aa OP_CHECKSIG',
            },
            {
                'type': 'pubkey',
                'pubkey': '0494b9d3e76c5b1629ecf97fff95d7a4bbdac87cc26099ada28066c6ff1eb919'
                '1223cd897194a08d0c2726c5747f1db49e8cf90e75dc3e3550ae9b30086f3cd5aa',
                'address': '1FvzCLoTPGANNjWoUo6jUGuAG3wg1w4YjR',
            },
        ),
        # A P2PK signature
        (
            '47304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220'
            '181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901', Bitcoin,
            {
                'asm': '304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb'
                '8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901',
            },
            {
                'type': 'unknown',
            },
        ),
        # A P2PKH output
        (
            '76a914db47858485fa2fd737bbfddd46e5ce106cc2693c88ac', Bitcoin,
            {
                'asm': 'OP_DUP OP_HASH160 db47858485fa2fd737bbfddd46e5ce106cc2693c '
                'OP_EQUALVERIFY OP_CHECKSIG',
            },
            {
                'type': 'pubkeyhash',
                'address': '1LzSfR6nFctA9yktzGh9wgdc2ioByaRT2r',
            },
        ),
        # A P2PKH output (testnet)
        (
            '76a914db47858485fa2fd737bbfddd46e5ce106cc2693c88ac', BitcoinTestnet,
            {
                'asm': 'OP_DUP OP_HASH160 db47858485fa2fd737bbfddd46e5ce106cc2693c '
                'OP_EQUALVERIFY OP_CHECKSIG',
            },
            {
                'type': 'pubkeyhash',
                'address': 'n1WPxUBm4eKQw6EWhqfXmbqvtiPtwcUoq7',
            },
        ),
        # A P2PKH signature
        (
            '47304402205720b4406b5ff54b4978b61a924b304f1f74d97121f2323d53b2271120f9219602204'
            'c9cd794420d192fae98e5d1e43afeac606f2cadecd1506788ab93f458c18347412103670df4024f'
            '4dfd2b35ae61e9eac4e533f419abe68edc46cee68755974cf3a453', Bitcoin,
            {
                'asm': '304402205720b4406b5ff54b4978b61a924b304f1f74d97121f2323d53b2271120f9'
                '219602204c9cd794420d192fae98e5d1e43afeac606f2cadecd1506788ab93f458c1834741 '
                '03670df4024f4dfd2b35ae61e9eac4e533f419abe68edc46cee68755974cf3a453'
            },
            {
                'type': 'unknown',
            },
        ),
        # An OP_RETURN output
        (
            '006a403464373835363335363064663133393863356164303539373865336365393764616266373'
            '3333537366562323633353134663933633032386366613636633732', Bitcoin,
            {
                'asm': '0 OP_RETURN 34643738353633353630646631333938633561643035393738653363'
                '653937646162663733333537366562323633353134663933633032386366613636633732'
            },
            {
                'type': 'op_return',
            },
        ),
        # TODO: An R-puzzle output
        # An erroneous script
        (
            '006a403464373835363335363064663133393863', Bitcoin,
            {
                'asm': '0 OP_RETURN [script error]'
            },
            {
                'type': 'op_return',
            },
        ),
    ), ids=['p2pk', 'p2pk-testnet', 'p2pk_sig', 'p2pkh_output', 'p2pkh_sig',
            'op_return', 'erroneous'])
    def test_to_json(self, script, network, json, extra):
        json['hex'] = script
        assert Script.from_hex(script).to_json(0, False, network) == json
        json.update(extra)
        assert Script.from_hex(script).to_json(JSONFlags.CLASSIFY_OUTPUT_SCRIPT, False,
                                               network) == json

    @pytest.mark.parametrize("op,word", (
        (OP_VERIF, "OP_VERIF"),
        (b'a', "97"),
        (b'\x01a', str(97 * 256 + 1)),
        (b'abcde', "6162636465"),
        (bytes([255, 255, 255, 255]), "-2147483647"),
        (bytes([255, 255, 255, 127]), "2147483647"),
    ))
    def test_op_to_asm_word(self, op, word):
        assert Script.op_to_asm_word(op, False) == word

    @pytest.mark.parametrize("op_hex,word", (
        ('30' * 10, '30' * 10),
        ('302502010102207fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a001',
         '302502010102207fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0[ALL]'),
    ))
    def test_op_to_asm_word_decode_sighash(self, op_hex, word):
        op = bytes.fromhex(op_hex)
        assert Script.op_to_asm_word(op, True) == word

    @pytest.mark.parametrize("script,result", (
        (Script() << OP_0, True),
        (Script() << OP_0 << OP_15, True),
        (Script() << OP_0 << OP_15 << OP_NOP, False),
        (Script() << OP_RESERVED, True),
        (Script(), True),
        (Script() << b'foobar' << b'baz', True),
        (Script() << OP_1 << b'foobar' << b'baz' << OP_1NEGATE, True),
        # Truncated Script
        (Script(b'\0\x01'), False),
    ))
    def test_is_push_only(self, script, result):
        assert script.is_push_only() is result

    @pytest.mark.parametrize("script,result", (
        (Script(), False),
        (Script() << OP_0, False),
        (Script() << OP_HASH160 << bytes(20) << OP_EQUAL, True),
        (Script() << OP_HASH256 << bytes(20) << OP_EQUAL, False),
        (Script() << OP_HASH160 << bytes(19) << OP_EQUAL, False),
        (Script() << OP_HASH160 << bytes(20) << OP_NUMEQUAL, False),
    ))
    def test_is_P2SH(self, script, result):
        assert script.is_P2SH() is result

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

    def test_from_hex_space(self):
        with pytest.raises(ValueError):
            Script.from_hex(' 01 ab05 deadbeef ')

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
    ), ids=["1"])
    def test_from_asm(self, asm, script):
        assert Script.from_asm(asm) == script

    @pytest.mark.parametrize("asm", (
        "OP_NOP5 OP_CHECKSIG 0 67 287542 -1 deadbeefdead",
    ), ids=["1"])
    def test_asm_both_ways(self, asm):
        script = Script.from_asm(asm)
        assert script.to_asm(False) == asm

    @pytest.mark.parametrize('text, answer', (
        ('', Script()),
        ('12020304', '12020304'),
        # This is a decimal number followed by OP_15
        ('12020304 OP_15', Script() << 12020304 << OP_15),
        # This is two decimal numbers, not hex with a space
        ('1202 0304', Script() << 1202 << 304),
    ))
    def test_from_text(self, text, answer):
        if isinstance(answer, str):
            answer = bytes.fromhex(answer)
        assert Script.from_text(text) == answer

    @pytest.mark.parametrize('text', (
        'abc',
        'OP_15 OP_OTHER',
    ))
    def test_from_text_error(self, text):
        with pytest.raises(ScriptError):
            Script.from_text(text)

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
            p = n % 3
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
    (b'abcd', bytes([4]) + b'abcd'),
))
def test_push_item(item, answer):
    # Also tests push_and_drop_item
    assert push_item(item) == answer
    assert push_and_drop_item(item) == answer + bytes([OP_DROP])


# Split out test to avoid long items on Windows where pytest has issues
@pytest.mark.parametrize("count, answer_prefix", (
    (75, bytes([75])),
    (76, bytes([OP_PUSHDATA1, 76])),
    (255, bytes([OP_PUSHDATA1, 255])),
    (256, bytes([OP_PUSHDATA2, 0, 1])),
    (260, bytes([OP_PUSHDATA2, 4, 1])),
    (65535, bytes([OP_PUSHDATA2, 0xff, 0xff])),
    (65536, bytes([OP_PUSHDATA4, 0, 0, 1, 0])),
    (65541, bytes([OP_PUSHDATA4, 5, 0, 1, 0])),
))
def test_push_item_long(count, answer_prefix):
    item = b'a' * count
    answer = answer_prefix + item
    assert push_item(item) == answer


@pytest.mark.parametrize("items,answer", (
    ([b''], pack_byte(OP_0) + pack_byte(OP_DROP)),
    ([b'', b''], pack_byte(OP_0) * 2 + pack_byte(OP_2DROP)),
    ([b'', b'\x04', b''], bytes((OP_0, OP_4, OP_0, OP_2DROP, OP_DROP))),
))
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
))
def test_push_int(value, encoding):
    assert push_int(value) == encoding


@pytest.mark.parametrize("value,encoding,is_minimal", (
    (-1, b'\x81', True),
    (-2, b'\x82', True),
    (-127, b'\xff', True),
    (-128, b'\x80\x80', True),
    (0, b'', True),
    (0, b'\x00', False),
    (0, b'\x80', False),
    (1, b'\x01', True),
    (2, b'\x02', True),
    (16, b'\x10', True),
    (127, b'\x7f', True),
    (128, b'\x80\x00', True),
    (129, b'\x81\x00', True),
    (255, b'\xff\x00', True),
    (256, b'\x00\x01', True),
    (32767, b'\xff\x7f', True),
    (32768, b'\x00\x80\x00', True),
))
def test_item_to_int(value, encoding, is_minimal):
    assert item_to_int(encoding) == value
    assert (int_to_item(value) == encoding) is is_minimal
    assert is_item_minimally_encoded(encoding) is is_minimal


@pytest.mark.parametrize("value,size,encoding", (
    (0, 0, b''),
    (0, 1, b'\0'),
    (0, 4, bytes(4)),
    (5, 0, None),
    (5, 1, b'\5'),
    (5, 2, b'\5\0'),
    (-1, 0, None),
    (-1, 1, b'\x81'),
    (-1, 2, b'\1\x80'),
    (-127, 1, b'\xff'),
    (-128, 1, None),
    (-128, 2, b'\x80\x80'),
))
def test_int_to_item_size(value, size, encoding):
    if encoding is None:
        with pytest.raises(ImpossibleEncoding):
            int_to_item(value, size)
    else:
        assert int_to_item(value, size) == encoding


@pytest.mark.parametrize("script,ops", (
    (bytes([OP_RESERVED, OP_DUP, OP_NOP, OP_15, OP_HASH160, OP_1NEGATE]) + push_item(b'BitcoinSV'),
     [OP_RESERVED, OP_DUP, OP_NOP, b'\x0f', OP_HASH160, b'\x81', b'BitcoinSV']),
    (b'', []),
))
def test_script_ops(script, ops):
    assert list(Script(script).ops()) == ops


@pytest.mark.parametrize("count", (80, 256, 65536))
def test_script_ops_long(count):
    script = push_item(b'a' * count)
    assert list(Script(script).ops()) == [b'a' * count]


@pytest.mark.parametrize("script,pairs", (
    (bytes([OP_RESERVED, OP_DUP, OP_NOP, OP_15, OP_HASH160, OP_1NEGATE]) + push_item(b'BitcoinSV'),
     [(OP_RESERVED, None), (OP_DUP, None), (OP_NOP, None), (OP_15, b'\x0f'),
      (OP_HASH160, None), (OP_1NEGATE, b'\x81'), (9, b'BitcoinSV')]),
), ids=['s1'])
def test_script_ops_and_items(script, pairs):
    assert list(Script(script).ops_and_items()) == pairs


@pytest.mark.parametrize("count", (2, 76, 80, 256, 65536))
def test_script_ops_truncated(count):
    script = push_item(bytes(count))[:-1]
    with pytest.raises(TruncatedScriptError):
        list(Script(script).ops())


@pytest.mark.parametrize("script", (
    'hello',
    [b''],
))
def test_script_ops_type_error(script):
    with pytest.raises(TypeError):
        list(Script(script).ops())


@pytest.mark.parametrize("item,op", (
    (b'', OP_FALSE),
    (b'\x00', 1),
    (b'\x01', OP_1),
    (b'\x02', OP_2),
    (b'\x03', OP_3),
    (b'\x04', OP_4),
    (b'\x05', OP_5),
    (b'\x06', OP_6),
    (b'\x07', OP_7),
    (b'\x08', OP_8),
    (b'\x09', OP_9),
    (b'\x0a', OP_10),
    (b'\x0b', OP_11),
    (b'\x0c', OP_12),
    (b'\x0d', OP_13),
    (b'\x0e', OP_14),
    (b'\x0f', OP_15),
    (b'\x10', OP_16),
    (b'\x11', 1),
    (b'\x81', OP_1NEGATE),
))
def test_minimal_push_opcode(item, op):
    assert minimal_push_opcode(item) == op


@pytest.mark.parametrize("length,op", (
    (75, 75),
    (76, OP_PUSHDATA1),
    (255, OP_PUSHDATA1),
    (256, OP_PUSHDATA2),
    (65535, OP_PUSHDATA2),
    (65536, OP_PUSHDATA4),
    ((1 << 32) - 1, OP_PUSHDATA4),
))
def test_minimal_push_zero(length, op):
    item = bytes(length)
    assert minimal_push_opcode(item) == op


def test_minimal_push_opcode_too_large():
    with pytest.raises(ValueError):
        minimal_push_opcode(bytes(1 << 32))


@pytest.mark.parametrize("zero", zeroes)
def test_cast_to_bool_zeros(zero):
    assert not cast_to_bool(zero)


@pytest.mark.parametrize("non_zero", non_zeroes)
def test_cast_to_bool_non_zeros(non_zero):
    assert cast_to_bool(non_zero)


# The testcases from bitcoin-sv/src/test/script_tests.cpp where the script to delete is
# not truncated.
find_and_delete_tests = [
    (Script() << OP_1 << OP_2, Script(), None),
    (Script() << OP_1 << OP_2 << OP_3, Script() << OP_2, Script() << OP_1 << OP_3),
    (Script() << OP_3 << OP_1 << OP_3 << OP_3 << OP_4 << OP_3, Script() << OP_3,
     Script() << OP_1 << OP_4),
    (Script.from_hex("0302ff03"), Script.from_hex("0302ff03"), Script()),
    (Script.from_hex("0302ff030302ff03"), Script.from_hex("0302ff03"), Script()),
    (Script.from_hex("0302ff030302ff03"), Script.from_hex("ff"), None),
    # PUSH(0xfeed) OP_1 OP_VERIFY
    (Script.from_hex("02feed5169"), Script.from_hex("feed51"), None),
    (Script.from_hex("02feed5169"), Script.from_hex("02feed51"), Script.from_hex("69")),
    (Script.from_hex("516902feed5169"), Script.from_hex("feed51"), None),
    (Script.from_hex("516902feed5169"), Script.from_hex("02feed51"), Script.from_hex("516969")),
    (Script.from_hex("516902feed5102feed5102feed5169"), Script.from_hex("02feed51"),
     Script.from_hex("516969")),
    # Single-pass
    (Script() << OP_0 << OP_0 << OP_1 << OP_1, Script() << OP_0 << OP_1, Script() << OP_0 << OP_1),
    (Script() << OP_0 << OP_0 << OP_1 << OP_0 << OP_1 << OP_1, Script() << OP_0 << OP_1,
     Script() << OP_0 << OP_1),
    (Script.from_hex("0003feed"), Script.from_hex("00"), Script.from_hex("03feed")),
    # My testcase
    (Script() << OP_0 << OP_1 << OP_1 << OP_1 << OP_1 << OP_1, Script() << OP_1 << OP_1,
     Script() << OP_0 << OP_1),
]


@pytest.mark.parametrize("script,delete,expected", find_and_delete_tests,
                         ids=[str(n) for n in range(len(find_and_delete_tests))])
def test_find_and_delete(script, delete, expected):
    if expected is None:
        expected = script
    assert script.find_and_delete(delete) == expected
