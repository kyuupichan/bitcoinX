import os
import random
from itertools import product

import pytest
import random

from bitcoinx.consts import JSONFlags
from bitcoinx.errors import *
from bitcoinx.hashes import ripemd160, hash160, sha1, sha256, double_sha256
from bitcoinx.script import *
from bitcoinx import (
    pack_varint, PrivateKey, pack_byte, Bitcoin, BitcoinTestnet, varint_len, SigHash
)

from .utils import random_tx, random_value


def _zeroes():
    # Yields a zero and negative zero
    for size in range(10):
        yield bytes(size)
        yield bytes(size) + b'\x80'

zeroes = list(_zeroes())
non_zeroes = [b'\1', b'\x81', b'\1\0', b'\0\1', b'\0\x81']


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
    ), ids=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14",
            "15", "16", "-1", "6 -1", "16 16 16 16", "17 17 17", "0...256", "signed 32",
            "1hex", "empty", "error", "many ops"])
    def test_to_asm(self, script, asm):
        assert Script(script).to_asm(False) == asm

    @pytest.mark.parametrize("script,coin,json,extra", (
        # A P2PK output
        ('410494b9d3e76c5b1629ecf97fff95d7a4bbdac87cc26099ada28066c6ff1eb9191223cd89719'
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
        ('47304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220'
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
                'asm': '[error]'
            },
            {
                'type': 'op_return',
            },
        ),
    ), ids = ['p2pk', 'p2pk-testnet', 'p2pk_sig', 'p2pkh_output', 'p2pkh_sig',
              'op_return', 'erroneous'])
    def test_to_json(self, script, coin, json, extra):
        json['hex'] = script
        assert Script.from_hex(script).to_json(0, False, coin) == json
        json.update(extra)
        assert Script.from_hex(script).to_json(JSONFlags.CLASSIFY_OUTPUT_SCRIPT, False,
                                               coin) == json

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
    ), ids=["1"])
    def test_from_asm(self, asm, script):
        assert Script.from_asm(asm) == script

    @pytest.mark.parametrize("asm", (
        "OP_NOP5 OP_CHECKSIG 0 67 287542 -1 deadbeefdead",
    ), ids=["1"])
    def test_asm_both_ways(self, asm):
        script = Script.from_asm(asm)
        assert script.to_asm(False) == asm

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
), ids=parameter_id)
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
    (push_item(b'a' * 80), [b'a' * 80]),
    (push_item(b'a' * 256), [b'a' * 256]),
    (push_item(b'a' * 65536), [b'a' * 65536]),
), ids=parameter_id)
def test_script_ops(script, ops):
    assert list(Script(script).ops()) == ops


@pytest.mark.parametrize("script,pairs", (
    (bytes([OP_RESERVED, OP_DUP, OP_NOP, OP_15, OP_HASH160, OP_1NEGATE]) + push_item(b'BitcoinSV'),
     [(OP_RESERVED, None), (OP_DUP, None), (OP_NOP, None), (OP_15, b'\x0f'),
      (OP_HASH160, None), (OP_1NEGATE, b'\x81'), (9, b'BitcoinSV')]),
), ids=['s1'])
def test_script_ops_and_items(script, pairs):
    assert list(Script(script).ops_and_items()) == pairs


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
    (bytes(75), 75),
    (bytes(76), OP_PUSHDATA1),
    (bytes(255), OP_PUSHDATA1),
    (bytes(256), OP_PUSHDATA2),
    (bytes(65535), OP_PUSHDATA2),
    (bytes(65536), OP_PUSHDATA4),
    # 32 should work but sometimes memory issues
    (bytes((1 << 28) - 1), OP_PUSHDATA4),
), ids=parameter_id)
def test_minimal_push_opcode(item, op):
    assert minimal_push_opcode(item) == op


def test_minimal_push_opcode_too_large():
    with pytest.raises(ValueError):
        minimal_push_opcode(bytes(1<<32))


@pytest.mark.parametrize("zero", zeroes)
def test_cast_to_bool_zeros(zero):
    assert not cast_to_bool(zero)


@pytest.mark.parametrize("non_zero", non_zeroes)
def test_cast_to_bool_zeros(non_zero):
    assert cast_to_bool(non_zero)


'''The testcases from bitcoin-sv/src/test/script_tests.cpp where the script to delete is
not truncated.'''
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


@pytest.fixture(params=(
    (100_000, 512, 20_000, 100),
    (1_000_000, 2048, 100_000, 1_000),
))
def policy(request):
    yield InterpreterPolicy(*request.param)


@pytest.fixture(params=(
    # is_consensus, is_genesis_enabled, is_utxo_after_genesis
    (False, False, False),
    (False, True, False),
    (False, True, True),
    (True, False, False),
    (True, True, False),
    (True, True, True),
))
def state(request, policy):
    is_consensus, is_genesis_enabled, is_utxo_after_genesis = request.param
    yield InterpreterState(policy, is_consensus=is_consensus,
                           is_genesis_enabled=is_genesis_enabled,
                           is_utxo_after_genesis=is_utxo_after_genesis)

@pytest.fixture(params=(
    # is_consensus, is_genesis_enabled
    (False, False),
    (False, True),
    (True, False),
    (True, True),
))
def state_old_utxo(request, policy):
    is_consensus, is_genesis_enabled = request.param
    yield InterpreterState(policy, is_consensus=is_consensus,
                           is_genesis_enabled=is_genesis_enabled, is_utxo_after_genesis=False)

# Note: this is just SIGHASH_ALL without FORKID
high_S_sig = '302502010102207fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a101'
undefined_sighash_sig = '300602010102010100'
has_forkid_sig = '300602010102010142'
no_forkid_sig = '300602010102010103'


class TestInterpreterState:

    def test_max_ops_per_script(self, policy):
        state = InterpreterState(policy)
        state.is_genesis_enabled = False
        assert state.max_ops_per_script == state.MAX_OPS_PER_SCRIPT_BEFORE_GENESIS

        state = InterpreterState(policy)
        state.is_genesis_enabled = True
        state.is_consensus = True
        assert state.max_ops_per_script == state.MAX_OPS_PER_SCRIPT_AFTER_GENESIS

        state = InterpreterState(policy)
        state.is_genesis_enabled = True
        state.is_consensus = False
        assert state.max_ops_per_script == policy.max_ops_per_script

    def test_max_script_size(self, policy):
        state = InterpreterState(policy)
        state.is_genesis_enabled = False
        assert state.max_script_size == state.MAX_SCRIPT_SIZE_BEFORE_GENESIS

        state = InterpreterState(policy)
        state.is_genesis_enabled = True
        state.is_consensus = True
        assert state.max_script_size == state.MAX_SCRIPT_SIZE_AFTER_GENESIS

        state = InterpreterState(policy)
        state.is_genesis_enabled = True
        state.is_consensus = False
        assert state.max_script_size == policy.max_script_size

    def test_max_script_num_length(self, policy):
        for is_genesis_enabled in (False, True):
            for is_consensus in (False, True):
                state = InterpreterState(policy)
                state.is_utxo_after_genesis = False
                state.is_genesis_enabled = is_genesis_enabled
                state.is_consensus = is_consensus
                assert state.max_script_num_length == state.MAX_SCRIPT_NUM_LENGTH_BEFORE_GENESIS

                state = InterpreterState(policy)
                state.is_utxo_after_genesis = True
                state.is_genesis_enabled = is_genesis_enabled
                state.is_consensus = is_consensus
                if is_consensus:
                    assert state.max_script_num_length == state.MAX_SCRIPT_NUM_LENGTH_AFTER_GENESIS
                else:
                    assert state.max_script_num_length == policy.max_script_num_length

    def test_validate_item_size(self, policy):
        state = InterpreterState(policy)
        state.is_utxo_after_genesis = False
        state.validate_item_size(state.MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS)
        with pytest.raises(InvalidPushSize):
            state.validate_item_size(state.MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS + 1)

        state = InterpreterState(policy)
        state.is_utxo_after_genesis = True
        state.is_consensus = True
        state.validate_item_size(state.MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS + 1)

        state = InterpreterState(policy)
        state.is_utxo_after_genesis = True
        state.is_consensus = False
        state.validate_item_size(state.MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS + 1)

    def test_bump_op_count(self, policy):
        state = InterpreterState(policy)
        state.bump_op_count(state.max_ops_per_script)
        with pytest.raises(TooManyOps):
            state.bump_op_count(1)

    def test_validate_minimal_push_opcode(self, policy):
        state = InterpreterState(policy, flags=0)
        state.validate_minimal_push_opcode(OP_PUSHDATA1, b'\1')
        state = InterpreterState(policy, flags=InterpreterFlags.REQUIRE_MINIMAL_PUSH)
        state.validate_minimal_push_opcode(OP_1, b'\1')
        with pytest.raises(MinimalEncodingError):
            state.validate_minimal_push_opcode(OP_PUSHDATA1, b'\1')

    def test_validate_stack_size(self, policy):
        state = InterpreterState(policy, is_utxo_after_genesis=True)
        state.stack = [b''] * state.MAX_STACK_ELEMENTS_BEFORE_GENESIS
        state.alt_stack = [b'']
        state.validate_stack_size()

        state = InterpreterState(policy, is_utxo_after_genesis=False)
        state.stack = [b''] * state.MAX_STACK_ELEMENTS_BEFORE_GENESIS
        state.alt_stack = []
        state.validate_stack_size()
        state.alt_stack.append(b'')
        with pytest.raises(StackSizeTooLarge):
            state.validate_stack_size()

    @pytest.mark.parametrize('sig_hex,flags,err_text', (
        ('', 0, None),
        ('', InterpreterFlags.REQUIRE_STRICT_DER, None),
        ('', InterpreterFlags.REQUIRE_LOW_S, None),
        ('', InterpreterFlags.REQUIRE_STRICT_ENCODING, None),
        ('300602610902010141', 0, None),
        ('300602610902010141', InterpreterFlags.REQUIRE_STRICT_DER, 'strict DER'),
        ('300602610902010141', InterpreterFlags.REQUIRE_LOW_S, 'strict DER'),
        ('300602610902010141', InterpreterFlags.REQUIRE_STRICT_ENCODING, 'strict DER'),
        (high_S_sig, 0, None),
        (high_S_sig, InterpreterFlags.REQUIRE_STRICT_DER, None),
        (high_S_sig, InterpreterFlags.REQUIRE_LOW_S, 'high S value'),
        (high_S_sig, InterpreterFlags.REQUIRE_STRICT_ENCODING, None),
        (undefined_sighash_sig, 0, None),
        (undefined_sighash_sig, InterpreterFlags.REQUIRE_STRICT_DER, None),
        (undefined_sighash_sig, InterpreterFlags.REQUIRE_LOW_S, None),
        (undefined_sighash_sig, InterpreterFlags.REQUIRE_STRICT_ENCODING, 'undefined sighash'),
        (has_forkid_sig, 0, None),
        (has_forkid_sig, InterpreterFlags.REQUIRE_STRICT_DER, None),
        (has_forkid_sig, InterpreterFlags.REQUIRE_LOW_S, None),
        (has_forkid_sig, InterpreterFlags.REQUIRE_STRICT_ENCODING, 'sighash must not use FORKID'),
        (no_forkid_sig, InterpreterFlags.ENABLE_FORKID, 'sighash must use FORKID'),
        (no_forkid_sig, InterpreterFlags.REQUIRE_STRICT_DER | InterpreterFlags.ENABLE_FORKID,
         'sighash must use FORKID'),
        (no_forkid_sig, InterpreterFlags.REQUIRE_LOW_S | InterpreterFlags.ENABLE_FORKID,
         'sighash must use FORKID'),
        (no_forkid_sig, InterpreterFlags.REQUIRE_STRICT_ENCODING
         | InterpreterFlags.ENABLE_FORKID, 'sighash must use FORKID'),
    ))
    def test_validate_signature(self, policy, sig_hex, flags, err_text):
        sig_bytes = bytes.fromhex(sig_hex)
        state = InterpreterState(policy, flags=flags)
        if err_text:
            with pytest.raises(InvalidSignature) as e:
                state.validate_signature(sig_bytes)
            assert err_text in str(e.value)
        else:
            state.validate_signature(sig_bytes)

    @pytest.mark.parametrize('pubkey,flags,fail', (
        ('', 0, False),
        ('', InterpreterFlags.REQUIRE_STRICT_DER, False),
        ('', InterpreterFlags.REQUIRE_LOW_S, False),
        ('', InterpreterFlags.REQUIRE_STRICT_ENCODING, True),
        ('00' * 33, 0, False),
        ('00' * 33, InterpreterFlags.REQUIRE_STRICT_ENCODING, True),
        ('00' * 65, 0, False),
        ('00' * 65, InterpreterFlags.REQUIRE_STRICT_ENCODING, True),
        # Good compressed
        ('036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2', 0, False),
        ('036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2',
         InterpreterFlags.REQUIRE_STRICT_ENCODING, False),
        # Bad compressed
        ('03' + '00' * 32, 0, False),
        ('03' + '00' * 32, InterpreterFlags.REQUIRE_STRICT_ENCODING, False),
        # Good uncompressed
        ('046d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e'
         '2487e6222a6664e079c8edf7518defd562dbeda1e7593dfd7f0be285880a24dab', 0, False),
        ('046d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e'
         '2487e6222a6664e079c8edf7518defd562dbeda1e7593dfd7f0be285880a24dab',
         InterpreterFlags.REQUIRE_STRICT_ENCODING, False),
        # Bad uncompressed
        ('04' + '00' * 64, 0, False),
        ('04' + '00' * 64, InterpreterFlags.REQUIRE_STRICT_ENCODING, False),
        # Good hybrid
        ('076d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e'
         '2487e6222a6664e079c8edf7518defd562dbeda1e7593dfd7f0be285880a24dab', 0, False),
        ('076d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e'
         '2487e6222a6664e079c8edf7518defd562dbeda1e7593dfd7f0be285880a24dab',
         InterpreterFlags.REQUIRE_STRICT_ENCODING, True),
        # Bad hybrid
        ('06' + '00' * 64, 0, False),
        ('06' + '00' * 64, InterpreterFlags.REQUIRE_STRICT_ENCODING, True),
    ))
    def test_validate_pubkey(self, policy, pubkey, flags, fail):
        pubkey_bytes = bytes.fromhex(pubkey)
        state = InterpreterState(policy, flags=flags)
        if fail:
            with pytest.raises(InvalidPublicKeyEncoding) as e:
                state.validate_pubkey(pubkey_bytes)
            assert 'invalid public key encoding' in str(e.value)
        else:
            state.validate_pubkey(pubkey_bytes)

    @pytest.mark.parametrize('sig_hex,flags,script_code,result', (
        ('30454501', 0, Script() << OP_1 << bytes.fromhex('30454501') << OP_2,
         Script() << OP_1 << OP_2),
        ('30454501', InterpreterFlags.ENABLE_FORKID,
         Script() << OP_1 << bytes.fromhex('30454501') << OP_2, None),
        ('30454541', 0, Script() << OP_1 << bytes.fromhex('30454541') << OP_2, None),
        ('30454541', InterpreterFlags.ENABLE_FORKID,
         Script() << OP_1 << bytes.fromhex('30454541') << OP_2, None),
    ))
    def test_cleanup_script_code(self, policy, sig_hex, flags, script_code, result):
        sig_bytes = bytes.fromhex(sig_hex)
        state = InterpreterState(policy, flags=flags)
        if result is None:
            assert state.cleanup_script_code(sig_bytes, script_code) == script_code
        else:
            assert state.cleanup_script_code(sig_bytes, script_code) == result

    @pytest.mark.parametrize('sig_hex,flags,raises', (
        ('', 0, False),
        ('', InterpreterFlags.REQUIRE_NULLFAIL, False),
        ('30454501', 0, False),
        ('30454541', InterpreterFlags.REQUIRE_NULLFAIL, True),
    ))
    def test_validate_nullfail(self, policy, sig_hex, flags, raises):
        sig_bytes = bytes.fromhex(sig_hex)
        state = InterpreterState(policy, flags=flags)
        if raises:
            with pytest.raises(NullFailError):
                state.validate_nullfail(sig_bytes)
        else:
            state.validate_nullfail(sig_bytes)

    @pytest.mark.parametrize('number, flags, after_genesis, value', (
        ('01020304', 0, False, 0x04030201),
        ('01020304', 0, True, 0x04030201),
        ('0102030405', 0, False, InvalidNumber),
        ('0102030405', 0, True, 0x0504030201),
        ('0102030400', 0, False, InvalidNumber),
        ('0102030400', 0, True, 0x04030201),
        ('0100', 0, False, 0x01),
        ('0100', 0, True, 0x01),
        ('0100', InterpreterFlags.REQUIRE_MINIMAL_PUSH, False, MinimalEncodingError),
        ('0100', InterpreterFlags.REQUIRE_MINIMAL_PUSH, True, MinimalEncodingError),
    ))
    def test_to_number_failures(self, policy, number, flags, after_genesis, value):
        state = InterpreterState(policy, flags=flags, is_utxo_after_genesis = after_genesis)
        number = bytes.fromhex(number)
        if not isinstance(value, int):
            with pytest.raises(value):
                state.to_number(number)
        else:
            assert state.to_number(number) == value


reserved_ops = (OP_VER, OP_RESERVED, OP_RESERVED1, OP_RESERVED2)


def value_bytes(x):
    if isinstance(x, bytes):
        return x
    if isinstance(x, str):
        return bytes.fromhex(x)
    return int_to_item(x)


def negate_bytes(x):
    return int_to_item(-item_to_int(value_bytes(x)))


class TestEvaluateScriptBase:

    @classmethod
    def setup_class(cls):
        cls._random_pushes = [
            OP_0, OP_1, OP_2, OP_3, OP_4, OP_5, OP_6, OP_7, OP_8, OP_9, OP_10,
            OP_11, OP_12, OP_13, OP_14, OP_15, OP_16, OP_1NEGATE
        ]
        # Avoid breaking small limits for some states
        cls._random_pushes.extend(os.urandom(random.randrange(1, 500)) for _ in range(10))

    def random_push_data(self):
        push = random.choice(self._random_pushes)
        if isinstance(push, bytes):
            return push, push
        if push == OP_0:
            return push, b''
        if push >= OP_1:
            return push, pack_byte(push - OP_1 + 1)
        assert push == OP_1NEGATE
        return push, b'\x81'

    def random_push(self):
        return self.random_push_data()[0]

    def require_stack(self, state, size, op):
        # Create a stack of size n and assert failure
        for n in range(size):
            script = Script()
            for _ in range(n):
                script <<= self.random_push()
            script <<= op
            with pytest.raises(InvalidStackOperation):
                state.evaluate_script(script)
            assert len(state.stack) == n
            state.reset()


class TestEvaluateScript(TestEvaluateScriptBase):

    def test_max_script_size(self, state):
        limit = state.max_script_size = min(state.max_script_size, 1_000_000)
        state.MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS = max(
            state.max_script_size, state.MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS)
        script = Script() << bytes(state.max_script_size - varint_len(state.max_script_size))
        state.evaluate_script(script)
        script = Script() << bytes(state.max_script_size)
        with pytest.raises(ScriptTooLarge):
            state.evaluate_script(script)

    def test_validate_item_size(self, state):
        # No limits after genesis
        if state.is_utxo_after_genesis:
            state.max_script_size = 10_000_010
            script = Script() << bytes(10_000_000)
            state.evaluate_script(script)
        else:
            script = Script() << bytes(state.MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS)
            state.evaluate_script(script)
            script = Script() << bytes(state.MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS + 1)
            with pytest.raises(InvalidPushSize):
                state.evaluate_script(script)

    def test_max_ops_per_script_good(self, state):
        state.max_ops_per_script = 2
        # Pushes do not contribute to limit
        script = Script() << 15 << OP_NOP << b'foo' << OP_NOP << OP_15
        state.evaluate_script(script)

    def test_max_ops_per_script_op_reserved(self, state):
        state.max_ops_per_script = 2
        # OP_RESERVED does not contribute to limit
        script = Script() << OP_0 << OP_IF << OP_RESERVED << OP_ENDIF
        state.evaluate_script(script)

    def test_max_ops_per_script_op_reserved(self, state):
        state.max_ops_per_script = 2
        script = Script() << OP_1 << OP_IF << OP_NOP << OP_ENDIF
        with pytest.raises(TooManyOps):
            state.evaluate_script(script)

    @pytest.mark.parametrize("op", (OP_2MUL, OP_2DIV))
    def test_disabled_opcodes(self, state, op):
        script = Script() << op
        with pytest.raises(DisabledOpcode) as e:
            state.evaluate_script(script)
        assert str(e.value) == f'{op.name} is disabled'

        script = Script() << OP_0 << OP_IF << op << OP_ENDIF
        # After genesis they are OK in unexecuted branches
        if state.is_utxo_after_genesis:
            state.evaluate_script(script)
        else:
            with pytest.raises(DisabledOpcode):
                state.evaluate_script(script)

    def test_truncated_script(self, state):
        script = Script() << b'foobar'
        script = Script(script.to_bytes()[:-1])
        with pytest.raises(TruncatedScriptError):
            state.evaluate_script(script)

    def test_truncated_script_after_op_return(self, state):
        script = Script() << OP_0 << OP_RETURN << b'foobar'
        script = Script(script.to_bytes()[:-1])
        # After genesis with top-level OP_RETURN truncated scripts are OK
        if state.is_utxo_after_genesis:
            state.evaluate_script(script)
            state.reset()
            # But after non-top-level OP_RETURN they are not as grammar is checked
            script = Script() << OP_1 << OP_IF << OP_RETURN << OP_ENDIF << b'foobar'
            script = Script(script.to_bytes()[:-1])
            with pytest.raises(TruncatedScriptError):
                state.evaluate_script(script)
        else:
            with pytest.raises(OpReturnError):
                state.evaluate_script(script)

    @pytest.mark.parametrize("flags", (0, InterpreterFlags.REQUIRE_MINIMAL_PUSH,
                                       InterpreterFlags.REQUIRE_MINIMAL_IF))
    def test_minimal_push_executed(self, policy, flags):
        state = InterpreterState(policy, flags=flags)
        # This is all fine
        script = Script() << OP_0 << OP_1 << OP_16 << b'foo' << bytes(300)
        state.evaluate_script(script)
        state.reset()

        script = Script(bytes([1, 5]))
        if flags == InterpreterFlags.REQUIRE_MINIMAL_PUSH:
            with pytest.raises(MinimalEncodingError):
                state.evaluate_script(script)
        else:
            state.evaluate_script(script)

    @pytest.mark.parametrize("flags", (0, InterpreterFlags.REQUIRE_MINIMAL_PUSH,
                                       InterpreterFlags.REQUIRE_MINIMAL_IF))
    def test_minimal_push_unexecuted(self, policy, flags):
        state = InterpreterState(policy, flags=flags)
        # Not executed, not a problem
        script = Script(bytes([OP_0, OP_IF, 1, 5, OP_ENDIF]))
        state.evaluate_script(script)

    @pytest.mark.parametrize("big", (True, False))
    def test_validate_stack_size(self, state, big):
        script = Script().push_many([OP_1] * state.MAX_STACK_ELEMENTS_BEFORE_GENESIS)
        if big:
            state.alt_stack = [b'']
        if state.is_utxo_after_genesis or not big:
            state.evaluate_script(script)
        else:
            with pytest.raises(StackSizeTooLarge):
                state.evaluate_script(script)

    @pytest.mark.parametrize("op, is_utxo_after_genesis",
                             product((OP_NOP1, OP_NOP2, OP_NOP3, OP_NOP4, OP_NOP5,
                                      OP_NOP6, OP_NOP7, OP_NOP8, OP_NOP9, OP_NOP10),
                                     (False, True))
    )
    def test_upgradeable_nops(self, policy, is_utxo_after_genesis, op):
        # Not testing lock time junk
        if op in {OP_NOP2, OP_NOP3} and not is_utxo_after_genesis:
            return
        script = Script() << op

        # No effect with no flags
        state = InterpreterState(policy, flags=0, is_utxo_after_genesis=is_utxo_after_genesis)
        state.evaluate_script(script)

        # Reject with flags
        state = InterpreterState(policy, flags=InterpreterFlags.REJECT_UPGRADEABLE_NOPS,
                                 is_utxo_after_genesis=is_utxo_after_genesis)
        with pytest.raises(UpgradeableNopError) as e:
            state.evaluate_script(script)
        assert str(e.value) == f'encountered upgradeable NOP {op.name}'

    @pytest.mark.parametrize('op', reserved_ops)
    def test_reserved_executed(self, state, op):
        script = Script() << OP_0 << op
        with pytest.raises(InvalidOpcode) as e:
            state.evaluate_script(script)
        assert f'invalid opcode {op.name}' in str(e.value)
        assert state.stack == [b'']
        assert state.alt_stack == []

    @pytest.mark.parametrize('op', reserved_ops)
    def test_reserved_unexecuted(self, state, op):
        script = Script() << OP_0 << OP_IF << op << OP_ENDIF
        state.evaluate_script(script)
        assert state.stack == []
        assert state.alt_stack == []

    def test_CAT(self, state):
        self.require_stack(state, 2, OP_CAT)
        script = Script() << b'foo' << b'bar' << OP_CAT
        state.evaluate_script(script)
        assert state.stack == [b'foobar']
        assert state.alt_stack == []

    def test_CAT_size_enforced(self, state):
        self.require_stack(state, 2, OP_CAT)

        item = bytes(state.MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS)
        script = Script() << item << b'' << OP_CAT
        state.evaluate_script(script)
        state.reset()

        script = Script() << item << b'1' << OP_CAT
        if state.is_utxo_after_genesis:
            state.evaluate_script(script)
        else:
            with pytest.raises(InvalidPushSize):
                state.evaluate_script(script)

    def test_SPLIT(self, state):
        self.require_stack(state, 2, OP_SPLIT)
        script = Script() << b'foobarbaz' << OP_3 << OP_SPLIT
        state.evaluate_script(script)
        assert state.stack == [b'foo', b'barbaz']
        assert state.alt_stack == []

    def test_SPLIT_0(self, state):
        script = Script() << b'foobar' << OP_0 << OP_SPLIT
        state.evaluate_script(script)
        assert state.stack == [b'', b'foobar']
        assert state.alt_stack == []

    def test_SPLIT_6(self, state):
        script = Script() << b'foobar' << OP_6 << OP_SPLIT
        state.evaluate_script(script)
        assert state.stack == [b'foobar', b'']
        assert state.alt_stack == []

    def test_SPLIT_M1(self, state):
        script = Script() << b'foobar' << OP_1NEGATE << OP_SPLIT
        with pytest.raises(InvalidSplit) as e:
            state.evaluate_script(script)
        assert 'cannot split item of length 6 at position -1' in str(e.value)

    def test_SPLIT_past(self, state):
        script = Script() << b'foobar' << OP_7 << OP_SPLIT
        with pytest.raises(InvalidSplit) as e:
            state.evaluate_script(script)
        assert 'cannot split item of length 6 at position 7' in str(e.value)

    def test_NUM2BIN_stack(self, state):
        self.require_stack(state, 2, OP_NUM2BIN)

    @pytest.mark.parametrize("value,size,result", (
        ('00', -3, None),
        ('00', 0x80000000, None),
        ('', 0, ''),
        ('', 1, '00'),
        ('', 7, '00000000000000'),
        ('01', 1, '01'),
        ('aa', 1, 'aa'),
        ('aa', 2, '2a80'),
        ('aa', 10, '2a000000000000000080'),
        ('abcdef4280', 4, 'abcdefc2'),
        ('80', 0, ''),
        ('80', 3, '000000'),
    ))
    def test_NUM2BIN(self, state, value, size, result):
        value = bytes.fromhex(value)
        script = Script() << value << size << OP_NUM2BIN
        if result is None:
            if size >= 0x80000000 and not state.is_utxo_after_genesis:
                with pytest.raises(InvalidNumber) as e:
                    state.evaluate_script(script)
            else:
                with pytest.raises(InvalidPushSize) as e:
                    state.evaluate_script(script)
                    assert f'invalid size {size:,d} in OP_NUM2BIN operation' == str(e.value)
            assert len(state.stack) == 2
        else:
            state.evaluate_script(script)
            assert len(state.stack) == 1
            assert state.stack[0].hex() == result
            assert not state.alt_stack

    def test_NUM2BIN_oversized(self, state):
        value = b'\x01'
        size = state.MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS + 1
        script = Script() << value << size << OP_NUM2BIN
        if state.is_utxo_after_genesis:
            state.evaluate_script(script)
            assert len(state.stack) == 1
            assert state.stack[0] == b'\1' + bytes(520)
        else:
            with pytest.raises(InvalidPushSize) as e:
                state.evaluate_script(script)
            assert 'item length 521 exceeds' in str(e.value)
            assert len(state.stack) == 2

    def test_BIN2NUM_stack(self, state):
        self.require_stack(state, 1, OP_BIN2NUM)

    @pytest.mark.parametrize("value,result", (
        ('00', ''),
        ('ffffff7f', 'ffffff7f'),
        ('ffffffff', 'ffffffff'),
        ('ffffffff00', 'ffffffff00'),
        ('ffffff7f80', 'ffffffff'),
        ('0100000000', '01'),
        ('fe00000000', 'fe00'),
        ('0f00', '0f'),
        ('0f80', '8f'),
        ('0100800000', '01008000'),
        ('0100800080', '01008080'),
        ('01000f0000', '01000f'),
        ('01000f0080', '01008f'),
    ))
    def test_BIN2NUM(self, state, value, result):
        value = bytes.fromhex(value)
        script = Script() << value << OP_BIN2NUM
        if len(result) // 2 > state.max_script_num_length:
            with pytest.raises(InvalidNumber):
                state.evaluate_script(script)
        else:
            state.evaluate_script(script)
        # Stack contains the result even on failure
        assert len(state.stack) == 1
        assert state.stack[0].hex() == result
        assert not state.alt_stack

    @pytest.mark.parametrize("opcode", (OP_1ADD, OP_1SUB, OP_NEGATE, OP_ABS, OP_NOT, OP_0NOTEQUAL))
    def test_unary_numeric(self, state, opcode):
        self.require_stack(state, 1, opcode)

    @pytest.mark.parametrize("op", (OP_2MUL, OP_2DIV))
    def test_disabled(self, state, op):
        script = Script() << OP_0 << op
        # Invalid in executed branch
        with pytest.raises(DisabledOpcode) as e:
            state.evaluate_script(script)
        assert f'{op.name} is disabled' in str(e.value)

        state.reset()
        script = Script() << OP_0 << OP_IF << op << OP_ENDIF
        # Valid in unexecuted branch if UTXO is after-genesis
        if state.is_utxo_after_genesis:
            state.evaluate_script(script)
        else:
            with pytest.raises(DisabledOpcode):
                state.evaluate_script(script)

    @pytest.mark.parametrize("value, result", (
        (0, 1),
        (-1, 0),
        (127, 128),
        (255, 256),
        (bytes(2), 1),
        (b'\0\x80', 1),
        (b'\1\x80', 0),
    ))
    def test_1ADD(self, state, value, result):
        script = Script() << value << OP_1ADD
        state.evaluate_script(script)
        assert state.stack == [int_to_item(result)]
        assert not state.alt_stack

    @pytest.mark.parametrize("value, result", (
        (0, -1),
        (-1, -2),
        (127, 126),
        (255, 254),
        (bytes(2), -1),
        (b'\1\x00', 0),
        (b'\1\x80', -2),
    ))
    def test_1SUB(self, state, value, result):
        script = Script() << value << OP_1SUB
        state.evaluate_script(script)
        assert state.stack == [int_to_item(result)]
        assert not state.alt_stack

    @pytest.mark.parametrize("value, result", (
        (0, 0),
        (-1, 1),
        (1, -1),
        (127, -127),
        (255, -255),
        (bytes(2), 0),
        (b'\1\x00', -1),
        (b'\1\x80', 1),
    ))
    def test_NEGATE(self, state, value, result):
        script = Script() << value << OP_NEGATE
        state.evaluate_script(script)
        assert state.stack == [int_to_item(result)]
        assert not state.alt_stack

    @pytest.mark.parametrize("value, result", (
        (0, 0),
        (-1, 1),
        (1, 1),
        (127, 127),
        (255, 255),
        (bytes(2), 0),
        (b'\x80', 0),
        (b'\x81', 1),
    ))
    def test_ABS(self, state, value, result):
        script = Script() << value << OP_ABS
        state.evaluate_script(script)
        assert state.stack == [int_to_item(result)]
        assert not state.alt_stack

    @pytest.mark.parametrize("value, result", (
        (0, 1),
        (-1, 0),
        (1, 0),
        (127, 0),
        (255, 0),
        (bytes(2), 1),
        (b'\x80', 1),
        (b'\x81', 0),
    ))
    def test_NOT(self, state, value, result):
        script = Script() << value << OP_NOT
        state.evaluate_script(script)
        assert state.stack == [int_to_item(result)]
        assert not state.alt_stack

    @pytest.mark.parametrize("value, result", (
        (0, 0),
        (-1, 1),
        (1, 1),
        (127, 1),
        (255, 1),
        (bytes(2), 0),
        (b'\x80', 0),
        (b'\x81', 1),
    ))
    def test_0NOTEQUAL(self, state, value, result):
        script = Script() << value << OP_0NOTEQUAL
        state.evaluate_script(script)
        assert state.stack == [int_to_item(result)]
        assert not state.alt_stack

    @pytest.mark.parametrize("opcode", (
        OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_MOD, OP_BOOLAND, OP_BOOLOR, OP_NUMEQUAL,
        OP_NUMEQUALVERIFY, OP_NUMNOTEQUAL, OP_LESSTHAN, OP_GREATERTHAN,
        OP_LESSTHANOREQUAL, OP_GREATERTHANOREQUAL, OP_MIN, OP_MAX))
    def test_binary_numeric_stack(self, state, opcode):
        self.require_stack(state, 2, opcode)

    @pytest.mark.parametrize("opcodes,result", (
        ((OP_3, OP_5, OP_ADD), 8),
        ((OP_1NEGATE, OP_5, OP_ADD), 4),
        ((-5, -6, OP_ADD), -11),
        ((b'\0', b'\x80', OP_ADD), 0),
        ((b'\0', b'\x81', OP_SUB), 1),
        ((b'', -1, OP_SUB), 1),
        ((OP_3, OP_5, OP_SUB), -2),
        ((OP_3, OP_5, OP_MUL), 15),
        ((255, OP_0, OP_MUL), 0),
        ((-15, -2, OP_MUL), 30),
        ((12, 13, OP_MUL), 156),
    ))
    def test_binary_numeric(self, state, opcodes, result):
        script = Script().push_many(opcodes)
        state.evaluate_script(script)
        assert state.stack == [int_to_item(result)]
        assert not state.alt_stack

    @pytest.mark.parametrize("a,b,mul", (
        ('05', '06', '1e'),
        ('05', '26', 'be00'),
        ('45', '26', '3e0a'),
        ('02', '5624', 'ac48'),
        ('05', '260332', 'be0ffa00'),
        ('06', '26033204', 'e4122c19'),
        ('a0a0', 'f5e4', '20b9dd0c'),
    ))
    def test_mul(self, state_old_utxo, a, b, mul):
        a, b, neg_a, neg_b = value_bytes(a), value_bytes(b), negate_bytes(a), negate_bytes(b)
        mul, neg_mul = value_bytes(mul), negate_bytes(mul)

        # Test negative values
        script = Script().push_many((a, b, OP_MUL, a, neg_b, OP_MUL,
                                     neg_a, b, OP_MUL, neg_a, neg_b, OP_MUL))
        state_old_utxo.evaluate_script(script)
        assert state_old_utxo.stack == [mul, neg_mul, neg_mul, mul]

        # Commutativity
        state_old_utxo.reset()
        script = Script().push_many((b, a, OP_MUL))
        state_old_utxo.evaluate_script(script)
        assert state_old_utxo.stack == [mul]

        # Identities
        state_old_utxo.reset()
        script = Script().push_many((a, 1, OP_MUL, a, b'\x81', OP_MUL, a, b'', OP_MUL,
                                     1, a, OP_MUL, b'\x81', a, OP_MUL, b'', a, OP_MUL))
        state_old_utxo.evaluate_script(script)
        assert state_old_utxo.stack == [a, neg_a, b''] * 2

    @pytest.mark.parametrize("a,b", (
        ('0102030405', '0102030405'),
        ('0105', '0102030405'),
        ('0102030405', '01'),
    ))
    def test_mul_error(self, state_old_utxo, a, b):
        a, b = value_bytes(a), value_bytes(b)
        script = Script().push_many((a, b, OP_MUL))
        with pytest.raises(InvalidNumber):
            state_old_utxo.evaluate_script(script)

    def test_overflow(self, state_old_utxo):
        script = Script().push_many((70000, 70000, OP_MUL))
        state_old_utxo.evaluate_script(script)
        state_old_utxo.reset()

        script = Script().push_many((70000, 70000, OP_MUL, OP_0, OP_ADD))
        with pytest.raises(InvalidNumber):
            state_old_utxo.evaluate_script(script)

    @pytest.mark.parametrize("a,b,div,mod", (
        (0x185377af, -0x05f41b01, -4, 0x00830bab),
        (408123311, -99883777, -4, 8588203),
        (0x185377af, 0x00001b01, 0xe69d, 0x0212),
        (408123311, 6913, 59037, 530),
        (15, 4, 3, 3),
        (15000, 4, 3750, 0),
        (15000, 4000, 3, 3000),
    ))
    def test_div_mod(self, state_old_utxo, a, b, div, mod):
        script = Script().push_many((a, b, OP_DIV, a, b, OP_MOD))
        state_old_utxo.evaluate_script(script)
        assert state_old_utxo.stack == [int_to_item(div), int_to_item(mod)]
        assert not state_old_utxo.alt_stack

        state_old_utxo.reset()
        script = Script().push_many((a, -b, OP_DIV, a, -b, OP_MOD))
        state_old_utxo.evaluate_script(script)
        assert state_old_utxo.stack == [int_to_item(-div), int_to_item(mod)]
        assert not state_old_utxo.alt_stack

        state_old_utxo.reset()
        script = Script().push_many((-a, b, OP_DIV, -a, b, OP_MOD))
        state_old_utxo.evaluate_script(script)
        assert state_old_utxo.stack == [int_to_item(-div), int_to_item(-mod)]
        assert not state_old_utxo.alt_stack

        state_old_utxo.reset()
        script = Script().push_many((-a, -b, OP_DIV, -a, -b, OP_MOD))
        state_old_utxo.evaluate_script(script)
        assert state_old_utxo.stack == [int_to_item(div), int_to_item(-mod)]
        assert not state_old_utxo.alt_stack

        state_old_utxo.reset()
        script = Script().push_many((-a, -b, OP_DIV, -a, -b, OP_MOD))
        state_old_utxo.evaluate_script(script)
        assert state_old_utxo.stack == [int_to_item(div), int_to_item(-mod)]
        assert not state_old_utxo.alt_stack

        for value in a, b:
            for zeroes in ('00', '80', '0000', '0080'):
                state_old_utxo.reset()
                script = Script().push_many((value, 0, OP_DIV))
                with pytest.raises(DivisionByZero) as e:
                    state_old_utxo.evaluate_script(script)
                assert 'division by zero' in str(e.value)

                state_old_utxo.reset()
                script = Script().push_many((value, 0, OP_MOD))
                with pytest.raises(DivisionByZero) as e:
                    state_old_utxo.evaluate_script(script)
                assert 'modulo by zero' in str(e.value)

            # Division identities
            state_old_utxo.reset()
            script = Script().push_many((value, 1, OP_DIV, value, b'\x81', OP_DIV,
                                         value, value, OP_DIV, value, -value, OP_DIV))
            state_old_utxo.evaluate_script(script)
            assert state_old_utxo.stack == [int_to_item(value), int_to_item(-value),
                                            b'\1', b'\x81']

    @pytest.mark.parametrize("a,b", (
        ('0102030405', '0102030405'),
        ('0105', '0102030405'),
        ('0102030405', '01'),
    ))
    def test_div_mod_error(self, state_old_utxo, a, b):
        a = bytes.fromhex(a)
        b = bytes.fromhex(b)

        script = Script().push_many((a, b, OP_DIV))
        with pytest.raises(InvalidNumber):
            state_old_utxo.evaluate_script(script)

        script = Script().push_many((a, b, OP_MOD))
        with pytest.raises(InvalidNumber):
            state_old_utxo.evaluate_script(script)

    @pytest.mark.parametrize("x,low,high,result", (
        (-1, 0, 2, 0),
        (0, 0, 2, 1),
        (1, 0, 2, 1),
        (2, 0, 2, 0),
        (4, 0, 2, 0),
        (0, 2, 0, 0),
        (1, 2, 0, 0),
        (2, 2, 0, 0),
        (2, b'', b'\3', 1),
        (86_000, 50_000, 100_000, 1),
        (65_536, 75_000, 100_000, 0),
    ))
    def test_WITHIN(self, state, x, low, high, result):
        script = Script() << x << low << high << OP_WITHIN
        state.evaluate_script(script)
        assert state.stack == [int_to_item(result)]

    def test_invalid_opcode(self, state):
        script = Script(b'\xff')
        with pytest.raises(InvalidOpcode) as e:
            state.evaluate_script(script)
        assert 'invalid opcode 255' in str(e.value)


class TestControlOperations(TestEvaluateScriptBase):

    def test_NOP(self, state):
        script = Script() << OP_NOP << OP_NOP
        state.evaluate_script(script)
        assert not state.stack
        assert not state.alt_stack

    @pytest.mark.parametrize("is_utxo_after_genesis", (False, True))
    def test_NOP_not_upgradeable(self, policy, is_utxo_after_genesis):
        script = Script() << OP_NOP

        # No effect regardless of flags; it's not an upgradeable NOP
        state = InterpreterState(policy, flags=0, is_utxo_after_genesis=is_utxo_after_genesis)
        state.evaluate_script(script)
        state = InterpreterState(policy, flags=InterpreterFlags.REJECT_UPGRADEABLE_NOPS,
                                 is_utxo_after_genesis=is_utxo_after_genesis)
        state.evaluate_script(script)

    @pytest.mark.parametrize('op', (OP_IF, OP_NOTIF))
    def test_IF_unbalanced_outer(self, state, op):
        script = Script() << OP_1 << op << OP_2
        with pytest.raises(UnbalancedConditional) as e:
            state.evaluate_script(script)
        assert f'unterminated {op.name} at end of script' in str(e.value)

    @pytest.mark.parametrize('op', (OP_IF, OP_NOTIF))
    def test_IF_unbalanced_inner(self, state, op):
        script = Script() << OP_2 << OP_2 << op << OP_IF << OP_ENDIF
        with pytest.raises(UnbalancedConditional) as e:
            state.evaluate_script(script)
        assert f'unterminated {op.name} at end of script' in str(e.value)

    @pytest.mark.parametrize('op', (OP_IF, OP_NOTIF))
    def test_no_value_IF(self, state, op):
        script = Script() << op
        with pytest.raises(InvalidStackOperation):
            state.evaluate_script(script)

    @pytest.mark.parametrize('op', (OP_IF, OP_NOTIF))
    def test_no_value_IF_unexecuted(self, state, op):
        script = Script() << OP_0 << OP_IF << op << OP_ENDIF << OP_ENDIF
        state.evaluate_script(script)

    @pytest.mark.parametrize('op,truth', product((OP_IF, OP_NOTIF), (False, True)))
    def test_IF_data(self, state, op, truth):
        values = [b'foo', b'bar']
        script = Script() << truth << op << values[0] << OP_ELSE << values[1] << OP_ENDIF
        state.evaluate_script(script)
        assert state.stack == [values[(op == OP_IF) ^ truth]]

    def test_ELSE_unbalanced(self, state):
        script = Script() << OP_1 << OP_ELSE
        with pytest.raises(UnbalancedConditional) as e:
            state.evaluate_script(script)
        assert 'unexpected OP_ELSE' in str(e.value)

    @pytest.mark.parametrize('op', (OP_IF, OP_NOTIF))
    def test_ELSE_unbalanced_2(self, state, op):
        script = Script() << OP_1 << op << OP_ELSE << OP_ENDIF << OP_ELSE
        with pytest.raises(UnbalancedConditional) as e:
            state.evaluate_script(script)
        assert 'unexpected OP_ELSE' in str(e.value)

    def test_double_ELSE(self, state):
        script = (Script() << OP_0 << OP_IF
                  << OP_ELSE << b'foo' << OP_ELSE << b'bar' << OP_ELSE << b'baz'
                  << OP_ENDIF)
        if state.is_utxo_after_genesis:
            with pytest.raises(UnbalancedConditional) as e:
                state.evaluate_script(script)
            assert 'unexpected OP_ELSE' in str(e.value)
        else:
            state.evaluate_script(script)
            assert state.stack == [b'foo', b'baz']

    def test_ENDIF_unbalanced(self, state):
        script = Script() << OP_1 << OP_ENDIF
        with pytest.raises(UnbalancedConditional) as e:
            state.evaluate_script(script)
        assert 'unexpected OP_ENDIF' in str(e.value)

    @pytest.mark.parametrize('op', (OP_IF, OP_NOTIF))
    def test_ENDIF_unbalanced_2(self, state, op):
        script = Script() << OP_1 << op << OP_ELSE << OP_ENDIF << OP_ENDIF
        with pytest.raises(UnbalancedConditional) as e:
            state.evaluate_script(script)
        assert 'unexpected OP_ENDIF' in str(e.value)

    @pytest.mark.parametrize('op', (OP_IF, OP_NOTIF))
    def test_require_minimal_if(self, state, op):
        state.flags |= InterpreterFlags.REQUIRE_MINIMAL_IF
        script = Script() << 2 << op << OP_ENDIF
        with pytest.raises(MinimalIfError) as e:
            state.evaluate_script(script)
        assert 'top of stack not True or False' in str(e.value)
        assert state.stack[-1] == b'\2'
        state.reset()

        script = Script() << bytes(1) << op << OP_ENDIF
        with pytest.raises(MinimalIfError) as e:
            state.evaluate_script(script)
        assert 'top of stack not True or False' in str(e.value)
        assert state.stack[-1] == b'\0'
        state.reset()

        script = Script() << b'\1\0' << op << OP_ENDIF
        with pytest.raises(MinimalIfError) as e:
            state.evaluate_script(script)
        assert 'top of stack not True or False' in str(e.value)
        assert state.stack[-1] == b'\1\0'
        state.reset()

        script = Script() << 0 << op << OP_ENDIF
        state.evaluate_script(script)
        state.reset()

        script = Script() << 1 << op << OP_ENDIF
        state.evaluate_script(script)

    @pytest.mark.parametrize("push", (OP_1, OP_10, OP_1NEGATE, b'foo', b'\1\0', b'\0\1'))
    def test_VERIFY(self, state, push):
        self.require_stack(state, 1, OP_VERIFY)
        script = Script() << push << OP_VERIFY
        state.evaluate_script(script)
        assert state.stack == []
        assert state.alt_stack == []

    @pytest.mark.parametrize("zero", zeroes)
    def test_VERIFY_failed(self, state, zero):
        script = Script() << zero << OP_VERIFY
        with pytest.raises(VerifyFailed):
            state.evaluate_script(script)
        assert state.stack == [zero]
        assert state.alt_stack == []

    def test_VERIFY_no_overflow(self, state):
        # cast_to_bool does not overflow
        script = Script().push_many((70000, 70000, OP_MUL, OP_VERIFY))
        state.evaluate_script(script)

    def test_RETURN_immediate(self, state):
        script = Script() << OP_RETURN
        if state.is_utxo_after_genesis:
            state.evaluate_script(script)
        else:
            with pytest.raises(OpReturnError):
                state.evaluate_script(script)
        assert state.stack == []
        assert state.alt_stack == []

    def test_RETURN_not_immediate(self, state):
        script = Script() << OP_1 << OP_RETURN
        if state.is_utxo_after_genesis:
            state.evaluate_script(script)
        else:
            with pytest.raises(OpReturnError):
                state.evaluate_script(script)
        assert state.stack == [b'\1']
        assert state.alt_stack == []

    def test_RETURN_unbalanced_IF(self, state):
        # Unabalanced ifs after a post-genesis top-level OP_RETURN are fine
        script = Script() << OP_1 << OP_RETURN << OP_IF
        if state.is_utxo_after_genesis:
            state.evaluate_script(script)
        else:
            with pytest.raises(OpReturnError):
                state.evaluate_script(script)
        assert state.stack == [b'\1']
        assert state.alt_stack == []

    def test_RETURN_invalid_op(self, state):
        # Invalid opcodes after a post-genesis top-level OP_RETURN are fine
        script = Script() << OP_0 << OP_RETURN << OP_RESERVED
        script = Script(script.to_bytes() + b'\0xff')
        if state.is_utxo_after_genesis:
            state.evaluate_script(script)
        else:
            with pytest.raises(OpReturnError):
                state.evaluate_script(script)
        assert state.stack == [b'']
        assert state.alt_stack == []

    def test_RETURN_unexecuted(self, state):
        # Unexecuted OP_RETURN ignored pre- and post-genesis
        script = Script() << OP_0 << OP_IF << OP_RETURN << OP_ENDIF
        state.evaluate_script(script)
        assert state.stack == []
        assert state.alt_stack == []

    def test_RETURN_executed_branch_invalid_grammar(self, state):
        script = Script() << OP_1 << OP_IF << OP_RETURN << OP_ENDIF << OP_IF
        if state.is_utxo_after_genesis:
            with pytest.raises(UnbalancedConditional):
                state.evaluate_script(script)
        else:
            with pytest.raises(OpReturnError):
                state.evaluate_script(script)
        assert state.stack == []
        assert state.alt_stack == []

    def test_RETURN_executed_branch_OP_RETURN_invalid_grammar(self, state):
        script = Script() << OP_1 << OP_IF << OP_RETURN << OP_ENDIF << OP_RETURN << OP_IF
        if state.is_utxo_after_genesis:
            # The unabalanced conditional is ignored as the top-level OP_RETURN stops execution
            state.evaluate_script(script)
        else:
            with pytest.raises(OpReturnError):
                state.evaluate_script(script)
        assert state.stack == []
        assert state.alt_stack == []

    def test_RETURN_executed_branch_invalid_opcode_executed(self, state):
        script = Script() << OP_1 << OP_IF << OP_RETURN << OP_ENDIF << OP_RESERVED
        if state.is_utxo_after_genesis:
            # It's OK; only check IF grammar
            state.evaluate_script(script)
        else:
            with pytest.raises(OpReturnError):
                state.evaluate_script(script)
        assert state.stack == []
        assert state.alt_stack == []

    def test_RETURN_executed_branch_invalid_opcode_unuexecuted(self, state):
        script = Script() << OP_1 << OP_IF << OP_RETURN << OP_ELSE << OP_RESERVED << OP_ENDIF
        if state.is_utxo_after_genesis:
            # It's OK as unexecuted
            state.evaluate_script(script)
        else:
            with pytest.raises(OpReturnError):
                state.evaluate_script(script)
        assert state.stack == []
        assert state.alt_stack == []

    @pytest.mark.parametrize('op', (OP_VERIF, OP_VERNOTIF))
    def test_VERIF_executed(self, state, op):
        # Unexecuted OP_RETURN ignored pre- and post-genesis
        script = Script() << op
        with pytest.raises(InvalidOpcode) as e:
            state.evaluate_script(script)
        assert f'invalid opcode {op.name}' in str(e.value)
        assert state.stack == []
        assert state.alt_stack == []

    @pytest.mark.parametrize('op', (OP_VERIF, OP_VERNOTIF))
    def test_VERIF_unexecuted(self, state, op):
        script = Script() << OP_0 << OP_IF << op << OP_ENDIF
        if state.is_utxo_after_genesis:
            state.evaluate_script(script)
        else:
            with pytest.raises(InvalidOpcode) as e:
                state.evaluate_script(script)
            assert f'invalid opcode {op.name}' in str(e.value)
        assert state.stack == []
        assert state.alt_stack == []


class TestStackOperations(TestEvaluateScriptBase):

    def test_DROP(self, state):
        self.require_stack(state, 1, OP_DROP)
        script = Script() << self.random_push() << OP_DROP
        state.evaluate_script(script)
        assert not state.stack
        assert not state.alt_stack

    def test_2DROP(self, state):
        self.require_stack(state, 2, OP_2DROP)
        script = Script() << self.random_push() << self.random_push() << OP_2DROP
        state.evaluate_script(script)
        assert not state.stack
        assert not state.alt_stack

    def test_DUP(self, state):
        self.require_stack(state, 1, OP_DUP)
        push, data = self.random_push_data()
        script = Script() << push << OP_DUP
        state.evaluate_script(script)
        assert state.stack == [data] * 2
        assert not state.alt_stack

    def test_2DUP(self, state):
        self.require_stack(state, 2, OP_2DUP)
        push_datas = [self.random_push_data() for _ in range(2)]
        pushes, datas = list(zip(*push_datas))
        script = Script().push_many(pushes) << OP_2DUP
        state.evaluate_script(script)
        assert state.stack == list(datas) * 2
        assert not state.alt_stack

    def test_3DUP(self, state):
        self.require_stack(state, 3, OP_3DUP)
        push_datas = [self.random_push_data() for _ in range(3)]
        pushes, datas = list(zip(*push_datas))
        script = Script().push_many(pushes) << OP_3DUP
        state.evaluate_script(script)
        assert state.stack == list(datas) * 2
        assert not state.alt_stack

    def test_OVER(self, state):
        self.require_stack(state, 2, OP_OVER)
        push_datas = [self.random_push_data() for _ in range(2)]
        pushes, datas = list(zip(*push_datas))
        script = Script().push_many(pushes) << OP_OVER
        state.evaluate_script(script)
        assert state.stack == [datas[0], datas[1], datas[0]]
        assert not state.alt_stack

    def test_2OVER(self, state):
        self.require_stack(state, 4, OP_2OVER)
        push_datas = [self.random_push_data() for _ in range(4)]
        pushes, datas = list(zip(*push_datas))
        script = Script().push_many(pushes) << OP_2OVER
        state.evaluate_script(script)
        assert state.stack == list(datas + datas[:2])
        assert not state.alt_stack

    def test_2ROT(self, state):
        self.require_stack(state, 6, OP_2ROT)
        push_datas = [self.random_push_data() for _ in range(8)]
        pushes, datas = list(zip(*push_datas))
        script = Script().push_many(pushes) << OP_2ROT
        state.evaluate_script(script)
        assert state.stack == list(datas[:2] + datas[4:] + datas[2:4])
        assert not state.alt_stack

    def test_2SWAP(self, state):
        self.require_stack(state, 4, OP_2SWAP)
        push_datas = [self.random_push_data() for _ in range(5)]
        pushes, datas = list(zip(*push_datas))
        script = Script().push_many(pushes) << OP_2SWAP
        state.evaluate_script(script)
        assert state.stack == list(datas[:1] + datas[3:] + datas[1:3])
        assert not state.alt_stack

    def test_IFDUP(self, state):
        self.require_stack(state, 1, OP_IFDUP)
        item = random.choice(zeroes)
        script = Script() << item << OP_IFDUP
        state.evaluate_script(script)
        assert state.stack == [item]
        assert not state.alt_stack
        state.reset()

        item = random.choice(non_zeroes)
        script = Script() << item << OP_IFDUP
        state.evaluate_script(script)
        assert state.stack == [item] * 2
        assert not state.alt_stack

    def test_IPDUP_no_minimal_if(self, state):
        # Has no effect
        state.flags |= InterpreterFlags.REQUIRE_MINIMAL_IF
        script = Script() << 2 << OP_IFDUP
        state.evaluate_script(script)
        assert state.stack == [b'\2'] * 2

    def test_DEPTH(self, state):
        push_datas = [self.random_push_data() for _ in range(10)]
        pushes, datas = list(zip(*push_datas))
        script = Script().push_many(pushes) << OP_DEPTH
        state.evaluate_script(script)
        assert state.stack == list(datas) + [int_to_item(len(push_datas))]
        assert not state.alt_stack

    def test_DEPTH_empty(self, state):
        script = Script() << OP_DEPTH
        state.evaluate_script(script)
        assert state.stack == [b'']
        assert not state.alt_stack

    def test_NIP(self, state):
        self.require_stack(state, 2, OP_NIP)
        push_datas = [self.random_push_data() for _ in range(2)]
        pushes, datas = list(zip(*push_datas))
        script = Script().push_many(pushes) << OP_NIP
        state.evaluate_script(script)
        assert state.stack == [datas[1]]
        assert not state.alt_stack

    def test_SWAP(self, state):
        self.require_stack(state, 2, OP_SWAP)
        push_datas = [self.random_push_data() for _ in range(2)]
        pushes, datas = list(zip(*push_datas))
        script = Script().push_many(pushes) << OP_SWAP
        state.evaluate_script(script)
        assert state.stack == list(reversed(datas))
        assert not state.alt_stack

    def test_TUCK(self, state):
        self.require_stack(state, 2, OP_TUCK)
        push_datas = [self.random_push_data() for _ in range(2)]
        pushes, datas = list(zip(*push_datas))
        script = Script().push_many(pushes) << OP_TUCK
        state.evaluate_script(script)
        assert state.stack == [datas[-1]] + list(datas)
        assert not state.alt_stack

    def test_ROT(self, state):
        self.require_stack(state, 3, OP_ROT)
        push_datas = [self.random_push_data() for _ in range(6)]
        pushes, datas = list(zip(*push_datas))
        script = Script().push_many(pushes) << OP_ROT
        state.evaluate_script(script)
        assert state.stack == list(datas[:3]) + list(datas[-2:]) + [datas[-3]]
        assert not state.alt_stack

    def test_PICK(self, state):
        # If not 2 items; no pop
        self.require_stack(state, 2, OP_PICK)

        # Test good pick
        count = random.randrange(1, 8)
        n = random.randrange(0, count)
        push_datas = [self.random_push_data() for _ in range(count)]
        pushes = [pair[0] for pair in push_datas]
        datas = [pair[1] for pair in push_datas]
        script = Script().push_many(pushes) << n << OP_PICK
        state.evaluate_script(script)
        assert state.stack == list(datas) + [datas[-(n + 1)]]
        assert not state.alt_stack
        state.reset()

        # Test bad pick
        n = random.choice([-1, count])
        push_datas = [self.random_push_data() for _ in range(count)]
        pushes = [pair[0] for pair in push_datas]
        datas = [pair[1] for pair in push_datas]
        script = Script().push_many(pushes) << n << OP_PICK
        with pytest.raises(InvalidStackOperation):
            state.evaluate_script(script)
        assert state.stack == list(datas)   # All intact, just n is popped
        assert not state.alt_stack

    def test_ROLL(self, state):
        # If not 2 items; no pop
        self.require_stack(state, 2, OP_ROLL)

        # Test good roll
        count = random.randrange(1, 8)
        n = random.randrange(0, count)
        push_datas = [self.random_push_data() for _ in range(count)]
        pushes = [pair[0] for pair in push_datas]
        datas = [pair[1] for pair in push_datas]
        script = Script().push_many(pushes) << n << OP_ROLL
        state.evaluate_script(script)
        expected = list(datas)
        expected.append(expected.pop(-(n + 1)))
        assert state.stack == expected
        assert not state.alt_stack
        state.reset()

        # Test bad roll
        n = random.choice([-1, count])
        push_datas = [self.random_push_data() for _ in range(count)]
        pushes = [pair[0] for pair in push_datas]
        datas = [pair[1] for pair in push_datas]
        script = Script().push_many(pushes) << n << OP_ROLL
        with pytest.raises(InvalidStackOperation):
            state.evaluate_script(script)
        assert state.stack == list(datas)   # All intact, just n is popped
        assert not state.alt_stack

    @pytest.mark.parametrize("value,size", (
        (b'', 0),
        (b'\x00', 1),
        (b'\x00\x80', 2),
        (bytes(20), 20),
   ))
    def test_SIZE(self, state, value, size):
        self.require_stack(state, 1, OP_SIZE)
        script = Script() << value << OP_SIZE
        state.evaluate_script(script)
        assert state.stack == [value, int_to_item(len(value))]
        assert not state.alt_stack

    def test_TOALTSTACK(self, state):
        self.require_stack(state, 1, OP_TOALTSTACK)
        script = Script() << OP_12 << OP_TOALTSTACK
        state.evaluate_script(script)
        assert not state.stack
        assert state.alt_stack == [b'\x0c']

    def test_FROMALTSTACK(self, state):
        script = Script() << OP_FROMALTSTACK
        with pytest.raises(InvalidStackOperation):
            state.evaluate_script(script)
        script = Script() << OP_10 << OP_TOALTSTACK << OP_8 << OP_FROMALTSTACK
        state.evaluate_script(script)
        assert state.stack == [b'\x08', b'\x0a']
        assert not state.alt_stack


a, b, aorb, aandb, axorb = (
    '340e7e1783661a81458d2626bcbd56e7f21cecf6798c3e580f86cf53be668fa7bef630128d0100377f5b64'
    '5063406a44f57e02c7ab45cf6a9861e8b8c49e11e830710773a24ddda66cf42a22a0acdcf4ccfb4de355de'
    '4446323693b4d9d13b06096a64c31858c49f1b6aa3ab5937bd36973526876358086e5e46cf1533fc464597'
    '614bb8ecdd1b696e8a27f9cd4b5ca48418d52350c663becad3d09139166a6ed6091852056aa7f764a3f0ba'
    '75c59cf7bb7068654fdbd03614fb1af66eea8dc8a5ad61c6044cc3b9688ca4e404aeeecae752a7ba169126'
    '9bae31cd6f4e7e476040f0bce220afc14f26549337fcbf50d3f23070fc671582d33927a24fce10ed1173c4'
    '48e965a15ef20c813b80e19f53314973c80a6ea4e1e1e2aceb0ba54bc547f6f1151031f0cb6fedd3507db2'
    '8687ab625c4c4bb00a2019b98c1af5e629a08a5588a0f5efe6506d367b75e514c8fbc65be799376256db8f'
    '4043548d6819c2f5c037edee0eab0b772927ac0770faa9692851f565587accc9fe3ca00d6e873836b71a41'
    '6c9a13fa8613e6c9ec9f5015c3744c29670aa77e7f3cabe944616e6450471e172364299c9cef5b28e30ea5'
    '2a2f2dc66cd3aa0348150c9280862fc2bd5e8261a188dd5eeaef19f98466f7bb44adf9f72f2ad537ef283d'
    '1adc6cf1cccad52b5863c0349187d9362f90ebf1de8b8c205183fdf4fde74068f35a178021f3c1903c7523'
    '481c98b5',
    'd29e99c9e7117b0e4b8e1108d15cf4b82c143f4575e98aeb81f8d8a38e4b630e7f1efd84837c261ff0c937'
    '1c5ff5f33d672b2730db3ee72f7b7d1c40062a725a370cd5a8a381d473ef1e4e6cb9103d046ecae7df627b'
    '64006ab6da029674a7c2bb2869dfc809ff6c6f7af88269f159f83de06da571fb392e1751cb942ad04e02af'
    'a5d53956da102ea2910bd2cab1ac6dd2efad5954bcd3444c6ce25cedabc0046d3e92f94ace76ed45509329'
    '17939cf0d83ccdf7529f27572affe033b6a441a3350bab0c0bdd98101d97247a8ecba37ae9a873f44a4c6b'
    'b73165ca5ac4d83ce0ad302a2e342e4084dd5d08ed1012ca3f242d085b86b6f470005c9d302a81d25ca170'
    'cf990ff594ef541dab9124594ff6cbb86d1421f1fb145c294e6eb04d640c38ee1963149b3db4192591e6de'
    'f4342b8799bdec1cd39234b7baef00aedcec9dd1fa839f958db0edc067aece15db288b8fcbc49b0d466796'
    'b086b2db3c896e57accb3457378000347871f01a2c28879f08217c0e7e29fb9a2c77482f88e2f06a87150c'
    '4cbfcbddee75e1bc3831dce961531ec84b80945c03dd4baea854e98b232021c80383335f1137fcd5b3119a'
    '060dbfcdc72288b8c93fec7c11966aa057df5bdea20911d3fdbf847a9d3aba0f6d01adbcb9d88ae4d6a204'
    '93e002d24549148e849c7c571b0527f65983d1f4b62fbe6e357e9710f5421ac94db907716dd196c388b6e6'
    '0e8a8ad7',
    'f69effdfe7777b8f4f8f372efdfdf6fffe1cfff77dedbefb8ffedff3be6fefaffffefd968f7d263fffdb77'
    '5c7ff5fb7df77f27f7fb7fef6ffb7dfcf8c6be73fa377dd7fba3cdddf7effe6e6eb9bcfdf4eefbefff77ff'
    '64467ab6dbb6dff5bfc6bb6a6ddfd859ffff7f7afbab79f7fdfebff56fa773fb396e5f57cf953bfc4e47bf'
    'e5dfb9fedf1b6fee9b2ffbcffbfcedd6fffd7b54fef3fecefff2ddfdbfea6eff3f9afb4feef7ff65f3f3bb'
    '77d79cf7fb7cedf75fdff7773efffaf7feeecdebb5afebce0fdddbb97d9fa4fe8eefeffaeffaf7fe5edd6f'
    'bfbf75cf7fcefe7fe0edf0beee34afc1cfff5d9bfffcbfdafff63d78ffe7b7f6f3397fbf7fee91ff5df3f4'
    'cff96ff5deff5c9dbb91e5df5ff7cbfbed1e6ff5fbf5feadef6fb54fe54ffeff1d7335fbfffffdf7d1fffe'
    'f6b7abe7ddfdefbcdbb23dbfbefff5eefdec9fd5faa3ffffeff0edf67fffef15dbfbcfdfefddbf6f56ff9f'
    'f0c7f6df7c99eef7ecfffdff3fab0b777977fc1f7cfaafff2871fd6f7e7bffdbfe7fe82feee7f87eb71f4d'
    '6cbfdbffee77e7fdfcbfdcfde3775ee96f8ab77e7ffdebefec75efef73673fdf23e73bdf9dfffffdf31fbf'
    '2e2fbfcfeff3aabbc93fecfe91966fe2ffdfdbffa389dddfffff9dfb9d7effbf6dadfdffbffadff7ffaa3d'
    '9bfc6ef3cdcbd5afdcfffc779b87fff67f93fbf5feafbe6e75fffff4fde75ae9fffb17f16df3d7d3bcf7e7'
    '4e9e9af7',
    '100e180183001a00418c0000901c54a020142c4471880a480180c8038e4203063e16300081000017704924'
    '1043406204652a02008b04c72a18610800040a104830000520a201d4226c140a20a0001c044cca45c3405a'
    '44002236920090502302092860c30808c40c0b6aa08249311930152024856158082e1640cb1422d0460087'
    '21413844d81028228003d0c8010c2480088501508443044840c0102902400444081050004a26e544009028'
    '15819cf098304865429b001600fb003226a0018025092104004c801008842460048aa24ae10023b0020022'
    '932021c84a4458046000302822202e400404540025101240132020005806148050000480000a00c0102140'
    '488905a114e204012b80201943304930480020a0e10040284a0aa049440430e01100109009240901106492'
    '84042b02180c4810020010b1880a00a608a088518880958584106d006324c414c828820bc3801300464386'
    '000210892809425580032446068000342821a00220288109080174045828c8882c34000d08823022871000'
    '4c9a03d88611e0882811500141500c084300845c031c0ba800406800000000000300211c10275800a30080'
    '020d2dc44402880048150c1000862a80155e0240a0081152e8af00788422b20b4401a9b429088024c62004'
    '12c000d04448140a00004014110501360980c1f0960b8c2011029510f54200484118070021d18080083422'
    '08088895',
    'e690e7de6477618f0e03372e6de1a25fde08d3b30c65b4b38e7e17f0302deca9c1e8cd960e7d26288f9253'
    '4c3cb59979925525f7707b2845e31cf4f8c2b463b2077dd2db01cc09d583ea644e19bce1f0a231aa3c37a5'
    '2046588049b64fa59cc4b2420d1cd0513bf374105b2930c6e4ceaad54b2212a3314049170481192c084738'
    'c49e81ba070b47cc1b2c2b07faf0c956f7787a047ab0fa86bf32cdd4bdaa6abb378aab4fa4d11a21f36393'
    '62560007634ca5921d44f7613e04fac5d84ecc6b90a6caca0f915ba9751b809e8a654db00efad44e5cdd4d'
    '2c9f5407358aa67b80edc096cc148181cbfb099bdaecad9aecd61d78a7e1a376a3397b3f7fe4913f4dd2b4'
    '87706a54ca1d589c9011c5c61cc782cba51e4f551af5be85a5651506a14bce1f0c73256bf6dbf4f6c19b6c'
    '72b380e5c5f1a7acd9b22d0e36f5f548f54c178472236a7a6be080f61cdb2b0113d34dd42c5dac6f10bc19'
    'f0c5e6565490aca26cfcd9b9392b0b4351565c1d5cd22ef62070896b26533753d24be822e665c85c300f4d'
    '2025d82768660775d4ae8cfca22752e12c8a33227ce1e047ec3587ef73673fdf20e71ac38dd8a7fd501f3f'
    '2c22920babf122bb812ae0ee91104562ea81d9bf0381cc8d17509d83195c4db429ac544b96f25fd3398a39'
    '893c6e238983c1a5dcffbc638a82fec076133a0568a4324e64fd6ae408a55aa1bee310f14c225753b4c3c5'
    '46961262',
)


class TestBitwiseLogic(TestEvaluateScriptBase):

    @pytest.mark.parametrize("value,result", (
        (b'', b''),
        (b'\1\2', b'\xfe\xfd'),
        (bytes(range(256)), bytes(255 - x for x in range(256))),
    ))
    def test_INVERT(self, state, value, result):
        self.require_stack(state, 1, OP_INVERT)
        script = Script() << value << OP_INVERT
        state.evaluate_script(script)
        assert state.stack == [result]
        assert not state.alt_stack

    @pytest.mark.parametrize("x1,x2,result", (
        ('', '', ''),
        ('01', '07', '01'),
        ('01', '0700', None),
        ('0100', '07', None),
        ('011f', '07ff', '011f'),
        ('f1f1f1f1f1f1f1f1', '7777777777777777', '7171717171717171'),
        (a, b, aandb),
        (b, a, aandb),
    ))
    def test_AND(self, state, x1, x2, result):
        self.require_stack(state, 1, OP_AND)
        script = Script() << bytes.fromhex(x1) << bytes.fromhex(x2) << OP_AND
        if result is None:
            with pytest.raises(InvalidOperandSize):
                state.evaluate_script(script)
            assert len(state.stack) == 2
        else:
            state.evaluate_script(script)
            assert state.stack == [bytes.fromhex(result)]
            assert not state.alt_stack

    @pytest.mark.parametrize("x1,x2,result", (
        ('', '', ''),
        ('01', '07', '07'),
        ('01', '0700', None),
        ('01', '', None),
        ('011f', '07ff', '07ff'),
        ('f1f1f1f1f1f1f1f1', '7777777777777777', 'f7f7f7f7f7f7f7f7'),
        (a, b, aorb),
        (b, a, aorb),
    ))
    def test_OR(self, state, x1, x2, result):
        self.require_stack(state, 1, OP_OR)
        script = Script() << bytes.fromhex(x1) << bytes.fromhex(x2) << OP_OR
        if result is None:
            with pytest.raises(InvalidOperandSize):
                state.evaluate_script(script)
            assert len(state.stack) == 2
        else:
            state.evaluate_script(script)
            assert state.stack == [bytes.fromhex(result)]
            assert not state.alt_stack

    @pytest.mark.parametrize("x1,x2,result", (
        ('', '', ''),
        ('01', '07', '06'),
        ('01', '0700', None),
        ('011f', '07ff', '06e0'),
        ('f1f1f1f1f1f1f1f1', '7777777777777777', '8686868686868686'),
        (a, a, '0' * len(a)),
        (a, b, axorb),
        (b, a, axorb),
    ))
    def test_XOR(self, state, x1, x2, result):
        self.require_stack(state, 1, OP_XOR)
        script = Script() << bytes.fromhex(x1) << bytes.fromhex(x2) << OP_XOR
        if result is None:
            with pytest.raises(InvalidOperandSize):
                state.evaluate_script(script)
            assert len(state.stack) == 2
        else:
            state.evaluate_script(script)
            assert state.stack == [bytes.fromhex(result)]
            assert not state.alt_stack

    @pytest.mark.parametrize("a,b,result", (
        ('0001', 0, '0001'),
        ('0001', 1, '0002'),
        ('0001', 2, '0004'),
        ('0001', 3, '0008'),
        ('0001', 5, '0020'),
        ('0001', 8, '0100'),
        ('0001', 15, '8000'),
        ('0001', 16, '0000'),
        ('0001', 1000, '0000'),
        ('', 0, ''),
        ('', 2, ''),
        ('', 8, ''),
        ('ff', 0, 'ff'),
        ('ff', 1, 'fe'),
        ('ff', 2, 'fc'),
        ('ff', 3, 'f8'),
        ('ff', 4, 'f0'),
        ('ff', 5, 'e0'),
        ('ff', 6, 'c0'),
        ('ff', 7, '80'),
        ('ff', 8, '00'),
        ('0080', 1, '0100'),
        ('008000', 1, '010000'),
        ('000080', 1, '000100'),
        ('800000', 1, '000000'),
        ('9f11f555', 0, '9f11f555'),
        ('9f11f555', 1, '3e23eaaa'),
        ('9f11f555', 2, '7c47d554'),
        ('9f11f555', 3, 'f88faaa8'),
        ('9f11f555', 4, 'f11f5550'),
        ('9f11f555', 5, 'e23eaaa0'),
        ('9f11f555', 6, 'c47d5540'),
        ('9f11f555', 7, '88faaa80'),
        ('9f11f555', 8, '11f55500'),
        ('9f11f555', 9, '23eaaa00'),
        ('9f11f555', 10, '47d55400'),
        ('9f11f555', 11, '8faaa800'),
        ('9f11f555', 12, '1f555000'),
        ('9f11f555', 13, '3eaaa000'),
        ('9f11f555', 14, '7d554000'),
        ('9f11f555', 15, 'faaa8000'),
    ))
    def test_LSHIFT(self, state_old_utxo, a, b, result):
        script = Script() << value_bytes(a) << value_bytes(b) << OP_LSHIFT
        state_old_utxo.evaluate_script(script)
        assert state_old_utxo.stack == [value_bytes(result)]

    @pytest.mark.parametrize("a,b",(
        ('000100', -1),
        ('01000000', -2),
    ))
    def test_LSHIFT_error(self, state_old_utxo, a, b):
        script = Script() << value_bytes(a) << value_bytes(b) << OP_LSHIFT
        with pytest.raises(NegativeShiftCount):
            state_old_utxo.evaluate_script(script)
        assert len(state_old_utxo.stack) == 2

    @pytest.mark.parametrize("a,b,result", (
        ('1000', 0, '1000'),
        ('1000', 1, '0800'),
        ('1000', 2, '0400'),
        ('1000', 3, '0200'),
        ('1000', 5, '0080'),
        ('8000', 8, '0080'),
        ('8000', 15, '0001'),
        ('8000', 16, '0000'),
        ('8000', 100, '0000'),
        ('', 0, ''),
        ('', 2, ''),
        ('', 8, ''),
        ('ff', 0, 'ff'),
        ('ff', 1, '7f'),
        ('ff', 2, '3f'),
        ('ff', 3, '1f'),
        ('ff', 4, '0f'),
        ('ff', 5, '07'),
        ('ff', 6, '03'),
        ('ff', 7, '01'),
        ('ff', 8, '00'),
        ('0100', 1, '0080'),
        ('010000', 1, '008000'),
        ('000100', 1, '000080'),
        ('000001', 1, '000000'),
        ('9f11f555', 0, '9f11f555'),
        ('9f11f555', 1, '4f88faaa'),
        ('9f11f555', 2, '27c47d55'),
        ('9f11f555', 3, '13e23eaa'),
        ('9f11f555', 4, '09f11f55'),
        ('9f11f555', 5, '04f88faa'),
        ('9f11f555', 6, '027c47d5'),
        ('9f11f555', 7, '013e23ea'),
        ('9f11f555', 8, '009f11f5'),
        ('9f11f555', 9, '004f88fa'),
        ('9f11f555', 10, '0027c47d'),
        ('9f11f555', 11, '0013e23e'),
        ('9f11f555', 12, '0009f11f'),
        ('9f11f555', 13, '0004f88f'),
        ('9f11f555', 14, '00027c47'),
        ('9f11f555', 15, '00013e23'),
    ))
    def test_RSHIFT(self, state_old_utxo, a, b, result):
        script = Script() << value_bytes(a) << value_bytes(b) << OP_RSHIFT
        state_old_utxo.evaluate_script(script)
        assert state_old_utxo.stack == [value_bytes(result)]

    @pytest.mark.parametrize("a,b",(
        ('000100', -1),
        ('01000000', -2),
    ))
    def test_RSHIFT_error(self, state_old_utxo, a, b):
        script = Script() << value_bytes(a) << value_bytes(b) << OP_RSHIFT
        with pytest.raises(NegativeShiftCount):
            state_old_utxo.evaluate_script(script)
        assert len(state_old_utxo.stack) == 2

    @pytest.mark.parametrize("x1,x2", (
        ('', ''),
        ('dead', 'dead'),
        ('01', '07'),
        ('01', '0100'),
    ))
    @pytest.mark.parametrize("opcode", (OP_EQUAL, OP_EQUALVERIFY))
    def test_EQUAL(self, state, x1, x2, opcode):
        self.require_stack(state, 2, opcode)
        script = Script() << bytes.fromhex(x1) << bytes.fromhex(x2) << opcode
        truth = x1 == x2
        if opcode == OP_EQUAL:
            state.evaluate_script(script)
            assert state.stack == [b'\1' if truth else b'']
        else:
            if truth:
                state.evaluate_script(script)
                assert not state.stack
            else:
                with pytest.raises(EqualVerifyFailed):
                    state.evaluate_script(script)
                assert len(state.stack) == 1
        assert not state.alt_stack


class TestCrypto(TestEvaluateScriptBase):

    @classmethod
    def setup_class(cls):
        cls.tx = random_tx()

    @pytest.mark.parametrize("hash_op,hash_func", (
        (OP_RIPEMD160, ripemd160),
        (OP_SHA1, sha1),
        (OP_SHA256, sha256),
        (OP_HASH160, hash160),
        (OP_HASH256, double_sha256),
    ))
    def test_hash_op(self, state, hash_op, hash_func):
        self.require_stack(state, 1, hash_op)
        script = Script() << b'foo' << hash_op
        state.evaluate_script(script)
        assert state.stack == [hash_func(b'foo')]
        assert not state.alt_stack

    @pytest.mark.parametrize("script_pubkey, script_code", (
        (Script(), Script()),
        (Script() << OP_CODESEPARATOR, Script()),
        (Script() << OP_0 << OP_CODESEPARATOR << OP_DROP, Script() << OP_DROP),
        (Script() << OP_0 << OP_CODESEPARATOR << OP_1 << OP_CODESEPARATOR << OP_2DROP,
         Script() << OP_2DROP),
        (Script() << OP_0 << OP_IF << OP_CODESEPARATOR << OP_ENDIF,
         Script() << OP_0 << OP_IF << OP_CODESEPARATOR << OP_ENDIF),
        (Script() << OP_1 << OP_IF << OP_CODESEPARATOR << OP_ENDIF, Script() << OP_ENDIF),
    ))
    def test_code_separator(self, policy, script_pubkey, script_code):
        input_index = random.randrange(0, len(self.tx.inputs))
        value = random_value()
        state = InterpreterState(policy, flags=0, is_consensus=False, is_genesis_enabled=True,
                                 is_utxo_after_genesis=True, tx=self.tx, input_index=input_index,
                                 value=value)

        # APPEND OP_CHECKSIGVERIFY to check if the correct script_code has been signed
        script_pubkey <<= OP_CHECKSIGVERIFY
        script_code <<= OP_CHECKSIGVERIFY

        # Create a random private key and sign the transaction
        privkey = PrivateKey.from_random()
        sighash = SigHash(SigHash.ALL)
        message_hash = self.tx.signature_hash(input_index, value, script_code, sighash=sighash)
        sig = privkey.sign(message_hash, hasher=None) + pack_byte(sighash)
        script_sig = Script() << sig << privkey.public_key.to_bytes()

        # This should complete if the correct script is signed
        state.evaluate_script(script_sig)
        state.evaluate_script(script_pubkey)
