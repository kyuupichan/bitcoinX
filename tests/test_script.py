import os

import pytest

from bitcoinx.script import *
from bitcoinx import pack_varint


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



@pytest.mark.parametrize("member", Ops.__members__)
def test_byte_exports(member):
    assert globals()[f'b_{member}'] == bytes([globals()[member]])



def test_P2PK_script():
    for n in (33, 65):
        data = os.urandom(n)
        assert P2PK_script(data) == bytes([len(data)]) + data + bytes([OP_CHECKSIG])


def test_P2PK_script_bad():
    data = os.urandom(20)
    with pytest.raises(ValueError):
        P2PK_script(data)


def test_P2PKHK_script():
    data = os.urandom(20)
    assert P2PKH_script(data) == (bytes([OP_DUP, OP_HASH160, len(data)]) + data +
                                  bytes([OP_EQUALVERIFY, OP_CHECKSIG]))


def test_P2PKH_script_bad():
    data = os.urandom(33)
    with pytest.raises(ValueError):
        P2PKH_script(data)


def test_P2SH_script():
    data = os.urandom(20)
    assert P2SH_script(data) == (bytes([OP_HASH160, len(data)]) + data +
                                 bytes([OP_EQUAL]))


def test_P2SH_script_bad():
    data = os.urandom(33)
    with pytest.raises(ValueError):
        P2SH_script(data)


@pytest.mark.parametrize("item,answer", (
    (b'', b_OP_0),
    (b'\x00', bytes([1, 0])),
    (b'\x01', b_OP_1),
    (b'\x02', b_OP_2),
    (b'\x03', b_OP_3),
    (b'\x04', b_OP_4),
    (b'\x05', b_OP_5),
    (b'\x06', b_OP_6),
    (b'\x07', b_OP_7),
    (b'\x08', b_OP_8),
    (b'\x09', b_OP_9),
    (b'\x0a', b_OP_10),
    (b'\x0b', b_OP_11),
    (b'\x0c', b_OP_12),
    (b'\x0d', b_OP_13),
    (b'\x0e', b_OP_14),
    (b'\x0f', b_OP_15),
    (b'\x10', b_OP_16),
    (b'\x11', bytes([1, 0x11])),
    (b'\x80', bytes([1, 0x80])),
    (b'\x81', b_OP_1NEGATE),
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
    ([b''], b_OP_0 + b_OP_DROP),
    ([b'', b''], b_OP_0 * 2 + b_OP_2DROP),
    ([b'', b'\x04', b''], b_OP_0 + b_OP_4 + b_OP_0 + b_OP_2DROP + b_OP_DROP),
), ids=parameter_id)
def test_push_and_drop_items(items, answer):
    assert push_and_drop_items(items) == answer


@pytest.mark.parametrize("value,encoding", (
    (-1, b_OP_1NEGATE),
    (-2, bytes([1, 0x82])),
    (-127, bytes([1, 0xff])),
    (-128, bytes([2, 128, 0x80])),
    (0, b_OP_0),
    (1, b_OP_1),
    (2, b_OP_2),
    (15, b_OP_15),
    (16, b_OP_16),
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
    assert list(script_ops(script)) == ops


@pytest.mark.parametrize("script", (
    push_item(bytes(2))[:-1],
    push_item(bytes(76))[:-1],
    push_item(bytes(80))[:-1],
    push_item(bytes(256))[:-1],
    push_item(bytes(65536))[:-1],
), ids=parameter_id)
def test_script_ops_truncated(script):
    with pytest.raises(TruncatedScriptError):
        list(script_ops(script))


@pytest.mark.parametrize("script", (
    1,
    'hello',
    [b''],
), ids=parameter_id)
def test_script_ops_type_error(script):
    with pytest.raises(TypeError):
        list(script_ops(script))
