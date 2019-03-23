# Copyright (c) 2019, Neil Booth
#
# All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

'''Bitcoin script'''


__all__ = (
    'Ops', 'push_item', 'push_int', 'push_and_drop_item', 'push_and_drop_items', 'item_to_int',
    'Script', 'ScriptError', 'TruncatedScriptError',
)


from enum import IntEnum

from .misc import int_to_le_bytes, le_bytes_to_int
from .packing import (
    pack_byte, pack_le_uint16, pack_le_uint32,
    unpack_le_uint16, unpack_le_uint32,
)


class ScriptError(Exception):
    pass


class TruncatedScriptError(ScriptError):
    pass


class Ops(IntEnum):
    OP_0 = 0x00
    OP_FALSE = OP_0
    OP_PUSHDATA1 = 0x4c
    OP_PUSHDATA2 = 0x4d
    OP_PUSHDATA4 = 0x4e
    OP_1NEGATE = 0x4f
    OP_RESERVED = 0x50
    OP_1 = 0x51
    OP_TRUE = OP_1
    OP_2 = 0x52
    OP_3 = 0x53
    OP_4 = 0x54
    OP_5 = 0x55
    OP_6 = 0x56
    OP_7 = 0x57
    OP_8 = 0x58
    OP_9 = 0x59
    OP_10 = 0x5a
    OP_11 = 0x5b
    OP_12 = 0x5c
    OP_13 = 0x5d
    OP_14 = 0x5e
    OP_15 = 0x5f
    OP_16 = 0x60

    # control
    OP_NOP = 0x61
    OP_VER = 0x62
    OP_IF = 0x63
    OP_NOTIF = 0x64
    OP_VERIF = 0x65
    OP_VERNOTIF = 0x66
    OP_ELSE = 0x67
    OP_ENDIF = 0x68
    OP_VERIFY = 0x69
    OP_RETURN = 0x6a

    # stack ops
    OP_TOALTSTACK = 0x6b
    OP_FROMALTSTACK = 0x6c
    OP_2DROP = 0x6d
    OP_2DUP = 0x6e
    OP_3DUP = 0x6f
    OP_2OVER = 0x70
    OP_2ROT = 0x71
    OP_2SWAP = 0x72
    OP_IFDUP = 0x73
    OP_DEPTH = 0x74
    OP_DROP = 0x75
    OP_DUP = 0x76
    OP_NIP = 0x77
    OP_OVER = 0x78
    OP_PICK = 0x79
    OP_ROLL = 0x7a
    OP_ROT = 0x7b
    OP_SWAP = 0x7c
    OP_TUCK = 0x7d

    # splice ops
    OP_CAT = 0x7e
    OP_SPLIT = 0x7f    # after monolith upgrade (May 2018)
    OP_NUM2BIN = 0x80  # after monolith upgrade (May 2018)
    OP_BIN2NUM = 0x81  # after monolith upgrade (May 2018)
    OP_SIZE = 0x82

    # bit logic
    OP_INVERT = 0x83
    OP_AND = 0x84
    OP_OR = 0x85
    OP_XOR = 0x86
    OP_EQUAL = 0x87
    OP_EQUALVERIFY = 0x88
    OP_RESERVED1 = 0x89
    OP_RESERVED2 = 0x8a

    # numeric
    OP_1ADD = 0x8b
    OP_1SUB = 0x8c
    OP_2MUL = 0x8d
    OP_2DIV = 0x8e
    OP_NEGATE = 0x8f
    OP_ABS = 0x90
    OP_NOT = 0x91
    OP_0NOTEQUAL = 0x92

    OP_ADD = 0x93
    OP_SUB = 0x94
    OP_MUL = 0x95
    OP_DIV = 0x96
    OP_MOD = 0x97
    OP_LSHIFT = 0x98
    OP_RSHIFT = 0x99

    OP_BOOLAND = 0x9a
    OP_BOOLOR = 0x9b
    OP_NUMEQUAL = 0x9c
    OP_NUMEQUALVERIFY = 0x9d
    OP_NUMNOTEQUAL = 0x9e
    OP_LESSTHAN = 0x9f
    OP_GREATERTHAN = 0xa0
    OP_LESSTHANOREQUAL = 0xa1
    OP_GREATERTHANOREQUAL = 0xa2
    OP_MIN = 0xa3
    OP_MAX = 0xa4

    OP_WITHIN = 0xa5

    # crypto
    OP_RIPEMD160 = 0xa6
    OP_SHA1 = 0xa7
    OP_SHA256 = 0xa8
    OP_HASH160 = 0xa9
    OP_HASH256 = 0xaa
    OP_CODESEPARATOR = 0xab
    OP_CHECKSIG = 0xac
    OP_CHECKSIGVERIFY = 0xad
    OP_CHECKMULTISIG = 0xae
    OP_CHECKMULTISIGVERIFY = 0xaf

    # expansion
    OP_NOP1 = 0xb0
    OP_CHECKLOCKTIMEVERIFY = 0xb1
    OP_NOP2 = OP_CHECKLOCKTIMEVERIFY
    OP_CHECKSEQUENCEVERIFY = 0xb2
    OP_NOP3 = OP_CHECKSEQUENCEVERIFY
    OP_NOP4 = 0xb3
    OP_NOP5 = 0xb4
    OP_NOP6 = 0xb5
    OP_NOP7 = 0xb6
    OP_NOP8 = 0xb7
    OP_NOP9 = 0xb8
    OP_NOP10 = 0xb9


globals().update((f'b_{name}', pack_byte(value)) for name, value in Ops.__members__.items())
globals().update(Ops.__members__)
__all__ += tuple(f'b_{name}' for name in Ops.__members__.keys())
__all__ += tuple(Ops.__members__.keys())


b_OP_DUP_OP_HASH160 = bytes([OP_DUP, OP_HASH160])
b_OP_EQUALVERIFY_OP_CHECKSIG = bytes([OP_EQUALVERIFY, OP_CHECKSIG])


def push_item(item):
    '''Returns script bytes to push item on the stack.'''
    dlen = len(item)
    if dlen <= 1:
        # Values 1...16 and 0x81 can be pushed specially as a single opcode.
        if dlen == 0:
            return b_OP_0
        value = item[0]
        if 0 < value <= 16:
            return pack_byte(OP_1 + value - 1)
        if value == 0x81:
            return b_OP_1NEGATE

    if dlen < OP_PUSHDATA1:
        return pack_byte(dlen) + item
    if dlen <= 0xff:
        return pack_byte(OP_PUSHDATA1) + pack_byte(dlen) + item
    if dlen <= 0xffff:
        return pack_byte(OP_PUSHDATA2) + pack_le_uint16(dlen) + item
    return pack_byte(OP_PUSHDATA4) + pack_le_uint32(dlen) + item


def push_and_drop_item(item):
    '''Push one item onto the stack and then pop it off.'''
    return push_item(item) + b_OP_DROP


def push_and_drop_items(items):
    '''Push several items onto the stack and then pop them all off.'''
    parts = [push_item(item) for item in items]
    if len(items) >= 2:
        parts.append(b_OP_2DROP * (len(parts) // 2))
    if len(items) & 1:
        parts.append(b_OP_DROP)
    return b''.join(parts)


def push_int(value):
    '''Returns script bytes to push a numerical value to the stack.  Stack values are stored as
    signed-magnitude little-endian numbers.
    '''
    if value == 0:
        return b_OP_0
    item = int_to_le_bytes(abs(value))
    if item[-1] & 0x80:
        item += pack_byte(0x80 if value < 0 else 0x00)
    elif value < 0:
        item = item[:-1] + pack_byte(item[-1] | 0x80)
    return push_item(item)


def item_to_int(item):
    '''Returns the value of a stack item interpreted as an integer.'''
    if not item:
        return 0
    if item[-1] & 0x80:
        return -le_bytes_to_int(item[:-1] + pack_byte(item[-1] & 0x7f))
    return le_bytes_to_int(item)


class Script(bytes):
    '''Wraps the raw bytes of a bitcoin script.'''

    def ops(self):
        '''A generator.  Yields script operations (does not check their validity) as integers, and
        data pushed on the stack as bytes.  Returns when the end of the script is reached.

        Raises TruncatedScriptError if the script was truncated.
        '''
        n = 0
        limit = len(self)

        while n < limit:
            op = self[n]
            n += 1
            if op > OP_16:
                yield op
            elif op <= OP_PUSHDATA4:
                try:
                    if op < OP_PUSHDATA1:
                        dlen = op
                    elif op == OP_PUSHDATA1:
                        dlen = self[n]
                        n += 1
                    elif op == OP_PUSHDATA2:
                        dlen, = unpack_le_uint16(self[n: n + 2])
                        n += 2
                    else:
                        dlen, = unpack_le_uint32(self[n: n + 4])
                        n += 4
                    data = self[n: n + dlen]
                    n += dlen
                    assert len(data) == dlen
                    yield data
                except Exception:
                    raise TruncatedScriptError from None
            elif op >= OP_1:
                yield pack_byte(op - OP_1 + 1)
            elif op == OP_1NEGATE:
                yield b'\x81'
            else:
                assert op == OP_RESERVED
                yield op

    @classmethod
    def op_to_asm_word(cls, op):
        '''Convert a single opcode, or data push, as returned by ops(), to a human-readable
        word.'''
        if isinstance(op, bytes):
            if len(op) <= 4:
                return str(item_to_int(op))
            # Should we implement bitcoind's sigHashDecode?
            return op.hex()
        try:
            return Ops(op).name
        except ValueError:
            return "OP_INVALIDOPCODE" if op == 0xff else "OP_UNKNOWN"

    def to_asm(self):
        '''Return a script converted to bitcoin's human-readable ASM format.'''
        op_to_asm_word = self.op_to_asm_word
        try:
            return ' '.join(op_to_asm_word(op) for op in self.ops())
        except TruncatedScriptError:
            return '[error]'

    def to_bytes(self):
        '''Return the script as a bytes() object.'''
        return self

    @classmethod
    def asm_word_to_bytes(cls, word):
        '''Convert an ASM word to bytes, either a 1-byte opcode or the data bytes.'''
        if word.startswith('OP_'):
            try:
                opcode = Ops[word]
            except KeyError:
                raise ScriptError(f'unrecognized op code {word}') from None
            return pack_byte(opcode)
        # Handle what looks like a decimal, provided it's in-range
        if word.isdigit() or word[0] == '-' and word[1:].isdigit():
            value = int(word)
            if abs(value) <= 2147483647:
                return push_int(value)
        try:
            return push_item(bytes.fromhex(word))
        except ValueError:
            raise ScriptError(f'invalid pushdata {word}') from None

    @classmethod
    def from_asm(cls, asm):
        '''Convert an ASM string to a script.'''
        asm_word_to_bytes = cls.asm_word_to_bytes
        return cls(b''.join(asm_word_to_bytes(word) for word in asm.split()))

    @classmethod
    def P2PK_script(cls, pubkey_bytes):
        if len(pubkey_bytes) not in (33, 65):
            raise ValueError('invalid pubkey_bytes')
        return cls(push_item(pubkey_bytes) + b_OP_CHECKSIG)

    @classmethod
    def P2PKH_script(cls, hash160_bytes):
        if len(hash160_bytes) != 20:
            raise ValueError('invalid hash160_bytes')
        return cls(b''.join((b_OP_DUP_OP_HASH160, push_item(hash160_bytes),
                             b_OP_EQUALVERIFY_OP_CHECKSIG)))

    @classmethod
    def P2SH_script(cls, hash160_bytes):
        if len(hash160_bytes) != 20:
            raise ValueError('invalid hash160_bytes')
        return cls(b''.join((b_OP_HASH160, push_item(hash160_bytes), b_OP_EQUAL)))
