# Copyright (c) 2018-2021, Neil Booth
#
# All rights reserved.
#
# Licensed under the the Open BSV License version 3; see LICENCE for details.
#

'''Bitcoin script'''


__all__ = (
    'Ops', 'Script', 'ScriptError', 'TruncatedScriptError',
    'push_item', 'push_int', 'push_and_drop_item', 'push_and_drop_items',
    'item_to_int', 'int_to_item', 'is_item_minimally_encoded', 'minimal_push_opcode',
    'classify_output_script', 'cast_to_bool',
)

import re
from enum import IntEnum
from functools import partial

from .consts import JSONFlags
from .errors import ScriptError, TruncatedScriptError, ImpossibleEncoding, InvalidSignature
from .misc import int_to_le_bytes, le_bytes_to_int
from .packing import (
    pack_byte, pack_le_uint16, pack_le_uint32, unpack_le_uint16, unpack_le_uint32,
)
from .signature import Signature


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

    # bit string ops
    OP_CAT = 0x7e
    OP_SPLIT = 0x7f
    OP_NUM2BIN = 0x80
    OP_BIN2NUM = 0x81
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


# pylint:disable=E0602,E1101

globals().update(Ops.__members__)
__all__ += tuple(Ops.__members__.keys())

b_OP_0 = pack_byte(Ops.OP_0)
b_OP_DROP = pack_byte(Ops.OP_DROP)
b_OP_2DROP = pack_byte(Ops.OP_2DROP)
b_OP_1NEGATE = pack_byte(Ops.OP_1NEGATE)
bool_items = [b'', b'\1']


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


def int_to_item(value, size=None):
    '''Returns an encoded stack item of an integer.  If size is None this is minimally
    encoded, othewise it is fit to that many bytes, raising ImpossibleEncoding if it
    cannot be done.
    '''
    try:
        encoding = int_to_le_bytes(abs(int(value)), size)
    except OverflowError:
        pass
    else:
        if value == 0:
            return encoding
        if value > 0:
            if encoding[-1] < 0x80:
                return encoding
            if size is None:
                return encoding + b'\0'
        else:
            if encoding[-1] < 0x80:
                return encoding[:-1] + pack_byte(encoding[-1] | 0x80)
            if size is None:
                return encoding + b'\x80'

    raise ImpossibleEncoding(f'value cannot be encoded in {size:,d} bytes')


def minimal_encoding(item):
    '''Return the minimal encoding of the number represented by item.'''
    return int_to_item(item_to_int(item))


def is_item_minimally_encoded(item):
    '''Return True if item is a minimally-encoded number.'''
    return minimal_encoding(item) == item


def minimal_push_opcode(item):
    '''Returns script bytes to push item on the stack.  Returns an int.'''
    dlen = len(item)
    if dlen <= 1:
        # Values 1...16 and 0x81 can be pushed specially as a single opcode.
        if dlen == 0:
            return OP_0
        value = item[0]
        if 0 < value <= 16:
            return OP_1 + value - 1
        if value == 0x81:
            return OP_1NEGATE

    if dlen < OP_PUSHDATA1:
        return dlen
    if dlen <= 0xff:
        return OP_PUSHDATA1
    if dlen <= 0xffff:
        return OP_PUSHDATA2
    if dlen <= 0xffffffff:
        return OP_PUSHDATA4
    raise ValueError('item is too large')


def cast_to_bool(item):
    '''Cast an item to a Python boolean True or False.

    Because the item is not converted to an integer, no restriction is placed on its size.
    '''
    if not item:
        return False
    # Take care of negative zeroes
    return item[-1] not in {0, 0x80} or any(item[n] for n in range(0, len(item) - 1))


def _to_bytes(item):
    '''Convert something (an OP_, an integer, or raw data) to a scriptlet.'''
    if isinstance(item, Ops):
        return pack_byte(item)
    if isinstance(item, (bytes, bytearray)):
        return push_item(item)
    if isinstance(item, int):
        return push_int(item)
    if isinstance(item, Script):
        return bytes(item)
    raise TypeError(f"cannot convert append {item} to a scriptlet")


def _classify_script(script, templates, unknown_class):
    our_template, items = script.to_template()

    for template, constructor in templates:
        if isinstance(template, bytes):
            if template != our_template:
                continue
        else:
            match = template.match(our_template)
            if not match:
                continue

        try:
            return constructor(*items)
        except (ValueError, TypeError):
            pass

    return unknown_class()


def _network_output_script_templates(network):
    from .address import (P2PKH_Address, P2SH_Address, P2PK_Output, OP_RETURN_Output,
                          P2MultiSig_Output)

    # Addresses have Network-specific constructors
    return (
        (bytes((Ops.OP_DUP, Ops.OP_HASH160, Ops.OP_PUSHDATA1, Ops.OP_EQUALVERIFY,
                Ops.OP_CHECKSIG)), partial(P2PKH_Address, network=network)),
        (bytes((Ops.OP_HASH160, Ops.OP_PUSHDATA1, Ops.OP_EQUAL)),
         partial(P2SH_Address, network=network)),
        (bytes((Ops.OP_PUSHDATA1, Ops.OP_CHECKSIG)), partial(P2PK_Output, network=network)),
        # Note this loses script ops other than pushdata
        (re.compile(pack_byte(Ops.OP_PUSHDATA1) + b'*' + pack_byte(Ops.OP_RETURN)),
         OP_RETURN_Output.from_template),
        (re.compile(pack_byte(Ops.OP_PUSHDATA1) + b'{3,}' + pack_byte(Ops.OP_CHECKMULTISIG)
                    + b'$'), P2MultiSig_Output.from_template),
    )


def classify_output_script(script, network):
    from .address import Unknown_Output

    templates = network.output_script_templates
    if templates is None:
        templates = network.output_script_templates = _network_output_script_templates(network)
    return _classify_script(script, templates, Unknown_Output)


class ScriptIterator:

    def __init__(self, script):
        self._raw = bytes(script)
        self._n = 0
        self._cs = 0

    def position(self):
        return self._n

    def script_code(self):
        '''Return the subscript that should be checked by OP_CHECKSIG et al.'''
        return Script(self._raw[self._cs:])

    def on_code_separator(self):
        '''Call when an OP_CODESEPARATOR is executed.'''
        self._cs = self._n

    def ops_and_items(self):
        '''A generator.  Iterates over the script yielding (op, item) pairs, stopping when the end
        of the script is reached.

        op is an integer as it might not be a member of Ops.  Data is the data pushed as
        bytes, or None if the op does not push data.

        Raises TruncatedScriptError if the script was truncated.
        '''
        raw = self._raw
        limit = len(raw)
        n = self._n

        while n < limit:
            op = raw[n]
            n += 1
            data = None

            if op <= OP_16:
                if op <= OP_PUSHDATA4:
                    try:
                        if op < OP_PUSHDATA1:
                            dlen = op
                        elif op == OP_PUSHDATA1:
                            dlen = raw[n]
                            n += 1
                        elif op == OP_PUSHDATA2:
                            dlen, = unpack_le_uint16(raw[n: n + 2])
                            n += 2
                        else:
                            dlen, = unpack_le_uint32(raw[n: n + 4])
                            n += 4
                        data = raw[n: n + dlen]
                        n += dlen
                        assert len(data) == dlen
                    except Exception:
                        raise TruncatedScriptError from None
                elif op >= OP_1:
                    data = pack_byte(op - OP_1 + 1)
                elif op == OP_1NEGATE:
                    data = b'\x81'
                else:
                    assert op == OP_RESERVED

            self._n = n
            yield op, data


class Script:
    '''Wraps the raw bytes of a bitcoin script.'''

    def __init__(self, script=b''):
        self._script = bytes(script)

    def __lshift__(self, item):
        '''Return a new script with other appended.

        Item can be bytes or an integer (which are pushed on the stack), an opcode
        such as OP_CHECKSIG, or another Script.
        '''
        return Script(self._script + _to_bytes(item))

    def push_many(self, items):
        '''Return a new script with items, an iterable, appended.

        More efficient than << with 3 items or more, about same with 2.
        '''
        return Script(self._script + b''.join(_to_bytes(item) for item in items))

    def __len__(self):
        '''The length of the script, in bytes.'''
        return len(self._script)

    def __bytes__(self):
        '''The script as bytes.'''
        return self._script

    def __str__(self):
        '''A user-readable script.'''
        return self.to_hex()

    def __repr__(self):
        '''A user-readable script.'''
        return f'Script<"{self.to_hex()}">'

    def __hash__(self):
        '''Hashable.'''
        return hash(self._script)

    def __eq__(self, other):
        '''A script equals anything buffer-like with the same bytes representation.'''
        return (isinstance(other, (bytes, bytearray, memoryview))
                or hasattr(other, '__bytes__')) and self._script == bytes(other)

    def ops_and_items(self):
        '''A generator.  Iterates over the script yielding (op, item) pairs, stopping when the end
        of the script is reached.

        op is an integer as it might not be a member of Ops.  Data is the data pushed as
        bytes, or None if the op does not push data.

        Raises TruncatedScriptError if the script was truncated.
        '''
        return ScriptIterator(self._script).ops_and_items()

    def ops(self):
        '''A generator.  Iterates over the script yielding ops, stopping when the end
        of the script is reached.

        For push-data opcodes op is the bytes pushed; otherwise it is the op as an integer.

        Raises TruncatedScriptError if the script was truncated.
        '''
        for op, data in self.ops_and_items():
            yield data if data is not None else op

    def is_push_only(self):
        '''Return True if the entire script only pushes data onto the stack.

        Note OP_RESERVED is considered an opcode that pushes data on the stack, and that a
        truncated script returns False.
        '''
        try:
            return all(op <= OP_16 for op, data in self.ops_and_items())
        except TruncatedScriptError:
            return False

    def is_P2SH(self):
        '''Fast test for P2SH scripts.'''
        script = self._script
        return (len(script) == 23 and script[0] == OP_HASH160 and script[1] == 0x14
                and script[22] == OP_EQUAL)

    def find_and_delete(self, subscript):
        '''Return a new script that has all instances of subscript removed.

        Note this function does not behave identically to FindAndDelete in the node code,
        but that is not problematic as it does behave identically in all ways it is
        actually used, i.e., when subscript to delete is not a truncated script.
        '''
        def undeleted_parts(raw, other):
            start = 0
            raw = memoryview(raw)
            if other:
                last = 0
                iterator = ScriptIterator(raw)
                try:
                    for _ignore in iterator.ops_and_items():
                        if raw[last: last + len(other)] == other and last >= start:
                            yield raw[start: last]
                            start = last + len(other)
                        last = iterator.position()
                except TruncatedScriptError:
                    pass
            yield raw[start:]

        assert isinstance(subscript, Script)
        return Script(b''.join(undeleted_parts(self._script, subscript._script)))

    @classmethod
    def op_to_asm_word(cls, op, decode_sighash):
        '''Convert a single opcode, or data push, as returned by ops(), to a human-readable word.
        The logic mirrors that of ScriptToAsmStr in bitcoin-sv/src/core_write.cpp.

        If decode_sighash is true, pushdata that look like a signature are suffixed with
        the appropriate SIGHASH flags.
        '''
        if isinstance(op, bytes):
            # Data items of up to four bytes are output as decimal.  This also handles
            # O_1NEGATE, OP_0 ... OP_16 the same as bitcoind's GetOpName.
            if len(op) <= 4:
                return str(item_to_int(op))

            # Print signatures as strings showing the sighash text.
            if decode_sighash and op[0] == 0x30:
                try:
                    return Signature.to_string(op)
                except InvalidSignature:
                    pass

            # All other data is output as hex.  Unfortunately this is ambiguous...
            return op.hex()
        try:
            return Ops(op).name
        except ValueError:
            return "OP_INVALIDOPCODE" if op == 0xff else "OP_UNKNOWN"

    def _asm_words(self, decode_sighash, truncated_word):
        '''A generator yielding ASM words; truncated scripts terminate with truncated_word.'''
        op_to_asm_word = self.op_to_asm_word
        try:
            for op in self.ops():
                yield op_to_asm_word(op, decode_sighash)
        except TruncatedScriptError:
            yield truncated_word

    def to_asm(self, decode_sighash, truncated_word='[script error]'):
        '''Return a script converted to bitcoin's human-readable ASM format.

        If decode_sighash is true, pushdata that look like a signature are suffixed with
        the appropriate SIGHASH flags.
        '''
        return ' '.join(self._asm_words(decode_sighash, truncated_word))

    def to_bytes(self):
        '''Return the script as a bytes() object.'''
        return self._script

    def to_json(self, flags, is_script_sig, network):
        '''Return the script as an (unconverted) json object; flags controls the output and is a
        JSONFlags instance.  Network is used when displaying addresses.'''
        result = {
            'asm': self.to_asm(decode_sighash=is_script_sig),
            'hex': self.to_hex(),
        }
        if not is_script_sig and flags & JSONFlags.CLASSIFY_OUTPUT_SCRIPT:
            from .address import P2PKH_Address, P2PK_Output

            output = classify_output_script(self, network)
            result['type'] = output.KIND
            if isinstance(output, P2PKH_Address):
                result['address'] = output.to_string()
            elif isinstance(output, P2PK_Output):
                result['pubkey'] = output.public_key.to_hex()
                result['address'] = output.to_address().to_string()
        return result

    @classmethod
    def from_hex(cls, hex_str):
        '''Convert a hexadecimal string (without whitespace) into raw script.

        Raises ValueError in the string cannot be converted.
        '''
        raw = bytes.fromhex(hex_str)
        # Test to ensure it does not contain whitespace.  We want whitespace to separate
        # asm words for Script.from_text() do not permit it in hex.
        if raw.hex() != hex_str:
            raise ValueError('hex_str is not pure hexadecimal')
        return cls(raw)

    def to_hex(self):
        '''Return the script as a hexadecimal string.'''
        return self._script.hex()

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
        '''Convert an ASM string to a script.

        Raises ScriptError if the text cannot be understood.
        '''
        asm_word_to_bytes = cls.asm_word_to_bytes
        return cls(b''.join(asm_word_to_bytes(word) for word in asm.split()))

    @classmethod
    def from_text(cls, text):
        '''Convert text to Bitcoin script.  First try Script.from_hex() and if that
        fails try Script.from_asm().

        Raises ScriptError if the text cannot be understood.
        '''
        try:
            return cls.from_hex(text)
        except ValueError:
            pass
        return cls.from_asm(text)

    def _stripped_ops(self):

        '''As for ops() except the result is a list, and operations that do not affect
        evaluation of the script are dropped.

        Data pushes that are deterministically dropped are not retained.
        If the script is truncated an OP_0 opcode is appended.
        '''
        result = []

        try:
            for op in self.ops():
                if op in {OP_NOP, OP_DROP, OP_2DROP}:
                    # Strip OP_NOP
                    if op == OP_NOP:
                        continue

                    # Remove (data, OP_DROP)
                    if op == OP_DROP and result and isinstance(result[-1], bytes):
                        result.pop()
                        continue

                    # Remove (data, data, OP_2DROP)
                    if (op == OP_2DROP and len(result) >= 2 and
                            isinstance(result[-1], bytes) and isinstance(result[-2], bytes)):
                        result.pop()
                        result.pop()
                        continue

                result.append(op)
        except TruncatedScriptError:
            result.append(OP_0)

        return result

    def to_template(self):
        '''Return a pair (template, items).

        template: a byte string indicating the pertinent script operations.
                  Useful for rapid pattern matching.
        items:    items pushed on the stack as part of the template.

        If the script is truncated an OP_0 opcode is appended (with no data item).
        '''
        stripped_ops = self._stripped_ops()

        template = bytes(OP_PUSHDATA1 if isinstance(op, bytes) else op for op in stripped_ops)
        items = [op for op in stripped_ops if isinstance(op, bytes)]
        return template, items
