# Copyright (c) 2018-2021, Neil Booth
#
# All rights reserved.
#
# Licensed under the the Open BSV License version 3; see LICENCE for details.
#

'''Bitcoin script'''


__all__ = (
    'Ops', 'Script', 'ScriptError', 'TruncatedScriptError', 'InterpreterError',
    'InterpreterPolicy', 'InterpreterState', 'InterpreterFlags',
    'cast_to_bool', 'push_item', 'push_int', 'push_and_drop_item', 'push_and_drop_items',
    'item_to_int', 'int_to_item', 'is_item_minimally_encoded', 'minimal_push_opcode',
    'classify_output_script', 'evaluate_script'
)

import operator
import re
from enum import IntEnum
from functools import partial

import attr

from .consts import (
    JSONFlags, LOCKTIME_THRESHOLD, SEQUENCE_FINAL, SEQUENCE_LOCKTIME_DISABLE_FLAG,
    SEQUENCE_LOCKTIME_MASK, SEQUENCE_LOCKTIME_TYPE_FLAG,
)
from .errors import (
    ScriptError, TruncatedScriptError, InterpreterError,
    StackSizeTooLarge, MinimalEncodingError, InvalidPublicKeyEncoding,
    ScriptTooLarge, TooManyOps, MinimalIfError, DivisionByZero, NegativeShiftCount,
    InvalidPushSize, DisabledOpcode, UnbalancedConditional, InvalidStackOperation,
    VerifyFailed, OpReturnError, InvalidOpcode, InvalidSplit, ImpossibleEncoding,
    InvalidNumber, InvalidOperandSize, EqualVerifyFailed, InvalidSignature, NullFailError,
    InvalidPublicKeyCount, NullDummyError, UpgradeableNopError, LockTimeError
)
from .hashes import ripemd160, hash160, sha1, sha256, double_sha256
from .misc import int_to_le_bytes, le_bytes_to_int
from .packing import (
    pack_byte, pack_le_uint16, pack_le_uint32, unpack_le_uint16, unpack_le_uint32,
)
from .signature import Signature, SigHash
from .util import cachedproperty


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


# pylint:disable=E0602

globals().update((f'b_{name}', pack_byte(value)) for name, value in Ops.__members__.items())
globals().update(Ops.__members__)
__all__ += tuple(Ops.__members__.keys())
__all__ += tuple(f'b_{name}' for name in Ops.__members__.keys())


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


def _coin_output_script_templates(coin):
    from .address import (P2PKH_Address, P2SH_Address, P2PK_Output, OP_RETURN_Output,
                          P2MultiSig_Output)

    # Addresses have Coin-specific constructors
    return (
        (bytes((Ops.OP_DUP, Ops.OP_HASH160, Ops.OP_PUSHDATA1, Ops.OP_EQUALVERIFY,
                Ops.OP_CHECKSIG)), partial(P2PKH_Address, coin=coin)),
        (bytes((Ops.OP_HASH160, Ops.OP_PUSHDATA1, Ops.OP_EQUAL)),
         partial(P2SH_Address, coin=coin)),
        (bytes((Ops.OP_PUSHDATA1, Ops.OP_CHECKSIG)), partial(P2PK_Output, coin=coin)),
        # Note this loses script ops other than pushdata
        (re.compile(pack_byte(Ops.OP_PUSHDATA1) + b'*' + pack_byte(Ops.OP_RETURN)),
         OP_RETURN_Output.from_template),
        (re.compile(pack_byte(Ops.OP_PUSHDATA1) + b'{3,}' + pack_byte(Ops.OP_CHECKMULTISIG)
                    + b'$'), P2MultiSig_Output.from_template),
    )


def classify_output_script(script, coin):
    from .address import Unknown_Output

    templates = coin.output_script_templates
    if templates is None:
        templates = coin.output_script_templates = _coin_output_script_templates(coin)
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
        '''Convert a single opcode, or data push, as returned by ops(), to a human-readable
        word.

        If decode_sighash is true, pushdata that look like a signature are suffixed with
        the appropriate SIGHASH flags.
        '''
        if isinstance(op, bytes):
            if len(op) <= 4:
                return str(item_to_int(op))
            # Print signatures as strings showing the sighash text.  Without sighash byte
            # normalized DER-encoded signatures are between 8 and 72 bytes
            if decode_sighash and op[0] == 0x30 and 9 <= len(op) <= 73:
                try:
                    return Signature(op).to_string()
                except InvalidSignature:
                    pass
            return op.hex()
        try:
            return Ops(op).name
        except ValueError:
            return "OP_INVALIDOPCODE" if op == 0xff else "OP_UNKNOWN"

    def to_asm(self, decode_sighash):
        '''Return a script converted to bitcoin's human-readable ASM format.

        If decode_sighash is true, pushdata that look like a signature are suffixed with
        the appropriate SIGHASH flags.
        '''
        op_to_asm_word = self.op_to_asm_word
        try:
            return ' '.join(op_to_asm_word(op, decode_sighash) for op in self.ops())
        except TruncatedScriptError:
            return '[error]'

    def to_bytes(self):
        '''Return the script as a bytes() object.'''
        return self._script

    def to_json(self, flags, is_script_sig, coin):
        '''Return the script as an (unconverted) json object; flags controls the output and is a
        JSONFlags instance.  Coin is used when displaying addresses.'''
        result = {
            'asm': self.to_asm(decode_sighash=is_script_sig),
            'hex': self.to_hex(),
        }
        if not is_script_sig and flags & JSONFlags.CLASSIFY_OUTPUT_SCRIPT:
            from .address import P2PKH_Address, P2PK_Output

            output = classify_output_script(self, coin)
            result['type'] = output.KIND
            if isinstance(output, P2PKH_Address):
                result['address'] = output.to_string()
            elif isinstance(output, P2PK_Output):
                result['pubkey'] = output.public_key.to_hex()
                result['address'] = output.to_address().to_string()
        return result

    @classmethod
    def from_hex(cls, hex_str):
        '''Instantiate from a hexadecimal string.'''
        return cls(bytes.fromhex(hex_str))

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
        '''Convert an ASM string to a script.'''
        asm_word_to_bytes = cls.asm_word_to_bytes
        return cls(b''.join(asm_word_to_bytes(word) for word in asm.split()))

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


UINT32_MAX = 0xffffffff
INT32_MAX = 0x7fffffff
bool_items = [b'', b'\1']


@attr.s(slots=True)
class Condition:
    '''Represents an open condition block whilst executing.'''
    opcode = attr.ib()       # OP_IF or OP_NOTIF
    execute = attr.ib()      # True or False; flips on OP_ELSE
    seen_else = attr.ib()    # True or False


class InterpreterPolicy:
    '''Policy rules fixed over the node session.'''

    def __init__(self, max_script_size, max_script_num_length, max_ops_per_script,
                 max_pubkeys_per_multisig):
        self.max_script_size = max_script_size
        self.max_script_num_length = max_script_num_length
        self.max_ops_per_script = max_ops_per_script
        self.max_pubkeys_per_multisig = max_pubkeys_per_multisig


class InterpreterFlags(IntEnum):
    # Require most compact opcode for pushing stack data, and require minimal-encoding of numbers
    REQUIRE_MINIMAL_PUSH = 1 << 0
    # Top of stack on OP_IF and OP_ENDIF must be boolean.
    REQUIRE_MINIMAL_IF = 1 << 1
    # Enforces strict DER signature encoding
    REQUIRE_STRICT_DER = 1 << 2
    # Enforces low-S signatures
    REQUIRE_LOW_S = 1 << 3
    # Enforces SigHash checks and public key encoding checks
    REQUIRE_STRICT_ENCODING = 1 << 4
    # Set if FORKID is enabled (post BTC/BCH fork)
    FORKID_ENABLED = 1 << 5
    # Fails script immediately if a failed signature was not null
    REQUIRE_NULLFAIL = 1 << 6
    # Fails script if the CHECKMULTISIG dummy argument is not null
    REQUIRE_NULLDUMMY = 1 << 7
    # Fails script if an upgradeable NOP is encountered
    REJECT_UPGRADEABLE_NOPS = 1 << 8
    # If set OP_CHECKLOCKTIMEVERIFY is permitted
    CHECKLOCKTIMEVERIFY = 1 << 9
    # If set OP_CHECKSEQUENCEVERIFY is permitted
    CHECKSEQUENCEVERIFY = 1 << 10


class InterpreterState:
    '''Things that vary per evaluation, typically because they're a function of the
    transaction input.'''

    MAX_SCRIPT_SIZE_BEFORE_GENESIS = 10_000
    MAX_SCRIPT_SIZE_AFTER_GENESIS = UINT32_MAX    # limited by P2P message size
    MAX_SCRIPT_NUM_LENGTH_BEFORE_GENESIS = 4
    MAX_SCRIPT_NUM_LENGTH_AFTER_GENESIS = 750_000
    MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS = 520
    MAX_STACK_ELEMENTS_BEFORE_GENESIS = 1_000
    MAX_OPS_PER_SCRIPT_BEFORE_GENESIS = 500
    MAX_OPS_PER_SCRIPT_AFTER_GENESIS = UINT32_MAX
    MAX_PUBKEYS_PER_MULTISIG_BEFORE_GENESIS = 20
    MAX_PUBKEYS_PER_MULTISIG_AFTER_GENESIS = UINT32_MAX

    def __init__(self, policy, *, flags=0, is_consensus=False, is_genesis_enabled=True,
                 is_utxo_after_genesis=True, tx=None, input_index=-1, value=-1):
        # These inputs must not be changed after construction because of caching
        self.policy = policy
        self.flags = flags
        self.is_consensus = is_consensus
        self.is_genesis_enabled = is_genesis_enabled
        self.is_utxo_after_genesis = is_utxo_after_genesis
        self.tx = tx
        self.input_index = input_index
        self.value = value
        self.reset()

    def reset(self):
        # These are updated by the interpreter whilst running
        self.stack = []
        self.alt_stack = []
        self.conditions = []
        self.execute = False
        self.iterator = None
        self.finished = False
        self.op_count = 0
        self.non_top_level_return_after_genesis = False

    def bump_op_count(self, bump):
        self.op_count += bump
        if self.op_count > self.max_ops_per_script:
            raise TooManyOps(f'op count exceeds the limit of {self.max_ops_per_script:,d}')

    def require_stack_depth(self, depth):
        if len(self.stack) < depth:
            raise InvalidStackOperation(f'stack depth {len(self.stack)} less than required '
                                        f'depth of {depth}')

    def require_alt_stack(self):
        if not self.alt_stack:
            raise InvalidStackOperation('alt stack is empty')

    def validate_minimal_push_opcode(self, op, item):
        if self.flags & InterpreterFlags.REQUIRE_MINIMAL_PUSH:
            expected_op = minimal_push_opcode(item)
            if op != expected_op:
                raise MinimalEncodingError(f'item not pushed with minimal opcode {expected_op}')

    def stack_size(self):
        return len(self.stack) + len(self.alt_stack)

    def validate_item_size(self, size):
        # No limit for post-genesis UTXOs.
        if not self.is_utxo_after_genesis:
            limit = self.MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS
            if size > limit:
                raise InvalidPushSize(f'item length {size:,d} exceeds the limit '
                                      f'of {limit:,d} bytes')

    def validate_stack_size(self):
        if self.is_utxo_after_genesis:
            return
        stack_size = self.stack_size()
        limit = self.MAX_STACK_ELEMENTS_BEFORE_GENESIS
        if stack_size > limit:
            raise StackSizeTooLarge(f'stack size exceeds the limit of {limit:,d} items')

    def validate_number_length(self, size, *, limit=None):
        if limit is None:
            limit = self.max_script_num_length
        if size > limit:
            raise InvalidNumber(f'number of length {size:,d} exceeds the limit '
                                f'of {limit:,d} bytes')

    def to_number(self, item, *, length_limit=None):
        # FIXME: size_t limiting in some cases
        self.validate_number_length(len(item), limit=length_limit)

        if (self.flags & InterpreterFlags.REQUIRE_MINIMAL_PUSH
                and not is_item_minimally_encoded(item)):
            raise MinimalEncodingError(f'number is not minimally encoded: {item.hex()}')

        return item_to_int(item)

    def validate_pubkey_count(self, count):
        limit = self.max_pubkeys_per_multisig
        if not 0 <= count <= limit:
            raise InvalidPublicKeyCount(f'number of public keys, {count:,d}, in OP_CHECKMULTISIG '
                                        f'lies outside range 0 <= count <= {limit:d}')

    def validate_signature(self, sig_bytes):
        '''Raise the InvalidSignature exception if the signature does not meet the requirements of
        self.flags.
        '''
        if not sig_bytes:
            return

        if (self.flags & (InterpreterFlags.REQUIRE_STRICT_DER | InterpreterFlags.REQUIRE_LOW_S
                          | InterpreterFlags.REQUIRE_STRICT_ENCODING)
                and not Signature.is_strict_der_encoding(sig_bytes)):
            raise InvalidSignature('signature does not follow strict DER encoding')

        if self.flags & InterpreterFlags.REQUIRE_LOW_S and not Signature.is_low_S(sig_bytes):
            raise InvalidSignature('signature has high S value')

        if self.flags & InterpreterFlags.REQUIRE_STRICT_ENCODING:
            sighash = SigHash(sig_bytes[-1])
            if not sighash.is_defined():
                raise InvalidSignature('undefined sighash type')
            if sighash.has_forkid() and not (self.flags & InterpreterFlags.FORKID_ENABLED):
                raise InvalidSignature('sighash must not use FORKID')
            if not sighash.has_forkid() and (self.flags & InterpreterFlags.FORKID_ENABLED):
                raise InvalidSignature('sighash must use FORKID')

    def validate_pubkey(self, pubkey_bytes):
        '''Raise the InvalidPublicKeyEncoding exception if the public key is not a standard
        compressed or uncompressed encoding and REQUIRE_STRICT_ENCODING is flagged.'''
        if self.flags & InterpreterFlags.REQUIRE_STRICT_ENCODING:
            length = len(pubkey_bytes)
            if length == 33 and pubkey_bytes[0] in {2, 3}:
                return
            if length == 65 and pubkey_bytes[0] == 4:
                return
            raise InvalidPublicKeyEncoding('invalid public key encoding')

    def validate_nullfail(self, sig_bytes):
        '''Fail immediately if a failed signature was not null.'''
        if self.flags & InterpreterFlags.REQUIRE_NULLFAIL and sig_bytes:
            raise NullFailError('signature check failed on a non-null signature')

    def validate_nulldummy(self):
        '''Fail if the multisig duumy pop isn't an empty stack item.'''
        if self.flags & InterpreterFlags.REQUIRE_NULLDUMMY and self.stack[-1]:
            raise NullDummyError('multisig dummy argument was not null')

    def cleanup_script_code(self, sig_bytes, script_code):
        '''Return script_code with signatures deleted if pre-BCH fork.'''
        sighash = SigHash(sig_bytes[-1])
        if self.flags & InterpreterFlags.FORKID_ENABLED or sighash.has_forkid():
            return script_code
        else:
            return script_code.find_and_delete(Script() << sig_bytes)

    def check_sig(self, pubkey_bytes, sig_bytes, script_code):
        '''Check a signature.  Returns True or False.'''
        if not sig_bytes or not self.tx:
            return False
        try:
            pubkey = PublicKey(pubkey_bytes)
        except ValueError:
            return False

        # Split out the DER signature and the sighash
        der_sig, sighash = Signature.normalize_der_signature(sig_bytes)
        message_hash = self.tx.signature_hash(self.input_index, self.value,
                                              script_code, sighash=sighash)
        return pubkey.verify_der_signature(der_sig, message_hash, hasher=None)

    def validate_locktime(self, locktime):
        # Are the lock times comparable?
        if (locktime < LOCKTIME_THRESHOLD) ^ (self.tx.locktime < LOCKTIME_THRESHOLD):
            raise LockTimeError('locktimes are not comparable')
        # Numeric comparison
        if locktime > self.tx.locktime:
            raise LockTimeError(f'locktime {locktime:,d} not reached')
        if self.tx.inputs[input_index].sequence == SEQUENCE_FINAL:
            raise LockTimeError('transaction input is final')

    def validate_sequence(self, sequence):
        # If this flag is set it behaves as a NOP
        if sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG:
            return
        # Is BIP68 triggered?
        if 0 <= self.tx.version < 2:
            raise LockTimeError('transaction version is under 2')
        txin_seq = self.tx.inputs[self.input_index].sequence
        if txin_seq & SEQUENCE_LOCKTIME_DISABLE_FLAG:
            raise LockTimeError('transaction index sequence is disabled')
        mask = SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK
        sequence &= mask
        txin_seq &= mask
        if (sequence < SEQUENCE_LOCKTIME_TYPE_FLAG) ^ (txin_seq < SEQUENCE_LOCKTIME_TYPE_FLAG):
            raise LockTimeError('sequences are not comparable')
        if sequence > txin_seq:
            raise LockTimeError(f'masked sequence number {sequence} not reached')

    def handle_upgradeable_nop(self, op):
        '''Raise on upgradeable nops if the flag is set.'''
        if self.flags & InterpreterFlags.REJECT_UPGRADEABLE_NOPS:
            raise UpgradeableNopError(f'encountered upgradeable NOP {op.name}')

    @cachedproperty
    def max_ops_per_script(self):
        if self.is_genesis_enabled:
            if self.is_consensus:
                return self.MAX_OPS_PER_SCRIPT_AFTER_GENESIS
            return self.policy.max_ops_per_script
        return self.MAX_OPS_PER_SCRIPT_BEFORE_GENESIS

    @cachedproperty
    def max_script_size(self):
        if self.is_genesis_enabled:
            if self.is_consensus:
                return self.MAX_SCRIPT_SIZE_AFTER_GENESIS
            return self.policy.max_script_size
        return self.MAX_SCRIPT_SIZE_BEFORE_GENESIS

    @cachedproperty
    def max_script_num_length(self):
        if self.is_utxo_after_genesis:
            if self.is_consensus:
                return self.MAX_SCRIPT_NUM_LENGTH_AFTER_GENESIS
            return self.policy.max_script_num_length
        return self.MAX_SCRIPT_NUM_LENGTH_BEFORE_GENESIS

    @cachedproperty
    def max_pubkeys_per_multisig(self):
        if self.is_utxo_after_genesis:
            if self.is_consensus:
                return self.MAX_PUBKEYS_PER_MULTISIG_AFTER_GENESIS
            return self.policy.max_pubkeys_per_multisig
        return self.MAX_PUBKEYS_PER_MULTISIG_BEFORE_GENESIS


def evaluate_script(state, script):

    if len(script) > state.max_script_size:
        raise ScriptTooLarge(f'script length {len(script):,d} exceeds the limit of '
                             f'{state.max_script_size:,d} bytes')

    state.op_count = 0
    state.non_top_level_return_after_genesis = False
    state.iterator = ScriptIterator(script)

    for op, item in state.iterator.ops_and_items():
        # Check pushitem size first
        if item is not None:
            state.validate_item_size(len(item))

        state.execute = (all(condition.execute for condition in state.conditions)
                         and (not state.non_top_level_return_after_genesis or op == OP_RETURN))

        # Pushitem and OP_RESERVED do not count towards op count.
        if op > Ops.OP_16:
            state.bump_op_count(1)

        # Some op codes are disabled.  For pre-genesis UTXOs these were an error in
        # unevaluated branches; for post-genesis UTXOs only if evaluated.
        if op in {OP_2MUL, OP_2DIV} and (state.execute or not state.is_utxo_after_genesis):
            raise DisabledOpcode(f'{Ops(op).name} is disabled')

        if state.execute and item is not None:
            state.validate_minimal_push_opcode(op, item)
            state.stack.append(item)
        elif state.execute or Ops.OP_IF <= op <= Ops.OP_ENDIF:
            op_handlers[op](state)
            if state.finished:
                return

        state.validate_stack_size()

    if state.conditions:
        raise UnbalancedConditional(f'unterminated {state.conditions[-1].opcode.name} '
                                    'at end of script')


#
# Control
#

def opcode_name(op):
    try:
        return Ops(op).name
    except ValueError:
        return str(op)


def invalid_opcode(_state, op):
    raise InvalidOpcode(f'invalid opcode {opcode_name(op)}')


def handle_NOP(_state):
    pass


def handle_IF(state, op):
    execute = False
    if state.execute:
        state.require_stack_depth(1)
        top = state.stack[-1]
        if state.flags & InterpreterFlags.REQUIRE_MINIMAL_IF:
            if state.stack[-1] not in bool_items:
                raise MinimalIfError('top of stack not True or False')
        state.stack.pop()
        execute = cast_to_bool(top)
        if op == OP_NOTIF:
            execute = not execute
    state.conditions.append(Condition(op, execute, False))


def handle_ELSE(state):
    top_condition = state.conditions[-1] if state.conditions else None
    # Only one ELSE is allowed per condition block after genesis
    if not top_condition or (top_condition.seen_else and state.is_utxo_after_genesis):
        raise UnbalancedConditional('unexpected OP_ELSE')
    top_condition.execute = not top_condition.execute
    top_condition.seen_else = True


def handle_ENDIF(state):
    # Only one ELSE is allowed per condition block after genesis
    if not state.conditions:
        raise UnbalancedConditional('unexpected OP_ENDIF')
    state.conditions.pop()


def handle_VERIF(state, op):
    # Post-genesis UTXOs permit OP_VERIF and OP_NOTVERIF in unexecuted branches
    if state.is_utxo_after_genesis and not state.execute:
        return
    invalid_opcode(state, op)


def handle_VERIFY(state):
    # (true -- ) or (false -- false) and return
    state.require_stack_depth(1)
    if not cast_to_bool(state.stack[-1]):
        raise VerifyFailed()
    state.stack.pop()


def handle_RETURN(state):
    if state.is_utxo_after_genesis:
        if state.conditions:
            # Check for invalid grammar if OP_RETURN in an if statement after genesis
            state.non_top_level_return_after_genesis = True
        else:
            # Terminate execution successfully.  The remainder of the script is ignored
            # even in the presence of unbalanced IFs, invalid opcodes etc.
            state.finished = True
    else:
        raise OpReturnError('OP_RETURN encountered')


#
# Stack operations
#
def handle_TOALTSTACK(state):
    state.require_stack_depth(1)
    state.alt_stack.append(state.stack.pop())


def handle_FROMALTSTACK(state):
    state.require_alt_stack()
    state.stack.append(state.alt_stack.pop())


def handle_DROP(state):
    # (x -- )
    state.require_stack_depth(1)
    state.stack.pop()


def handle_2DROP(state):
    # (x1 x2 -- )
    state.require_stack_depth(2)
    state.stack.pop()
    state.stack.pop()


def handle_nDUP(state, n):
    # (x -- x x) or (x1 x2 -- x1 x2 x1 x2) or (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
    state.require_stack_depth(n)
    state.stack.extend(state.stack[-n:])


def handle_OVER(state):
    # (x1 x2 -- x1 x2 x1)
    state.require_stack_depth(2)
    state.stack.append(state.stack[-2])


def handle_2OVER(state):
    # (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
    state.require_stack_depth(4)
    state.stack.extend(state.stack[-4: -2])


def handle_ROT(state):
    # (x1 x2 x3 -- x2 x3 x1)
    state.require_stack_depth(3)
    state.stack.append(state.stack.pop(-3))


def handle_2ROT(state):
    # (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
    state.require_stack_depth(6)
    state.stack.extend([state.stack.pop(-6), state.stack.pop(-5)])


def handle_SWAP(state):
    # ( x1 x2 -- x2 x1 )
    state.require_stack_depth(2)
    state.stack.append(state.stack.pop(-2))


def handle_2SWAP(state):
    # (x1 x2 x3 x4 -- x3 x4 x1 x2)
    state.require_stack_depth(4)
    state.stack.extend([state.stack.pop(-4), state.stack.pop(-3)])


def handle_IFDUP(state):
    # (x - 0 | x x)
    state.require_stack_depth(1)
    last = state.stack[-1]
    if cast_to_bool(last):
        state.stack.append(last)


def handle_DEPTH(state):
    # ( -- stacksize)
    state.stack.append(int_to_item(len(state.stack)))


def handle_NIP(state):
    # (x1 x2 -- x2)
    state.require_stack_depth(2)
    state.stack.pop(-2)


def handle_TUCK(state):
    # ( x1 x2 -- x2 x1 x2 )
    state.require_stack_depth(2)
    state.stack.insert(-2, state.stack[-1])


def handle_PICK_ROLL(state, op):
    # pick: (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
    # roll: (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
    state.require_stack_depth(2)
    n = int(state.to_number(state.stack[-1]))
    state.stack.pop()
    depth = len(state.stack)
    if not 0 <= n < depth:
        raise InvalidStackOperation(f'{op.name} with argument {n:,d} used '
                                    f'on stack with depth {depth:,d}')
    if op == OP_PICK:
        state.stack.append(state.stack[-(n + 1)])
    else:
        state.stack.append(state.stack.pop(-(n + 1)))


#
# Bitwise logic
#

def handle_INVERT(state):
    # (x -- out)
    state.require_stack_depth(1)
    state.stack[-1] = bytes(x ^ 255 for x in state.stack[-1])


def handle_binary_bitop(state, binop):
    # (x1 x2 -- out)
    state.require_stack_depth(2)
    x1 = state.stack[-2]
    x2 = state.stack[-1]
    if len(x1) != len(x2):
        raise InvalidOperandSize('operands to bitwise operator must have same size')
    state.stack.pop()
    state.stack[-1] = bytes(binop(b1, b2) for b1, b2 in zip(x1, x2))


def handle_EQUAL(state):
    # (x1 x2 -- bool).   Bitwise equality
    state.require_stack_depth(2)
    state.stack.append(bool_items[state.stack.pop() == state.stack.pop()])


def handle_EQUALVERIFY(state):
    # (x1 x2 -- )
    handle_EQUAL(state)
    if not cast_to_bool(state.stack[-1]):
        raise EqualVerifyFailed()
    state.stack.pop()


def shift_left(value, count):
    n_bytes, n_bits = divmod(count, 8)
    n_bytes = min(n_bytes, len(value))

    def pairs(value, n_bytes):
        for n in range(n_bytes, len(value) - 1):
            yield value[n], value[n + 1]
        if n_bytes < len(value):
            yield value[-1], 0
        for n in range(n_bytes):
            yield 0, 0

    return bytes(((lhs << n_bits) & 255) + (rhs >> (8 - n_bits))
                 for lhs, rhs in pairs(value, n_bytes))


def shift_right(value, count):
    n_bytes, n_bits = divmod(count, 8)
    n_bytes = min(n_bytes, len(value))

    def pairs(value, n_bytes):
        for n in range(n_bytes):
            yield 0, 0
        if n_bytes < len(value):
            yield 0, value[0]
        for n in range(len(value) - 1 - n_bytes):
            yield value[n], value[n + 1]

    return bytes(((lhs << (8 - n_bits)) & 255) + (rhs >> n_bits)
                 for lhs, rhs in pairs(value, n_bytes))


def handle_LSHIFT(state):
    # (x n -- out).   Logical bit-shift maintaining item size
    state.require_stack_depth(2)
    n = int(state.to_number(state.stack[-1]))
    if n < 0:
        raise NegativeShiftCount(f'invalid shift left of {n:,d} bits')
    state.stack.pop()
    state.stack[-1] = shift_left(state.stack[-1], n)


def handle_RSHIFT(state):
    # (x n -- out).   Logical bit-shift maintaining item size
    state.require_stack_depth(2)
    n = int(state.to_number(state.stack[-1]))
    if n < 0:
        raise NegativeShiftCount(f'invalid right left of {n:,d} bits')
    state.stack.pop()
    state.stack[-1] = shift_right(state.stack[-1], n)


#
# Numeric
#

def handle_unary_numeric(state, unary_op):
    # (x -- out)
    state.require_stack_depth(1)
    value = state.to_number(state.stack[-1])
    state.stack[-1] = int_to_item(unary_op(value))


def handle_binary_numeric(state, binary_op):
    # (x1 x2 -- out)
    state.require_stack_depth(2)
    x1 = state.to_number(state.stack[-2])
    x2 = state.to_number(state.stack[-1])
    try:
        result = binary_op(x1, x2)
    except ZeroDivisionError:
        raise DivisionByZero('division by zero' if binary_op is bitcoin_div
                             else 'modulo by zero') from None
    state.stack.pop()
    state.stack[-1] = int_to_item(result)


def handle_NUMEQUALVERIFY(state):
    # (x1 x2 -- )
    handle_binary_numeric(state, operator.eq)
    if not cast_to_bool(state.stack[-1]):
        raise NumEqualVerifyFailed()
    state.stack.pop()


def bitcoin_div(a, b):
    # In bitcoin script division is rounded towards zero
    result = abs(a) // abs(b)
    return -result if (a >= 0) ^ (b >= 0) else result


def bitcoin_mod(a, b):
    # In bitcoin script a % b is abs(a) % abs(b) with the sign of a.
    # Then (a % b) * b + a == a
    result = abs(a) % abs(b)
    return result if a >= 0 else -result


def logical_and(x1, x2):
    return 1 if (x1 and x2) else 0


def logical_or(x1, x2):
    return 1 if (x1 or x2) else 0


def handle_WITHIN(state):
    # (x max min -- out)    True if x is >= min and < max.
    state.require_stack_depth(3)
    x = item_to_int(state.stack[-3])
    mn = item_to_int(state.stack[-2])
    mx = item_to_int(state.stack[-1])
    state.stack.pop()
    state.stack.pop()
    state.stack[-1] = bool_items[mn <= x < mx]


#
# Crypto
#

def handle_hash(state, hash_func):
    # (x -- x x)
    state.require_stack_depth(1)
    state.stack.append(hash_func(state.stack.pop()))


def handle_CODESEPARATOR(state):
    # script_code starts after the code separator
    state.iterator.on_code_separator()


def handle_CHECKSIG(state):
    # (sig pubkey -- bool)
    state.require_stack_depth(2)
    sig_bytes = state.stack[-2]
    pubkey_bytes = state.stack[-1]
    state.validate_signature(sig_btyes)
    state.validate_pubkey(pubkey_bytes)
    script_code = state.iterator.script_code()
    script_code = state.cleanup_script_code(sig_bytes, script_code)
    is_good = state.check_sig(sig_bytes, pubkey_bytes, script_code)
    if not is_good:
        state.validate_nullfail(sig_bytes)
    state.stack.pop()
    state.stack[-1] = bool_items[is_good]


def handle_CHECKSIGVERIFY(state):
    # (sig pubkey -- )
    handle_CHECKSIG(state)
    if state.stack[-1] == b_OP_0:
        raise CheckSigVerifyFailed('OP_CHECKSIGVERIFY failed')
    state.stack.pop()


def handle_CHECKMULTISIG(state):
    # ([sig ...] sig_count [pubkey ...] pubkey_count -- bool)
    state.require_stack_depth(1)
    # Limit key count to 4 bytes
    key_count = state.to_number(state.stack[-1], length_limit=4)
    state.validate_pubkey_count(key_count)
    state.bump_op_count(key_count)
    # Ensure we can read sig_count, also limited to 4 bytes
    state.require_stack_depth(key_count + 2)
    sig_count = state.to_number(state.stack[-(key_count + 2)], length_limit=4)
    if not 0 <= sig_count <= key_count:
        raise InvalidSignatureCount(f'number of signatures, {sig_count:,d}, in OP_CHECKMULTISIG '
                                    f'lies outside range 0 <= count <= {key_count:,d}')

    # Ensure we have all the sigs
    item_count = key_count + sig_count + 2
    state.require_stack_depth(item_count)

    # Remove signatures for pre-BCH fork scripts
    script_code = state.iterator.script_code()
    first_sig_index = -(key_count + 3)
    for n in range(sig_count):
        script_code = state.cleanup_script_code(state.stack[first_sig_index - n], script_code)

    keys_remaining = key_count
    sigs_remaining = sig_count
    key_base_index = -(key_count + 2)
    sig_base_index = key_base_index - (sig_count + 1)
    # Loop while the remaining number of sigs to check does not exceed the remaining keys
    while keys_remaining >= sigs_remaining > 0:
        sig_bytes = state.stack[sig_base_index + sigs_remaining]
        state.validate_signature(sig_btyes)
        pubkey_bytes = state.stack[key_base_index + keys_remaining]
        state.validate_pubkey(pubkey_bytes)
        is_good = state.check_sig(sig_bytes, pubkey_bytes, script_code)
        if is_good:
            sigs_remaining -= 1
        keys_remaining -= 1

    is_good = keys_remaining >= sigs_remaining

    # Clean up the stack
    for n in range(item_count):
        # If the operation failed NULLFAIL requires all signatures be empty
        if not is_good and n >= key_count + 2:
            state.validate_nullfail(state.stack[-1])
        state.stack.pop()

    # An old CHECKMULTISIG bug consumes an extra argument.  Check it's null.
    state.require_stack_depth(1)
    state.validate_nulldummy()
    state.stack[-1] = bool_items[is_good]


def handle_CHECKMULTISIGVERIFY(state):
    # (sig pubkey -- )
    handle_CHECKMULTISIG(state)
    if state.stack[-1] == b_OP_0:
        raise CheckMultiSigVerifyFailed('OP_CHECKMULTISIGVERIFY failed')
    state.stack.pop()


#
# Byte string operations
#

def handle_CAT(state):
    # (x1 x2 -- x1x2 )
    state.require_stack_depth(2)
    item = state.stack[-2] + state.stack[-1]
    state.validate_item_size(len(item))
    state.stack.pop()
    state.stack[-1] = item


def handle_SPLIT(state):
    # (x posiition -- x1 x2)
    state.require_stack_depth(2)
    x = state.stack[-2]
    n = int(state.to_number(state.stack[-1]))
    if not 0 <= n <= len(x):
        raise InvalidSplit(f'cannot split item of length {len(x):,d} at position {n:,d}')
    state.stack[-2] = x[:n]
    state.stack[-1] = x[n:]


def handle_NUM2BIN(state):
    # (in size -- out)  encode the value of "in" in size bytes
    state.require_stack_depth(2)
    size = int(state.to_number(state.stack[-1]))
    if size < 0 or size > INT32_MAX:
        raise InvalidPushSize(f'invalid size {size:,d} in OP_NUM2BIN operation')
    state.validate_item_size(size)
    state.stack.pop()
    state.stack[-1] = int_to_item(item_to_int(state.stack[-1]), size)


def handle_BIN2NUM(state):
    # (in -- out)    minimally encode in as a number
    state.require_stack_depth(1)
    state.stack[-1] = minimal_encoding(state.stack[-1])
    state.validate_number_length(len(state.stack[-1]))


def handle_SIZE(state):
    # ( x -- x size(x) )
    state.require_stack_depth(1)
    size = len(state.stack[-1])
    state.stack.append(int_to_item(size))


#
# Expansion
#

def handle_upgradeable_nop(state, op):
    state.handle_upgradeable_nop(op)


def handle_CHECKLOCKTIMEVERIFY(state):
    if state.is_utxo_after_genesis or not (state.flags & InterpreterFlags.CHECKLOCKTIMEVERIFY):
        handle_upgradeable_nops(state, OP_NOP2)
    state.require_stack_depth(1)
    locktime = state.to_number(state.stack[-1], length_limit=5)
    if locktime < 0:
        raise LockTimeError(f'locktime {locktime:,d} is negative')
    state.validate_locktime(locktime)


def handle_CHECKSEQUENCEVERIFY(state):
    if state.is_utxo_after_genesis or not (state.flags & InterpreterFlags.CHECKSEQUENCEVERIFY):
        handle_upgradeable_nops(state, OP_NOP3)
    state.require_stack_depth(1)
    sequence = state.to_number(state.stack[-1], length_limit=5)
    if sequence < 0:
        raise LockTimeError(f'sequence {sequence:,d} is negative')
    state.validate_sequence(sequence)


op_handlers = [partial(invalid_opcode, op=op) for op in range(256)]

#
# Control
#
op_handlers[OP_NOP] = handle_NOP
op_handlers[OP_VER] = partial(invalid_opcode, op=OP_VER)
op_handlers[OP_IF] = partial(handle_IF, op=OP_IF)
op_handlers[OP_NOTIF] = partial(handle_IF, op=OP_NOTIF)
op_handlers[OP_VERIF] = partial(handle_VERIF, op=OP_VERIF)
op_handlers[OP_VERNOTIF] = partial(handle_VERIF, op=OP_VERNOTIF)
op_handlers[OP_ELSE] = handle_ELSE
op_handlers[OP_ENDIF] = handle_ENDIF
op_handlers[OP_VERIFY] = handle_VERIFY
op_handlers[OP_RETURN] = handle_RETURN

#
# Stack operations
#
op_handlers[OP_TOALTSTACK] = handle_TOALTSTACK
op_handlers[OP_FROMALTSTACK] = handle_FROMALTSTACK
op_handlers[OP_DROP] = handle_DROP
op_handlers[OP_2DROP] = handle_2DROP
op_handlers[OP_DUP] = partial(handle_nDUP, n=1)
op_handlers[OP_2DUP] = partial(handle_nDUP, n=2)
op_handlers[OP_3DUP] = partial(handle_nDUP, n=3)
op_handlers[OP_OVER] = handle_OVER
op_handlers[OP_2OVER] = handle_2OVER
op_handlers[OP_2ROT] = handle_2ROT
op_handlers[OP_2SWAP] = handle_2SWAP
op_handlers[OP_IFDUP] = handle_IFDUP
op_handlers[OP_DEPTH] = handle_DEPTH
op_handlers[OP_NIP] = handle_NIP
op_handlers[OP_PICK] = partial(handle_PICK_ROLL, op=OP_PICK)
op_handlers[OP_ROLL] = partial(handle_PICK_ROLL, op=OP_ROLL)
op_handlers[OP_ROT] = handle_ROT
op_handlers[OP_SWAP] = handle_SWAP
op_handlers[OP_TUCK] = handle_TUCK

#
# Byte string operations
#
op_handlers[OP_CAT] = handle_CAT
op_handlers[OP_SPLIT] = handle_SPLIT
op_handlers[OP_NUM2BIN] = handle_NUM2BIN
op_handlers[OP_BIN2NUM] = handle_BIN2NUM
op_handlers[OP_SIZE] = handle_SIZE

#
# Bitwise logic
#
op_handlers[OP_INVERT] = handle_INVERT
op_handlers[OP_AND] = partial(handle_binary_bitop, binop=operator.and_)
op_handlers[OP_OR] = partial(handle_binary_bitop, binop=operator.or_)
op_handlers[OP_XOR] = partial(handle_binary_bitop, binop=operator.xor)
op_handlers[OP_EQUAL] = handle_EQUAL
op_handlers[OP_EQUALVERIFY] = handle_EQUALVERIFY
op_handlers[OP_LSHIFT] = handle_LSHIFT
op_handlers[OP_RSHIFT] = handle_RSHIFT
op_handlers[OP_RESERVED1] = partial(invalid_opcode, op=OP_RESERVED1)
op_handlers[OP_RESERVED2] = partial(invalid_opcode, op=OP_RESERVED2)

#
# Numeric
#
op_handlers[OP_1ADD] = partial(handle_unary_numeric, unary_op=lambda x: x + 1)
op_handlers[OP_1SUB] = partial(handle_unary_numeric, unary_op=lambda x: x - 1)
# OP_2MUL = 0x8d
# OP_2DIV = 0x8e
op_handlers[OP_NEGATE] = partial(handle_unary_numeric, unary_op=operator.neg)
op_handlers[OP_ABS] = partial(handle_unary_numeric, unary_op=operator.abs)
op_handlers[OP_NOT] = partial(handle_unary_numeric, unary_op=operator.not_)
op_handlers[OP_0NOTEQUAL] = partial(handle_unary_numeric, unary_op=operator.truth)
op_handlers[OP_ADD] = partial(handle_binary_numeric, binary_op=operator.add)
op_handlers[OP_SUB] = partial(handle_binary_numeric, binary_op=operator.sub)
op_handlers[OP_MUL] = partial(handle_binary_numeric, binary_op=operator.mul)
op_handlers[OP_DIV] = partial(handle_binary_numeric, binary_op=bitcoin_div)
op_handlers[OP_MOD] = partial(handle_binary_numeric, binary_op=bitcoin_mod)
op_handlers[OP_BOOLAND] = partial(handle_binary_numeric, binary_op=logical_and)
op_handlers[OP_BOOLOR] = partial(handle_binary_numeric, binary_op=logical_or)
op_handlers[OP_NUMEQUAL] = partial(handle_binary_numeric, binary_op=operator.eq)
op_handlers[OP_NUMEQUALVERIFY] = handle_NUMEQUALVERIFY
op_handlers[OP_NUMNOTEQUAL] = partial(handle_binary_numeric, binary_op=operator.ne)
op_handlers[OP_LESSTHAN] = partial(handle_binary_numeric, binary_op=operator.lt)
op_handlers[OP_GREATERTHAN] = partial(handle_binary_numeric, binary_op=operator.gt)
op_handlers[OP_LESSTHANOREQUAL] = partial(handle_binary_numeric, binary_op=operator.le)
op_handlers[OP_GREATERTHANOREQUAL] = partial(handle_binary_numeric, binary_op=operator.ge)
op_handlers[OP_MIN] = partial(handle_binary_numeric, binary_op=min)
op_handlers[OP_MAX] = partial(handle_binary_numeric, binary_op=max)
op_handlers[OP_WITHIN] = handle_WITHIN

#
# Crypto
#
op_handlers[OP_RIPEMD160] = partial(handle_hash, hash_func=ripemd160)
op_handlers[OP_SHA1] = partial(handle_hash, hash_func=sha1)
op_handlers[OP_SHA256] = partial(handle_hash, hash_func=sha256)
op_handlers[OP_HASH160] = partial(handle_hash, hash_func=hash160)
op_handlers[OP_HASH256] = partial(handle_hash, hash_func=double_sha256)
op_handlers[OP_CODESEPARATOR] = handle_CODESEPARATOR
op_handlers[OP_CHECKSIG] = handle_CHECKSIG
op_handlers[OP_CHECKSIGVERIFY] = handle_CHECKSIGVERIFY
op_handlers[OP_CHECKMULTISIG] = handle_CHECKMULTISIG
op_handlers[OP_CHECKMULTISIGVERIFY] = handle_CHECKMULTISIGVERIFY

#
# Expansion
#
for _op in (OP_NOP1, OP_NOP4, OP_NOP5, OP_NOP6, OP_NOP7, OP_NOP8, OP_NOP9, OP_NOP10):
    op_handlers[_op] = partial(handle_upgradeable_nop, op=_op)
op_handlers[OP_NOP2] = handle_CHECKLOCKTIMEVERIFY
op_handlers[OP_NOP3] = handle_CHECKSEQUENCEVERIFY
