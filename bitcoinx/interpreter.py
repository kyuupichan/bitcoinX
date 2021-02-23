# Copyright (c) 2018-2021, Neil Booth
#
# All rights reserved.
#
# Licensed under the the Open BSV License version 3; see LICENCE for details.
#

'''Bitcoin script interpreter.'''

__all__ = (
    'InterpreterError', 'InterpreterLimits', 'InterpreterState', 'InterpreterFlags',
    'MinerPolicy', 'TxInputContext',
)


import operator
from enum import IntFlag
from functools import partial

import attr

from .consts import (
    LOCKTIME_THRESHOLD, SEQUENCE_FINAL, SEQUENCE_LOCKTIME_DISABLE_FLAG,
    SEQUENCE_LOCKTIME_MASK, SEQUENCE_LOCKTIME_TYPE_FLAG, UINT32_MAX, UINT64_MAX, INT32_MAX,
)
from .consts import INT64_MAX
from .errors import (
    InterpreterError, NumEqualVerifyFailed,
    StackSizeTooLarge, MinimalEncodingError, InvalidPublicKeyEncoding,
    ScriptTooLarge, TooManyOps, MinimalIfError, DivisionByZero, NegativeShiftCount,
    InvalidPushSize, DisabledOpcode, UnbalancedConditional, InvalidStackOperation,
    VerifyFailed, OpReturnError, InvalidOpcode, InvalidSplit,
    InvalidNumber, InvalidOperandSize, EqualVerifyFailed, InvalidSignature, NullFailError,
    InvalidPublicKeyCount, NullDummyError, UpgradeableNopError, LockTimeError, PushOnlyError,
    CheckSigVerifyFailed, CheckMultiSigVerifyFailed, InvalidSignatureCount, CleanStackError,
)
from .hashes import ripemd160, hash160, sha1, sha256, double_sha256
from .limited_stack import LimitedStack
from .misc import cachedproperty
# pylint:disable=E0611
from .script import (
    Script, ScriptIterator, Ops, OP_16, OP_IF, OP_ENDIF, OP_RETURN,
    int_to_item, item_to_int, minimal_push_opcode, is_item_minimally_encoded, minimal_encoding,
    cast_to_bool, bool_items,
)
from .signature import Signature, SigHash, SigEncoding


class InterpreterFlags(IntFlag):
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
    # Fails script immediately if a failed signature was not null
    REQUIRE_NULLFAIL = 1 << 5
    # Fails script if the CHECKMULTISIG dummy argument is not null
    REQUIRE_NULLDUMMY = 1 << 6
    # Fails script if an upgradeable NOP is encountered
    REJECT_UPGRADEABLE_NOPS = 1 << 7
    # Set if FORKID is enabled (post BTC/BCH fork)
    ENABLE_FORKID = 1 << 8
    # If set OP_CHECKLOCKTIMEVERIFY is permitted
    ENABLE_CHECKLOCKTIMEVERIFY = 1 << 9
    # If set OP_CHECKSEQUENCEVERIFY is permitted
    ENABLE_CHECKSEQUENCEVERIFY = 1 << 10
    # If set verify_script handles P2SH outputs
    ENABLE_P2SH = 1 << 11
    # If true verify_input() requires script_sig to be PUSHDATA only
    REQUIRE_SIGPUSH_ONLY = 1 << 12
    # If true verify_input() requires a clean stack on exit
    REQUIRE_CLEANSTACK = 1 << 13


# New blocks must comply with these flags (but old blocks may not)
# See GetBlockScriptFlags() in src/validation.cpp
MANDATORY_SCRIPT_VERIFY_FLAGS = (
    InterpreterFlags.ENABLE_P2SH |                  # Activated on Apr 1 2012
    InterpreterFlags.REQUIRE_STRICT_DER |           # BIP 66 activated at height 363725
    InterpreterFlags.ENABLE_CHECKLOCKTIMEVERIFY |   # BIP 65 activated at height 388381
    InterpreterFlags.ENABLE_CHECKSEQUENCEVERIFY |   # BIP112 activated at height 419328
    InterpreterFlags.ENABLE_FORKID |                # UAHF activated at height 478558
    InterpreterFlags.REQUIRE_STRICT_ENCODING |      # UAHF activated at height 478558
    InterpreterFlags.REQUIRE_LOW_S |                # DAA activated at height 504031
    InterpreterFlags.REQUIRE_NULLFAIL |             # DAA activated at height 504031
    InterpreterFlags.REQUIRE_SIGPUSH_ONLY           # Genesis activated at height 620538
)


# See src/policy/policy.h
STANDARD_SCRIPT_VERIFY_FLAGS = (
    MANDATORY_SCRIPT_VERIFY_FLAGS
    | InterpreterFlags.REQUIRE_MINIMAL_PUSH
    | InterpreterFlags.REQUIRE_NULLDUMMY
    | InterpreterFlags.REJECT_UPGRADEABLE_NOPS
    | InterpreterFlags.REQUIRE_CLEANSTACK
)


@attr.s(slots=True)
class MinerPolicy:
    '''Miner policy rules.

    Generally fixed over the node session and apply to non-consensus post-genesis
    transactions for e.g. mempool acceptance.

    Consensus rules determine what is accepted in a block and are looser.
    '''
    # In bytes, e.g. 10_000_000
    max_script_size = attr.ib()
    # In bytes, e.g. 256
    max_script_num_length = attr.ib()
    # In bytes, e.g. 10_000_000
    max_stack_memory_usage = attr.ib()
    # e.g. 1_000_000
    max_ops_per_script = attr.ib()
    # e.g. 64
    max_pubkeys_per_multisig = attr.ib()
    # Transactions in blocks must pass script verification with these flags
    consensus_flags = attr.ib(default=MANDATORY_SCRIPT_VERIFY_FLAGS)
    # Standard transactions must comply with these flags
    standard_flags = attr.ib(default=STANDARD_SCRIPT_VERIFY_FLAGS)


class InterpreterLimits:
    '''Limits to apply to a particular invocation of the interpreter.  Use the from_policy()
    method to initialize appropriately for a given miner policy and context.

    Note: all attributes should be considered read-only, do not set them directly.'''

    # Class constants
    MAX_SCRIPT_SIZE_BEFORE_GENESIS = 10_000
    MAX_SCRIPT_SIZE_AFTER_GENESIS = UINT32_MAX    # limited by P2P message size
    MAX_SCRIPT_NUM_LENGTH_BEFORE_GENESIS = 4
    MAX_SCRIPT_NUM_LENGTH_AFTER_GENESIS = 750_000
    MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS = 520
    MAX_STACK_ELEMENTS_BEFORE_GENESIS = 1_000
    MAX_STACK_MEMORY_USAGE_AFTER_GENESIS = INT64_MAX
    MAX_OPS_PER_SCRIPT_BEFORE_GENESIS = 500
    MAX_OPS_PER_SCRIPT_AFTER_GENESIS = UINT32_MAX
    MAX_PUBKEYS_PER_MULTISIG_BEFORE_GENESIS = 20
    MAX_PUBKEYS_PER_MULTISIG_AFTER_GENESIS = UINT32_MAX

    DYNAMIC_ATTRS = (
        'flags', 'script_num_length', 'stack_memory_usage', 'pubkeys_per_multisig', 'item_size',
    )

    def __init__(self, policy, is_genesis_enabled, is_consensus, base_flags='standard'):
        '''Inintialize limits appropriate for the given miner policy.

        is_genesis_enabled is True if the Genesis upgrade is activated.  is_consensus is
        True if validating transactions in a block, False if validating more strictly for
        mempool acceptance or relay.  These affect script resource limits.

        base_flags is the set of script verification InterpreterFlags to use, or the
        string 'consensus' or 'standard' to take the flags from the miner policy.  When
        accessed via the flags property they are adjusted to ensure consistency and
        whether the script being validated comes from a post-genesis UTXO or not.

        The limits can be re-used to validate many UTXOs in a transaction or block by
        calling set_utxo_state() before each validation; this is done automatically by
        TxInputContext.verify().
        '''
        self.policy = policy
        self.is_genesis_enabled = is_genesis_enabled
        self.is_consensus = is_consensus
        self.base_flags = base_flags
        self.is_utxo_after_genesis = is_genesis_enabled

    def set_utxo_state(self, is_after_genesis):
        if is_after_genesis and not self.is_genesis_enabled:
            raise ValueError('cannot have a UTXO after genesis if genesis is not enabled')
        if is_after_genesis != self.is_utxo_after_genesis:
            self.is_utxo_after_genesis = is_after_genesis
            for attrib in self.DYNAMIC_ATTRS:
                if hasattr(self, attrib):
                    delattr(self, attrib)

    @cachedproperty
    def script_size(self):
        '''Implements the max script size rule.'''
        if self.is_genesis_enabled:
            if self.is_consensus:
                return self.MAX_SCRIPT_SIZE_AFTER_GENESIS
            return self.policy.max_script_size
        return self.MAX_SCRIPT_SIZE_BEFORE_GENESIS

    @cachedproperty
    def ops_per_script(self):
        '''Implements the max ops per script rule.'''
        if self.is_genesis_enabled:
            if self.is_consensus:
                return self.MAX_OPS_PER_SCRIPT_AFTER_GENESIS
            return self.policy.max_ops_per_script
        return self.MAX_OPS_PER_SCRIPT_BEFORE_GENESIS

    @cachedproperty
    def flags(self):
        '''Return sanitized flags .'''
        flags = self.base_flags
        if flags == 'standard':
            flags = self.policy.standard_flags
            # See StandardScriptVerifyFlags() in src/policy/policy.h
            if self.is_genesis_enabled:
                flags |= InterpreterFlags.REQUIRE_SIGPUSH_ONLY
        elif flags == 'consensus':
            flags = self.policy.consensus_flags

        # Require strict encoding if FORKID is enabled
        if flags & InterpreterFlags.ENABLE_FORKID:
            flags |= InterpreterFlags.REQUIRE_STRICT_ENCODING

        # Disable CLEANSTACK check unless P2SH is enabled as the P2SH inputs would remain.
        if not flags & InterpreterFlags.ENABLE_P2SH:
            flags &= ~InterpreterFlags.REQUIRE_CLEANSTACK

        # For post-genesis UTXOs obsolete script features are disabled
        if self.is_utxo_after_genesis:
            flags &= ~(InterpreterFlags.ENABLE_CHECKLOCKTIMEVERIFY
                       | InterpreterFlags.ENABLE_CHECKSEQUENCEVERIFY
                       | InterpreterFlags.ENABLE_P2SH)

        return flags

    @cachedproperty
    def script_num_length(self):
        '''Implements the max script memory usage rule.'''
        if self.is_utxo_after_genesis:
            if self.is_consensus:
                return self.MAX_SCRIPT_NUM_LENGTH_AFTER_GENESIS
            return self.policy.max_script_num_length
        return self.MAX_SCRIPT_NUM_LENGTH_BEFORE_GENESIS

    @cachedproperty
    def stack_memory_usage(self):
        '''Implements the max script memory usage rule.'''
        if self.is_utxo_after_genesis:
            if self.is_consensus:
                return self.MAX_STACK_MEMORY_USAGE_AFTER_GENESIS
            return self.policy.max_stack_memory_usage
        # Before genesis other stricter limitations applied so this can be infinite
        return INT64_MAX

    @cachedproperty
    def pubkeys_per_multisig(self):
        '''Implements the rule re maximum public keys in an OP_CHECKMULTISIG[VERIFY].'''
        if self.is_utxo_after_genesis:
            if self.is_consensus:
                return self.MAX_PUBKEYS_PER_MULTISIG_AFTER_GENESIS
            return self.policy.max_pubkeys_per_multisig
        return self.MAX_PUBKEYS_PER_MULTISIG_BEFORE_GENESIS

    @cachedproperty
    def item_size(self):
        # No limit for post-genesis UTXOs
        if self.is_utxo_after_genesis:
            return UINT64_MAX
        else:
            return self.MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS

    def cleanup_script_code(self, sig_bytes, script_code):
        '''Return script_code with signatures deleted if pre-BCH fork.'''
        sighash = SigHash.from_sig_bytes(sig_bytes)
        if self.flags & InterpreterFlags.ENABLE_FORKID or sighash.has_forkid():
            return script_code
        else:
            return script_code.find_and_delete(Script() << sig_bytes)

    def validate_nullfail(self, sig_bytes):
        '''Fail immediately if a failed signature was not null.'''
        if sig_bytes and self.flags & InterpreterFlags.REQUIRE_NULLFAIL:
            raise NullFailError('signature check failed on a non-null signature')

    def validate_nulldummy(self, dummy):
        '''Fail if the multisig duumy pop isn't an empty stack item.'''
        if dummy and self.flags & InterpreterFlags.REQUIRE_NULLDUMMY:
            raise NullDummyError('multisig dummy argument was not null')

    def validate_signature(self, sig_bytes):
        '''Raise the InvalidSignature exception if the signature does not meet the requirements of
        self.flags.
        '''
        if not sig_bytes:
            return

        flags = self.flags
        if flags & (InterpreterFlags.REQUIRE_STRICT_DER
                    | InterpreterFlags.REQUIRE_LOW_S
                    | InterpreterFlags.REQUIRE_STRICT_ENCODING):
            kind = Signature.analyze_encoding(sig_bytes)
            if not kind & SigEncoding.STRICT_DER:
                raise InvalidSignature('signature does not follow strict DER encoding')

            if flags & InterpreterFlags.REQUIRE_LOW_S and not kind & SigEncoding.LOW_S:
                raise InvalidSignature('signature has high S value')

        if flags & InterpreterFlags.REQUIRE_STRICT_ENCODING:
            sighash = SigHash.from_sig_bytes(sig_bytes)
            if not sighash.is_defined():
                raise InvalidSignature('undefined sighash type')
            if sighash.has_forkid() and not (flags & InterpreterFlags.ENABLE_FORKID):
                raise InvalidSignature('sighash must not use FORKID')
            if not sighash.has_forkid() and (flags & InterpreterFlags.ENABLE_FORKID):
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

    def validate_pubkey_count(self, count):
        limit = self.pubkeys_per_multisig
        if not 0 <= count <= limit:
            raise InvalidPublicKeyCount(f'number of public keys, {count:,d}, in multi-sig check '
                                        f'lies outside range 0 <= count <= {limit:d}')

    def validate_number_length(self, size, *, limit=None):
        if limit is None:
            limit = self.script_num_length
        if size > limit:
            raise InvalidNumber(f'number of length {size:,d} bytes exceeds the limit '
                                f'of {limit:,d} bytes')

    def to_number(self, item, *, length_limit=None):
        self.validate_number_length(len(item), limit=length_limit)

        if (self.flags & InterpreterFlags.REQUIRE_MINIMAL_PUSH
                and not is_item_minimally_encoded(item)):
            raise MinimalEncodingError(f'number is not minimally encoded: {item.hex()}')

        return item_to_int(item)

    def validate_item_size(self, size):
        '''Enforces the limit on stack item size.'''
        if size > self.item_size:
            raise InvalidPushSize(f'item length {size:,d} exceeds the limit '
                                  f'of {self.item_size:,d} bytes')

    def validate_minimal_push_opcode(self, op, item):
        if self.flags & InterpreterFlags.REQUIRE_MINIMAL_PUSH:
            expected_op = minimal_push_opcode(item)
            if op != expected_op:
                raise MinimalEncodingError(f'item not pushed with minimal opcode {expected_op}')

    def validate_upgradeable_nop(self, op):
        '''Raise on upgradeable nops if the flag is set.'''
        if self.flags & InterpreterFlags.REJECT_UPGRADEABLE_NOPS:
            raise UpgradeableNopError(f'encountered upgradeable NOP {op.name}')


@attr.s(slots=True)
class TxInputContext:
    '''The context of a transaction input when evaluating its script_sig against a previous
    outputs script_pubkey.'''

    # The transaction containing the input, an instance of Tx
    tx = attr.ib()
    # The index of the input
    input_index = attr.ib()
    # The previous output it is spending, an instance of TxOutput
    utxo = attr.ib()
    # True if the UTXO was created after the Genesis upgrade
    is_utxo_after_genesis = attr.ib()

    def verify_input(self, limits):
        '''Return the boolean result of validating the input subject to limits.'''
        # Update limits appropriately for the UTXO state
        limits.set_utxo_state(self.is_utxo_after_genesis)

        script_sig = self.tx.inputs[self.input_index].script_sig
        if limits.flags & InterpreterFlags.REQUIRE_SIGPUSH_ONLY and not script_sig.is_push_only():
            raise PushOnlyError('script_sig is not pushdata only')

        script_pubkey = self.utxo.script_pubkey
        is_P2SH = limits.flags & InterpreterFlags.ENABLE_P2SH and script_pubkey.is_P2SH()

        state = InterpreterState(limits, self)
        state.evaluate_script(script_sig)
        if is_P2SH:
            stack_copy = state.stack.make_copy()
        state.evaluate_script(script_pubkey)
        if not state.stack or not cast_to_bool(state.stack[-1]):
            return False

        # Additional validation for P2SH transactions
        if is_P2SH:
            if not script_sig.is_push_only():
                raise PushOnlyError('P2SH script_sig is not pushdata only')
            state.stack.restore_copy(stack_copy)
            pubkey_script = Script(state.stack.pop())
            state.evaluate_script(pubkey_script)
            if not state.stack or not cast_to_bool(state.stack[-1]):
                return False

        if limits.flags & InterpreterFlags.REQUIRE_CLEANSTACK and len(state.stack) != 1:
            raise CleanStackError('stack is not clean')

        return True

    def check_sig(self, sig_bytes, pubkey_bytes, script_code):
        '''Check a signature.  Returns True or False.'''
        if not sig_bytes:
            return False
        from .keys import PublicKey
        try:
            pubkey = PublicKey.from_bytes(pubkey_bytes)
        except ValueError:
            return False

        # Split out to a normalized DER signature and the sighash
        der_sig, sighash = Signature.split_and_normalize(sig_bytes)
        message_hash = self.tx.signature_hash(self.input_index, self.utxo.value,
                                              script_code, sighash)

        return pubkey.verify_der_signature(der_sig, message_hash, hasher=None)

    def validate_locktime(self, locktime):
        # Are the lock times comparable?
        if (locktime < LOCKTIME_THRESHOLD) ^ (self.tx.locktime < LOCKTIME_THRESHOLD):
            raise LockTimeError('locktimes are not comparable')
        # Numeric comparison
        if locktime > self.tx.locktime:
            raise LockTimeError(f'locktime {locktime:,d} not reached')
        if self.tx.inputs[self.input_index].sequence == SEQUENCE_FINAL:
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
            raise LockTimeError(f'masked sequence number {sequence:,d} not reached')


@attr.s(slots=True)
class Condition:
    '''Represents an open condition block whilst executing.'''
    opcode = attr.ib()       # OP_IF or OP_NOTIF
    execute = attr.ib()      # True or False; flips on OP_ELSE
    seen_else = attr.ib()    # True or False


class InterpreterState:
    '''Interpreter state that updates as a script executes.'''

    def __init__(self, limits, txin_context=None):
        self.limits = limits
        self._txin_context = txin_context
        self.stack = LimitedStack(self.limits.stack_memory_usage)
        self.alt_stack = self.stack.make_child_stack()
        self.conditions = []
        self.execute = False
        self.iterator = None
        self.op_count = 0

    def txin_context(self, op):
        if self._txin_context is None:
            raise RuntimeError(f'cannot process {op.name} without a TxInputContext')
        return self._txin_context

    def bump_op_count(self, bump):
        self.op_count += bump
        if self.op_count > self.limits.ops_per_script:
            raise TooManyOps(f'op count exceeds the limit of {self.limits.ops_per_script:,d}')

    def require_stack_depth(self, depth):
        if len(self.stack) < depth:
            raise InvalidStackOperation(f'stack depth {len(self.stack)} less than required '
                                        f'depth of {depth}')

    def require_alt_stack(self):
        if not self.alt_stack:
            raise InvalidStackOperation('alt stack is empty')

    def validate_stack_size(self):
        '''Enforces the limits on combined stack size.

        For post-genesis UTXOs the limit is instead on stack memory usage.
        '''
        if self.limits.is_utxo_after_genesis:
            return
        stack_size = len(self.stack) + len(self.alt_stack)
        limit = InterpreterLimits.MAX_STACK_ELEMENTS_BEFORE_GENESIS
        if stack_size > limit:
            raise StackSizeTooLarge(f'combined stack size exceeds the limit of {limit:,d} items')

    def evaluate_script(self, script):
        '''Evaluate a script and update state.'''
        if len(script) > self.limits.script_size:
            raise ScriptTooLarge(f'script length {len(script):,d} exceeds the limit of '
                                 f'{self.limits.script_size:,d} bytes')

        handlers = self._handlers
        self.conditions = []
        self.op_count = 0
        self.iterator = ScriptIterator(script)
        non_top_level_return_after_genesis = False

        for op, item in self.iterator.ops_and_items():
            # Check pushitem size first
            if item is not None:
                self.limits.validate_item_size(len(item))

            self.execute = (all(condition.execute for condition in self.conditions)
                            and (not non_top_level_return_after_genesis or op == OP_RETURN))

            # Pushitem and OP_RESERVED do not count towards op count.
            if op > OP_16:
                self.bump_op_count(1)

            # Some op codes are disabled.  For pre-genesis UTXOs these were an error in
            # unevaluated branches; for post-genesis UTXOs only if evaluated.
            if op in {Ops.OP_2MUL, Ops.OP_2DIV} and (self.execute or
                                                     not self.limits.is_utxo_after_genesis):
                raise DisabledOpcode(f'{Ops(op).name} is disabled')

            if self.execute and item is not None:
                self.limits.validate_minimal_push_opcode(op, item)
                self.stack.append(item)
            elif self.execute or OP_IF <= op <= OP_ENDIF:
                try:
                    handlers[op](self)
                except OpReturnError:
                    if not self.limits.is_utxo_after_genesis:
                        raise
                    # A top-level post-geneis OP_RETURN terminates successfully, ignoring
                    # the rest of the script even in the presence of unbalanced IFs,
                    # invalid opcodes etc.  Otherwise the grammar is checked.
                    if not self.conditions:
                        return
                    non_top_level_return_after_genesis = True

            self.validate_stack_size()

        if self.conditions:
            raise UnbalancedConditional(f'unterminated {self.conditions[-1].opcode.name} '
                                        'at end of script')

    #
    # Control
    #
    def on_NOP(self):
        pass

    def on_IF(self, op):
        execute = False
        if self.execute:
            self.require_stack_depth(1)
            top = self.stack[-1]
            if top not in bool_items and self.limits.flags & InterpreterFlags.REQUIRE_MINIMAL_IF:
                raise MinimalIfError('top of stack not True or False')
            self.stack.pop()
            execute = cast_to_bool(top)
            if op == Ops.OP_NOTIF:
                execute = not execute
        self.conditions.append(Condition(op, execute, False))

    def on_ELSE(self):
        top_condition = self.conditions[-1] if self.conditions else None
        # Only one ELSE is allowed per condition block after genesis
        if not top_condition or (top_condition.seen_else and self.limits.is_utxo_after_genesis):
            raise UnbalancedConditional('unexpected OP_ELSE')
        top_condition.execute = not top_condition.execute
        top_condition.seen_else = True

    def on_ENDIF(self):
        # Only one ELSE is allowed per condition block after genesis
        if not self.conditions:
            raise UnbalancedConditional('unexpected OP_ENDIF')
        self.conditions.pop()

    def on_VERIF(self, op):
        # Post-genesis UTXOs permit OP_VERIF and OP_NOTVERIF in unexecuted branches
        if self.limits.is_utxo_after_genesis and not self.execute:
            return
        self.on_invalid_opcode(op)

    def on_VERIFY(self):
        # (true -- ) or (false -- false) and return
        self.require_stack_depth(1)
        if not cast_to_bool(self.stack[-1]):
            raise VerifyFailed()
        self.stack.pop()

    def on_RETURN(self):
        raise OpReturnError('OP_RETURN encountered')

    def on_invalid_opcode(self, op):
        try:
            name = Ops(op).name
        except ValueError:
            name = str(op)

        raise InvalidOpcode(f'invalid opcode {name}')

    #
    # Stack operations
    #
    def on_TOALTSTACK(self):
        self.require_stack_depth(1)
        self.alt_stack.append(self.stack.pop())

    def on_FROMALTSTACK(self):
        self.require_alt_stack()
        self.stack.append(self.alt_stack.pop())

    def on_DROP(self):
        # (x -- )
        self.require_stack_depth(1)
        self.stack.pop()

    def on_2DROP(self):
        # (x1 x2 -- )
        self.require_stack_depth(2)
        self.stack.pop()
        self.stack.pop()

    def on_nDUP(self, n):
        # (x -- x x) or (x1 x2 -- x1 x2 x1 x2) or (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
        self.require_stack_depth(n)
        self.stack.extend(self.stack[-n:])

    def on_OVER(self):
        # (x1 x2 -- x1 x2 x1)
        self.require_stack_depth(2)
        self.stack.append(self.stack[-2])

    def on_2OVER(self):
        # (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
        self.require_stack_depth(4)
        self.stack.extend(self.stack[-4: -2])

    def on_ROT(self):
        # (x1 x2 x3 -- x2 x3 x1)
        self.require_stack_depth(3)
        self.stack.append(self.stack.pop(-3))

    def on_2ROT(self):
        # (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
        self.require_stack_depth(6)
        self.stack.extend([self.stack.pop(-6), self.stack.pop(-5)])

    def on_SWAP(self):
        # ( x1 x2 -- x2 x1 )
        self.require_stack_depth(2)
        self.stack.append(self.stack.pop(-2))

    def on_2SWAP(self):
        # (x1 x2 x3 x4 -- x3 x4 x1 x2)
        self.require_stack_depth(4)
        self.stack.extend([self.stack.pop(-4), self.stack.pop(-3)])

    def on_IFDUP(self):
        # (x - 0 | x x)
        self.require_stack_depth(1)
        last = self.stack[-1]
        if cast_to_bool(last):
            self.stack.append(last)

    def on_DEPTH(self):
        # ( -- stacksize)
        self.stack.append(int_to_item(len(self.stack)))

    def on_NIP(self):
        # (x1 x2 -- x2)
        self.require_stack_depth(2)
        self.stack.pop(-2)

    def on_TUCK(self):
        # ( x1 x2 -- x2 x1 x2 )
        self.require_stack_depth(2)
        self.stack.insert(-2, self.stack[-1])

    def on_PICK_ROLL(self, op):
        # pick: (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
        # roll: (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
        self.require_stack_depth(2)
        n = int(self.limits.to_number(self.stack[-1]))
        self.stack.pop()
        depth = len(self.stack)
        if not 0 <= n < depth:
            raise InvalidStackOperation(f'{op.name} with argument {n:,d} used '
                                        f'on stack with depth {depth:,d}')
        if op == Ops.OP_PICK:
            self.stack.append(self.stack[-(n + 1)])
        else:
            self.stack.append(self.stack.pop(-(n + 1)))

    #
    # Bitwise logic
    #
    def on_INVERT(self):
        # (x -- out)
        self.require_stack_depth(1)
        self.stack[-1] = bytes(x ^ 255 for x in self.stack[-1])

    def on_binary_bitop(self, binop):
        # (x1 x2 -- out)
        self.require_stack_depth(2)
        x1 = self.stack[-2]
        x2 = self.stack[-1]
        if len(x1) != len(x2):
            raise InvalidOperandSize('operands to bitwise operator must have same size')
        self.stack.pop()
        self.stack[-1] = bytes(binop(b1, b2) for b1, b2 in zip(x1, x2))

    def on_EQUAL(self):
        # (x1 x2 -- bool).   Bitwise equality
        self.require_stack_depth(2)
        self.stack.append(bool_items[self.stack.pop() == self.stack.pop()])

    def on_EQUALVERIFY(self):
        # (x1 x2 -- )
        self.on_EQUAL()
        if not cast_to_bool(self.stack[-1]):
            raise EqualVerifyFailed()
        self.stack.pop()

    def on_LSHIFT(self):
        # (x n -- out).   Logical bit-shift maintaining item size
        self.require_stack_depth(2)
        n = int(self.limits.to_number(self.stack[-1]))
        if n < 0:
            raise NegativeShiftCount(f'invalid shift left of {n:,d} bits')
        self.stack.pop()
        self.stack[-1] = shift_left(self.stack[-1], n)

    def on_RSHIFT(self):
        # (x n -- out).   Logical bit-shift maintaining item size
        self.require_stack_depth(2)
        n = int(self.limits.to_number(self.stack[-1]))
        if n < 0:
            raise NegativeShiftCount(f'invalid right left of {n:,d} bits')
        self.stack.pop()
        self.stack[-1] = shift_right(self.stack[-1], n)

    #
    # Numeric
    #
    def on_unary_numeric(self, unary_op):
        # (x -- out)
        self.require_stack_depth(1)
        value = self.limits.to_number(self.stack[-1])
        self.stack[-1] = int_to_item(unary_op(value))

    def on_binary_numeric(self, binary_op):
        # (x1 x2 -- out)
        self.require_stack_depth(2)
        x1 = self.limits.to_number(self.stack[-2])
        x2 = self.limits.to_number(self.stack[-1])
        try:
            result = binary_op(x1, x2)
        except ZeroDivisionError:
            raise DivisionByZero('division by zero' if binary_op is bitcoin_div
                                 else 'modulo by zero') from None
        self.stack.pop()
        self.stack[-1] = int_to_item(result)

    def on_NUMEQUALVERIFY(self):
        # (x1 x2 -- )
        self.on_binary_numeric(operator.eq)
        if not cast_to_bool(self.stack[-1]):
            raise NumEqualVerifyFailed('OP_NUMEQUALVERIFY failed')
        self.stack.pop()

    def on_WITHIN(self):
        # (x max min -- out)    True if x is >= min and < max.
        self.require_stack_depth(3)
        x = item_to_int(self.stack[-3])
        mn = item_to_int(self.stack[-2])
        mx = item_to_int(self.stack[-1])
        self.stack.pop()
        self.stack.pop()
        self.stack[-1] = bool_items[mn <= x < mx]

    #
    # Crypto
    #
    def on_hash(self, hash_func):
        # (x -- x x)
        self.require_stack_depth(1)
        self.stack.append(hash_func(self.stack.pop()))

    def on_CODESEPARATOR(self):
        # script_code starts after the code separator
        self.iterator.on_code_separator()

    def on_CHECKSIG(self, op):
        # (sig pubkey -- bool)
        check_sig = self.txin_context(op).check_sig
        self.require_stack_depth(2)
        sig_bytes = self.stack[-2]
        pubkey_bytes = self.stack[-1]
        self.limits.validate_signature(sig_bytes)
        self.limits.validate_pubkey(pubkey_bytes)
        script_code = self.iterator.script_code()
        script_code = self.limits.cleanup_script_code(sig_bytes, script_code)
        is_good = check_sig(sig_bytes, pubkey_bytes, script_code)
        if not is_good:
            self.limits.validate_nullfail(sig_bytes)
        self.stack.pop()
        self.stack[-1] = bool_items[is_good]

    def on_CHECKSIGVERIFY(self):
        # (sig pubkey -- )
        self.on_CHECKSIG(Ops.OP_CHECKSIGVERIFY)
        if not cast_to_bool(self.stack[-1]):
            raise CheckSigVerifyFailed('OP_CHECKSIGVERIFY failed')
        self.stack.pop()

    def on_CHECKMULTISIG(self, op):
        # ([sig ...] sig_count [pubkey ...] pubkey_count -- bool)
        check_sig = self.txin_context(op).check_sig

        self.require_stack_depth(1)
        # Limit key count to 4 bytes
        key_count = self.limits.to_number(self.stack[-1], length_limit=4)
        self.limits.validate_pubkey_count(key_count)
        self.bump_op_count(key_count)
        # Ensure we can read sig_count, also limited to 4 bytes
        self.require_stack_depth(key_count + 2)
        sig_count = self.limits.to_number(self.stack[-(key_count + 2)], length_limit=4)
        if not 0 <= sig_count <= key_count:
            raise InvalidSignatureCount(f'number of signatures, {sig_count:,d}, in {op.name} '
                                        f'lies outside range 0 <= count <= {key_count:,d}')

        # Ensure we have all the sigs
        item_count = key_count + sig_count + 2
        self.require_stack_depth(item_count)

        # Remove signatures for pre-BCH fork scripts
        cleanup_script_code = self.limits.cleanup_script_code
        script_code = self.iterator.script_code()
        first_sig_index = -(key_count + 3)
        for n in range(sig_count):
            script_code = cleanup_script_code(self.stack[first_sig_index - n], script_code)

        keys_remaining = key_count
        sigs_remaining = sig_count
        key_base_index = -(key_count + 2)
        sig_base_index = key_base_index - (sig_count + 1)
        # Loop while the remaining number of sigs to check does not exceed the remaining keys
        while keys_remaining >= sigs_remaining > 0:
            sig_bytes = self.stack[sig_base_index + sigs_remaining]
            self.limits.validate_signature(sig_bytes)
            pubkey_bytes = self.stack[key_base_index + keys_remaining]
            self.limits.validate_pubkey(pubkey_bytes)
            is_good = check_sig(sig_bytes, pubkey_bytes, script_code)
            if is_good:
                sigs_remaining -= 1
            keys_remaining -= 1

        is_good = keys_remaining >= sigs_remaining

        # Clean up the stack
        for n in range(item_count):
            # If the operation failed NULLFAIL requires all signatures be empty
            if not is_good and n >= key_count + 2:
                self.limits.validate_nullfail(self.stack[-1])
            self.stack.pop()

        # An old CHECKMULTISIG bug consumes an extra argument.  Check it's null.
        self.require_stack_depth(1)
        self.limits.validate_nulldummy(self.stack[-1])
        self.stack[-1] = bool_items[is_good]

    def on_CHECKMULTISIGVERIFY(self):
        # ([sig ...] sig_count [pubkey ...] pubkey_count -- )
        self.on_CHECKMULTISIG(Ops.OP_CHECKMULTISIGVERIFY)
        if not cast_to_bool(self.stack[-1]):
            raise CheckMultiSigVerifyFailed('OP_CHECKMULTISIGVERIFY failed')
        self.stack.pop()

    #
    # Byte string operations
    #
    def on_CAT(self):
        # (x1 x2 -- x1x2 )
        self.require_stack_depth(2)
        item = self.stack[-2] + self.stack[-1]
        self.limits.validate_item_size(len(item))
        self.stack.pop()
        self.stack[-1] = item

    def on_SPLIT(self):
        # (x posiition -- x1 x2)
        self.require_stack_depth(2)
        x = self.stack[-2]
        n = int(self.limits.to_number(self.stack[-1]))
        if not 0 <= n <= len(x):
            raise InvalidSplit(f'cannot split item of length {len(x):,d} at position {n:,d}')
        self.stack[-2] = x[:n]
        self.stack[-1] = x[n:]

    def on_NUM2BIN(self):
        # (in size -- out)  encode the value of "in" in size bytes
        self.require_stack_depth(2)
        size = int(self.limits.to_number(self.stack[-1]))
        if size < 0 or size > INT32_MAX:
            raise InvalidPushSize(f'invalid size {size:,d} in OP_NUM2BIN operation')
        self.limits.validate_item_size(size)
        self.stack.pop()
        self.stack[-1] = int_to_item(item_to_int(self.stack[-1]), size)

    def on_BIN2NUM(self):
        # (in -- out)    minimally encode in as a number
        self.require_stack_depth(1)
        self.stack[-1] = minimal_encoding(self.stack[-1])
        self.limits.validate_number_length(len(self.stack[-1]))

    def on_SIZE(self):
        # ( x -- x size(x) )
        self.require_stack_depth(1)
        size = len(self.stack[-1])
        self.stack.append(int_to_item(size))

    #
    # Expansion
    #
    def on_upgradeable_nop(self, op):
        self.limits.validate_upgradeable_nop(op)

    def on_CHECKLOCKTIMEVERIFY(self):
        if not self.limits.flags & InterpreterFlags.ENABLE_CHECKLOCKTIMEVERIFY:
            self.on_upgradeable_nop(Ops.OP_NOP2)
        else:
            context = self.txin_context(Ops.OP_CHECKLOCKTIMEVERIFY)
            self.require_stack_depth(1)
            locktime = self.limits.to_number(self.stack[-1], length_limit=5)
            if locktime < 0:
                raise LockTimeError(f'locktime {locktime:,d} is negative')
            context.validate_locktime(locktime)

    def on_CHECKSEQUENCEVERIFY(self):
        if not self.limits.flags & InterpreterFlags.ENABLE_CHECKSEQUENCEVERIFY:
            self.on_upgradeable_nop(Ops.OP_NOP3)
        else:
            context = self.txin_context(Ops.OP_CHECKSEQUENCEVERIFY)
            self.require_stack_depth(1)
            sequence = self.limits.to_number(self.stack[-1], length_limit=5)
            if sequence < 0:
                raise LockTimeError(f'sequence {sequence:,d} is negative')
            context.validate_sequence(sequence)

    @classmethod
    def bind_handlers(cls):
        handlers = [partial(cls.on_invalid_opcode, op=op) for op in range(256)]

        #
        # Control
        #
        handlers[Ops.OP_NOP] = cls.on_NOP
        handlers[Ops.OP_VER] = partial(cls.on_invalid_opcode, op=Ops.OP_VER)
        handlers[Ops.OP_IF] = partial(cls.on_IF, op=Ops.OP_IF)
        handlers[Ops.OP_NOTIF] = partial(cls.on_IF, op=Ops.OP_NOTIF)
        handlers[Ops.OP_VERIF] = partial(cls.on_VERIF, op=Ops.OP_VERIF)
        handlers[Ops.OP_VERNOTIF] = partial(cls.on_VERIF, op=Ops.OP_VERNOTIF)
        handlers[Ops.OP_ELSE] = cls.on_ELSE
        handlers[Ops.OP_ENDIF] = cls.on_ENDIF
        handlers[Ops.OP_VERIFY] = cls.on_VERIFY
        handlers[Ops.OP_RETURN] = cls.on_RETURN

        #
        # Stack operations
        #
        handlers[Ops.OP_TOALTSTACK] = cls.on_TOALTSTACK
        handlers[Ops.OP_FROMALTSTACK] = cls.on_FROMALTSTACK
        handlers[Ops.OP_DROP] = cls.on_DROP
        handlers[Ops.OP_2DROP] = cls.on_2DROP
        handlers[Ops.OP_DUP] = partial(cls.on_nDUP, n=1)
        handlers[Ops.OP_2DUP] = partial(cls.on_nDUP, n=2)
        handlers[Ops.OP_3DUP] = partial(cls.on_nDUP, n=3)
        handlers[Ops.OP_OVER] = cls.on_OVER
        handlers[Ops.OP_2OVER] = cls.on_2OVER
        handlers[Ops.OP_2ROT] = cls.on_2ROT
        handlers[Ops.OP_2SWAP] = cls.on_2SWAP
        handlers[Ops.OP_IFDUP] = cls.on_IFDUP
        handlers[Ops.OP_DEPTH] = cls.on_DEPTH
        handlers[Ops.OP_NIP] = cls.on_NIP
        handlers[Ops.OP_PICK] = partial(cls.on_PICK_ROLL, op=Ops.OP_PICK)
        handlers[Ops.OP_ROLL] = partial(cls.on_PICK_ROLL, op=Ops.OP_ROLL)
        handlers[Ops.OP_ROT] = cls.on_ROT
        handlers[Ops.OP_SWAP] = cls.on_SWAP
        handlers[Ops.OP_TUCK] = cls.on_TUCK

        #
        # Byte string operations
        #
        handlers[Ops.OP_CAT] = cls.on_CAT
        handlers[Ops.OP_SPLIT] = cls.on_SPLIT
        handlers[Ops.OP_NUM2BIN] = cls.on_NUM2BIN
        handlers[Ops.OP_BIN2NUM] = cls.on_BIN2NUM
        handlers[Ops.OP_SIZE] = cls.on_SIZE

        #
        # Bitwise logic
        #
        handlers[Ops.OP_INVERT] = cls.on_INVERT
        handlers[Ops.OP_AND] = partial(cls.on_binary_bitop, binop=operator.and_)
        handlers[Ops.OP_OR] = partial(cls.on_binary_bitop, binop=operator.or_)
        handlers[Ops.OP_XOR] = partial(cls.on_binary_bitop, binop=operator.xor)
        handlers[Ops.OP_EQUAL] = cls.on_EQUAL
        handlers[Ops.OP_EQUALVERIFY] = cls.on_EQUALVERIFY
        handlers[Ops.OP_LSHIFT] = cls.on_LSHIFT
        handlers[Ops.OP_RSHIFT] = cls.on_RSHIFT

        #
        # Numeric
        #
        handlers[Ops.OP_1ADD] = partial(cls.on_unary_numeric, unary_op=lambda x: x + 1)
        handlers[Ops.OP_1SUB] = partial(cls.on_unary_numeric, unary_op=lambda x: x - 1)
        # OP_2MUL = 0x8d
        # OP_2DIV = 0x8e
        handlers[Ops.OP_NEGATE] = partial(cls.on_unary_numeric, unary_op=operator.neg)
        handlers[Ops.OP_ABS] = partial(cls.on_unary_numeric, unary_op=operator.abs)
        handlers[Ops.OP_NOT] = partial(cls.on_unary_numeric, unary_op=operator.not_)
        handlers[Ops.OP_0NOTEQUAL] = partial(cls.on_unary_numeric, unary_op=operator.truth)
        handlers[Ops.OP_ADD] = partial(cls.on_binary_numeric, binary_op=operator.add)
        handlers[Ops.OP_SUB] = partial(cls.on_binary_numeric, binary_op=operator.sub)
        handlers[Ops.OP_MUL] = partial(cls.on_binary_numeric, binary_op=operator.mul)
        handlers[Ops.OP_DIV] = partial(cls.on_binary_numeric, binary_op=bitcoin_div)
        handlers[Ops.OP_MOD] = partial(cls.on_binary_numeric, binary_op=bitcoin_mod)
        handlers[Ops.OP_BOOLAND] = partial(cls.on_binary_numeric, binary_op=logical_and)
        handlers[Ops.OP_BOOLOR] = partial(cls.on_binary_numeric, binary_op=logical_or)
        handlers[Ops.OP_NUMEQUAL] = partial(cls.on_binary_numeric, binary_op=operator.eq)
        handlers[Ops.OP_NUMEQUALVERIFY] = cls.on_NUMEQUALVERIFY
        handlers[Ops.OP_NUMNOTEQUAL] = partial(cls.on_binary_numeric, binary_op=operator.ne)
        handlers[Ops.OP_LESSTHAN] = partial(cls.on_binary_numeric, binary_op=operator.lt)
        handlers[Ops.OP_GREATERTHAN] = partial(cls.on_binary_numeric, binary_op=operator.gt)
        handlers[Ops.OP_LESSTHANOREQUAL] = partial(cls.on_binary_numeric, binary_op=operator.le)
        handlers[Ops.OP_GREATERTHANOREQUAL] = partial(cls.on_binary_numeric, binary_op=operator.ge)
        handlers[Ops.OP_MIN] = partial(cls.on_binary_numeric, binary_op=min)
        handlers[Ops.OP_MAX] = partial(cls.on_binary_numeric, binary_op=max)
        handlers[Ops.OP_WITHIN] = cls.on_WITHIN

        #
        # Crypto
        #
        handlers[Ops.OP_RIPEMD160] = partial(cls.on_hash, hash_func=ripemd160)
        handlers[Ops.OP_SHA1] = partial(cls.on_hash, hash_func=sha1)
        handlers[Ops.OP_SHA256] = partial(cls.on_hash, hash_func=sha256)
        handlers[Ops.OP_HASH160] = partial(cls.on_hash, hash_func=hash160)
        handlers[Ops.OP_HASH256] = partial(cls.on_hash, hash_func=double_sha256)
        handlers[Ops.OP_CODESEPARATOR] = cls.on_CODESEPARATOR
        handlers[Ops.OP_CHECKSIG] = partial(cls.on_CHECKSIG, op=Ops.OP_CHECKSIG)
        handlers[Ops.OP_CHECKSIGVERIFY] = cls.on_CHECKSIGVERIFY
        handlers[Ops.OP_CHECKMULTISIG] = partial(cls.on_CHECKMULTISIG, op=Ops.OP_CHECKMULTISIG)
        handlers[Ops.OP_CHECKMULTISIGVERIFY] = cls.on_CHECKMULTISIGVERIFY

        #
        # Expansion
        #
        for _op in (Ops.OP_NOP1, Ops.OP_NOP4, Ops.OP_NOP5, Ops.OP_NOP6, Ops.OP_NOP7,
                    Ops.OP_NOP8, Ops.OP_NOP9, Ops.OP_NOP10):
            handlers[_op] = partial(cls.on_upgradeable_nop, op=_op)
        handlers[Ops.OP_NOP2] = cls.on_CHECKLOCKTIMEVERIFY
        handlers[Ops.OP_NOP3] = cls.on_CHECKSEQUENCEVERIFY

        cls._handlers = handlers


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


InterpreterState.bind_handlers()
