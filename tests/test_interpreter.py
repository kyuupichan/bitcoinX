import copy
import os
import random
from itertools import product

import pytest

from bitcoinx.consts import (
    UINT32_MAX, INT32_MAX, INT64_MAX, UINT64_MAX, SEQUENCE_FINAL,
    SEQUENCE_LOCKTIME_DISABLE_FLAG, SEQUENCE_LOCKTIME_TYPE_FLAG,
)
from bitcoinx.errors import *
from bitcoinx.hashes import ripemd160, hash160, sha1, sha256, double_sha256
from bitcoinx.interpreter import *
from bitcoinx.script import *
from bitcoinx import (
    pack_varint, PrivateKey, pack_byte, varint_len, SigHash,
    compact_signature_to_der, der_signature_to_compact, CURVE_ORDER, be_bytes_to_int,
    int_to_be_bytes,
)

from .utils import random_tx, read_tx, random_value, zeroes, non_zeroes


policies = [
    # A fairly restrictive policy
    InterpreterPolicy(100_000, 64, 20_000, 1_000, 16),
    # A loose policy
    InterpreterPolicy(10_000_000, 256, 10_000_000, 32_000, 256),
]


@pytest.fixture(params=policies)
def policy(request):
    yield request.param


def create_interpreter_limits():
    args_s = (
        (True, True, True),
        (True, True, False),
        (True, False, True),
        (True, False, False),
        (False, False, True),
        (False, False, False),
    )
    return [InterpreterLimits.from_policy(policy, *args)
            for policy in policies for args in args_s]

all_interpreter_limits = create_interpreter_limits()


@pytest.fixture(params=all_interpreter_limits)
def limits(request):
    yield copy.copy(request.param)


@pytest.fixture(params=[l for l in all_interpreter_limits if not l.is_utxo_after_genesis])
def old_limits(request):
    yield copy.copy(request.param)


@pytest.fixture(params=(
    0,
    InterpreterFlags.REQUIRE_STRICT_DER,
    InterpreterFlags.REQUIRE_LOW_S,
    InterpreterFlags.REQUIRE_STRICT_ENCODING,
    InterpreterFlags.REQUIRE_MINIMAL_PUSH,
    InterpreterFlags.ENABLE_FORKID,
))
def checksig_state(request, limits):
    tx = random_tx(False)
    input_index = random.randrange(0, len(tx.inputs))
    value = random_value()
    yield InterpreterState(limits, flags=request.param, tx=tx, input_index=input_index,
                           value=value)


@pytest.fixture(params=(0, InterpreterFlags.REQUIRE_MINIMAL_PUSH))
def checklocktime_state(old_limits, request):
    tx = random_tx(False)
    input_index = random.randrange(0, len(tx.inputs))
    value = random_value()
    flags = request.param + (InterpreterFlags.ENABLE_CHECKLOCKTIMEVERIFY
                             | InterpreterFlags.ENABLE_CHECKSEQUENCEVERIFY)
    yield InterpreterState(old_limits, flags=flags, tx=tx, input_index=input_index, value=value)


@pytest.fixture(params=(0, InterpreterFlags.REQUIRE_MINIMAL_PUSH, ))
def numeric_state(request, limits):
    yield InterpreterState(limits, flags=request.param)


@pytest.fixture(params=(
    0,
    InterpreterFlags.REQUIRE_PUSH_ONLY,
    InterpreterFlags.ENABLE_FORKID,
    InterpreterFlags.ENABLE_P2SH,
    InterpreterFlags.REQUIRE_CLEANSTACK | InterpreterFlags.ENABLE_P2SH,
))
def verify_state(request, limits):
    yield InterpreterState(limits, flags=request.param)


@pytest.fixture(params=(
    InterpreterFlags.ENABLE_P2SH,
    InterpreterFlags.ENABLE_P2SH | InterpreterFlags.REQUIRE_MINIMAL_PUSH,
))
def P2SH_state(old_limits, request):
    yield InterpreterState(old_limits, flags=request.param, value=0)


def random_sighash(state, valid=True):
    choices = [SigHash.ALL, SigHash.NONE]
    if state.input_index < len(state.tx.outputs):
        choices.append(SigHash.SINGLE)
    choices += [value | SigHash.ANYONE_CAN_PAY for value in choices]
    if not (valid ^ bool(state.flags & InterpreterFlags.ENABLE_FORKID)):
        choices = [choice + SigHash.FORKID for choice in choices]
    if not valid:
        choices = choices + [choice + 0x10 for choice in choices]
    return SigHash(random.choice(choices))


@pytest.fixture(params=(0, InterpreterFlags.REQUIRE_MINIMAL_PUSH))
def state(limits, request):
    yield InterpreterState(limits, flags=request.param)



# Note: this is just SIGHASH_ALL without FORKID
high_S_sig = '302502010102207fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a101'
undefined_sighash_sig = '300602010102010100'
has_forkid_sig = '300602010102010142'
no_forkid_sig = '300602010102010103'


class TestInterpreterLimits:

    @pytest.mark.parametrize('is_genesis_enabled, is_utxo_after_genesis, is_consensus',
                             product((False, True), (False, True), (False, True)))
    def test_from_policy(self, policy, is_genesis_enabled, is_utxo_after_genesis, is_consensus):
        if is_utxo_after_genesis and not is_genesis_enabled:
            with pytest.raises(ValueError):
                InterpreterLimits.from_policy(policy, is_genesis_enabled, is_utxo_after_genesis,
                                              is_consensus)
            return

        limits = InterpreterLimits.from_policy(policy, is_genesis_enabled,
                                               is_utxo_after_genesis, is_consensus)

        # Test script_size
        if is_genesis_enabled:
            if is_consensus:
                assert limits.script_size == UINT32_MAX
            else:
                assert limits.script_size == policy.max_script_size
        else:
            assert limits.script_size == 10_000

        # Test script_num_length
        if is_utxo_after_genesis:
            if is_consensus:
                assert limits.script_num_length == 750 * 1000
            else:
                assert limits.script_num_length == policy.max_script_num_length
        else:
            assert limits.script_num_length == 4

        # Test stack_memory_usage
        if is_utxo_after_genesis:
            if is_consensus:
                assert limits.stack_memory_usage == INT64_MAX
            else:
                assert limits.stack_memory_usage == policy.max_stack_memory_usage
        else:
            assert limits.stack_memory_usage == INT64_MAX

        # Test ops_per_script
        if is_genesis_enabled:
            if is_consensus:
                assert limits.ops_per_script == UINT32_MAX
            else:
                assert limits.ops_per_script == policy.max_ops_per_script
        else:
            assert limits.ops_per_script == 500

        # Test pubkeys_per_multisig
        if is_utxo_after_genesis:
            if is_consensus:
                assert limits.pubkeys_per_multisig == UINT32_MAX
            else:
                assert limits.pubkeys_per_multisig == policy.max_pubkeys_per_multisig
        else:
            assert limits.pubkeys_per_multisig == 20

        # Max item size
        if is_utxo_after_genesis:
            assert limits.item_size == UINT64_MAX
        else:
            assert limits.item_size == 520

        assert limits.is_utxo_after_genesis is limits.is_utxo_after_genesis


class TestInterpreterState:

    def test_validate_item_size(self, state):
        state.validate_item_size(state.limits.item_size)
        with pytest.raises(InvalidPushSize):
            state.validate_item_size(state.limits.item_size + 1)

    def test_bump_op_count(self, state):
        state.bump_op_count(state.limits.ops_per_script)
        with pytest.raises(TooManyOps):
            state.bump_op_count(1)

    def test_validate_minimal_push_opcode(self, state):
        if state.flags & InterpreterFlags.REQUIRE_MINIMAL_PUSH:
            with pytest.raises(MinimalEncodingError):
                state.validate_minimal_push_opcode(OP_PUSHDATA1, b'\1')
        else:
            state.validate_minimal_push_opcode(OP_PUSHDATA1, b'\1')

    def test_validate_stack_size(self, state):
        state.stack = [b''] * InterpreterLimits.MAX_STACK_ELEMENTS_BEFORE_GENESIS
        if state.limits.is_utxo_after_genesis:
            state.alt_stack = [b'']
            state.validate_stack_size()
        else:
            state.stack = [b''] * InterpreterLimits.MAX_STACK_ELEMENTS_BEFORE_GENESIS
            state.alt_stack = []
            state.validate_stack_size()
            state.alt_stack.append(b'')
            with pytest.raises(StackSizeTooLarge):
                state.validate_stack_size()
        state.reset()


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
    def test_validate_signature(self, limits, sig_hex, flags, err_text):
        sig_bytes = bytes.fromhex(sig_hex)
        state = InterpreterState(limits, flags=flags)
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
    def test_validate_pubkey(self, limits, pubkey, flags, fail):
        pubkey_bytes = bytes.fromhex(pubkey)
        state = InterpreterState(limits, flags=flags)
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
    def test_cleanup_script_code(self, limits, sig_hex, flags, script_code, result):
        sig_bytes = bytes.fromhex(sig_hex)
        state = InterpreterState(limits, flags=flags)
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
    def test_validate_nullfail(self, limits, sig_hex, flags, raises):
        sig_bytes = bytes.fromhex(sig_hex)
        state = InterpreterState(limits, flags=flags)
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
    def test_to_number_failures(self, limits, number, flags, after_genesis, value):
        if after_genesis != limits.is_utxo_after_genesis:
            return
        state = InterpreterState(limits, flags=flags)
        number = bytes.fromhex(number)
        if not isinstance(value, int):
            with pytest.raises(value):
                state.to_number(number)
        else:
            assert state.to_number(number) == value


reserved_ops = (OP_VER, OP_RESERVED, OP_RESERVED1, OP_RESERVED2)


def value_bytes(x):
    #if isinstance(x, bytes):
    #    return x
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
        # Don't allocate too much!
        state.limits.script_size = limit = min(state.limits.script_size, 2_000_000)
        # Ensure we don't fail annoyingly
        state.stack.size_limit = limit + 100
        state.limits.item_size = limit
        script = Script() << bytes(limit - varint_len(limit))
        state.evaluate_script(script)
        script = Script() << bytes(limit)
        with pytest.raises(ScriptTooLarge):
            state.evaluate_script(script)

    def test_validate_item_size(self, state):
        # No limits after genesis
        if state.limits.is_utxo_after_genesis:
            # Avoid blowing up on other rules
            state.limits.script_size = 1_000_010
            state.stack.size_limit = 1_000_100
            script = Script() << bytes(1_000_000)
            state.evaluate_script(script)
        else:
            limit = InterpreterLimits.MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS
            script = Script() << bytes(limit)
            state.evaluate_script(script)
            state.reset()
            script = Script() << bytes(limit + 1)
            with pytest.raises(InvalidPushSize):
                state.evaluate_script(script)

    def test_max_ops_per_script_good(self, state):
        state.limits.ops_per_script = 2
        # Pushes do not contribute to limit
        script = Script() << 15 << OP_NOP << b'foo' << OP_NOP << OP_15
        state.evaluate_script(script)

    def test_max_ops_per_script_op_reserved(self, state):
        state.limits.ops_per_script = 2
        # OP_RESERVED does not contribute to limit
        script = Script() << OP_0 << OP_IF << OP_RESERVED << OP_ENDIF
        state.evaluate_script(script)

    def test_max_ops_per_script_bad(self, state):
        state.limits.ops_per_script = 2
        script = Script() << OP_1 << OP_IF << OP_NOP << OP_ENDIF
        with pytest.raises(TooManyOps):
            state.evaluate_script(script)

    def test_stack_memory_usage_limit(self, policy):
        item = bytes(100)
        count = 20
        overhead = 32
        limit = count * (overhead + len(item))

        limits = InterpreterLimits(1_000_000, 2048, limit, 1_000, 64, 1_000, True)
        # Apply the policy limit
        state = InterpreterState(limits)
        script = Script().push_many([item] * count)
        # Should work fine
        state.evaluate_script(script)
        assert state.stack.combined_size() == state.stack.size_limit

        # Test the alt-stack is counted
        state.reset()
        script = Script().push_many([item] * (count - 1) + [OP_TOALTSTACK, OP_DUP])
        # Should work fine
        state.evaluate_script(script)
        assert state.stack.combined_size() == state.stack.size_limit

        # Reduce the limit by 1
        limits = InterpreterLimits(1_000_000, 2048, limit - 1, 1_000, 64, 1_000, True)
        state = InterpreterState(limits)
        script = Script().push_many([item] * count)
        with pytest.raises(StackMemoryUsageError):
            state.evaluate_script(script)
        assert state.stack.combined_size() == state.stack.size_limit - (len(item) + overhead - 1)

        # Test the alt-stack is counted
        state.reset()
        script = Script().push_many([item] * (count - 1) + [OP_TOALTSTACK, OP_DUP])
        with pytest.raises(StackMemoryUsageError):
            state.evaluate_script(script)
        assert state.stack.combined_size() == state.stack.size_limit - (len(item) + overhead - 1)

    @pytest.mark.parametrize("op", (OP_2MUL, OP_2DIV))
    def test_disabled_opcodes(self, state, op):
        script = Script() << op
        with pytest.raises(DisabledOpcode) as e:
            state.evaluate_script(script)
        assert str(e.value) == f'{op.name} is disabled'

        script = Script() << OP_0 << OP_IF << op << OP_ENDIF
        # After genesis they are OK in unexecuted branches
        if state.limits.is_utxo_after_genesis:
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
        if state.limits.is_utxo_after_genesis:
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
    def test_minimal_push_executed(self, state, flags):
        state.flags = flags
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
    def test_minimal_push_unexecuted(self, state, flags):
        state.flags = flags
        # Not executed, not a problem
        script = Script(bytes([OP_0, OP_IF, 1, 5, OP_ENDIF]))
        state.evaluate_script(script)

    @pytest.mark.parametrize("big", (True, False))
    def test_validate_stack_size(self, state, big):
        script = Script().push_many([OP_1] * InterpreterLimits.MAX_STACK_ELEMENTS_BEFORE_GENESIS)
        if big:
            state.alt_stack = [b'']
        if state.limits.is_utxo_after_genesis or not big:
            state.stack.size_limit = 1_000_000
            state.evaluate_script(script)
        else:
            with pytest.raises(StackSizeTooLarge):
                state.evaluate_script(script)

    @pytest.mark.parametrize("op", (OP_NOP1, OP_NOP2, OP_NOP3, OP_NOP4, OP_NOP5,
                                    OP_NOP6, OP_NOP7, OP_NOP8, OP_NOP9, OP_NOP10))
    def test_upgradeable_nops(self, state, op):
        # Not testing lock time junk
        if op in {OP_NOP2, OP_NOP3} and not state.limits.is_utxo_after_genesis:
            return
        script = Script() << op

        # No effect with no flags
        state.evaluate_script(script)

        # Reject with flags
        state.flags = InterpreterFlags.REJECT_UPGRADEABLE_NOPS
        with pytest.raises(UpgradeableNopError) as e:
            state.evaluate_script(script)
        assert str(e.value) == f'encountered upgradeable NOP {op.name}'

    def test_invalid_opcode(self, state):
        script = Script(b'\xff')
        with pytest.raises(InvalidOpcode) as e:
            state.evaluate_script(script)
        assert 'invalid opcode 255' in str(e.value)

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


class TestVerifyScript(TestEvaluateScriptBase):

    @pytest.mark.parametrize('result', (True, False))
    def test_sig_push_only(self, verify_state, result):
        state = verify_state
        script_sig = Script() << OP_0 << OP_DROP << int(result)
        script_pubkey = Script()
        if state.flags & InterpreterFlags.REQUIRE_PUSH_ONLY:
            with pytest.raises(PushOnlyError):
                state.verify_script(script_sig, script_pubkey)
        else:
            assert state.verify_script(script_sig, script_pubkey) is result

    @pytest.mark.parametrize('script_sig, script_pubkey, triggers, result', (
        (Script(), Script(), False, False),
        (Script() << OP_0, Script() << OP_DROP, False, False),
        (Script() << OP_1 << OP_2, Script() << OP_DROP, False, True),
        (Script() << OP_0 << OP_2, Script() << OP_DROP, False, False),
        (Script() << OP_0 << OP_2 << OP_1, Script() << OP_DROP, True, True),
        (Script() << OP_0 << OP_0, Script(), False, False),
        (Script() << OP_1 << OP_2, Script(), True, True),
        (Script() << OP_0 << OP_1 << OP_1, Script() << OP_2DROP, False, False),
    ))
    def test_cleanstack(self, verify_state, script_sig, script_pubkey, triggers, result):
        state = verify_state
        if state.flags & InterpreterFlags.REQUIRE_CLEANSTACK and triggers:
            with pytest.raises(CleanStackError):
                state.verify_script(script_sig, script_pubkey)
        else:
            assert state.verify_script(script_sig, script_pubkey) is result

    @pytest.mark.parametrize('succeed', (True, False))
    def test_P2SH_spend(self, P2SH_state, succeed):
        state = P2SH_state
        # funding transaction a0f1aaa2fb4582c89e0511df0374a5a2833bf95f7314f4a51b55b7b71e90ce0f
        script_pubkey = Script.from_hex('a914748284390f9e263a4b766a75d0633c50426eb87587')

        # A P2SH 1-of-2 multisig
        spending_tx = read_tx('4d8eabfc.txn')
        input_index = 2

        state.tx = spending_tx
        state.input_index = input_index

        # Test success and failure by modifying an output
        spending_tx.outputs[0].value += not succeed
        script_sig = spending_tx.inputs[input_index].script_sig

        assert state.verify_script(script_sig, script_pubkey) is succeed

    def test_P2SH_push_only(self, P2SH_state):
        state = P2SH_state
        script_pubkey = Script.from_hex('a914748284390f9e263a4b766a75d0633c50426eb87587')

        # A P2SH 1-of-2 multisig
        spending_tx = read_tx('4d8eabfc.txn')
        input_index = 2

        state.tx = spending_tx
        state.input_index = input_index

        # Prepend an OP_NOP
        script_sig = Script(pack_byte(OP_NOP) + bytes(spending_tx.inputs[input_index].script_sig))

        with pytest.raises(PushOnlyError) as e:
            state.verify_script(script_sig, script_pubkey)
        assert 'P2SH script_sig is not pushdata only' == str(e.value)


class TestObsoleteCoreGarbage(TestEvaluateScriptBase):

    def test_CLTV_negative(self, checklocktime_state):
        state = checklocktime_state
        self.require_stack(state, 1, OP_CHECKLOCKTIMEVERIFY)
        script = Script() << OP_1NEGATE << OP_CHECKLOCKTIMEVERIFY
        with pytest.raises(LockTimeError) as e:
            state.evaluate_script(script)
        assert f'locktime -1 is negative' in str(e.value)

    def test_CLTV_number_length(self, checklocktime_state):
        state = checklocktime_state
        script = Script() << bytes(6) << OP_CHECKLOCKTIMEVERIFY
        with pytest.raises(InvalidNumber) as e:
            state.evaluate_script(script)

    def test_CLTV_minimal(self, checklocktime_state):
        state = checklocktime_state
        state.tx.locktime = 1
        state.tx.inputs[state.input_index].sequence = 5000
        script = Script() << bytes(5) << OP_CHECKLOCKTIMEVERIFY
        if state.flags & InterpreterFlags.REQUIRE_MINIMAL_PUSH:
            with pytest.raises(MinimalEncodingError):
                state.evaluate_script(script)
        else:
            state.evaluate_script(script)
        # Nothing is popped
        assert len(state.stack) == 1

    @pytest.mark.parametrize("locktime, tx_locktime, is_final, text", (
        (499_000_000, 1_000_000_000, None, 'locktimes are not comparable'),
        (1_000_000_000, 499_000_000, None, 'locktimes are not comparable'),
        (1_234_567, 800_000, None, 'locktime 1,234,567 not reached'),
        (800_000, 800_000, False, None),
        (100_000, 800_000, False, None),
        (800_000, 800_000, True, 'transaction input is final'),
        (100_000, 800_000, True, 'transaction input is final'),
    ))
    def test_CLTV(self, checklocktime_state, locktime, tx_locktime, is_final, text):
        state = checklocktime_state
        state.tx.locktime = tx_locktime
        state.tx.inputs[state.input_index].sequence = SEQUENCE_FINAL if is_final else 5000
        script = Script() << locktime << OP_CHECKLOCKTIMEVERIFY
        if text is None:
            state.evaluate_script(script)
        else:
            with pytest.raises(LockTimeError) as e:
                state.evaluate_script(script)
            assert text in str(e.value)
        assert len(state.stack) == 1

    def test_CSV_negative(self, checklocktime_state):
        state = checklocktime_state
        self.require_stack(state, 1, OP_CHECKSEQUENCEVERIFY)
        script = Script() << OP_1NEGATE << OP_CHECKSEQUENCEVERIFY
        with pytest.raises(LockTimeError) as e:
            state.evaluate_script(script)
        assert f'sequence -1 is negative' in str(e.value)

    def test_CSV_number_length(self, checklocktime_state):
        state = checklocktime_state
        script = Script() << bytes(6) << OP_CHECKSEQUENCEVERIFY
        with pytest.raises(InvalidNumber) as e:
            state.evaluate_script(script)

    def test_CSV_minimal(self, checklocktime_state):
        state = checklocktime_state
        state.tx = copy.copy(state.tx)
        state.tx.version = 2
        state.tx.inputs[state.input_index].sequence = 0
        script = Script() << bytes(5) << OP_CHECKSEQUENCEVERIFY
        if state.flags & InterpreterFlags.REQUIRE_MINIMAL_PUSH:
            with pytest.raises(MinimalEncodingError):
                state.evaluate_script(script)
        else:
            state.evaluate_script(script)
        # Nothing is popped
        assert len(state.stack) == 1

    def test_CSV_tx_version(self, checklocktime_state):
        state = checklocktime_state
        state.tx = copy.copy(state.tx)
        state.tx.version = random.randrange(-2, 2)
        state.tx.inputs[state.input_index].sequence = 500
        script = Script() << 0 << OP_CHECKSEQUENCEVERIFY
        if state.tx.version >= 0:
            with pytest.raises(LockTimeError) as e:
                state.evaluate_script(script)
            assert 'transaction version is under 2' in str(e.value)
        else:
            state.evaluate_script(script)
        assert len(state.stack) == 1

    @pytest.mark.parametrize("sequence, tx_sequence, text", (
        (SEQUENCE_LOCKTIME_DISABLE_FLAG + 20, 0, None),
        (SEQUENCE_LOCKTIME_DISABLE_FLAG + 20, 4_000_000_000, None),
        (0, SEQUENCE_LOCKTIME_DISABLE_FLAG + 20, 'transaction index sequence is disabled'),
        (500_000, SEQUENCE_LOCKTIME_DISABLE_FLAG + 20, 'transaction index sequence is disabled'),
        (SEQUENCE_LOCKTIME_TYPE_FLAG, 60_000, 'sequences are not comparable'),
        (60_000, SEQUENCE_LOCKTIME_TYPE_FLAG, 'sequences are not comparable'),
        (50_000, 40_000, 'masked sequence number 50,000 not reached'),
        (80_000, 10_000, 'masked sequence number 14,464 not reached'),
        (40_000, 50_000, None),
        (50_000, 50_000, None),
        (SEQUENCE_LOCKTIME_TYPE_FLAG + 5_000,
         SEQUENCE_LOCKTIME_TYPE_FLAG + 4_000, 'masked sequence number 4,199,304 not reached'),
        (SEQUENCE_LOCKTIME_TYPE_FLAG + 5_000, SEQUENCE_LOCKTIME_TYPE_FLAG + 6_000, None),
    ))
    def test_CSV(self, checklocktime_state, sequence, tx_sequence, text):
        state = checklocktime_state
        state.tx.version = random.randrange(2, 8)
        state.tx.inputs[state.input_index].sequence = tx_sequence
        script = Script() << sequence << OP_CHECKSEQUENCEVERIFY
        if text is None:
            state.evaluate_script(script)
        else:
            with pytest.raises(LockTimeError) as e:
                state.evaluate_script(script)
            assert text in str(e.value)
        assert len(state.stack) == 1


class TestNumeric(TestEvaluateScriptBase):

    @pytest.mark.parametrize("opcode", (OP_1ADD, OP_1SUB, OP_NEGATE, OP_ABS, OP_NOT, OP_0NOTEQUAL))
    def test_unary_numeric(self, numeric_state, opcode):
        self.require_stack(numeric_state, 1, opcode)

    @pytest.mark.parametrize("value, result, minimal", (
        (0, 1, True),
        (-1, 0, True,),
        (127, 128, True),
        (255, 256, True),
        (bytes(2), 1, False),
        (b'\0\x80', 1, False),
        (b'\1\x80', 0, False),
    ))
    def test_1ADD(self, numeric_state, value, result, minimal):
        state = numeric_state
        script = Script() << value << OP_1ADD
        if not minimal and state.flags & InterpreterFlags.REQUIRE_MINIMAL_PUSH:
            with pytest.raises(MinimalEncodingError):
                state.evaluate_script(script)
            assert len(state.stack) == 1
        else:
            state.evaluate_script(script)
            assert state.stack == [int_to_item(result)]
        assert not state.alt_stack

    @pytest.mark.parametrize("value, result, minimal", (
        (0, -1, True),
        (-1, -2, True),
        (127, 126, True),
        (255, 254, True),
        (bytes(2), -1, False),
        (b'\1\x00', 0, False),
        (b'\1\x80', -2, False),
    ))
    def test_1SUB(self, numeric_state, value, result, minimal):
        state = numeric_state
        script = Script() << value << OP_1SUB
        if not minimal and state.flags & InterpreterFlags.REQUIRE_MINIMAL_PUSH:
            with pytest.raises(MinimalEncodingError):
                state.evaluate_script(script)
            assert len(state.stack) == 1
        else:
            state.evaluate_script(script)
            assert state.stack == [int_to_item(result)]
        assert not state.alt_stack

    @pytest.mark.parametrize("value, result, minimal", (
        (0, 0, True),
        (-1, 1, True),
        (1, -1, True),
        (127, -127, True),
        (255, -255, True),
        (bytes(2), 0, False),
        (b'\1\x00', -1, False),
        (b'\1\x80', 1, False),
    ))
    def test_NEGATE(self, numeric_state, value, result, minimal):
        state = numeric_state
        script = Script() << value << OP_NEGATE
        if not minimal and state.flags & InterpreterFlags.REQUIRE_MINIMAL_PUSH:
            with pytest.raises(MinimalEncodingError):
                state.evaluate_script(script)
            assert len(state.stack) == 1
        else:
            state.evaluate_script(script)
            assert state.stack == [int_to_item(result)]
        assert not state.alt_stack

    @pytest.mark.parametrize("value, result, minimal", (
        (0, 0, True),
        (-1, 1, True),
        (1, 1, True),
        (127, 127, True),
        (255, 255, True),
        (bytes(2), 0, False),
        (b'\x80', 0, False),
        (b'\x81', 1, True),
    ))
    def test_ABS(self, numeric_state, value, result, minimal):
        state = numeric_state
        script = Script() << value << OP_ABS
        if not minimal and state.flags & InterpreterFlags.REQUIRE_MINIMAL_PUSH:
            with pytest.raises(MinimalEncodingError):
                state.evaluate_script(script)
            assert len(state.stack) == 1
        else:
            state.evaluate_script(script)
            assert state.stack == [int_to_item(result)]
        assert not state.alt_stack

    @pytest.mark.parametrize("value, result, minimal", (
        (0, 1, True),
        (-1, 0, True),
        (1, 0, True),
        (127, 0, True),
        (255, 0, True),
        (bytes(2), 1, False),
        (b'\x80', 1, False),
        (b'\x81', 0, True),
    ))
    def test_NOT(self, numeric_state, value, result, minimal):
        state = numeric_state
        script = Script() << value << OP_NOT
        if not minimal and state.flags & InterpreterFlags.REQUIRE_MINIMAL_PUSH:
            with pytest.raises(MinimalEncodingError):
                state.evaluate_script(script)
            assert len(state.stack) == 1
        else:
            state.evaluate_script(script)
            assert state.stack == [int_to_item(result)]
        assert not state.alt_stack

    @pytest.mark.parametrize("value, result, minimal", (
        (0, 0, True),
        (-1, 1, True),
        (1, 1, True),
        (127, 1, True),
        (255, 1, True),
        (bytes(2), 0, False),
        (b'\x80', 0, False),
        (b'\x81', 1, True),
    ))
    def test_0NOTEQUAL(self, numeric_state, value, result, minimal):
        state = numeric_state
        script = Script() << value << OP_0NOTEQUAL
        if not minimal and state.flags & InterpreterFlags.REQUIRE_MINIMAL_PUSH:
            with pytest.raises(MinimalEncodingError):
                state.evaluate_script(script)
            assert len(state.stack) == 1
        else:
            state.evaluate_script(script)
            assert state.stack == [int_to_item(result)]
        assert not state.alt_stack

    @pytest.mark.parametrize("opcode", (
        OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_MOD, OP_BOOLAND, OP_BOOLOR, OP_NUMEQUAL,
        OP_NUMEQUALVERIFY, OP_NUMNOTEQUAL, OP_LESSTHAN, OP_GREATERTHAN,
        OP_LESSTHANOREQUAL, OP_GREATERTHANOREQUAL, OP_MIN, OP_MAX))
    def test_binary_numeric_stack(self, numeric_state, opcode):
        self.require_stack(numeric_state, 2, opcode)

    @pytest.mark.parametrize("opcodes,result, minimal", (
        ((OP_3, OP_5, OP_ADD), 8, True),
        ((OP_1NEGATE, OP_5, OP_ADD), 4, True),
        ((-5, -6, OP_ADD), -11, True),
        ((b'\1', b'\x80', OP_ADD), 1, False),
        ((b'\x80', b'\1', OP_ADD), 1, False),
        ((b'', -1, OP_SUB), 1, True),
        ((OP_3, OP_5, OP_SUB), -2, True),
        ((b'\0', b'\x81', OP_SUB), 1, False),
        ((b'\x81', b'\0', OP_SUB), -1, False),
        ((OP_3, OP_5, OP_MUL), 15, True),
        ((255, OP_0, OP_MUL), 0, True),
        ((12, 13, OP_MUL), 156, True),
        ((-15, b'\2\0', OP_MUL), -30, False),
        ((b'\2\0', 12, OP_MUL), 24, False),
        ((12, 5, OP_DIV), 2, True),
        ((-12, b'\5\0', OP_DIV), -2, False),
        ((b'\x0c\0', -5, OP_DIV), -2, False),
        ((13, 5, OP_MOD), 3, True),
        ((-13, b'\5\0', OP_MOD), -3, False),
        ((b'\x0d\0', -5, OP_MOD), 3, False),
        ((-1, 0, OP_BOOLAND), 0, True),
        ((-13, b'\5\0', OP_BOOLAND), 1, False),
        ((b'\0', 1, OP_BOOLAND), 0, False),
        ((-1, 0, OP_BOOLOR), 1, True),
        ((-13, b'\5\0', OP_BOOLOR), 1, False),
        ((b'\0', 0, OP_BOOLOR), 0, False),
        ((2, 2, OP_NUMEQUAL), 1, True),
        ((2, 3, OP_NUMEQUAL), 0, True),
        ((0, b'\0', OP_NUMEQUAL), 1, False),
        ((b'\1\x80', -1, OP_NUMEQUAL), 1, False),
        ((2, 2, OP_NUMNOTEQUAL), 0, True),
        ((2, 3, OP_NUMNOTEQUAL), 1, True),
        ((0, b'\0', OP_NUMNOTEQUAL), 0, False),
        ((b'\1\x80', -1, OP_NUMNOTEQUAL), 0, False),
        ((1, 1, OP_LESSTHAN), 0, True),
        ((1, -1, OP_LESSTHAN), 0, True),
        ((-1, b'\1\0', OP_LESSTHAN), 1, False),
        ((b'\1\x80', -1, OP_LESSTHAN), 0, False),
        ((1, 1, OP_GREATERTHAN), 0, True),
        ((1, -1, OP_GREATERTHAN), 1, True),
        ((-1, b'\1\0', OP_GREATERTHAN), 0, False),
        ((b'\1\x80', -1, OP_GREATERTHAN), 0, False),
        ((1, 1, OP_LESSTHANOREQUAL), 1, True),
        ((1, -1, OP_LESSTHANOREQUAL), 0, True),
        ((-1, b'\1\0', OP_LESSTHANOREQUAL), 1, False),
        ((b'\1\x80', -1, OP_LESSTHANOREQUAL), 1, False),
        ((1, 1, OP_GREATERTHANOREQUAL), 1, True),
        ((1, -1, OP_GREATERTHANOREQUAL), 1, True),
        ((-1, b'\1\0', OP_GREATERTHANOREQUAL), 0, False),
        ((b'\1\x80', -1, OP_GREATERTHANOREQUAL), 1, False),
        ((1, 1, OP_MIN), 1, True),
        ((2, -1, OP_MIN), -1, True),
        ((-1, b'\1\0', OP_MIN), -1, False),
        ((b'\1\x80', -2, OP_MIN), -2, False),
        ((1, 1, OP_MAX), 1, True),
        ((2, -1, OP_MAX), 2, True),
        ((-1, b'\1\0', OP_MAX), 1, False),
        ((b'\1\x80', -2, OP_MAX), -1, False),
    ))
    def test_binary_numeric(self, numeric_state, opcodes, result, minimal):
        state = numeric_state
        script = Script().push_many(opcodes)
        if not minimal and state.flags & InterpreterFlags.REQUIRE_MINIMAL_PUSH:
            with pytest.raises(MinimalEncodingError):
                state.evaluate_script(script)
            assert len(state.stack) == 2
        else:
            state.evaluate_script(script)
            assert state.stack == [int_to_item(result)]
        assert not state.alt_stack

    @pytest.mark.parametrize("opcodes,result, minimal", (
        ((2, 2), True, True),
        ((2, 3), False, True),
        ((0, b'\0'), True, False),
        ((b'\1\x80', -1), True, False),
    ))
    def test_NUMEQUALVERIFY(self, numeric_state, opcodes, result, minimal):
        state = numeric_state
        script = Script().push_many(opcodes)
        script <<= OP_NUMEQUALVERIFY
        if not minimal and state.flags & InterpreterFlags.REQUIRE_MINIMAL_PUSH:
            with pytest.raises(MinimalEncodingError):
                state.evaluate_script(script)
            assert len(state.stack) == 2
        elif result:
            state.evaluate_script(script)
            assert not state.stack
        else:
            with pytest.raises(NumEqualVerifyFailed) as e:
                state.evaluate_script(script)
            assert 'OP_NUMEQUALVERIFY failed' in str(e.value)
            assert state.stack == [b'']
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
    def test_mul(self, numeric_state, a, b, mul):
        state = numeric_state
        a, b, neg_a, neg_b = value_bytes(a), value_bytes(b), negate_bytes(a), negate_bytes(b)
        mul, neg_mul = value_bytes(mul), negate_bytes(mul)

        # Test negative values
        script = Script().push_many((a, b, OP_MUL, a, neg_b, OP_MUL,
                                     neg_a, b, OP_MUL, neg_a, neg_b, OP_MUL))
        state.evaluate_script(script)
        assert state.stack == [mul, neg_mul, neg_mul, mul]

        # Commutativity
        state.reset()
        script = Script().push_many((b, a, OP_MUL))
        state.evaluate_script(script)
        assert state.stack == [mul]

        # Identities
        state.reset()
        script = Script().push_many((a, 1, OP_MUL, a, b'\x81', OP_MUL, a, b'', OP_MUL,
                                     1, a, OP_MUL, b'\x81', a, OP_MUL, b'', a, OP_MUL))
        state.evaluate_script(script)
        assert state.stack == [a, neg_a, b''] * 2

    @pytest.mark.parametrize("a,b", (
        ('0102030405', '0102030405'),
        ('0105', '0102030405'),
        ('0102030405', '01'),
    ))
    def test_mul_error(self, numeric_state, a, b):
        state = numeric_state
        a, b = value_bytes(a), value_bytes(b)
        script = Script().push_many((a, b, OP_MUL))
        if state.limits.script_num_length == 4:
            with pytest.raises(InvalidNumber):
                state.evaluate_script(script)
        else:
            state.evaluate_script(script)

    def test_overflow(self, numeric_state):
        state = numeric_state
        script = Script().push_many((70000, 70000, OP_MUL))
        state.evaluate_script(script)
        state.reset()

        script = Script().push_many((70000, 70000, OP_MUL, OP_0, OP_ADD))
        if state.limits.script_num_length == 4:
            with pytest.raises(InvalidNumber):
                state.evaluate_script(script)
        else:
            state.evaluate_script(script)

    @pytest.mark.parametrize("a,b,div,mod", (
        (0x185377af, -0x05f41b01, -4, 0x00830bab),
        (408123311, -99883777, -4, 8588203),
        (0x185377af, 0x00001b01, 0xe69d, 0x0212),
        (408123311, 6913, 59037, 530),
        (15, 4, 3, 3),
        (15000, 4, 3750, 0),
        (15000, 4000, 3, 3000),
    ))
    def test_div_mod(self, numeric_state, a, b, div, mod):
        state = numeric_state
        script = Script().push_many((a, b, OP_DIV, a, b, OP_MOD))
        state.evaluate_script(script)
        assert state.stack == [int_to_item(div), int_to_item(mod)]
        assert not state.alt_stack

        state.reset()
        script = Script().push_many((a, -b, OP_DIV, a, -b, OP_MOD))
        state.evaluate_script(script)
        assert state.stack == [int_to_item(-div), int_to_item(mod)]
        assert not state.alt_stack

        state.reset()
        script = Script().push_many((-a, b, OP_DIV, -a, b, OP_MOD))
        state.evaluate_script(script)
        assert state.stack == [int_to_item(-div), int_to_item(-mod)]
        assert not state.alt_stack

        state.reset()
        script = Script().push_many((-a, -b, OP_DIV, -a, -b, OP_MOD))
        state.evaluate_script(script)
        assert state.stack == [int_to_item(div), int_to_item(-mod)]
        assert not state.alt_stack

        state.reset()
        script = Script().push_many((-a, -b, OP_DIV, -a, -b, OP_MOD))
        state.evaluate_script(script)
        assert state.stack == [int_to_item(div), int_to_item(-mod)]
        assert not state.alt_stack

        for value in a, b:
            for zeroes in ('00', '80', '0000', '0080'):
                state.reset()
                script = Script().push_many((value, 0, OP_DIV))
                with pytest.raises(DivisionByZero) as e:
                    state.evaluate_script(script)
                assert 'division by zero' in str(e.value)

                state.reset()
                script = Script().push_many((value, 0, OP_MOD))
                with pytest.raises(DivisionByZero) as e:
                    state.evaluate_script(script)
                assert 'modulo by zero' in str(e.value)

            # Division identities
            state.reset()
            script = Script().push_many((value, 1, OP_DIV, value, b'\x81', OP_DIV,
                                         value, value, OP_DIV, value, -value, OP_DIV))
            state.evaluate_script(script)
            assert state.stack == [int_to_item(value), int_to_item(-value),
                                            b'\1', b'\x81']

    @pytest.mark.parametrize("a,b", (
        ('0102030405', '0102030405'),
        ('0105', '0102030405'),
        ('0102030405', '01'),
    ))
    def test_div_mod_error(self, numeric_state, a, b):
        state = numeric_state
        a = bytes.fromhex(a)
        b = bytes.fromhex(b)

        for op in (OP_DIV, OP_MOD):
            script = Script().push_many((a, b, op))
            if state.limits.script_num_length == 4:
                with pytest.raises(InvalidNumber):
                    state.evaluate_script(script)
            else:
                state.evaluate_script(script)

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
    def test_WITHIN(self, numeric_state, x, low, high, result):
        state = numeric_state
        script = Script() << x << low << high << OP_WITHIN
        state.evaluate_script(script)
        assert state.stack == [int_to_item(result)]


class TestControlOperations(TestEvaluateScriptBase):

    def test_NOP(self, state):
        script = Script() << OP_NOP << OP_NOP
        state.evaluate_script(script)
        assert not state.stack
        assert not state.alt_stack

    def test_NOP_not_upgradeable(self, state):
        script = Script() << OP_NOP
        # No effect regardless of flags; it's not an upgradeable NOP
        state.evaluate_script(script)
        state.flags += InterpreterFlags.REJECT_UPGRADEABLE_NOPS
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
        if state.limits.is_utxo_after_genesis:
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
        if state.limits.is_utxo_after_genesis:
            state.evaluate_script(script)
        else:
            with pytest.raises(OpReturnError):
                state.evaluate_script(script)
        assert state.stack == []
        assert state.alt_stack == []

    def test_RETURN_not_immediate(self, state):
        script = Script() << OP_1 << OP_RETURN
        if state.limits.is_utxo_after_genesis:
            state.evaluate_script(script)
        else:
            with pytest.raises(OpReturnError):
                state.evaluate_script(script)
        assert state.stack == [b'\1']
        assert state.alt_stack == []

    def test_RETURN_unbalanced_IF(self, state):
        # Unabalanced ifs after a post-genesis top-level OP_RETURN are fine
        script = Script() << OP_1 << OP_RETURN << OP_IF
        if state.limits.is_utxo_after_genesis:
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
        if state.limits.is_utxo_after_genesis:
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
        if state.limits.is_utxo_after_genesis:
            with pytest.raises(UnbalancedConditional):
                state.evaluate_script(script)
        else:
            with pytest.raises(OpReturnError):
                state.evaluate_script(script)
        assert state.stack == []
        assert state.alt_stack == []

    def test_RETURN_executed_branch_OP_RETURN_invalid_grammar(self, state):
        script = Script() << OP_1 << OP_IF << OP_RETURN << OP_ENDIF << OP_RETURN << OP_IF
        if state.limits.is_utxo_after_genesis:
            # The unabalanced conditional is ignored as the top-level OP_RETURN stops execution
            state.evaluate_script(script)
        else:
            with pytest.raises(OpReturnError):
                state.evaluate_script(script)
        assert state.stack == []
        assert state.alt_stack == []

    def test_RETURN_executed_branch_invalid_opcode_executed(self, state):
        script = Script() << OP_1 << OP_IF << OP_RETURN << OP_ENDIF << OP_RESERVED
        if state.limits.is_utxo_after_genesis:
            # It's OK; only check IF grammar
            state.evaluate_script(script)
        else:
            with pytest.raises(OpReturnError):
                state.evaluate_script(script)
        assert state.stack == []
        assert state.alt_stack == []

    def test_RETURN_executed_branch_invalid_opcode_unuexecuted(self, state):
        script = Script() << OP_1 << OP_IF << OP_RETURN << OP_ELSE << OP_RESERVED << OP_ENDIF
        if state.limits.is_utxo_after_genesis:
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
        if state.limits.is_utxo_after_genesis:
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
    def test_LSHIFT(self, state, a, b, result):
        script = Script() << value_bytes(a) << value_bytes(b) << OP_LSHIFT
        state.evaluate_script(script)
        assert state.stack == [value_bytes(result)]

    @pytest.mark.parametrize("a,b",(
        ('000100', -1),
        ('01000000', -2),
    ))
    def test_LSHIFT_error(self, state, a, b):
        script = Script() << value_bytes(a) << value_bytes(b) << OP_LSHIFT
        with pytest.raises(NegativeShiftCount):
            state.evaluate_script(script)
        assert len(state.stack) == 2

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
    def test_RSHIFT(self, state, a, b, result):
        script = Script() << value_bytes(a) << value_bytes(b) << OP_RSHIFT
        state.evaluate_script(script)
        assert state.stack == [value_bytes(result)]

    @pytest.mark.parametrize("a,b",(
        ('000100', -1),
        ('01000000', -2),
    ))
    def test_RSHIFT_error(self, state, a, b):
        script = Script() << value_bytes(a) << value_bytes(b) << OP_RSHIFT
        with pytest.raises(NegativeShiftCount):
            state.evaluate_script(script)
        assert len(state.stack) == 2

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


def hybrid_encoding(pubkey):
    encoding = pubkey.to_bytes(compressed=False)
    short = pubkey.to_bytes()
    return pack_byte(short[0] + 4) + encoding[1:]


def make_not_strict_DER(sig):
    # Put an extra byte on the end
    return bytes([sig[0], sig[1] + 1]) + sig[2:] + pack_byte(0)


def make_not_low_S(sig):
    compact_sig = der_signature_to_compact(sig)
    s = be_bytes_to_int(compact_sig[32:])
    compact_sig_high_S = compact_sig[:32] + int_to_be_bytes(CURVE_ORDER - s, 32)
    return compact_signature_to_der(compact_sig_high_S)


def checksig_scripts(state, sighash, op, kind):
    if kind == 'insert_sig':
        script_pubkey = Script() << OP_DROP << op
    else:
        script_pubkey = Script() << op

    # Create a random private key and sign the transaction
    privkey = PrivateKey.from_random()
    message_hash = state.tx.signature_hash(state.input_index, state.value,
                                           script_pubkey, sighash)
    if kind == 'bad_hash':
        message_hash = sha256(message_hash)
    sig = privkey.sign(message_hash, hasher=None)
    if kind == 'not_strict_DER':
        sig = make_not_strict_DER(sig)
    elif kind == 'not_low_S':
        sig = make_not_low_S(sig)
    sig += pack_byte(sighash)
    if kind == 'empty_sig':
        sig = b''
    if kind == 'invalid_pubkey':
        pubkey_encoding = b'\2' + bytes(32)
    elif kind == 'bad_pubkey_encoding':
        pubkey_encoding = hybrid_encoding(privkey.public_key)
    else:
        pubkey_encoding = privkey.public_key.to_bytes()
    script_sig = Script() << sig << pubkey_encoding

    if kind == 'insert_sig':
        script_pubkey = Script() << sig << script_pubkey

    return script_sig, script_pubkey


def checkmultisig_scripts(state, sighash, op, kind, min_m=0):
    min_n = max(min_m, 0)

    # Let's test m of n multisig.  m, and or n, can be zero.
    n = random.randrange(min_n, 10)
    m = random.randrange(min_m, n + 1)

    privkeys = [PrivateKey.from_random() for _ in range(n)]

    # Sign the transaction with the first m keys after a random shuffle. The script_sig
    # must begin with the dummy push.
    keys_to_use = list(privkeys)
    random.shuffle(keys_to_use)
    keys_to_use = keys_to_use[:m]
    indexes_used = [privkeys.index(key) for key in keys_to_use]

    pubkey_encodings = [privkey.public_key.to_bytes() for privkey in privkeys]
    if kind == 'bad_pubkey_encoding':
        index = random.randrange(min(indexes_used), len(pubkey_encodings))
        pubkey_encodings[index] = hybrid_encoding(privkeys[index].public_key)
    elif kind == 'bad_pubkey_encoding_missed' and min(indexes_used, default=-1) > 0:
        index = random.randrange(0, min(indexes_used))
        pubkey_encodings[index] = hybrid_encoding(privkeys[index].public_key)
    elif kind == 'invalid_pubkey':
        index = random.choice(indexes_used)
        pubkey_encodings[index] = b'\2' + bytes(32)
    elif kind == 'invalid_pubkey_missed' and m < n:
        index = random.choice(list(set(range(n)).difference(indexes_used)))
        pubkey_encodings[index] = b'\2' + bytes(32)

    # Pubkey script pushes the public keys and then their count followed by OP_CHECKMULTISIG
    pubkey_parts = [m] + pubkey_encodings + [n, op]
    extra_no_sigs = []
    if kind == 'insert_sig' and m > 0:
        insert_sig_count = random.randrange(1, 6)
        extra_no_sigs = [OP_DROP] * insert_sig_count
    script_pubkey = Script().push_many(pubkey_parts + extra_no_sigs)

    message_hash = state.tx.signature_hash(state.input_index, state.value,
                                           script_pubkey, sighash)
    if kind == 'bad_hash':
        message_hash = sha256(message_hash)
    # Sigs must be in order of the keys
    sigs = [privkey.sign(message_hash, hasher=None)
            for privkey in privkeys if privkey in keys_to_use]

    if sigs:
        index = random.randrange(0, len(sigs))
        sig = sigs[index]
        if kind == 'not_strict_DER':
            sigs[index] = make_not_strict_DER(sigs[index])
        elif kind == 'not_low_S':
            sigs[index] = make_not_low_S(sigs[index])
        sigs = [sig + pack_byte(sighash) for sig in sigs]
        if kind == 'empty_sig':
            sigs[index] = b''
        elif kind == 'all_empty_sig':
            sigs = [b''] * len(sigs)
        if kind == 'wrong_order':
            assert m >= 2
            while True:
                other_index = random.randrange(0, len(sigs))
                if other_index != index:
                    break
            sigs[index], sigs[other_index] = sigs[other_index], sigs[index]

    if kind == 'no_dummy':
        script_sig = Script()
    elif kind == 'nonnull_dummy':
        script_sig = Script() << b'\0'
    else:
        script_sig = Script() << OP_0
    script_sig = script_sig.push_many(sigs)

    if kind == 'insert_sig' and m > 0:
        extra_with_sigs = []
        for _ in range(insert_sig_count):
            extra_with_sigs.append(random.choice(sigs))
            extra_with_sigs.append(OP_DROP)
        script_pubkey = Script().push_many(pubkey_parts + extra_with_sigs)

    return script_sig, script_pubkey, m, n


class TestCrypto(TestEvaluateScriptBase):

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
    def test_CODESEPARATOR(self, checksig_state, script_pubkey, script_code):
        state = checksig_state
        sighash = random_sighash(state)

        # APPEND OP_CHECKSIGVERIFY to check if the correct script_code has been signed
        script_pubkey <<= OP_CHECKSIGVERIFY
        script_code <<= OP_CHECKSIGVERIFY

        # Create a random private key and sign the transaction
        privkey = PrivateKey.from_random()
        message_hash = state.tx.signature_hash(state.input_index, state.value,
                                               script_code, sighash)
        sig = privkey.sign(message_hash, hasher=None) + pack_byte(sighash)
        script_sig = Script() << sig << privkey.public_key.to_bytes()

        # This should complete if the correct script is signed
        state.evaluate_script(script_sig)
        state.evaluate_script(script_pubkey)

    @pytest.mark.parametrize("op", (OP_CHECKSIG, OP_CHECKSIGVERIFY))
    def test_CHECKSIG_good(self, checksig_state, op):
        state = checksig_state
        self.require_stack(state, 2, op)

        sighash = random_sighash(state)
        script_sig, script_pubkey = checksig_scripts(state, sighash, op, 'good')

        # This should complete if the correct script is signed
        state.evaluate_script(script_sig)
        state.evaluate_script(script_pubkey)
        if op == OP_CHECKSIG:
            assert state.stack == [b'\1']
        else:
            assert not state.stack
        assert not state.alt_stack

    @pytest.mark.parametrize("op", (OP_CHECKSIG, OP_CHECKSIGVERIFY))
    def test_CHECKSIG_bad_sig(self, checksig_state, op):
        state = checksig_state
        sighash = random_sighash(state)
        script_sig, script_pubkey = checksig_scripts(state, sighash, op, 'bad_hash')

        # This should complete if the correct script is signed
        state.evaluate_script(script_sig)
        if op == OP_CHECKSIG:
            state.evaluate_script(script_pubkey)
        else:
            with pytest.raises(CheckSigVerifyFailed):
                state.evaluate_script(script_pubkey)
        assert state.stack == [b'']

    @pytest.mark.parametrize("op", (OP_CHECKSIG, OP_CHECKSIGVERIFY))
    def test_CHECKSIG_find_and_delete(self, checksig_state, op):
        state = checksig_state
        sighash = random_sighash(state)
        # find_and_delete of sigs is not done with forkid
        if sighash.has_forkid():
            return
        # Insert the sig in the pubkey to check it's removed
        script_sig, script_pubkey = checksig_scripts(state, sighash, op, 'insert_sig')
        state.evaluate_script(script_sig)
        state.evaluate_script(script_pubkey)
        if op == OP_CHECKSIG:
            assert state.stack == [b'\1']
        else:
            assert not state.stack

    @pytest.mark.parametrize("op", (OP_CHECKSIG, OP_CHECKSIGVERIFY))
    def test_CHECKSIG_not_strict_DER(self, checksig_state, op):
        state = checksig_state
        sighash = random_sighash(state)
        script_sig, script_pubkey = checksig_scripts(state, sighash, op, 'not_strict_DER')
        state.evaluate_script(script_sig)
        if state.flags & (InterpreterFlags.REQUIRE_STRICT_DER | InterpreterFlags.REQUIRE_LOW_S
                          | InterpreterFlags.REQUIRE_STRICT_ENCODING):
            with pytest.raises(InvalidSignature) as e:
                state.evaluate_script(script_pubkey)
            assert 'strict DER encoding' in str(e.value)
            assert len(state.stack) == 2
        else:
            state.evaluate_script(script_pubkey)

    @pytest.mark.parametrize("op", (OP_CHECKSIG, OP_CHECKSIGVERIFY))
    def test_CHECKSIG_not_low_S(self, checksig_state, op):
        state = checksig_state
        sighash = random_sighash(state)
        script_sig, script_pubkey = checksig_scripts(state, sighash, op, 'not_low_S')
        state.evaluate_script(script_sig)
        if state.flags & InterpreterFlags.REQUIRE_LOW_S:
            with pytest.raises(InvalidSignature) as e:
                state.evaluate_script(script_pubkey)
            assert 'signature has high S value' in str(e.value)
            assert len(state.stack) == 2
        else:
            state.evaluate_script(script_pubkey)

    @pytest.mark.parametrize("op", (OP_CHECKSIG, OP_CHECKSIGVERIFY))
    def test_CHECKSIG_bad_sighash(self, checksig_state, op):
        state = checksig_state
        sighash = random_sighash(state, valid=False)
        script_sig, script_pubkey = checksig_scripts(state, sighash, op, 'good')
        state.evaluate_script(script_sig)
        if state.flags & InterpreterFlags.REQUIRE_STRICT_ENCODING:
            with pytest.raises(InvalidSignature) as e:
                state.evaluate_script(script_pubkey)
            if not sighash.is_defined():
                assert 'undefined sighash type' in str(e.value)
            elif sighash.has_forkid():
                assert 'sighash must not use FORKID' in str(e.value)
            else:
                assert 'sighash must use FORKID' in str(e.value)
            assert len(state.stack) == 2
        else:
            state.evaluate_script(script_pubkey)

    @pytest.mark.parametrize("op", (OP_CHECKSIG, OP_CHECKSIGVERIFY))
    def test_CHECKSIG_bad_pubkey_encoding(self, checksig_state, op):
        state = checksig_state
        sighash = random_sighash(state)
        script_sig, script_pubkey = checksig_scripts(state, sighash, op, 'bad_pubkey_encoding')
        state.evaluate_script(script_sig)
        if state.flags & InterpreterFlags.REQUIRE_STRICT_ENCODING:
            with pytest.raises(InvalidPublicKeyEncoding) as e:
                state.evaluate_script(script_pubkey)
            assert 'invalid public key encoding' == str(e.value)
            assert len(state.stack) == 2
        else:
            state.evaluate_script(script_pubkey)

    @pytest.mark.parametrize("op", (OP_CHECKSIG, OP_CHECKSIGVERIFY))
    def test_CHECKSIG_empty_sig(self, checksig_state, op):
        state = checksig_state
        sighash = random_sighash(state)
        script_sig, script_pubkey = checksig_scripts(state, sighash, op, 'empty_sig')
        state.evaluate_script(script_sig)
        if op == OP_CHECKSIG:
            # Empty sig should not raise any errors but just fail a signature check
            state.evaluate_script(script_pubkey)
        else:
            with pytest.raises(CheckSigVerifyFailed):
                state.evaluate_script(script_pubkey)
        assert state.stack == [b'']

    @pytest.mark.parametrize("op", (OP_CHECKSIG, OP_CHECKSIGVERIFY))
    def test_CHECKSIG_invalid_pubkey(self, checksig_state, op):
        state = checksig_state
        sighash = random_sighash(state)
        script_sig, script_pubkey = checksig_scripts(state, sighash, op, 'invalid_pubkey')
        state.evaluate_script(script_sig)
        if op == OP_CHECKSIG:
            # Invalid public key should not raise any errors but just fail a signature check
            state.evaluate_script(script_pubkey)
        else:
            with pytest.raises(CheckSigVerifyFailed):
                state.evaluate_script(script_pubkey)
        assert state.stack == [b'']

    @pytest.mark.parametrize("op", (OP_CHECKSIG, OP_CHECKSIGVERIFY))
    def test_CHECKSIG_NULLFAIL(self, checksig_state, op):
        state = checksig_state
        sighash = random_sighash(state)
        script_sig, script_pubkey = checksig_scripts(state, sighash, op, 'bad_hash')
        state.evaluate_script(script_sig)

        state.flags |= InterpreterFlags.REQUIRE_NULLFAIL
        with pytest.raises(NullFailError):
            state.evaluate_script(script_pubkey)
        assert len(state.stack) == 2

        # Now try with an empty sig
        state.reset()
        script_sig, script_pubkey = checksig_scripts(state, sighash, op, 'empty_sig')
        state.evaluate_script(script_sig)
        if op == OP_CHECKSIG:
            state.evaluate_script(script_pubkey)
        else:
            with pytest.raises(CheckSigVerifyFailed):
                state.evaluate_script(script_pubkey)
        assert state.stack == [b'']

    @pytest.mark.parametrize("op", (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY))
    def test_CHECKMULTISIG_good(self, checksig_state, op):
        state = checksig_state
        sighash = random_sighash(state)

        script_sig, script_pubkey, _, _ = checkmultisig_scripts(state, sighash, op, 'good')

        # This should complete if the correct script is signed
        state.evaluate_script(script_sig)
        state.evaluate_script(script_pubkey)

        if op == OP_CHECKMULTISIG:
            assert state.stack == [b'\1']
        else:
            assert not state.stack
        assert not state.alt_stack

    @pytest.mark.parametrize("op", (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY))
    def test_CHECKMULTISIG_wrong_order(self, checksig_state, op):
        state = checksig_state
        sighash = random_sighash(state)

        script_sig, script_pubkey, _, _ = checkmultisig_scripts(state, sighash, op,
                                                                'wrong_order', min_m=2)

        # The sigs are good but in the wrong order
        state.evaluate_script(script_sig)
        if op == OP_CHECKMULTISIG:
            state.evaluate_script(script_pubkey)
        else:
            with pytest.raises(CheckMultiSigVerifyFailed):
                state.evaluate_script(script_pubkey)
        assert state.stack == [b'']


    @pytest.mark.parametrize("op", (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY))
    def test_CHECKMULTISIG_stack_size(self, checksig_state, op):
        state = checksig_state
        script = Script() << op
        with pytest.raises(InvalidStackOperation):
            state.evaluate_script(script)
        state.reset()

        script = Script() << OP_0 << op
        with pytest.raises(InvalidStackOperation):
            state.evaluate_script(script)
        state.reset()

        # This would be OK but there is no dummy
        script = Script() << OP_0 << OP_0 << op
        with pytest.raises(InvalidStackOperation):
            state.evaluate_script(script)
        state.reset()

        # This is OK - no sigs, no pubkeys
        script = Script() << OP_0 << OP_0 << OP_0 << op
        state.evaluate_script(script)

    @pytest.mark.parametrize("op", (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY))
    def test_CHECKMULTISIG_key_count(self, checksig_state, op):
        # This test also ends up loosely testing excessive op count, invalid stack operations,
        # minimal encoding and the 4-byte rule
        state = checksig_state
        script = Script() << OP_0 << OP_0 << OP_1NEGATE << op
        with pytest.raises(InvalidPublicKeyCount) as e:
            state.evaluate_script(script)
        assert 'number of public keys, -1, in multi-sig check lies outside' in str(e.value)
        state.reset()

        script = Script() << OP_0 << OP_0 << state.limits.pubkeys_per_multisig << op
        if state.limits.pubkeys_per_multisig > INT32_MAX:
            with pytest.raises(InvalidNumber) as e:
                state.evaluate_script(script)
            assert 'number of length 5 bytes exceeds the limit of 4 bytes' in str(e.value)
        else:
            with pytest.raises(InvalidStackOperation):
                state.evaluate_script(script)
        state.reset()

        script = Script() << OP_0 << OP_0 << state.limits.pubkeys_per_multisig + 1 << op
        if state.limits.pubkeys_per_multisig > INT32_MAX:
            with pytest.raises(InvalidNumber) as e:
                state.evaluate_script(script)
            assert 'number of length 5 bytes exceeds the limit of 4 bytes' in str(e.value)
        else:
            with pytest.raises(InvalidPublicKeyCount) as e:
                state.evaluate_script(script)
        state.reset()

        script = Script() << OP_0 << OP_0 << int_to_item(0, 5) << op
        with pytest.raises(InvalidNumber) as e:
            state.evaluate_script(script)
        assert 'number of length 5 bytes exceeds the limit of 4 bytes' in str(e.value)
        state.reset()

        script = Script() << OP_0 << OP_0 << int_to_item(0, 2) << op
        if state.flags & InterpreterFlags.REQUIRE_MINIMAL_PUSH:
            with pytest.raises(MinimalEncodingError):
                state.evaluate_script(script)
        else:
            state.evaluate_script(script)

    @pytest.mark.parametrize("op", (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY))
    def test_CHECKMULTISIG_op_count(self, checksig_state, op):
        state = checksig_state
        sighash = random_sighash(state)

        script_sig, script_pubkey, _, n = checkmultisig_scripts(state, sighash, op, 'good')

        # This should complete if the correct script is signed
        state.evaluate_script(script_sig)
        state.evaluate_script(script_pubkey)

        # 1 for the CHECKMULTISIG op, n for the number of keys
        assert state.op_count == n + 1

    @pytest.mark.parametrize("op", (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY))
    def test_CHECKMULTISIG_sig_count(self, checksig_state, op):
        # This test also ends up loosely testing excessive op count, invalid stack operations,
        # minimal encoding and the 4-byte rule
        state = checksig_state
        script = Script() << OP_0 << OP_1NEGATE << OP_0 << op
        with pytest.raises(InvalidSignatureCount) as e:
            state.evaluate_script(script)
        assert 'number of signatures, -1, in OP_CHECKMULTISIG lies outside' in str(e.value)
        state.reset()

        key_count = random.randrange(1, 10)
        sig_count = key_count + 1
        script = Script() << sig_count
        script = script.push_many([OP_0] * key_count + [key_count, op])
        with pytest.raises(InvalidSignatureCount) as e:
            state.evaluate_script(script)
        assert f'number of signatures, {sig_count}, in OP_CHECKMULTISIG lies ' in str(e.value)
        state.reset()

        script = Script() << int_to_item(0, 5) << OP_0 << op
        with pytest.raises(InvalidNumber) as e:
            state.evaluate_script(script)
        assert 'number of length 5 bytes exceeds the limit of 4 bytes' in str(e.value)
        state.reset()

        script = Script() << OP_0 << int_to_item(0, 2) << OP_0 << op
        if state.flags & InterpreterFlags.REQUIRE_MINIMAL_PUSH:
            with pytest.raises(MinimalEncodingError):
                state.evaluate_script(script)
        else:
            state.evaluate_script(script)

    @pytest.mark.parametrize("op", (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY))
    def test_CHECKMULTISIG_sig_stack_depth(self, checksig_state, op):
        # This test also ends up loosely testing excessive op count, invalid stack operations,
        # minimal encoding and the 4-byte rule
        state = checksig_state

        key_count = random.randrange(2, 6)
        sig_count = random.randrange(1, key_count + 1)
        # Push one too few sigs
        script = Script().push_many([OP_0] * (sig_count - 1) + [sig_count])
        script = script.push_many([OP_0] * key_count + [key_count, op])
        with pytest.raises(InvalidStackOperation):
            state.evaluate_script(script)

    @pytest.mark.parametrize("op", (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY))
    def test_CHECKMULTISIG_bad_sig(self, checksig_state, op):
        state = checksig_state
        sighash = random_sighash(state)
        script_sig, script_pubkey, _, _ = checkmultisig_scripts(state, sighash, op, 'bad_hash',
                                                                min_m=1)

        # This should complete if the correct script is signed
        state.evaluate_script(script_sig)
        if op == OP_CHECKMULTISIG:
            state.evaluate_script(script_pubkey)
        else:
            with pytest.raises(CheckMultiSigVerifyFailed):
                state.evaluate_script(script_pubkey)
        assert state.stack == [b'']

    @pytest.mark.parametrize("op", (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY))
    def test_CHECKMULTISIG_find_and_delete(self, checksig_state, op):
        state = checksig_state
        sighash = random_sighash(state)
        # find_and_delete of sigs is not done with forkid
        if sighash.has_forkid():
            return
        # Insert sigs in the pubkey to check they're removed
        script_sig, script_pubkey, _, _ = checkmultisig_scripts(state, sighash, op, 'insert_sig')
        state.evaluate_script(script_sig)
        state.evaluate_script(script_pubkey)
        if op == OP_CHECKMULTISIG:
            assert state.stack == [b'\1']
        else:
            assert not state.stack

    @pytest.mark.parametrize("op", (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY))
    def test_CHECKMULTISIG_not_strict_DER(self, checksig_state, op):
        state = checksig_state
        sighash = random_sighash(state)
        script_sig, script_pubkey, m, n = checkmultisig_scripts(state, sighash, op,
                                                                'not_strict_DER', min_m=1)
        state.evaluate_script(script_sig)
        if state.flags & (InterpreterFlags.REQUIRE_STRICT_DER | InterpreterFlags.REQUIRE_LOW_S
                          | InterpreterFlags.REQUIRE_STRICT_ENCODING):
            with pytest.raises(InvalidSignature) as e:
                state.evaluate_script(script_pubkey)
            assert 'strict DER encoding' in str(e.value)
            assert len(state.stack) == m + n + 3
        else:
            state.evaluate_script(script_pubkey)

    @pytest.mark.parametrize("op", (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY))
    def test_CHECKMULTISIG_not_low_S(self, checksig_state, op):
        state = checksig_state
        sighash = random_sighash(state)
        script_sig, script_pubkey, m, n = checkmultisig_scripts(state, sighash, op,
                                                                'not_low_S', min_m=1)
        state.evaluate_script(script_sig)
        if state.flags & InterpreterFlags.REQUIRE_LOW_S:
            with pytest.raises(InvalidSignature) as e:
                state.evaluate_script(script_pubkey)
            assert 'signature has high S value' in str(e.value)
            assert len(state.stack) == m + n + 3
        else:
            state.evaluate_script(script_pubkey)

    @pytest.mark.parametrize("op", (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY))
    def test_CHECKMULTISIG_bad_sighash(self, checksig_state, op):
        state = checksig_state
        sighash = random_sighash(state, valid=False)
        script_sig, script_pubkey, m, n = checkmultisig_scripts(state, sighash, op,
                                                                'good', min_m=1)
        state.evaluate_script(script_sig)
        if state.flags & InterpreterFlags.REQUIRE_STRICT_ENCODING:
            with pytest.raises(InvalidSignature) as e:
                state.evaluate_script(script_pubkey)
            if not sighash.is_defined():
                assert 'undefined sighash type' in str(e.value)
            elif sighash.has_forkid():
                assert 'sighash must not use FORKID' in str(e.value)
            else:
                assert 'sighash must use FORKID' in str(e.value)
            assert len(state.stack) == m + n + 3
        else:
            state.evaluate_script(script_pubkey)

    @pytest.mark.parametrize("op", (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY))
    def test_CHECKMULTISIG_bad_pubkey_encoding(self, checksig_state, op):
        state = checksig_state
        sighash = random_sighash(state)
        script_sig, script_pubkey, m, n = checkmultisig_scripts(state, sighash, op,
                                                                'bad_pubkey_encoding', min_m=1)
        state.evaluate_script(script_sig)
        # Only public keys actually used are checked
        if state.flags & InterpreterFlags.REQUIRE_STRICT_ENCODING:
            with pytest.raises(InvalidPublicKeyEncoding) as e:
                state.evaluate_script(script_pubkey)
            assert 'invalid public key encoding' == str(e.value)
            assert len(state.stack) == m + n + 3
        else:
            state.evaluate_script(script_pubkey)

        # Bad encodings are only noticed if consumed...
        script_sig, script_pubkey, m, n = checkmultisig_scripts(
            state, sighash, op, 'bad_pubkey_encoding_missed')
        state.evaluate_script(script_sig)
        state.evaluate_script(script_pubkey)

    @pytest.mark.parametrize("op", (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY))
    def test_CHECKMULTISIG_empty_sig(self, checksig_state, op):
        state = checksig_state
        sighash = random_sighash(state)
        script_sig, script_pubkey, m, n = checkmultisig_scripts(state, sighash, op,
                                                                'empty_sig', min_m=1)
        state.evaluate_script(script_sig)
        if op == OP_CHECKMULTISIG:
            # Empty sig should not raise any errors but just fail a signature check
            state.evaluate_script(script_pubkey)
        else:
            with pytest.raises(CheckMultiSigVerifyFailed):
                state.evaluate_script(script_pubkey)
        assert state.stack == [b'']

    @pytest.mark.parametrize("op", (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY))
    def test_CHECKMULTISIG_invalid_pubkey(self, checksig_state, op):
        state = checksig_state
        sighash = random_sighash(state)
        script_sig, script_pubkey, m, n = checkmultisig_scripts(state, sighash, op,
                                                                'invalid_pubkey', min_m=1)
        state.evaluate_script(script_sig)
        if op == OP_CHECKMULTISIG:
            # Invalid public key should not raise any errors but just fail a signature check
            state.evaluate_script(script_pubkey)
        else:
            with pytest.raises(CheckMultiSigVerifyFailed):
                state.evaluate_script(script_pubkey)
        assert state.stack == [b'']

        state.reset()
        # If the pubkey is not used, its invalid state is missed
        script_sig, script_pubkey, m, n = checkmultisig_scripts(state, sighash, op,
                                                                'invalid_pubkey_missed', min_m=1)
        state.evaluate_script(script_sig)
        state.evaluate_script(script_pubkey)

    @pytest.mark.parametrize("op", (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY))
    def test_CHECKMULTISIG_NULLFAIL(self, checksig_state, op):
        state = checksig_state
        sighash = random_sighash(state)
        script_sig, script_pubkey, m, n = checkmultisig_scripts(state, sighash, op,
                                                                'bad_hash', min_m=1)

        state.evaluate_script(script_sig)
        state.flags |= InterpreterFlags.REQUIRE_NULLFAIL
        with pytest.raises(NullFailError):
            state.evaluate_script(script_pubkey)
        assert len(state.stack) <= m + 1

        # Now try with an empty sig
        state.reset()
        script_sig, script_pubkey, m, n = checkmultisig_scripts(state, sighash, op,
                                                                'all_empty_sig', min_m=1)
        state.evaluate_script(script_sig)
        if op == OP_CHECKMULTISIG:
            state.evaluate_script(script_pubkey)
        else:
            with pytest.raises(CheckMultiSigVerifyFailed):
                state.evaluate_script(script_pubkey)
        assert state.stack == [b'']

    @pytest.mark.parametrize("op", (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY))
    def test_CHECKMULTISIG_DUMMY(self, checksig_state, op):
        state = checksig_state
        sighash = random_sighash(state)

        # Test we need a dummy
        script_sig, script_pubkey, m, n = checkmultisig_scripts(state, sighash, op, 'no_dummy')
        state.evaluate_script(script_sig)
        with pytest.raises(InvalidStackOperation):
            state.evaluate_script(script_pubkey)
        state.reset()

        # Test non-null dummy
        script_sig, script_pubkey, m, n = checkmultisig_scripts(state, sighash, op,
                                                                'nonnull_dummy')
        state.evaluate_script(script_sig)
        # Fine with non-null dummy
        state.evaluate_script(script_pubkey)
        state.reset()

        old_flags = state.flags
        try:
            state.flags |= InterpreterFlags.REQUIRE_NULLDUMMY
            state.evaluate_script(script_sig)
            with pytest.raises(NullDummyError):
                state.evaluate_script(script_pubkey)
        finally:
            state.flags = old_flags


class TestByteStringOperations(TestEvaluateScriptBase):

    @pytest.mark.parametrize("op", (OP_CAT, OP_SPLIT, OP_NUM2BIN))
    def test_doubles(self, numeric_state, op):
        self.require_stack(numeric_state, 2, op)

    @pytest.mark.parametrize("op", (OP_BIN2NUM, OP_SIZE))
    def test_dBIN2NUM_stack(self, numeric_state, op):
        self.require_stack(numeric_state, 1, op)

    @pytest.mark.parametrize("left,right", (
        (b'foo', b'bar'),
        (b'bar', b'tender'),
    ))
    def test_CAT(self, numeric_state, left, right):
        state = numeric_state
        script = Script() << left << right << OP_CAT
        state.evaluate_script(script)
        assert state.stack == [left + right]
        assert state.alt_stack == []

    def test_CAT_size_enforced(self, numeric_state):
        state = numeric_state

        item = bytes(InterpreterLimits.MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS)
        script = Script() << item << b'' << OP_CAT
        state.evaluate_script(script)
        state.reset()

        script = Script() << item << b'1' << OP_CAT
        if state.limits.is_utxo_after_genesis:
            state.evaluate_script(script)
        else:
            with pytest.raises(InvalidPushSize):
                state.evaluate_script(script)

    @pytest.mark.parametrize("value, num, result", (
        (b'foobar', OP_3, [b'foo', b'bar']),
        (b'foobar', OP_0, [b'', b'foobar']),
        (b'foobar', OP_6, [b'foobar', b'']),
    ))
    def test_SPLIT(self, numeric_state, value, num, result):
        state = numeric_state
        script = Script() << value << num << OP_SPLIT
        state.evaluate_script(script)
        assert state.stack == result
        assert state.alt_stack == []

        # Negative
        state.reset()
        num = random.randrange(-10, 0)
        script = Script() << value << num << OP_SPLIT
        with pytest.raises(InvalidSplit) as e:
            state.evaluate_script(script)
        assert f'cannot split item of length {len(value)} at position {num}' in str(e.value)
        assert len(state.stack) == 2

        # Too large
        state.reset()
        num = len(value) + random.randrange(1, 10)
        script = Script() << value << num << OP_SPLIT
        with pytest.raises(InvalidSplit) as e:
            state.evaluate_script(script)
        assert f'cannot split item of length {len(value)} at position {num}' in str(e.value)
        assert len(state.stack) == 2

    def test_SPLIT_minimal(self, numeric_state):
        state = numeric_state
        script = Script() << b'foobar' << b'\0' << OP_SPLIT
        if state.flags == InterpreterFlags.REQUIRE_MINIMAL_PUSH:
            with pytest.raises(MinimalEncodingError):
                state.evaluate_script(script)
            assert state.stack == [b'foobar', b'\0']
        else:
            state.evaluate_script(script)
            assert state.stack == [b'', b'foobar']

    @pytest.mark.parametrize("value,size,result", (
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
    def test_NUM2BIN(self, numeric_state, value, size, result):
        state = numeric_state
        value = bytes.fromhex(value)
        script = Script() << value << size << OP_NUM2BIN
        state.evaluate_script(script)
        assert len(state.stack) == 1
        assert state.stack[0].hex() == result
        assert not state.alt_stack

    def test_NUM2BIN_minimal(self, numeric_state):
        state = numeric_state
        script = Script() << b'' << b'\3\0' << OP_NUM2BIN
        if state.flags == InterpreterFlags.REQUIRE_MINIMAL_PUSH:
            with pytest.raises(MinimalEncodingError):
                state.evaluate_script(script)
            assert state.stack == [b'', b'\3\0']
        else:
            state.evaluate_script(script)
            assert state.stack == [b'\0\0\0']

    def test_NUM2BIN_oversized(self, numeric_state):
        state = numeric_state
        value = b'\x01'
        size = InterpreterLimits.MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS + 1
        script = Script() << value << size << OP_NUM2BIN
        if state.limits.is_utxo_after_genesis:
            state.evaluate_script(script)
            assert len(state.stack) == 1
            assert state.stack[0] == b'\1' + bytes(520)
        else:
            with pytest.raises(InvalidPushSize) as e:
                state.evaluate_script(script)
            assert 'item length 521 exceeds' in str(e.value)
            assert len(state.stack) == 2

    @pytest.mark.parametrize("size", (-1, -3, INT32_MAX + 1))
    def test_NUM2BIN_invalid_size(self, numeric_state, size):
        state = numeric_state
        script = Script() << b'\x01' << size << OP_NUM2BIN
        if size > INT32_MAX and not state.limits.is_utxo_after_genesis:
            with pytest.raises(InvalidNumber) as e:
                state.evaluate_script(script)
            assert 'number of length 5 bytes exceeds the limit of 4 bytes' == str(e.value)
        else:
            with pytest.raises(InvalidPushSize) as e:
                state.evaluate_script(script)
            assert f'invalid size {size:,d} in OP_NUM2BIN operation' == str(e.value)
        assert len(state.stack) == 2

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
    def test_BIN2NUM(self, numeric_state, value, result):
        state = numeric_state
        value = bytes.fromhex(value)
        script = Script() << value << OP_BIN2NUM
        if len(result) // 2 > state.limits.script_num_length:
            with pytest.raises(InvalidNumber):
                state.evaluate_script(script)
        else:
            state.evaluate_script(script)
        # Stack contains the result even on failure
        assert len(state.stack) == 1
        assert state.stack[0].hex() == result
        assert not state.alt_stack

    def test_BIN2NUM_oversized(self, numeric_state):
        state = numeric_state

        # A minimally-encoded result of the max length is good
        result = b'\6' * state.limits.script_num_length
        script = Script() << result + b'\0' << OP_BIN2NUM
        state.evaluate_script(script)
        assert state.stack == [result]

        state.reset()
        result = b'\6' * (state.limits.script_num_length + 1)
        script = Script() << result + b'\0' << OP_BIN2NUM
        with pytest.raises(InvalidNumber):
            state.evaluate_script(script)
        # Even though it failed the result is on the stack
        assert state.stack == [result]

    @pytest.mark.parametrize("value,size", (
        (b'', 0),
        (b'\x00', 1),
        (b'\x00\x80', 2),
        (bytes(20), 20),
   ))
    def test_SIZE(self, numeric_state, value, size):
        state = numeric_state
        script = Script() << value << OP_SIZE
        state.evaluate_script(script)
        assert state.stack == [value, int_to_item(len(value))]
        assert not state.alt_stack
