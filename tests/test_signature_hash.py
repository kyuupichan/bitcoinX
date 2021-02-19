from os import urandom
import random

import pytest

from bitcoinx import (
    int_to_be_bytes, Script, SigHash, double_sha256, SEQUENCE_FINAL, TxInput, TxOutput, Tx,
    pack_le_uint32,
    OP_FALSE, OP_1, OP_2, OP_3, OP_CHECKSIG, OP_IF, OP_VERIF, OP_RETURN, OP_CODESEPARATOR
)


ONE = int_to_be_bytes(1, size=32)

# My Python translation of the code in bitcoin-sv/src/test/sighash_tests.cpp that represents
# the original reference signature_hash() code

def ref_sighash(script_code, tx, input_index, hash_type):
    assert input_index < len(tx.inputs)

    # In case concatenating two scripts ends up with two codeseparators, or an
    # extra one at the end, this prevents all those possible incompatibilities.
    script_code.find_and_delete(Script() << OP_CODESEPARATOR)

    # Blank out other inputs' signatures
    empty_script = Script()
    for tx_in in tx.inputs:
        tx_in.script_sig = empty_script
    tx.inputs[input_index].script_sig = script_code

    # Blank out some of the outputs
    if (hash_type & 0x1f) == SigHash.NONE:
        # Wildcard payee
        tx.outputs.clear()
        # Let the others update at will:
        for n, tx_in in enumerate(tx.inputs):
            if n != input_index:
                tx_in.sequence = 0
    elif (hash_type & 0x1f) == SigHash.SINGLE:
        if input_index >= len(tx.outputs):
            return ONE
        tx_output = tx.outputs[input_index]
        tx.outputs = [TxOutput(-1, Script()) for _ in range(input_index)]
        tx.outputs.append(tx_output)
        # Let the others update at will:
        for n, tx_in in enumerate(tx.inputs):
            if n != input_index:
                tx_in.sequence = 0

    # Blank out other inputs completely; not recommended for open transactions
    if hash_type & SigHash.ANYONE_CAN_PAY:
        tx.inputs = [tx.inputs[input_index]]

    preimage = tx.to_bytes() + pack_le_uint32(hash_type)

    return double_sha256(preimage)


random_ops = [OP_FALSE, OP_1, OP_2, OP_3, OP_CHECKSIG, OP_IF,
              OP_VERIF, OP_RETURN, OP_CODESEPARATOR]


def random_script():
    result = Script()
    for _ in range(random.randrange(0, 10)):
        result <<= random.choice(random_ops)
    return result


def random_bool():
    return random.random() >= 0.5


def random_input():
    sequence = SEQUENCE_FINAL if random_bool() else random.randrange(0, SEQUENCE_FINAL)
    return TxInput(urandom(32), random.randrange(0, 4), random_script(), sequence)


def random_output():
    return TxOutput(random.randrange(0, 100_000_000), random_script())


def random_transaction(is_single):
    version = random.randrange(- (1 << 31), 1 << 31)
    locktime = 0 if random_bool() else random.randrange(0, 1 << 32)
    n_inputs = random.randrange(1, 5)
    n_outputs = n_inputs + random.randrange(-1, 1) if is_single else random.randrange(1, 5)
    inputs = [random_input() for _ in range(n_inputs)]
    outputs = [random_output() for _ in range(n_outputs)]

    return Tx(version, inputs, outputs, locktime)


@pytest.mark.parametrize('execution_count', range(1000))
def test_sighash(execution_count):
    '''Tests the original Satoshi signature_hash on random transactions.'''
    hash_type = random.randrange(0, 1 << 32)
    sighash_type = SigHash(hash_type)

    tx = random_transaction((hash_type & 0x1f) == SigHash.SINGLE)
    script_code = random_script()
    input_index = random.randrange(0, len(tx.inputs))

    live_hash = tx._original_signature_hash(input_index, script_code, sighash_type)

    # ref_sighash modifies the tx so do it second
    ref_hash = ref_sighash(script_code, tx, input_index, hash_type)

    assert live_hash == ref_hash
