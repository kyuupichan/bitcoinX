import random

import pytest

from bitcoinx import (
    int_to_be_bytes, Script, SigHash, double_sha256, TxOutput, pack_le_uint32, OP_CODESEPARATOR,
)

from .utils import random_tx, random_script


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
        tx.outputs = [TxOutput.null() for _ in range(input_index)]
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


@pytest.mark.parametrize('execution_count', range(1000))
def test_sighash(execution_count):
    '''Tests the original Satoshi signature_hash on random transactions.'''
    hash_type = random.randrange(0, 1 << 32)
    sighash_type = SigHash(hash_type)

    tx = random_tx((hash_type & 0x1f) == SigHash.SINGLE)
    script_code = random_script()
    input_index = random.randrange(0, len(tx.inputs))

    live_hash = tx._original_signature_hash(input_index, script_code, sighash_type)

    # ref_sighash modifies the tx so do it second
    ref_hash = ref_sighash(script_code, tx, input_index, hash_type)

    assert live_hash == ref_hash
