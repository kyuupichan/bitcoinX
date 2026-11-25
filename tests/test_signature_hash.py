import random

import pytest

from bitcoinx import (
    int_to_be_bytes, Script, SigHash, double_sha256, Tx, TxInput, TxOutput, pack_le_uint32,
    OP_CODESEPARATOR,
)

from .utils import random_tx, random_script


ONE = int_to_be_bytes(1, size=32)


# My Python translation of the code in bitcoin-sv/src/test/sighash_tests.cpp that represents
# the original reference signature_hash() code
def ref_sighash(script_code, tx, input_index, hash_type):
    assert input_index < len(tx.inputs)

    # In case concatenating two scripts ends up with two codeseparators, or an
    # extra one at the end, this prevents all those possible incompatibilities.
    script_code = script_code.find_and_delete(Script() << OP_CODESEPARATOR)

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


@pytest.mark.parametrize('_execution_count', range(1000))
def test_sighash(_execution_count):
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


# Expected digests from SV Node v1.2.3 test/functional/test_framework/script.py.
@pytest.mark.parametrize('index, hash_type, expected', (
    (1, 0x01, 'e079382249842b8705ef0c757e279a7cbf61f0d6c2ff9c95ce683adef604e0ea'),
    (1, 0x41, '08fa08fffd9b2bacb56d136bfa23bf37ab88be3fd7834ff93e50304da3c35f3d'),
    (1, 0x61, '6e892301ead5bafb76d000741ddf0894e233444bec914412df25ad7a7cf895af'),
    (1, 0x62, '43f1122cf0e8ef01cfd02d391234981d641446a3f4d2f66951dd3ba44a47d2a5'),
    (1, 0x63, '1f8f2b10b7215f3c181e61e3494dd51558938fe74afdd3617ffa509324d0d92f'),
    (1, 0xe1, '827e89f332f48ab3d600ffed2073676137a145fb437d2c5605273196671aa9a9'),
    (1, 0xe2, 'd9b96caeb870cee08a8f22030e72e0377524caff3339409554fe6fa39141fbfd'),
    (1, 0xe3, '0754a11f4634f82beb1302f9fd407875d8464cbcde52246b8ea2a010e1684990'),
    (2, 0x43, '6bb65a975c5cb8c5a4065d16a99d7668137c5800387c22b7b7096c5f87d66ef4'),
    (2, 0x63, '01' + '00' * 31),
    (2, 0xe3, '01' + '00' * 31),
))
def test_chronicle_signature_hash(index, hash_type, expected):
    inputs = [
        TxInput(bytes([n]) * 32, n, Script(b'\x51'), 0xfffffffd - n)
        for n in range(1, 4)
    ]
    outputs = [TxOutput(1500, Script(b'\x51')), TxOutput(2500, Script(b'\x52'))]
    tx = Tx(2, inputs, outputs, 37)
    # Starts with a push of 0xab, followed by two actual OP_CODESEPARATOR opcodes.
    script_code = bytes.fromhex('01abab51ab52')
    sighash = SigHash(hash_type)
    digest = tx.signature_hash(index, 4100, script_code, sighash, chronicle=True)
    assert digest.hex() == expected

    if not sighash & SigHash.CHRONICLE:
        assert tx.signature_hash(index, 4100, script_code, sighash) == digest
    else:
        assert tx.signature_hash(index, 5100, script_code, sighash, chronicle=True) == digest
        assert tx.signature_hash(index, 4100, script_code, sighash) != digest
