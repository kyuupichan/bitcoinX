from io import BytesIO
import json
import os

import pytest

from bitcoinx import Script, PublicKey, SigHash
from bitcoinx.tx import *
from bitcoinx.tx import LOCKTIME_THRESHOLD


data_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


def read_tx_hex(filename):
    with open(os.path.join(data_dir, filename)) as f:
        return f.read().strip()


def read_tx(filename):
    return Tx.from_hex(read_tx_hex(filename))


def test_tx_read():
    tx = read_tx('b59de025.txn')

    assert tx.version == 2
    assert len(tx.inputs) == 7
    assert len(tx.outputs) == 3
    assert tx.locktime == 0


def test_from_bytes():
    tx_bytes = bytes.fromhex(read_tx_hex('b59de025.txn'))
    tx = Tx.from_bytes(tx_bytes)
    assert tx.to_bytes() == tx_bytes


def test_from_hex():
    tx_hex = read_tx_hex('b59de025.txn')
    tx = Tx.from_hex(tx_hex)
    assert tx.to_hex() == tx_hex


def test_to_bytes_to_hex():
    tx_hex = read_tx_hex('b59de025.txn')
    tx = Tx.from_hex(tx_hex)
    assert tx.to_bytes() == bytes.fromhex(tx_hex)
    assert tx.to_hex() == tx_hex


def test_repr():
    tx = read_tx('afda808f.txn')
    assert repr(tx) == (
        'Tx(version=1, inputs=[TxInput(prev_hash="00000000000000000000000000000000000000000000'
        '00000000000000000000", prev_idx=4294967295, script_sig="0319c4082f626d67706f6f6c2e636f6d2'
        'f5473537148110d9e7fcc3cf74ee70c0200", sequence=4294967295)], outputs=[TxOutput(value='
        '1250005753, script_pk="76a914db1aea84aad494d9f5b253327da23c4e51266c9388ac")], locktime=0)'
    )


def read_signature_hashes(filename):
    with open(os.path.join(data_dir, filename)) as f:
        contents = f.read().strip()
    return [bytes.fromhex(line) for line in contents.splitlines()]


tx_testcases = ['503fd37f.txn']


def read_json_tx(filename):
    with open(os.path.join(data_dir, filename)) as f:
        d = json.loads(f.read())
    return (Tx.from_hex(d['tx_hex']), d['input_values'],
            [bytes.fromhex(pk_hex) for pk_hex in d['input_pk_scripts']])


@pytest.mark.parametrize("filename", tx_testcases)
def test_signature_hash(filename):
    tx, values, pk_scripts = read_json_tx(filename)
    correct_hashes = read_signature_hashes(filename.replace('.txn', '.sig_hashes'))

    n = 0
    for input_index, (value, pk_script, txin) in enumerate(zip(values, pk_scripts, tx.inputs)):
        for sighash in range(256):
            signature_hash = tx.signature_hash(input_index, value, pk_script,
                                               sighash=SigHash(sighash))
            assert signature_hash == correct_hashes[n]
            n += 1


def test_signature_hash_bad():
    tx, _, _ = read_json_tx('503fd37f.txn')

    with pytest.raises(IndexError):
        tx.signature_hash(-1, 5, b'')
    with pytest.raises(IndexError):
        tx.signature_hash(2, 5, b'')
    with pytest.raises(ValueError):
        tx.signature_hash(0, -1, b'')
    with pytest.raises(TypeError):
        tx.signature_hash(0, 0, b'', sighash=1)
    tx.signature_hash(0, 0, b'')
    tx.signature_hash(1, 0, b'', sighash=SigHash(1))


@pytest.mark.parametrize("filename", tx_testcases)
def test_signatures(filename):
    tx, values, pk_scripts = read_json_tx(filename)

    for input_index, (value, pk_script, txin) in enumerate(zip(values, pk_scripts, tx.inputs)):
        signature, pubkey = txin.script_sig.ops()
        pubkey = PublicKey.from_bytes(pubkey)
        signature_hash = tx.signature_hash(input_index, value, pk_script,
                                           sighash=SigHash(signature[-1]))
        assert pubkey.verify_der_signature(signature[:-1], signature_hash, None)


class TestTx:

    def test_is_coinbase(self):
        tx = read_tx('afda808f.txn')
        assert tx.is_coinbase()

    def test_are_inputs_final(self):
        tx = read_tx('b59de025.txn')
        assert tx.are_inputs_final()
        tx.inputs[4].sequence += 1
        assert not tx.are_inputs_final()

    @pytest.mark.parametrize("locktime,inputs_final,height,timestamp,answer", (
        # Locktime 0 is always final
        (0, False, 0, 0, True),
        (0, False, 1, 1, True),
        (0, True, 0, 0, True),
        (0, True, 1, 1, True),
        # Locktime 1 is final only from block height 2
        (1, False, 0, 0, False),
        (1, False, 1, 0, False),
        (1, False, 2, 0, True),
        # If all inputs a final a tx is always final
        (1, True, 0, 0, True),
        (1, True, 1, 0, True),
        (1, True, 2, 0, True),
        # If < LOCKTIME_THRESHOLD, it's height-based
        (LOCKTIME_THRESHOLD - 1, False, LOCKTIME_THRESHOLD - 1, 0, False),
        (LOCKTIME_THRESHOLD - 1, False, LOCKTIME_THRESHOLD, 0, True),
        (LOCKTIME_THRESHOLD - 1, True, LOCKTIME_THRESHOLD - 1, 0, True),
        (LOCKTIME_THRESHOLD - 1, True, LOCKTIME_THRESHOLD, 0, True),
        # If >= LOCKTIME_THRESHOLD, it's time-based
        (LOCKTIME_THRESHOLD, False, LOCKTIME_THRESHOLD + 1, 0, False),
        (LOCKTIME_THRESHOLD, False, 0, LOCKTIME_THRESHOLD, False),
        (LOCKTIME_THRESHOLD, False, 0, LOCKTIME_THRESHOLD + 1, True),
        (LOCKTIME_THRESHOLD, True, LOCKTIME_THRESHOLD + 1, 0, True),
        (LOCKTIME_THRESHOLD, True, 0, LOCKTIME_THRESHOLD, True),
        (LOCKTIME_THRESHOLD, True, 0, LOCKTIME_THRESHOLD + 1, True),
    ))
    def test_is_final_for_block(self, locktime, inputs_final, height, timestamp, answer):
        tx = read_tx('b59de025.txn')
        tx.locktime = locktime
        if not inputs_final:
            tx.inputs[0].sequence = 0xfffffffe
        assert tx.is_final_for_block(height, timestamp) == answer


class TestTxInput:

    def test_is_coinbase(self):
        txin = TxInput(bytes(32), 0xffffffff, b'', 0xffffffff)
        assert txin.is_coinbase()
        txin.prev_idx = 0
        assert not txin.is_coinbase()
        txin.prev_idx = 0xffffffff
        assert txin.is_coinbase()
        txin.prev_hash = bytes(31) + b'\1'
        assert not txin.is_coinbase()

    def test_is_final(self):
        txin = TxInput(bytes(32), 0xffffffff, b'', 0xffffffff)
        assert txin.is_final()
        txin.sequence -= 1
        assert not txin.is_final()
