from io import BytesIO
import os

import pytest

from bitcoinx.tx import *


data_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


def read_tx(filename):
    with open(os.path.join(data_dir, filename)) as f:
        return bytes.fromhex(f.read().strip())


def test_tx_read():
    tx_bytes = read_tx('b59de025.txn')
    bio = BytesIO(tx_bytes)
    tx = Tx.read(bio.read)

    assert tx.version == 2
    assert len(tx.inputs) == 7
    assert len(tx.outputs) == 3
    assert tx.locktime == 0


def test_from_bytes():
    tx_bytes = read_tx('b83acf939.txn')
    tx = Tx.from_bytes(tx_bytes)
    assert tx.to_bytes() == tx_bytes


def test_from_hex():
    tx_bytes = read_tx('b83acf939.txn')
    tx = Tx.from_hex(tx_bytes.hex())
    assert tx.to_bytes() == tx_bytes


def test_to_bytes_to_hex():
    tx_bytes = read_tx('b59de025.txn')
    bio = BytesIO(tx_bytes)
    tx = Tx.read(bio.read)
    assert tx.to_bytes() == tx_bytes
    assert tx.to_hex() == tx_bytes.hex()


def test_is_coinbase():
    tx_bytes = read_tx('afda808f.txn')
    bio = BytesIO(tx_bytes)
    tx = Tx.read(bio.read)
    assert len(tx.inputs) == 1
    assert tx.inputs[0].is_coinbase()
    assert tx.is_coinbase()


def test_repr():
    tx_bytes = read_tx('afda808f.txn')
    bio = BytesIO(tx_bytes)
    tx = Tx.read(bio.read)
    assert repr(tx) == (
        'Tx(version=1, inputs=[TxInput(prev_hash="00000000000000000000000000000000000000000000'
        '00000000000000000000", prev_idx=4294967295, script_sig="0319c4082f626d67706f6f6c2e636f6d2'
        'f5473537148110d9e7fcc3cf74ee70c0200", sequence=4294967295)], outputs=[TxOutput(value='
        '1250005753, script_pk="76a914db1aea84aad494d9f5b253327da23c4e51266c9388ac")], locktime=0)'
    )
