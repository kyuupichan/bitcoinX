from os import urandom
import random


from bitcoinx import Tx, TxInput, TxOutput


def random_input():
    prev_hash = urandom(32)
    prev_idx = random.randrange(0, 6)
    script_sig = urandom(50)
    sequence = random.choice([0xffffffff, 0, 5_000])
    return TxInput(prev_hash, prev_idx, script_sig, sequence)


def random_value():
    return random.randrange(0, 1_000_000_000)


def random_output():
    value = random_value()
    script_pubkey = urandom(25)
    return TxOutput(value, script_pubkey)


def random_tx():
    version = random.randrange(0, 4)
    ninputs = random.randrange(1, 5)
    inputs = [random_input() for _ in range(ninputs)]
    noutputs = random.randrange(1, 5)
    outputs = [random_output() for _ in range(noutputs)]
    locktime = random.choice([0, 100_000, 700_000, 1_000_000_000, 3_000_000_000])

    return Tx(version, inputs, outputs, locktime)
