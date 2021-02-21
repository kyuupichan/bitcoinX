from os import urandom, path
import json
from random import randrange, choice, random


from bitcoinx import (
    Tx, TxInput, TxOutput, Script, SEQUENCE_FINAL,
    OP_FALSE, OP_1, OP_2, OP_3, OP_CHECKSIG, OP_IF, OP_VERIF, OP_RETURN, OP_CODESEPARATOR
)


data_dir = path.join(path.dirname(path.realpath(__file__)), 'data')


random_ops = [OP_FALSE, OP_1, OP_2, OP_3, OP_CHECKSIG, OP_IF,
              OP_VERIF, OP_RETURN, OP_CODESEPARATOR]

def _zeroes():
    # Yields a zero and negative zero
    for size in range(10):
        yield bytes(size)
        yield bytes(size) + b'\x80'


zeroes = list(_zeroes())
non_zeroes = [b'\1', b'\x81', b'\1\0', b'\0\1', b'\0\x81']


def random_value():
    '''Random value of a TxOutput.'''
    return randrange(0, 100_000_000)


def random_script():
    ops = [choice(random_ops) for _ in range(randrange(0, 10))]
    return Script().push_many(ops)


def random_bool():
    return random() >= 0.5


def random_input():
    sequence = SEQUENCE_FINAL if random_bool() else randrange(0, SEQUENCE_FINAL)
    return TxInput(urandom(32), randrange(0, 4), random_script(), sequence)


def random_output():
    return TxOutput(random_value(), random_script())


def random_tx(is_single):
    version = randrange(- (1 << 31), 1 << 31)
    locktime = 0 if random_bool() else randrange(0, 1 << 32)
    n_inputs = randrange(1, 5)
    n_outputs = n_inputs + randrange(-1, 1) if is_single else randrange(1, 5)
    inputs = [random_input() for _ in range(n_inputs)]
    outputs = [random_output() for _ in range(n_outputs)]

    return Tx(version, inputs, outputs, locktime)


def read_tx_hex(filename):
    with open(path.join(data_dir, filename)) as f:
        return f.read().strip()


def read_tx(filename):
    return Tx.from_hex(read_tx_hex(filename))


def read_signature_hashes(filename):
    with open(path.join(data_dir, filename)) as f:
        contents = f.read().strip()
    return [bytes.fromhex(line) for line in contents.splitlines()]


def read_json_tx(filename):
    with open(path.join(data_dir, filename)) as f:
        d = json.loads(f.read())
    return (Tx.from_hex(d['tx_hex']), d['input_values'],
            [bytes.fromhex(pk_hex) for pk_hex in d['input_pk_scripts']])
