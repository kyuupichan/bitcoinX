import json
import os
from random import randrange, choice, random


from bitcoinx import (
    Tx, TxInput, TxOutput, Script, TxInputContext, SEQUENCE_FINAL,
    OP_FALSE, OP_1, OP_2, OP_3, OP_CHECKSIG, OP_IF, OP_VERIF, OP_RETURN, OP_CODESEPARATOR
)
from bitcoinx import misc

data_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


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
    return TxInput(os.urandom(32), randrange(0, 4), random_script(), sequence)


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


def random_txinput_context():
    tx = random_tx(False)
    input_index = randrange(0, len(tx.inputs))
    utxo = random_output()

    return TxInputContext(tx, input_index, utxo)


def read_file(filename):
    with open(os.path.join(data_dir, filename)) as f:
        return f.read()


def read_text_file(filename):
    return read_file(filename).strip()


def read_tx(filename):
    return Tx.from_hex(read_text_file(filename))


def read_signature_hashes(filename):
    with open(os.path.join(data_dir, filename)) as f:
        contents = f.read().strip()
    return [bytes.fromhex(line) for line in contents.splitlines()]


def read_json_tx(filename):
    with open(os.path.join(data_dir, filename)) as f:
        d = json.loads(f.read())
    return (Tx.from_hex(d['tx_hex']), d['input_values'],
            [bytes.fromhex(pk_hex) for pk_hex in d['input_pk_scripts']])


class Replace_os_urandom:

    os_urandom = os.urandom

    def __init__(self, values):
        self.values = values
        self.count = 0

    def our_urandom(self, n):
        if self.values:
            result = self.values.pop()
            assert len(result) == n
            return result
        raise EOFError

    def __enter__(self):
        assert os.urandom is self.os_urandom
        os.urandom = self.our_urandom

    def __exit__(self, type, value, traceback):
        os.urandom = self.os_urandom
