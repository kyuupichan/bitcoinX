import asyncio
import json
import os
import random

import asqlite3

from bitcoinx import (
    Tx, TxInput, TxOutput, Script, TxInputContext, SEQUENCE_FINAL,
    OP_FALSE, OP_1, OP_2, OP_3, OP_CHECKSIG, OP_IF, OP_VERIF, OP_RETURN, OP_CODESEPARATOR,
    Bitcoin, BitcoinTestnet, Headers, pack_header, SimpleHeader
)
from bitcoinx.misc import chunks

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
    return random.randrange(0, 100_000_000)


def random_script():
    ops = [random.choice(random_ops) for _ in range(random.randrange(0, 10))]
    return Script().push_many(ops)


def random_bool():
    return random.random() >= 0.5


def random_input():
    sequence = SEQUENCE_FINAL if random_bool() else random.randrange(0, SEQUENCE_FINAL)
    return TxInput(os.urandom(32), random.randrange(0, 4), random_script(), sequence)


def random_output():
    return TxOutput(random_value(), random_script())


def random_tx(is_single):
    version = random.randrange(- (1 << 31), 1 << 31)
    locktime = 0 if random_bool() else random.randrange(0, 1 << 32)
    n_inputs = random.randrange(1, 5)
    n_outputs = n_inputs + random.randrange(-1, 1) if is_single else random.randrange(1, 5)
    inputs = [random_input() for _ in range(n_inputs)]
    outputs = [random_output() for _ in range(n_outputs)]

    return Tx(version, inputs, outputs, locktime)


def random_txinput_context():
    tx = random_tx(False)
    input_index = random.randrange(0, len(tx.inputs))
    utxo = random_output()

    return TxInputContext(tx, input_index, utxo)


def data_dir_path(filename):
    return os.path.join(data_dir, filename)


def read_file(filename, count=None):
    with open(data_dir_path(filename), 'rb') as f:
        return f.read(count)


def read_text_file(filename):
    return read_file(filename).decode().strip()


def read_tx(filename):
    return Tx.from_hex(read_text_file(filename))


def read_signature_hashes(filename):
    with open(data_dir_path(filename)) as f:
        contents = f.read().strip()
    return [bytes.fromhex(line) for line in contents.splitlines()]


def read_json_tx(filename):
    with open(data_dir_path(filename)) as f:
        d = json.loads(f.read())
    return (Tx.from_hex(d['tx_hex']), d['input_values'],
            [bytes.fromhex(pk_hex) for pk_hex in d['input_pk_scripts']])


def first_mainnet_headers(count):
    raw_headers = read_file('mainnet-headers-2016.raw', count * 80)
    simple_headers = [SimpleHeader(raw_header) for raw_header in chunks(raw_headers, 80)]
    return simple_headers


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

    def __exit__(self, _type, _value, _traceback):
        os.urandom = self.os_urandom


def run_test_with_headers(test_func, network=Bitcoin):
    async def run():
        async with asqlite3.connect(':memory:') as conn:
            # Create two copies of the tables with different schemas, to ensure the code
            # always queries with the appropriate schema
            headers1 = Headers(conn, 'main', BitcoinTestnet)
            await headers1.initialize()
            await conn.execute("ATTACH ':memory:' as second")
            headers = Headers(conn, 'second', network)
            await headers.initialize()
            await test_func(headers)

    asyncio.run(run())


def create_random_header(prev_header):
    version = random.randrange(0, 10)
    merkle_root = os.urandom(32)
    timestamp = prev_header.timestamp + random.randrange(-300, 900)
    bits = prev_header.bits
    nonce = random.randrange(0, 1 << 32)
    raw_header = pack_header(version, prev_header.hash, merkle_root, timestamp, bits, nonce)
    return SimpleHeader(raw_header)


def create_random_branch(prev_header, length):
    branch = []
    for _ in range(length):
        header = create_random_header(prev_header)
        branch.append(header)
        prev_header = header
    return branch


def create_random_tree(base_header, branch_count=10, max_branch_length=10):
    headers = [base_header]
    tree = []
    for _ in range(branch_count):
        branch_header = random.choice(headers)
        branch_length = random.randrange(1, max_branch_length + 1)
        branch = create_random_branch(branch_header, branch_length)
        tree.append((branch_header, branch))
        # To form a branch, a branch must be based on other than a tip
        headers.extend(branch[:-1])

    return tree


async def insert_tree(headers, tree):
    for _, branch in tree:
        await headers.insert_headers(branch, check_work=False)


def in_caplog(caplog, message, count=1):
    cap_count = sum(message in record.message for record in caplog.records)
    if count is None:
        return bool(cap_count)
    return count == cap_count


def print_caplog(caplog):
    for record in caplog.records:
        print(record.message)
