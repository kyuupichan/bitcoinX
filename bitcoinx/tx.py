# Copyright (c) 2019, Neil Booth
#
# All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


__all__ = (
    'Tx', 'TxInput', 'TxOutput',
)

import attr
from io import BytesIO

from .hashes import hash_to_hex_str, double_sha256
from .packing import (
    pack_le_int32, pack_le_uint32, pack_varbytes, pack_le_int64, pack_list,
    read_le_int32, read_le_uint32, read_varbytes, read_le_int64, read_list,
)
from .script import Script
from .signature import SigHash


ZERO = bytes(32)
UINT32_MAX = (1 << 32) - 1
LOCKTIME_THRESHOLD = 500_000_000


@attr.s(slots=True)
class Tx:
    '''A bitcoin transaction.'''
    version = attr.ib()
    inputs = attr.ib()
    outputs = attr.ib()
    locktime = attr.ib()

    def is_coinbase(self):
        '''Return True iff the tx is a coinbase transaction.'''
        return self.inputs[0].is_coinbase()

    @classmethod
    def read(cls, read):
        return cls(
            read_le_int32(read),
            read_list(read, TxInput.read),
            read_list(read, TxOutput.read),
            read_le_uint32(read),
        )

    @classmethod
    def from_bytes(cls, raw):
        return cls.read(BytesIO(raw).read)

    def to_bytes(self):
        return b''.join((
            pack_le_int32(self.version),
            pack_list(self.inputs, TxInput.to_bytes),
            pack_list(self.outputs, TxOutput.to_bytes),
            pack_le_uint32(self.locktime),
        ))

    @classmethod
    def from_hex(cls, hex_str):
        return cls.from_bytes(bytes.fromhex(hex_str))

    def to_hex(self):
        return self.to_bytes().hex()

    def _hash_prevouts(self):
        preimage = b''.join(txin.prevout_bytes() for txin in self.inputs)
        return double_sha256(preimage)

    def _hash_sequence(self):
        preimage = b''.join(pack_le_uint32(txin.sequence) for txin in self.inputs)
        return double_sha256(preimage)

    def _hash_outputs(self):
        preimage = b''.join(txout.to_bytes() for txout in self.outputs)
        return double_sha256(preimage)

    def signature_hash(self, input_index, value, script, *, sighash=None):
        if not 0 <= input_index < len(self.inputs):
            raise IndexError(f'invalid input index: {input_index}')
        if value < 0:
            raise ValueError(f'value cannot be negative: {value}')
        if sighash is None:
            sighash = SigHash(SigHash.ALL | SigHash.FORKID)
        if not isinstance(sighash, SigHash):
            raise TypeError('sighash must be a SigHash instance')

        txin = self.inputs[input_index]
        hash_prevouts = hash_sequence = hash_outputs = ZERO

        sighash_not_single_none = sighash.base not in (SigHash.SINGLE, SigHash.NONE)
        if not sighash.anyone_can_pay:
            hash_prevouts = self._hash_prevouts()
            if sighash_not_single_none:
                hash_sequence = self._hash_sequence()
        if sighash_not_single_none:
            hash_outputs = self._hash_outputs()
        elif (sighash.base == SigHash.SINGLE and input_index < len(self.outputs)):
            hash_outputs = double_sha256(self.outputs[input_index].to_bytes())

        preimage = b''.join((
            pack_le_int32(self.version),
            hash_prevouts,
            hash_sequence,
            txin.to_bytes_for_signature(value, script),
            hash_outputs,
            pack_le_uint32(self.locktime),
            pack_le_uint32(sighash),
        ))

        return double_sha256(preimage)

    def are_inputs_final(self):
        '''Return True if all inputs are final.'''
        return all(txin.is_final() for txin in self.inputs)

    def is_final_for_block(self, block_height, timestamp):
        '''Return True if a transaction is final for the given height and timestamp.

        Transactions cannot be mined unless final.  BIP113 introduced the consensus rule
        that the timestamp is the MTP of the previous block; the median timestamp of the
        11 blocks with heights [block_height-11, block_height-1].  The previous consensus
        rule was to use the block's timestamp.
        '''
        return (
            self.locktime == 0 or
            self.locktime < (block_height if self.locktime < LOCKTIME_THRESHOLD else timestamp) or
            self.are_inputs_final()
        )

    def hash(self):
        '''Return the transaction hash.   Only makes sense for fully-signed transactions.'''
        return double_sha256(self.to_bytes())

    def hex_hash(self):
        '''Return the transaction hash as a hex string if it is complete, otherwise None.'''
        tx_hash = self.hash()
        return hash_to_hex_str(tx_hash) if tx_hash else None

    def total_output_value(self):
        '''Return the sum of the output values.'''
        return sum(output.value for output in self.outputs)


@attr.s(slots=True, repr=False)
class TxInput:
    '''A bitcoin transaction input.'''
    prev_hash = attr.ib()
    prev_idx = attr.ib()
    script_sig = attr.ib()
    sequence = attr.ib()

    def is_coinbase(self):
        '''Return True iff the input is the single input of a coinbase transaction.'''
        return self.prev_idx == UINT32_MAX and self.prev_hash == ZERO

    @classmethod
    def read(cls, read):
        return cls(
            read(32),                       # prev_hash
            read_le_uint32(read),           # prev_idx
            Script(read_varbytes(read)),    # script_sig
            read_le_uint32(read),           # sequence
        )

    def prevout_bytes(self):
        return self.prev_hash + pack_le_uint32(self.prev_idx)

    def to_bytes_for_signature(self, value, script):
        return b''.join((
            self.prevout_bytes(),
            pack_varbytes(bytes(script)),
            pack_le_int64(value),
            pack_le_uint32(self.sequence),
        ))

    def to_bytes(self):
        return b''.join((
            self.prevout_bytes(),
            pack_varbytes(bytes(self.script_sig)),
            pack_le_uint32(self.sequence),
        ))

    def is_final(self):
        return self.sequence == 0xffffffff

    def __repr__(self):
        return (
            f'TxInput(prev_hash="{hash_to_hex_str(self.prev_hash)}", prev_idx={self.prev_idx}, '
            f'script_sig="{self.script_sig}", sequence={self.sequence})'
        )


@attr.s(slots=True, repr=False)
class TxOutput:
    '''A bitcoin transaction output.'''
    value = attr.ib()
    script_pubkey = attr.ib()

    @classmethod
    def read(cls, read):
        return cls(
            read_le_int64(read),           # value
            Script(read_varbytes(read)),   # script_pubkey
        )

    def to_bytes(self):
        return b''.join((
            pack_le_int64(self.value),
            pack_varbytes(bytes(self.script_pubkey)),
        ))

    def __repr__(self):
        return (
            f'TxOutput(value={self.value}, script_pubkey="{self.script_pubkey}")'
        )
