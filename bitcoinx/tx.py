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
MINUS_1 = 4294967295


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


@attr.s(slots=True, repr=False)
class TxInput:
    '''A bitcoin transaction input.'''
    prev_hash = attr.ib()
    prev_idx = attr.ib()
    script_sig = attr.ib()
    sequence = attr.ib()

    def is_coinbase(self):
        '''Return True iff the input is the single input of a coinbase transaction.'''
        return self.prev_idx == MINUS_1 and self.prev_hash == ZERO

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
        '''Pass value to get a serialization to be used in transaction signatures.'''
        return b''.join((
            self.prevout_bytes(),
            pack_varbytes(bytes(self.script_sig)),
            pack_le_uint32(self.sequence),
        ))

    def __repr__(self):
        return (
            f'TxInput(prev_hash="{hash_to_hex_str(self.prev_hash)}", prev_idx={self.prev_idx}, '
            f'script_sig="{self.script_sig}", sequence={self.sequence})'
        )


@attr.s(slots=True, repr=False)
class TxOutput:
    '''A bitcoin transaction output.'''
    value = attr.ib()
    script_pk = attr.ib()

    @classmethod
    def read(cls, read):
        return cls(
            read_le_int64(read),           # value
            Script(read_varbytes(read)),   # script_pk
        )

    def to_bytes(self):
        return b''.join((
            pack_le_int64(self.value),
            pack_varbytes(bytes(self.script_pk)),
        ))

    def __repr__(self):
        return (
            f'TxOutput(value={self.value}, script_pk="{self.script_pk}")'
        )


@attr.s(slots=True, repr=False)
class TxInputAnnotated:
    '''A bitcoin transaction input.'''
    tx_input = attr.ib()    # A TxInput instance
    value = attr.ib()
    script_pk = attr.ib()
    public_key = attr.ib()
