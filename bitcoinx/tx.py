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

from .hashes import hash_to_hex_str
from .packing import (
    pack_le_int32, pack_le_uint32, pack_varint, pack_varbytes, pack_le_int64, pack_list,
    read_le_int32, read_le_uint32, read_varint, read_varbytes, read_le_int64, read_list,
)


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
            read(32),               # prev_hash
            read_le_uint32(read),   # prev_idx
            read_varbytes(read),    # script_sig
            read_le_uint32(read),   # sequence
        )

    def to_bytes(self):
        return b''.join((
            self.prev_hash,
            pack_le_uint32(self.prev_idx),
            pack_varbytes(self.script_sig),
            pack_le_uint32(self.sequence),
        ))

    def __repr__(self):
        return (
            f'TxInput(prev_hash="{hash_to_hex_str(self.prev_hash)}", prev_idx={self.prev_idx}, '
            f'script_sig="{self.script_sig.hex()}", sequence={self.sequence})'
        )


@attr.s(slots=True, repr=False)
class TxOutput:
    '''A bitcoin transaction output.'''
    value = attr.ib()
    script_pk = attr.ib()

    @classmethod
    def read(cls, read):
        return cls(
            read_le_int64(read),   # value
            read_varbytes(read),   # script_pk
        )

    def to_bytes(self):
        return b''.join((
            pack_le_int64(self.value),
            pack_varbytes(self.script_pk),
        ))

    def __repr__(self):
        return (
            f'TxOutput(value={self.value}, script_pk="{self.script_pk.hex()}")'
        )
