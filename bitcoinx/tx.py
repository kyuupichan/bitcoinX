# Copyright (c) 2018-2021, Neil Booth
#
# All rights reserved.
#
# Licensed under the the Open BSV License version 3; see LICENCE for details.
#


__all__ = (
    'Tx', 'TxInput', 'TxOutput',
)

import attr
import datetime
from io import BytesIO
from typing import List

from .consts import JSONFlags, LOCKTIME_THRESHOLD, ZERO, ONE, SEQUENCE_FINAL
from .hashes import hash_to_hex_str, double_sha256
from .packing import (
    pack_le_int32, pack_le_uint32, pack_varbytes, pack_le_int64, pack_list, varint_len,
    read_le_int32, read_le_uint32, read_varbytes, read_le_int64, read_list
)
from .script import Script, Ops
from .signature import SigHash


@attr.s(slots=True)
class Tx:
    '''A bitcoin transaction.'''
    version: int = attr.ib()
    inputs: List["TxInput"] = attr.ib()
    outputs: List["TxOutput"] = attr.ib()
    locktime: int = attr.ib()

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

    def _forkid_signature_hash(self, input_index, value, script_code, sighash):
        '''Return the post-fork preimage that needs to be signed for the given input, script, and
        sighash type.  Value is the value of the output being spent, which is committed to.
        '''
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
            txin.to_bytes_for_signature(value, script_code),
            hash_outputs,
            pack_le_uint32(self.locktime),
            pack_le_uint32(sighash),
        ))

        return double_sha256(preimage)

    def _original_signature_hash(self, input_index, script_code, sighash):
        '''Return the pre-fork preimage that needs to be signed for the given input, script, and
        sighash type.
        '''
        assert input_index < len(self.inputs)

        if sighash.base == SigHash.SINGLE and input_index >= len(self.outputs):
            return ONE

        def serialize_input(n):
            if sighash.anyone_can_pay:
                n = input_index
            tx_input = self.inputs[n]
            if n != input_index and sighash.base in (SigHash.SINGLE, SigHash.NONE):
                sequence = 0
            else:
                sequence = tx_input.sequence
            if n == input_index:
                script = Script(script_code).find_and_delete(Script() << Ops.OP_CODESEPARATOR)
            else:
                script = b''

            return b''.join((
                tx_input.prevout_bytes(),
                pack_varbytes(bytes(script)),
                pack_le_uint32(sequence),
            ))

        def serialize_output(n):
            if sighash.base == SigHash.SINGLE and n != input_index:
                return TxOutput.NULL_SERIALIZATION
            else:
                return self.outputs[n].to_bytes()

        if sighash.anyone_can_pay:
            input_args = [0]
        else:
            input_args = list(range(len(self.inputs)))

        if sighash.base == SigHash.NONE:
            output_args = []
        elif sighash.base == SigHash.SINGLE:
            output_args = list(range(input_index + 1))
        else:
            output_args = list(range(len(self.outputs)))

        preimage = b''.join((
            pack_le_int32(self.version),
            pack_list(input_args, serialize_input),
            pack_list(output_args, serialize_output),
            pack_le_uint32(self.locktime),
            pack_le_uint32(sighash),
        ))

        return double_sha256(preimage)

    def signature_hash(self, input_index, value, script_code, sighash):
        '''Return the hash that needs to be signed for the given input, script, and sighash type.
        Value is the value of the output being spent, which is committed to as part of the
        signature post-fork.

        scrpipt is a subset of the output's script_pubkey that is being signed; it can be
        raw bytes or a Script object.  This starts at its beginning, or from the byte
        beyond the most recent OP_CODESEPARATOR, and ends at the end of the output script.
        '''
        if not 0 <= input_index < len(self.inputs):
            raise IndexError(f'invalid input index: {input_index}')
        if value < 0:
            raise ValueError(f'value cannot be negative: {value}')
        if not isinstance(sighash, SigHash):
            raise TypeError('sighash must be a SigHash instance')

        if sighash.has_forkid():
            return self._forkid_signature_hash(input_index, value, script_code, sighash)

        return self._original_signature_hash(input_index, script_code, sighash)

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

    @staticmethod
    def size_io(inputs, outputs):
        '''Return the size of a transaction with the given inputs and outputs.

        Faster than serializing and taking its length.
        '''
        # 8 for version and locktime
        return (varint_len(len(inputs)) + sum(tx_input.size() for tx_input in inputs) +
                varint_len(len((outputs))) + sum(output.size() for output in outputs) + 8)

    def size(self):
        '''Return the size of the transaction.  More efficient than serializing to bytes.'''
        return self.size_io(self.inputs, self.outputs)

    def total_output_value(self):
        '''Return the sum of the output values.'''
        return sum(output.value for output in self.outputs)

    def to_json(self, flags, network):
        result = {
            'version': self.version,
            'nInputs': len(self.inputs),
            'vin': [input.to_json(flags, index) for index, input in enumerate(self.inputs)],
            'nOutputs': len(self.outputs),
            'vout': [output.to_json(flags, network, index)
                     for index, output in enumerate(self.outputs)],
            'locktime': self.locktime,
            'hash': self.hex_hash(),
        }
        if flags & JSONFlags.SIZE:
            result['size'] = self.size()
        if flags & JSONFlags.LOCKTIME_MEANING:
            result['locktimeMeaning'] = locktime_description(self.locktime)
        return result


@attr.s(slots=True, repr=False)
class TxInput:
    '''A bitcoin transaction input.'''
    prev_hash: bytes = attr.ib()
    prev_idx: int = attr.ib()
    script_sig: Script = attr.ib()
    sequence: int = attr.ib()

    def is_coinbase(self):
        '''Return True iff the input is the single input of a coinbase transaction.'''
        return self.prev_idx == 0xffffffff and self.prev_hash == ZERO

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

    def to_hex(self):
        return self.to_bytes().hex()

    @classmethod
    def from_bytes(cls, raw):
        return cls.read(BytesIO(raw).read)

    @classmethod
    def from_hex(cls, hex_str):
        return cls.from_bytes(bytes.fromhex(hex_str))

    def size(self):
        '''Return the serialized size of the input in bytes.'''
        n = len(self.script_sig)
        # 40 for prevout and sequence
        return 40 + varint_len(n) + n

    def is_final(self):
        return self.sequence == SEQUENCE_FINAL

    def to_json(self, flags, index=None):
        if self.is_coinbase():
            result = {
                'coinbase': self.script_sig.to_hex(),
                'text': self.script_sig.to_bytes().decode(errors='replace'),
                'sequence': self.sequence,
            }
        else:
            result = {
                'hash': self.prev_hash.hex(),
                'idx': self.prev_idx,
                'script': self.script_sig.to_json(flags, True, None),
                'sequence': self.sequence,
            }

        if flags & JSONFlags.ENUMERATE_INPUTS and index is not None:
            result['nInput'] = index
        return result

    def __repr__(self):
        return (
            f'TxInput(prev_hash="{hash_to_hex_str(self.prev_hash)}", prev_idx={self.prev_idx}, '
            f'script_sig="{self.script_sig}", sequence={self.sequence})'
        )


@attr.s(slots=True, repr=False)
class TxOutput:
    '''A bitcoin transaction output.'''
    value: int = attr.ib()
    script_pubkey: Script = attr.ib()

    @classmethod
    def read(cls, read):
        return cls(
            read_le_int64(read),           # value
            Script(read_varbytes(read)),   # script_pubkey
        )

    @classmethod
    def null(cls):
        return cls(-1, Script())

    def to_bytes(self):
        return b''.join((
            pack_le_int64(self.value),
            pack_varbytes(bytes(self.script_pubkey)),
        ))

    def size(self):
        '''Return the serialized size of the output in bytes.'''
        n = len(self.script_pubkey)
        # 8 for the value
        return 8 + varint_len(n) + n

    def to_hex(self):
        return self.to_bytes().hex()

    @classmethod
    def from_bytes(cls, raw):
        return cls.read(BytesIO(raw).read)

    @classmethod
    def from_hex(cls, hex_str):
        return cls.from_bytes(bytes.fromhex(hex_str))

    def to_json(self, flags, network, index=None):
        result = {
            'value': self.value,
            'script': self.script_pubkey.to_json(flags, False, network),
        }
        if flags & JSONFlags.ENUMERATE_OUTPUTS and index is not None:
            result['nOutput'] = index
        return result

    def __repr__(self):
        return (
            f'TxOutput(value={self.value}, script_pubkey="{self.script_pubkey}")'
        )


TxOutput.NULL_SERIALIZATION = TxOutput.null().to_bytes()


def locktime_description(locktime):
    '''A human-readable description of meaning of locktime.'''
    if locktime == 0:
        return 'valid in any block'
    if locktime < 500_000_000:
        return f'valid in blocks with height greater than {locktime:,d}'
    utc = datetime.datetime.utcfromtimestamp(locktime)
    return f'valid in blocks with MTP greater than {utc.isoformat(" ")} UTC'
