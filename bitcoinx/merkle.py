# Copyright (c) 2024, Neil Booth
#
# All rights reserved.
#
# This file is licensed under the Open BSV License version 3, see LICENCE for details.

'''Merkle trees, branches, proofs and roots.'''

import json
from io import BytesIO
from math import ceil, log

from .errors import MerkleError
from .hashes import double_sha256, hash_to_hex_str, hex_str_to_hash
from .packing import (
    pack_varint, read_varint, PackingError,
)


__all__ = ('merkle_path_length', 'merkle_root')


def merkle_path_length(tx_count):
    return max(1, ceil(log(tx_count, 2)))


def merkle_root(hashes):
    '''Given a list of transaction hashes for a block, return the merkle root.'''
    if not hashes:
        raise ValueError('hashes list cannot be empty')

    while len(hashes) > 1:
        hashes = list(next_level(hashes))

    return hashes[0]


def next_level(hashes):
    '''Generator for the hashes one level up the merkle tree.'''
    hash_fn = double_sha256
    for n in range(0, len(hashes) - 1, 2):
        yield hash_fn(hashes[n] + hashes[n + 1])
    if len(hashes) & 1:
        yield hash_fn(hashes[-1] * 2)


def calc_level(hashes, in_offsets, is_first):
    if is_first:
        offsets = set(offset ^ 1 for offset in in_offsets)
        offsets.update(in_offsets)
    else:
        offsets = set(offset ^ 1 for offset in in_offsets).difference(in_offsets)
    offsets.discard(len(hashes))
    level = {offset: hashes[offset] for offset in offsets}
    return level, {offset // 2 for offset in in_offsets}


def level_map(level):
    result = {offset: hash_ for offset, hash_ in level}
    if any(result[offset] != hash_ for offset, hash_ in level):
        raise MerkleError('conflicting leaves in path')
    return result


def iterate_path(path, length):
    for level in path:
        yield level, length
        length = (length + 1) // 2


def uplift_level(level, length):
    '''Move up a level in the merkle tree.'''
    result = {}
    for offset in set(offset | 1 for offset in level):
        if offset == length:
            result[offset // 2] = double_sha256(level[offset - 1] * 2)
        else:
            result[offset // 2] = double_sha256(level[offset - 1] + level[offset])

    return result


def validate_path(path):
    '''Check the path is good and return a (merkle root, tx count, canonical path) triple.

    Rejects offsets that are out of range, extraneous leaves, and missing leaves.
    Removes redundant leaves.'''
    if not path:
        raise MerkleError('path cannot be empty')

    # By protocol the greatest offset is that of the last tx in the block
    tx_count = max(path[0].keys()) + 1
    length = merkle_path_length(tx_count)
    if len(path) != length:
        raise MerkleError(f'path length for {tx_count:,d} transactions should be {length}')

    # Our own independent copy so we can remove duplicates
    path = [level.copy() for level in path]
    for level, length in iterate_path(path, tx_count):
        # Reject negative offsets
        if level and min(level.keys()) < 0:
            raise MerkleError('extraneous leaves in path')

        if length == tx_count:
            # First level acts as the uplift
            uplift, level = level, {}
            if tx_count == 1:
                break

        offsets = set(uplift.keys())
        required_offsets = set(offset ^ 1 for offset in offsets).difference(offsets)
        required_offsets.discard(length)
        level_offsets = set(level.keys())
        if required_offsets.difference(level_offsets):
            raise MerkleError('missing leaves in path')
        other_offsets = level_offsets.difference(required_offsets)
        for offset in other_offsets:
            uhash = uplift.get(offset)
            if uhash is None:
                raise MerkleError('extraneous leaves in path')
            # Deduplicate
            if uhash != level.pop(offset):
                raise MerkleError('conflicting leaves in path')

        # Level is good; merge it, check for phantoms, and calculate the next uplift.
        uplift.update(level)
        if length & 1 == 0 and uplift[length - 1] == uplift[length - 2]:
            raise MerkleError('merkle tree has phantom branch')
        uplift = uplift_level(uplift, length)

    return uplift[0], tx_count, path


class BUMP:
    '''BSV Unified Merkle Path.'''

    def __init__(self, path):
        '''path should be an iterable, each entry being a dictionary mapping offsets to hashes.

        The levels in the path range from the broadest level of the tree to the narrowest,
        ending when the tree has width <=2.  The last tx in the block is always present in
        the first level..
        '''
        self.root, self.tx_count, self.path = validate_path(path)

    def __eq__(self, other):
        return self.is_compatible(other) and self.path == other.path

    def is_compatible(self, other):
        '''Return True if other is a BUMP for the same block.'''
        if not isinstance(other, BUMP):
            raise TypeError('other must be of type BUMP')
        return self.root == other.root and self.tx_count == other.tx_count

    def tx_hashes(self):
        '''Returns a map of transaction_hash -> pos_in_block proven by this BUMP.'''
        return {tx_hash: offset for offset, tx_hash in self.path[0].items()}

    def merge(self, other):
        '''Return a new BUMP representing the merger of this one with another.'''
        if not self.is_compatible(other):
            raise MerkleError('cannot merge with a BUMP of a different block')

        def merge_level(lhs, rhs):
            result = lhs.copy()
            result.update(rhs)
            return result

        return BUMP([merge_level(lhs, rhs) for lhs, rhs in zip(self.path, other.path)])

    def to_bytes(self, height):
        '''Return the bump in binary format.'''
        def parts():
            yield pack_varint(height)
            for level in self.path:
                yield pack_varint(len(level))
                for offset, hash_ in level.items():
                    yield pack_varint(offset)
                    yield hash_

        return b''.join(parts())

    def to_json(self, height):
        def level_json(level):
            # Lowest offsets first
            pairs = sorted((offset, hash_) for offset, hash_ in level.items())
            return [{'offset': offset, 'hash': hash_to_hex_str(hash_)} for offset, hash_ in pairs]

        return json.dumps({
            'blockHeight': height,
            'path': [level_json(level) for level in self.path],
        })

    @classmethod
    def from_json(cls, text):
        data = json.loads(text)
        height = data['blockHeight']
        path = [
            level_map([(leaf['offset'], hex_str_to_hash(leaf['hash'])) for leaf in level])
            for level in data['path']
        ]
        return height, cls(path)

    @classmethod
    def from_bytes(cls, raw):
        '''Returns a (height, bump) pair.'''
        read = BytesIO(raw).read
        result = cls.read(read)
        if read(1) != b'':
            raise PackingError('excess bytes in raw data')
        return result

    @classmethod
    def read(cls, read):
        '''Returns a (height, bump) pair.'''
        def read_level_map(read):
            return level_map([(read_varint(read), read(32)) for _ in range(read_varint(read))])

        try:
            height = read_varint(read)
            level = read_level_map(read)
            tx_count = max(level.keys()) + 1

            path = [level]
            path.extend(read_level_map(read) for _ in range(merkle_path_length(tx_count) - 1))

            if path[-1] and any(len(hash_) != 32 for hash_ in path[-1].values()):
                raise PackingError('hashes have length 32 bytes')
        except PackingError:
            raise PackingError('truncated stream reading BUMP') from None

        return height, cls(path)

    @classmethod
    def create(cls, tx_hashes, hashes_to_prove):
        def levels(hashes, offsets):
            is_first = True
            while True:
                level, offsets = calc_level(hashes, offsets, is_first)
                yield level
                if len(hashes) <= 2:
                    return
                hashes = list(next_level(hashes))
                is_first = False

        if not tx_hashes:
            raise MerkleError('tx_hashes cannot be empty')

        offset_map = {tx_hash: offset for offset, tx_hash in enumerate(tx_hashes)}
        if len(offset_map) != len(tx_hashes):
            raise MerkleError('duplicate transaction hashes')

        try:
            offsets = set((offset_map[hash_to_prove] for hash_to_prove in hashes_to_prove))
            # Always include the last transaction
            offsets.add(len(tx_hashes) - 1)
        except KeyError:
            raise MerkleError('all hashes to prove must be present') from None

        return cls(list(levels(tx_hashes, offsets)))
