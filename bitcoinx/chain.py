# Copyright (c) 2018, 2019, Neil Booth
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
    'Chain', 'CheckPoint', 'Headers', 'MissingHeader', 'HeaderStorage',
)

import array
from collections import namedtuple
import logging
import math
from struct import Struct

from bitcoinx.hashes import hash_to_hex_str
from bitcoinx.packing import pack_le_uint32, unpack_le_uint32
from bitcoinx.util import map_file


empty_header = bytes(80)
logger = logging.getLogger('chain')


# The prev_work of a checkpoint is the cumulative work prior to the checkpoint and does
# not including the work of the checkpoint itself
CheckPoint = namedtuple('CheckPoint', 'raw_header height prev_work')


class MissingHeader(Exception):
    pass


class BadHeadersFile(Exception):
    pass


class Chain(object):
    '''A dumb object representing a chain of headers back to the genesis block (implemented
    through parent chains).

    Public attributes:
        parent  the parent chain this one forks from, can be None
        height  the height of the chain
        tip     the Header object of the chain tip
        work    cumulative chain work to the tip
    '''

    def __init__(self, parent, tip, tip_header_index, prev_work):
        '''common_height is the greatest height common to the chain and its parent.'''
        self.parent = parent
        self.tip = tip
        self.work = prev_work + tip.work()
        self._header_indices = array.array('I')
        self._header_indices.append(tip_header_index)
        self._first_height = tip.height

    @classmethod
    def from_checkpoint(cls, checkpoint, coin):
        tip = coin.deserialized_header(checkpoint.raw_header, checkpoint.height)
        return cls(None, tip, tip.height, checkpoint.prev_work)

    def append(self, header, header_index):
        '''Append a header to the chain along with its index in storage.'''
        self.tip = header
        self._header_indices.append(header_index)
        self.work += header.work()

    def header_index(self, height):
        '''Return the index of the header in storage.'''
        if height >= self._first_height:
            try:
                return self._header_indices[height - self._first_height]
            except IndexError:
                pass
        elif self.parent:
            return self.parent.header_index(height)
        elif height >= 0:
            return height
        raise MissingHeader(f'no header at height {height}')

    def log2_work(self, dps=8):
        result = math.log(self.work, 2)
        if dps is not None:
            result = round(result, dps)
        return result

    @property
    def height(self):
        return self._first_height + len(self._header_indices) - 1


class HeaderStorage(object):
    '''Implementation of raw header storage for flat files.

    Block headers are looked up by index, which in general is not equal to its height.

    If a block header is read that has not been set, MissingHeader is raised.

    Block headers are 80 bytes; the caller is responsible for their validation.

    Flat files are stored as a reserved area, followed by the headers consecutively.
    The reserved area has the following format:
       a) reserved area size (little endian uint16)
       b) version number (little endian uint16)
       c) block header count (little endian uint32)
    '''
    struct_reserved = Struct('<HHI')

    def __init__(self, filename, checkpoint):
        '''Open filename for header storage with the given checkpoint.

        If opening the file raises FileNotFoundError then it is created.

        If the file exists but is not consistent with the given checkpoint (too few
        headers or the header conflicts) then the file is re-created as if it didn't
        exist.

        On successful return the storage file is good for the checkpoint.
        '''
        self.filename = filename
        self.checkpoint = checkpoint
        self.mmap = None
        self.reserved_size = self.struct_reserved.size
        self.header_count = 0

    def _offset(self, key):
        return self.reserved_size + key * 80

    def _create_file(self):
        s = self.struct_reserved
        self.reserved_size = s.size
        with open(self.filename, 'wb') as f:
            f.write(s.pack(s.size, 0, self.checkpoint.height + 1))
            f.seek(self._offset(self.checkpoint.height))
            f.write(self.checkpoint.raw_header)

    def _open_file(self):
        logger.debug(f'opening headers file {self.filename}')
        s = self.struct_reserved
        self.mmap = map_file(self.filename)
        if len(self.mmap) >= s.size:
            self.reserved_size, version, self.header_count = s.unpack(self.mmap[:s.size])
            if version == 0 and self[self.checkpoint.height] == self.checkpoint.raw_header:
                return
        self.mmap.close()
        self.mmap = None
        raise BadHeadersFile(f'invalid headers file {self.filename}')

    def open_or_create(self):
        try:
            self._open_file()
            return
        except FileNotFoundError:
            logger.debug(f'{self.filename} not found, creating it')
        except (BadHeadersFile, MissingHeader):
            logger.debug(f're-creating headers file {self.filename}')
        self._create_file()
        self._open_file()

    def _set_count(self, count):
        self.mmap[4:8] = pack_le_uint32(count)

    def _set_raw_header(self, index, raw_header):
        if not isinstance(raw_header, bytes) or len(raw_header) != 80:
            raise TypeError('raw header must be binary of length 80')
        # Grow if needed
        mmap = self.mmap
        start = self._offset(index)
        if start >= len(mmap):
            mmap.close()
            mmap = self.mmap = map_file(self.filename, self._offset(index + 5_000))
        if index >= len(self):
            self._set_count(index + 1)
        self.mmap[start: start + 80] = raw_header

    def __getitem__(self, key):
        def header(index):
            start = self._offset(index)
            result = self.mmap[start: start + 80]
            if not result or result == empty_header:
                raise MissingHeader(f'no header at index {index}')
            return result

        if isinstance(key, int):
            if key < 0:
                key += len(self)
            return header(key)
        elif isinstance(key, slice):
            return [header(index) for index in range(*key.indices(len(self)))]
        raise TypeError(f'key {key} should be an integer')

    def __setitem__(self, key, raw_header):
        if isinstance(key, int):
            if not 0 <= key <= self.checkpoint.height:
                raise ValueError(f'cannot set header at height {key:,d}')
            self._set_raw_header(key, raw_header)
        else:
            raise TypeError(f'key {key} should be an integer')

    def __len__(self):
        count, = unpack_le_uint32(self.mmap[4:8])
        return count

    def append(self, raw_header):
        header_index = len(self)
        self._set_raw_header(header_index, raw_header)
        return header_index

    def pop_last(self):
        new_count = len(self) - 1
        self._set_count(new_count)
        offset = self._offset(new_count)
        self.mmap[offset: offset + 80] = empty_header

    def close(self):
        self.mmap.close()

    def flush(self):
        return self.mmap.flush()


class Headers(object):
    '''A collection of block headers, including a checkpoint header, arranged into chains.
    Each header header belongs to precisely one chain.  Each chain has a parent chain
    which it forked from, except one chain whose parent is None.

    Headers before the checkpoint can be set and no validation is performed; the caller is
    presumed to have done any necessary validation.  Headers after the checkpoint must be
    added; this looks up the previous header and raises MissingHeader if it cannot be
    found.  If the previous header is the tip of a chain the new header extends that chain
    and replaces its tip, otherwise a new chain is created with the header as its tip.

    Chains can only fork after the checkpoint header.  Headers before the checkpoint may
    be missing (i.e., the chain may have holes) and attempts to retrieve them raise a
    MissingHeader exception.  After the checkpoint all headers in a chain exist by
    construction.

    Headers can be looked up by height on a given chain.  They can be looked up by hash in
    which case the header and its chain are returned as a pair.

    Deserialized "Header" objects that are returnd always have their hash and height set
    in addition to the standard header attributes such as nonce and timestamp.
    '''

    def __init__(self, coin, storage):
        self.coin = coin
        self.storage = storage
        self._chains = []
        self._short_hashes = bytearray()
        self._heights = array.array('I')
        self._chain_indices = array.array('H')
        self._cache = {}

        # Create the base chain out to the checkpoint
        self._add_chain(Chain.from_checkpoint(storage.checkpoint, coin))
        # Read in chains from storage
        self._read_headers()

    def _add_chain(self, chain):
        chain.index = len(self._chains)
        self._chains.append(chain)
        self._add_chain_tip(chain)

    def _add_chain_tip(self, chain):
        header = chain.tip
        self._short_hashes.extend(header.hash[:4])
        self._heights.append(header.height)
        self._chain_indices.append(chain.index)
        # Add to cache; prevent it getting too big
        cache = self._cache
        cache[header.hash] = header, chain
        if len(cache) > 1000:
            keys = list(cache.keys())
            for n in range(len(cache) // 2):
                del cache[keys[n]]
            cache.update({chain.tip.hash: (chain.tip, chain) for chain in self._chains})

    def _header_index_slow(self, header_hash):
        key = header_hash[:4]
        start = 0
        while True:
            index = self._short_hashes.find(key, start)
            if index % 4 == 0:
                our_index = index // 4
                raw_header = self.storage[our_index + self.storage.checkpoint.height]
                if self.coin.header_hash(raw_header) == header_hash:
                    return raw_header, our_index
            if index == -1:
                raise MissingHeader(f'no header with hash {hash_to_hex_str(header_hash)}')
            start += 1

    def _read_headers(self):
        '''Read in all the headers from storage.'''
        read_header = self._read_header
        for header_index in range(self.storage.checkpoint.height + 1, len(self.storage)):
            read_header(header_index)

    def _read_header(self, header_index):
        '''Read a single header from storage.  The header must connect, either to extend an
        existing chain or create a new one.  Return the chain the header lies on.
        '''
        new_tip = self.coin.deserialized_header(self.storage[header_index], -1)
        prev_header, chain = self.lookup_header_and_chain(new_tip.prev_hash)
        new_tip.height = prev_header.height + 1
        if chain.tip.hash == prev_header.hash:
            chain.append(new_tip, header_index)
            self._add_chain_tip(chain)
        else:
            prev_work = self.chainwork_to_height(chain, prev_header.height)
            chain = Chain(chain, new_tip, header_index, prev_work)
            self._add_chain(chain)
        return chain

    def add_raw_header(self, raw_header):
        '''Add a single header to storage if it connects, either to extend an existing chain or
        create a new one.  Return the chain the header lies on.
        '''
        header_index = self.storage.append(raw_header)
        try:
            return self._read_header(header_index)
        except MissingHeader:
            self.storage.pop_last()
            raise

    def set_one(self, height, raw_header):
        '''Set the raw header for a height before the checkpoint.

        The caller is responsible for the validity of the raw header.'''
        self.storage[height] = raw_header

    def chainwork_range(self, chain, start_height, end_height):
        '''Returns the chainwork for the half-open range [start_height, end_height).'''
        raw_header = self.storage.__getitem__
        get_header_index = chain.header_index
        header_work = self.coin.header_work
        return sum(header_work(raw_header(get_header_index(h)))
                   for h in range(start_height, end_height))

    def chainwork_to_height(self, chain, height):
        '''Returns the chainwork to and including height on a chain.'''
        return chain.work - self.chainwork_range(chain, height + 1, chain.tip.height + 1)

    def raw_header_at_height(self, chain, height):
        return self.storage[chain.header_index(height)]

    def header_at_height(self, chain, height):
        raw_header = self.raw_header_at_height(chain, height)
        return self.coin.deserialized_header(raw_header, height)

    def lookup_header_and_chain(self, header_hash):
        result = self._cache.get(header_hash)
        if result:
            return result
        raw_header, our_index = self._header_index_slow(header_hash)
        header = self.coin.deserialized_header(raw_header, self._heights[our_index])
        return header, self._chains[self._chain_indices[our_index]]

    def __len__(self):
        return len(self.storage)

    def chains(self):
        return self._chains

    def chain_count(self):
        return len(self._chains)

    def longest_chain(self):
        longest = self._chains[0]
        for chain in self._chains:
            if chain.work > longest.work:
                longest = chain
        return longest

    def median_time_past(self, chain, height):
        '''Returns the median time past on chain at height.'''
        raw_header = self.raw_header_at_height
        timestamp = self.coin.header_timestamp
        timestamps = [timestamp(raw_header(chain, h))
                      for h in range(height, max(-1, height - 11), -1)]
        return sorted(timestamps)[len(timestamps) // 2]

    def required_bits(self, chain, height, timetsamp=None):
        '''Returns the required bits for a new header at the given height with the
        given timestamp.  Testnet uses the timestamp; mainnet does not.'''
        return self.coin.required_bits(chain, height, timestamp)
