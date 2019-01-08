# Copyright (c) 2018, Neil Booth
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

from bitcoinx.hashes import hash_to_hex_str
from bitcoinx.packing import pack_le_uint32, unpack_le_uint32
from bitcoinx.util import map_file


empty_header = bytes(80)


# The prev_work of a checkpoint is the cumulative work prior to the checkpoint and does
# not including the work of the checkpoint itself
CheckPoint = namedtuple('CheckPoint', 'raw_header height prev_work')


class MissingHeader(Exception):
    pass


class Chain(object):
    '''A dumb object representing a chain of headers back to the genesis block (implemented
    through parent chains).

    Public attributes:
        height  the height of the chain
        tip     the Header object of the chain tip
        work    cumulative chain work to the tip
    '''

    def __init__(self, parent, common_height, work):
        '''common_height is the greatest height common to the chain and its parent.'''
        self._parent = parent
        self._common_height = common_height
        self._header_idxs = array.array('I')
        self.work = work
        self.tip = None

    @classmethod
    def from_checkpoint(cls, checkpoint, coin):
        chain = cls(None, -1, checkpoint.prev_work)
        chain._header_idxs = array.array('I', range(checkpoint.height))
        chain._add_header(coin.deserialized_header(checkpoint.raw_header, checkpoint.height),
                          checkpoint.height)
        return chain

    def _header_idx(self, height):
        if height >= 0:
            index = height - self._common_height - 1
            if index < 0:
                return self._parent._header_idx(height)
            try:
                return self._header_idxs[index]
            except IndexError:
                pass
        raise MissingHeader(f'no header at height {height}') from None

    def _add_header(self, header, header_idx):
        self.tip = header
        self._header_idxs.append(header_idx)
        self.work += header.work()

    @property
    def height(self):
        return self._common_height + len(self._header_idxs)


class HeaderStorage(object):
    '''Implementation a dumb raw header storage abstraction for flat files.

    Headers are looked up by index.  Note that a header's index need not equal its height,
    and usually will not.

    If a header is read that has not been set, MissingHeader is raised.

    There are no requirements on headers other than being 80 bytes and not zeroed out.
    '''

    def __init__(self, file_name):
        '''Open header storage file file_name.  It must exist and have been initialised.'''
        self.file_name = file_name
        self.mmap = map_file(file_name)

    def _grow(self, size):
        mmap = self.mmap
        start = 4 + size * 80
        if start >= len(mmap):
            self.mmap.close()
            self.mmap = mmap = map_file(self.file_name, 4 + (size + 50_000) * 80)
        if size >= len(self):
            mmap[:4] = pack_le_uint32(size + 1)
        return mmap, start

    def _set_raw_header(self, header_idx, raw_header):
        # header_idx is assumed checked
        if not isinstance(raw_header, bytes):
            raise TypeError('raw header must be of type bytes')
        if len(raw_header) != 80:
            raise ValueError('raw header must be of length 80')
        mmap, start = self._grow(header_idx)
        mmap[start: start + 80] = raw_header

    def __getitem__(self, key):
        if isinstance(key, int):
            return self.raw_header(key)
        else:
            raise TypeError(f'key {key} should be an integer')

    def __setitem__(self, key, value):
        if isinstance(key, int):
            self._set_raw_header(key, value)
        else:
            raise TypeError(f'key {key} should be an integer')

    def __len__(self):
        count, = unpack_le_uint32(self.mmap[:4])
        return count

    @classmethod
    def create_new(cls, file_name):
        with open(file_name, 'wb') as f:
            f.write(bytes(4))
        return cls(file_name)

    @classmethod
    def open_or_create(cls, file_name):
        try:
            return cls(file_name)
        except FileNotFoundError:
            return cls.create_new(file_name)

    def raw_header(self, header_idx):
        start = 4 + header_idx * 80
        header = self.mmap[start: start + 80]
        if not header or header == empty_header:
            raise MissingHeader(f'no header at index {header_idx}')
        return header

    def append(self, raw_header):
        header_idx = len(self)
        self._set_raw_header(header_idx, raw_header)
        return header_idx

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

    def __init__(self, coin, storage, checkpoint):
        '''The storage must have been initialized and have the checkpoint header saved.'''
        self.coin = coin
        self._checkpoint = checkpoint
        self._storage = storage
        self._chains = []
        self._short_hashes = bytearray()
        self._heights = array.array('I')
        self._chain_indices = array.array('H')
        self._cache = {}

        assert storage[checkpoint.height] == checkpoint.raw_header
        # Create the base chain out to the checkpoint
        self._add_chain(Chain.from_checkpoint(coin, checkpoint))

    def _add_chain(self, chain):
        chain.index = len(self._chains)
        self._chains.append(chain)

    def _add_header(self, chain, header):
        header_idx = self._storage.add_header(header.raw)
        chain._add_header(header, header_idx)
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
            cache.update({chain.tip.hash: (chain.tip, chain)
                          for chain in self._chains})

    def _header_idx_slow(self, header_hash):
        key = header_hash[:4]
        start = 0
        while True:
            index = self._short_hashes.find(key, start)
            if index % 4 == 0:
                header_idx = index // 4
                raw_header = self._storage.raw_header(header_idx)
                if self.coin.header_hash(raw_header) == header_hash:
                    return raw_header, header_idx
            if index == -1:
                raise MissingHeader(f'no header with hash {hash_to_hex_str(header_hash)}')
            start += 1

    def set_header(self, height, raw_header):
        '''Set the raw header for a height before the checkpoint.

        The caller is responsible for the validity of the raw header.'''
        if not 0 <= height <= self._checkpoint.height:
            raise ValueError(f'cannot set header at height {height:,d}')
        self._storage[height] = raw_header

    def add_raw_headers(self, raw_headers):
        '''Add an iterable of raw headers to the chains.'''
        deserialized_header = self.coin.deserialized_header
        lookup_header_and_chain = self.lookup_header_and_chain
        add_header = self._add_header

        for raw_header in raw_headers:
            # Height is set below
            header = deserialized_header(raw_header, -1)
            prev_header, chain = lookup_header_and_chain(header.prev_hash)
            if chain.tip.hash != prev_header.hash:
                # Ignore headers we already have
                try:
                    lookup_header_and_chain(header.hash)
                    continue
                except MissingHeader:
                    pass
                prev_work = self.chainwork_to_height(chain, prev_header.height)
                chain = Chain(chain, prev_header.height, prev_work)
                self._add_chain(chain)
            header.height = prev_header.height + 1
            add_header(chain, header)

    def chainwork_to_height(self, chain, height):
        '''Returns the chainwork to and including height on a chain.'''
        raw_header = self._storage.raw_header
        get_header_idx = chain._header_idx
        header_work = self.coin.header_work

        later_work = sum(header_work(raw_header(get_header_idx(h)))
                         for h in range(height + 1, chain.tip.height + 1))
        return chain.work - later_work

    def header_at_height(self, chain, height):
        return self._storage.raw_header(chain._header_idx(height))

    def lookup_header_and_chain(self, header_hash):
        result = self._cache.get(header_hash)
        if result:
            return result
        raw_header, header_idx = self._header_idx_slow(header_hash)
        header = self.coin.deserialized_header(raw_header, self._heights[header_idx])
        chain_index = self._chain_indices[header_idx]
        return header, self._chains[chain_index]

    def chains(self):
        return self._chains
