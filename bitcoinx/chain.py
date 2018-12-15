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
    'Chain', 'Headers', 'MissingHeader', 'HeaderStorage',
)

import array
import itertools

from bitcoinx.hashes import hash_to_hex_str
from bitcoinx.packing import pack_le_uint32, unpack_le_uint32
from bitcoinx.util import map_file


class MissingHeader(Exception):
    pass


class HeaderStorage(object):
    '''Implementation of a block header storage abstraction for flat
    files.'''

    def __init__(self, file_name):
        self.file_name = file_name
        self.mmap = map_file(file_name)

    def raw_header(self, header_idx):
        start = 4 + header_idx * 80
        return self.mmap[start: start + 80]

    def add_header(self, raw_header):
        mmap = self.mmap
        header_idx, = unpack_le_uint32(mmap[:4])
        start = 4 + header_idx * 80
        if start >= len(mmap):
            new_size = len(mmap) + 80 * 50_000
            mmap.close()
            self.mmap = mmap = _map(self.file_name, new_size)
        mmap[start: start + 80] = raw_header
        mmap[:4] = pack_le_uint32(header_idx + 1)
        return header_idx

    def close(self):
        self.mmap.close()

    def flush(self):
        return self.mmap.flush()


class Headers(object):
    '''A collection of block headers arranged into chains.  A header
    belongs to a unique chain.

    Adding a header appendeds it to the tip of an existing chain or
    creates a new chain if it forms a branch.
    '''

    def __init__(self, coin, storage):
        self.coin = coin
        self._storage = storage
        self._chains = []
        self._short_hashes = bytearray()
        self._heights = array.array('I')
        self._chain_indices = array.array('H')
        self._cache = {}

        # Add the genesis header
        chain = Chain(None, -1, 0)
        self._chains.append(chain)
        header = coin.deserialized_header(coin.genesis_header)
        header.height = 0
        self._add_header(chain, header)

    def _add_header(self, chain, header):
        header_idx = self._storage.add_header(header.raw)
        chain._add_header(header, header_idx)
        self._short_hashes.extend(header.hash[:4])
        self._heights.append(header.height)
        self._chain_indices.append(chain._index)
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
                raise MissingHeader(f'no header with hash '
                                    f'{hash_to_hex_str(header_hash)}')
            start += 1

    def add_raw_headers(self, raw_headers):
        '''Add an iterable of raw headers to the chains.'''
        deserialized_header = self.coin.deserialized_header
        lookup_header_and_chain = self.lookup_header_and_chain
        add_header = self._add_header

        for raw_header in raw_headers:
            header = deserialized_header(raw_header)
            prev_header, chain = lookup_header_and_chain(header.prev_hash)
            if chain.tip.hash != prev_header.hash:
                # Ignore headers we already have
                try:
                    lookup_header_and_chain(header.hash)
                    continue
                except MissingHeader:
                    pass
                prev_work = self.chainwork_to_height(chain,
                                                     prev_header.height)
                chain = Chain(chain, prev_header.height, prev_work)
                self._chains.append(chain)
            header.height = prev_header.height + 1
            add_header(chain, header)

    def chainwork_to_height(self, chain, height):
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
        header = self.coin.deserialized_header(raw_header)
        header.height = self._heights[header_idx]
        chain_index = self._chain_indices[header_idx]
        return header, self._chains[chain_index]

    def chains(self):
        return self._chains


class Chain(object):
    '''Represents a header chain back to the genesis block.

    Public attributes:
        height  the height of the chain
        tip     the Header object of the chain tip
        work    cumulative chain work
    '''

    counter = itertools.count()

    def __init__(self, parent, max_common_height, work):
        self._parent = parent
        self._max_common_height = max_common_height
        self._header_idxs = array.array('I')
        self._index = next(Chain.counter)
        self.work = work
        self.tip = None

    def _header_idx(self, height):
        if height >= 0:
            index = height - self._max_common_height - 1
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
        return self._max_common_height + len(self._header_idxs)
