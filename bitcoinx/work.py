# Copyright (c) 2018-2021, Neil Booth
#
# All rights reserved.
#
# Licensed under the the Open BSV License version 3; see LICENCE for details.
#

__all__ = (
    'bits_to_target', 'target_to_bits', 'bits_to_work', 'grind_header',
)

from collections import defaultdict
from functools import lru_cache

from .errors import InsufficientPoW, IncorrectBits
from .hashes import double_sha256, hash_to_value
from .packing import pack_header, pack_le_uint32


@lru_cache()
def bits_to_target(bits):
    if not 0 <= bits <= 0x2100ffff:
        raise ValueError(f'bits value 0x{bits:x} out of range')

    word = bits & 0x00ffffff
    # target_to_bits never generates these values
    if (not 0x8000 <= word <= 0x7fffff) and bits:
        raise ValueError(f'bits value 0x{bits:x} is invalid')

    size = bits >> 24
    shift = 8 * (size - 3)
    if shift <= 0:
        result = word >> -shift
        # target_to_bits never generates these values
        if (result << -shift) != word:
            raise ValueError(f'bits value 0x{bits:x} is invalid')
        return result
    else:
        return word << shift


def target_to_bits(target):
    bits = target.bit_length()
    if target < 0 or bits > 256:
        raise ValueError(f'target 0x{target:x} out of range')

    size = (bits + 7) // 8
    shift = 8 * (size - 3)
    if shift <= 0:
        word = target << -shift
    else:
        word = target >> shift

    # Avoid setting the sign bit
    if word & 0x00800000:
        word >>= 8
        size += 1

    return word | (size << 24)


@lru_cache()
def bits_to_work(bits):
    return (1 << 256) // (bits_to_target(bits) + 1)


class PoWChecker:

    def __init__(self, headers):
        self.headers = headers
        # Map from chain_id to a map from height to header object
        self.cache_by_chain = defaultdict(dict)
        self.network = self.headers.network
        self.required_bits = getattr(self, f'required_bits_{self.network.name}')
        # Map from new chain ID to (prev_chain_id, new_id_first_height) pairs
        self.chains = {}

    def register_chain_id(self, chain_id, prev_chain_id, first_height):
        # first_height is the height of the first block of the new chain.
        self.chains[chain_id] = (prev_chain_id, first_height)

    def chain_id_for_height(self, chain_id, height):
        while True:
            entry = self.chains.get(chain_id)
            if not entry:
                return chain_id
            prior_chain_id, first_height = entry
            if height >= first_height:
                return chain_id
            chain_id = prior_chain_id

    async def check(self, header):
        bits = await self.required_bits(header)
        if header.bits != bits:
            raise IncorrectBits(header, bits)
        if header.hash_value() > header.target():
            raise InsufficientPoW(header)
        # Add the header to the cache
        cache = self.cache_by_chain[header.chain_id]
        cache[header.height] = header
        if len(cache) >= 200:
            self.shrink(cache)

    async def header_at_height(self, chain_id, height):
        chain_id = self.chain_id_for_height(chain_id, height)
        cache = self.cache_by_chain[chain_id]
        header = cache.get(height)
        if not header:
            header = await self.headers._header_at_height(chain_id, height)
            cache[height] = header
        return header

    async def median_time_past(self, chain_id, for_height):
        timestamps = [(await self.header_at_height(chain_id, height)).timestamp
                      for height in range(max(0, for_height - 11), for_height)]
        return sorted(timestamps)[len(timestamps) // 2]

    def shrink(self, cache):
        tip_height = max(cache)
        old_height = tip_height - 150
        old_heights = [height for height in cache if height < old_height]
        fort_height = tip_height - tip_height % 2016
        try:
            old_heights.remove(fort_height)
        except ValueError:
            pass
        for height in old_heights:
            del cache[height]

    async def required_bits_fortnightly(self, header):
        '''Bitcoin's original DAA.'''
        if header.height == 0:
            return self.network.genesis_header.bits

        prev = await self.header_at_height(header.chain_id, header.height - 1)
        if header.height % 2016:
            return prev.bits
        prior = await self.header_at_height(header.chain_id, header.height - 2016)

        # Off-by-one with prev.timestamp.  Constrain the actual time.
        period = prev.timestamp - prior.timestamp
        target_period = 2016 * 600
        adj_period = min(max(period, target_period // 4), target_period * 4)

        prior_target = bits_to_target(prev.bits)
        new_target = (prior_target * adj_period) // target_period
        return target_to_bits(min(new_target, self.network.max_target))

    async def required_bits_EDA(self, header):
        '''The less said the better.'''
        bits = await self.required_bits_fortnightly(header)
        if header.height % 2016 == 0:
            return bits

        mtp_diff = (await self.median_time_past(header.chain_id, header.height)
                    - await self.median_time_past(header.chain_id, header.height - 6))
        if mtp_diff < 12 * 3600:
            return bits

        # Increase target by 25% (reducing difficulty by 20%).
        new_target = bits_to_target(bits)
        new_target += new_target >> 2
        return target_to_bits(min(new_target, self.network.max_target))

    async def required_bits_DAA(self, header):
        '''BCH's shoddy difficulty adjustment algorithm.  He was warned, he shrugged.'''
        async def median_prior_header(chain_id, ref_height):
            '''Select the median of the 3 prior headers, for a curious definition of median.'''
            def maybe_swap(m, n):
                if prev3[m].timestamp > prev3[n].timestamp:
                    prev3[m], prev3[n] = prev3[n], prev3[m]

            prev3 = [await self.header_at_height(chain_id, height)
                     for height in range(ref_height - 3, ref_height)]
            maybe_swap(0, 2)
            maybe_swap(0, 1)
            maybe_swap(1, 2)
            return prev3[1]

        start = await median_prior_header(header.chain_id, header.height - 144)
        end = await median_prior_header(header.chain_id, header.height)

        period_work = end.chain_work() - start.chain_work()
        period_time = min(max(end.timestamp - start.timestamp, 43200), 172800)

        Wn = (period_work * 600) // period_time
        new_target = (1 << 256) // Wn - 1
        return target_to_bits(min(new_target, self.network.max_target))

    async def required_bits_mainnet(self, header):
        # Unlike testnet, required_bits is not a function of the timestamp
        if header.height < 478558:
            return await self.required_bits_fortnightly(header)
        elif header.height <= 504031:
            return await self.required_bits_EDA(header)
        else:
            return await self.required_bits_DAA(header)

    async def required_bits_testnet_common(self, header, has_DAA_minpow):
        async def prior_non_special_bits(genesis_bits):
            for test_height in range(header.height - 1, -1, -1):
                bits = (await self.header_at_height(header.chain_id, test_height)).bits
                if test_height % 2016 == 0 or bits != genesis_bits:
                    return bits
            # impossible to fall through here

        if header.height == 0:
            return self.network.genesis_header.bits

        prior = await self.header_at_height(header.chain_id, header.height - 1)
        is_slow = (header.timestamp - prior.timestamp) > 20 * 60

        if header.height <= self.network.DAA_height:
            # Note: testnet did not use the EDA
            if header.height % 2016 == 0:
                return await self.required_bits_fortnightly(header)
            if is_slow:
                return self.network.genesis_header.bits
            return await prior_non_special_bits(self.network.genesis_header.bits)
        else:
            if is_slow and has_DAA_minpow:
                return self.network.genesis_header.bits
            return await self.required_bits_DAA(header)

    async def required_bits_testnet(self, header):
        return await self.required_bits_testnet_common(header, True)

    async def required_bits_STN(self, header):
        return await self.required_bits_testnet_common(header, False)

    async def required_bits_regtest(self, _header):
        # Regtest has no retargeting.
        return self.network.genesis_header.bits


def grind_header(version, prev_hash, merkle_root, timestamp, bits, max_tries=None):
    '''Grind the nonce until a header meeting the PoW target is found.  Return the header
    bytes once found, otherwise None.'''
    target = bits_to_target(bits)

    if max_tries is None:
        max_tries = 1 << 32

    header = bytearray(pack_header(version, prev_hash, merkle_root, timestamp, bits, 0))
    for nonce in range(max_tries):
        header[76:80] = pack_le_uint32(nonce)
        value = hash_to_value(double_sha256(header))
        if value <= target:
            return bytes(header)

    return None
