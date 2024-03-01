# Copyright (c) 2018-2021, Neil Booth
#
# All rights reserved.
#
# Licensed under the the Open BSV License version 3; see LICENCE for details.
#

__all__ = (
    'bits_to_target', 'target_to_bits', 'bits_to_work', 'bits_to_difficulty', 'grind_header',
)


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


def bits_to_difficulty(bits):
    from .networks import Bitcoin
    return Bitcoin.max_target / bits_to_target(bits)


@lru_cache()
def bits_to_work(bits):
    return (1 << 256) // (bits_to_target(bits) + 1)


class PoWChecker:

    def __init__(self, network):
        self.network = network
        self.required_bits = getattr(self, f'required_bits_{self.network.name}')

    async def check(self, headers_obj, header):
        bits = await self.required_bits(headers_obj, header)
        if header.bits != bits:
            raise IncorrectBits(header, bits)
        if header.hash_value() > header.target():
            raise InsufficientPoW(header)

    async def required_bits_fortnightly(self, headers_obj, header):
        '''Bitcoin's original DAA.'''
        if header.height == 0:
            return self.network.genesis_header.bits

        prev = await headers_obj.header_at_height_cached(header.chain_id, header.height - 1)
        if header.height % 2016:
            return prev.bits
        prior = await headers_obj.header_at_height_cached(header.chain_id, header.height - 2016)

        # Off-by-one with prev.timestamp.  Constrain the actual time.
        period = prev.timestamp - prior.timestamp
        target_period = 2016 * 600
        adj_period = min(max(period, target_period // 4), target_period * 4)

        prior_target = bits_to_target(prev.bits)
        new_target = (prior_target * adj_period) // target_period
        return target_to_bits(min(new_target, self.network.max_target))

    async def required_bits_EDA(self, headers_obj, header):
        '''The less said the better.'''
        bits = await self.required_bits_fortnightly(headers_obj, header)
        if header.height % 2016 == 0:
            return bits

        mtp = headers_obj.median_time_past
        mtp_diff = (await mtp(header.chain_id, header.height - 1)
                    - await mtp(header.chain_id, header.height - 7))
        if mtp_diff < 12 * 3600:
            return bits

        # Increase target by 25% (reducing difficulty by 20%).
        new_target = bits_to_target(bits)
        new_target += new_target >> 2
        return target_to_bits(min(new_target, self.network.max_target))

    async def required_bits_DAA(self, headers_obj, header):
        '''BCH's shoddy difficulty adjustment algorithm.  He was warned, he shrugged.'''
        async def median_prior_header(chain_id, ref_height):
            '''Select the median of the 3 prior headers, for a curious definition of median.'''
            def maybe_swap(m, n):
                if prev3[m].timestamp > prev3[n].timestamp:
                    prev3[m], prev3[n] = prev3[n], prev3[m]

            prev3 = [await headers_obj.header_at_height_cached(chain_id, height)
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

    async def required_bits_mainnet(self, headers_obj, header):
        # Unlike testnet, required_bits is not a function of the timestamp
        if header.height < 478558:
            return await self.required_bits_fortnightly(headers_obj, header)
        elif header.height <= 504031:
            return await self.required_bits_EDA(headers_obj, header)
        else:
            return await self.required_bits_DAA(headers_obj, header)

    async def required_bits_testnet_common(self, headers_obj, header, has_DAA_minpow):
        if header.height == 0:
            return self.network.genesis_header.bits

        prior = await headers_obj.header_at_height_cached(header.chain_id, header.height - 1)
        is_slow = (header.timestamp - prior.timestamp) > 20 * 60

        if header.height <= self.network.DAA_height:
            # Note: testnet did not use the EDA
            if header.height % 2016 == 0:
                return await self.required_bits_fortnightly(headers_obj, header)
            if is_slow:
                return self.network.genesis_header.bits
            height = header.height - header.height % 2016
            return (await headers_obj.header_at_height_cached(header.chain_id, height)).bits
        else:
            if is_slow and has_DAA_minpow:
                return self.network.genesis_header.bits
            return await self.required_bits_DAA(headers_obj, header)

    async def required_bits_testnet(self, headers_obj, header):
        return await self.required_bits_testnet_common(headers_obj, header, True)

    async def required_bits_STN(self, headers_obj, header):
        return await self.required_bits_testnet_common(headers_obj, header, False)

    async def required_bits_regtest(self, _headers_obj, _header):
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
