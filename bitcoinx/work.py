# Copyright (c) 2018, 2019 Neil Booth
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
    'bits_to_target', 'target_to_bits', 'bits_to_work',
)

from functools import lru_cache


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


def _required_bits_fortnightly(headers, chain, height):
    '''Bitcoin's original DAA.'''
    if height == 0:
        return headers.coin.genesis_bits
    prev = headers.header_at_height(chain, height - 1)
    if height % 2016:
        return prev.bits
    prior = headers.header_at_height(chain, height - 2016)

    # Off-by-one with prev.timestamp.  Constrain the actual time.
    period = prev.timestamp - prior.timestamp
    target_period = 2016 * 600
    adj_period = min(max(period, target_period // 4), target_period * 4)

    prior_target = bits_to_target(prev.bits)
    new_target = (prior_target * adj_period) // target_period
    return target_to_bits(min(new_target, headers.coin.max_target))


def _required_bits_DAA(headers, chain, height):
    '''BCH's shoddy difficulty adjustment algorithm.  He was warned, he shrugged.'''
    def median_prior_header(ref_height):
        '''Select the median of the 3 prior headers, for a curious definition of median.'''
        def maybe_swap(m, n):
            if prev3[m].timestamp > prev3[n].timestamp:
                prev3[m], prev3[n] = prev3[n], prev3[m]

        prev3 = [header_at_height(chain, h) for h in range(ref_height - 3, ref_height)]
        maybe_swap(0, 2)
        maybe_swap(0, 1)
        maybe_swap(1, 2)
        return prev3[1]

    header_at_height = headers.header_at_height
    start = median_prior_header(height - 144)
    end = median_prior_header(height)

    period_work = headers.chainwork_range(chain, start.height + 1, end.height + 1)
    period_time = min(max(end.timestamp - start.timestamp, 43200), 172800)

    Wn = (period_work * 600) // period_time
    new_target = (1 << 256) // Wn - 1
    return target_to_bits(min(new_target, headers.coin.max_target))


def _required_bits_EDA(headers, chain, height):
    '''The less said the better.'''
    bits = _required_bits_fortnightly(headers, chain, height)
    if height % 2016 == 0:
        return bits

    mtp_diff = (headers.median_time_past(chain, height - 1) -
                headers.median_time_past(chain, height - 7))
    if mtp_diff < 12 * 3600:
        return bits

    # Increase target by 25% (reducing difficulty by 20%).
    new_target = bits_to_target(bits)
    new_target += new_target >> 2
    return target_to_bits(min(new_target, headers.coin.max_target))


def required_bits_mainnet(headers, chain, height, _timestamp=None):
    # Unlike testnet, required_bits is not a function of the timestamp
    if height < 478558:
        return _required_bits_fortnightly(headers, chain, height)
    elif height <= 504031:
        return _required_bits_EDA(headers, chain, height)
    else:
        return _required_bits_DAA(headers, chain, height)


def _required_bits_testnet(headers, chain, height, timestamp, daa_height):
    def prior_non_special_bits():
        genesis_bits = headers.coin.genesis_bits
        raw_header = headers.raw_header_at_height
        header_bits = headers.coin.header_bits
        for test_height in range(height - 1, -1, -1):
            bits = header_bits(raw_header(chain, test_height))
            if test_height % 2016 == 0 or bits != genesis_bits:
                return bits
        # impossible to fall through here

    prior_raw_header = headers.raw_header_at_height(chain, height - 1)
    prior_timestamp = headers.coin.header_timestamp(prior_raw_header)
    is_slow = (timestamp - prior_timestamp) > 20 * 60

    if height <= daa_height:
        # Note: testnet did not use the EDA
        if height % 2016 == 0:
            return _required_bits_fortnightly(headers, chain, height)
        if is_slow:
            return headers.coin.genesis_bits
        return prior_non_special_bits()
    else:
        if is_slow:
            return headers.coin.genesis_bits
        return _required_bits_DAA(headers, chain, height)


def required_bits_testnet(headers, chain, height, timestamp):
    return _required_bits_testnet(headers, chain, height, timestamp, 1188697)


def required_bits_scaling_testnet(headers, chain, height, timestamp):
    return _required_bits_testnet(headers, chain, height, timestamp, 2200)
