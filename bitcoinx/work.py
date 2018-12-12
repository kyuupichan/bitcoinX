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
