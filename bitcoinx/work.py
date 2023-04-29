# Copyright (c) 2018-2021, Neil Booth
#
# All rights reserved.
#
# Licensed under the the Open BSV License version 3; see LICENCE for details.
#

__all__ = (
    'bits_to_target', 'target_to_bits', 'bits_to_work', 'grind_header',
)

from functools import lru_cache

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


def grind_header(version, prev_hash, merkle_root, timestamp, bits):
    '''Grind the nonce until a header meeting the PoW target is found.  Return the header
    bytes once found, otherwise None.'''
    target = bits_to_target(bits)

    header = bytearray(pack_header(version, prev_hash, merkle_root, timestamp, bits, 0))
    for nonce in range(1 << 32):
        header[76:80] = pack_le_uint32(nonce)
        value = hash_to_value(double_sha256(header))
        if value <= target:
            return bytes(header)

    return None
