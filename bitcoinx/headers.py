# Copyright (c) 2024 Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.


from dataclasses import dataclass

from .hashes import hash_to_hex_str, hash_to_value, double_sha256 as header_hash
from .misc import le_bytes_to_int, cachedproperty
from .packing import unpack_le_uint32, unpack_le_int32
from .work import bits_to_target, bits_to_work, bits_to_difficulty


__all__ = (
    'Chain', 'Header', 'SimpleHeader', 'header_hash',
)


@dataclass
class SimpleHeader:
    '''A trivial wrapper of a raw header.'''
    raw: bytes

    def __hash__(self):
        return le_bytes_to_int(self.hash[:4])

    @property
    def version(self):
        result, = unpack_le_int32(self.raw[:4])
        return result

    @property
    def prev_hash(self):
        return self.raw[4:36]

    @property
    def merkle_root(self):
        return self.raw[36:68]

    @property
    def timestamp(self):
        result, = unpack_le_uint32(self.raw[68:72])
        return result

    @property
    def bits(self):
        result, = unpack_le_uint32(self.raw[72:76])
        return result

    @property
    def nonce(self):
        result, = unpack_le_uint32(self.raw[76:80])
        return result

    @cachedproperty
    def hash(self):
        return header_hash(self.raw)

    def work(self):
        return bits_to_work(self.bits)

    def target(self):
        return bits_to_target(self.bits)

    def hash_value(self):
        return hash_to_value(self.hash)

    def hex_str(self):
        return hash_to_hex_str(self.hash)

    def difficulty(self):
        return bits_to_difficulty(self.bits)

    def __str__(self):
        hths = hash_to_hex_str
        return (f'SimpleHeader(version=0x{self.version:x}, prev_hash={hths(self.prev_hash)}, '
                f'merkle_root={hths(self.merkle_root)}, timestamp={self.timestamp}, '
                f'bits=0x{self.bits}, nonce={self.nonce}, hash={hths(self.hash)})')

    @staticmethod
    def are_headers_chained(headers):
        prev_hash = None
        for header in headers:
            if header.prev_hash != prev_hash and prev_hash is not None:
                return False
            prev_hash = header.hash
        return True


@dataclass
class Header(SimpleHeader):
    '''SimpleHeader with extra metadata from the database.'''
    height: int
    chain_id: int
    le_work: bytes

    def __eq__(self, other):
        return isinstance(other, (Header, SimpleHeader)) and self.hash == other.hash

    def __hash__(self):
        return le_bytes_to_int(self.hash[1:5])

    def chain_work(self):
        return le_bytes_to_int(self.le_work)

    def __str__(self):
        hths = hash_to_hex_str
        return (f'Header(version=0x{self.version:x}, prev_hash={hths(self.prev_hash)}, '
                f'merkle_root={hths(self.merkle_root)}, timestamp={self.timestamp}, '
                f'bits=0x{self.bits}, nonce={self.nonce}, hash={hths(self.hash)}, '
                f'height={self.height} chain_work={self.chain_work():x})')


@dataclass
class Chain:
    '''A header chain and its tip.'''
    chain_id: int
    tip: Header

    def chain_work(self):
        return self.tip.chain_work()

    def __hash__(self):
        return self.chain_id
