# Copyright (c) 2019-2021, Neil Booth
#
# All right reserved.
#
# Licensed under the the Open BSV License version 3; see LICENCE for details.
#


'''Bitcoin addresses and script classifications.'''

__all__ = (
    'Address', 'P2PKH_Address', 'P2SH_Address',
    'P2PK_Output', 'P2MultiSig_Output', 'OP_RETURN_Output', 'Unknown_Output',
)

from abc import ABC, abstractmethod

from bitcoinx import cashaddr
from .hashes import hash160 as calc_hash160
from .base58 import base58_decode_check, base58_encode_check
from .networks import Bitcoin
from .packing import pack_byte
from .script import Script, Ops, push_item, push_int, item_to_int


class Address(ABC):

    def __init__(self, network):
        self._network = network

    @abstractmethod
    def to_string(self):
        pass

    @classmethod
    def from_string(cls, text, network):
        '''Construct from an address string.'''
        if len(text) > 35:
            try:
                return cls._from_cashaddr_string(text, network)
            except ValueError:
                pass

        raw = base58_decode_check(text)

        if len(raw) != 21:
            raise ValueError(f'invalid address: {text}')

        verbyte, hash160 = raw[0], raw[1:]
        if verbyte == network.P2PKH_verbyte:
            return P2PKH_Address(hash160, network)
        if verbyte == network.P2SH_verbyte:
            return P2SH_Address(hash160, network)

        raise ValueError(f'unknown version byte {verbyte} for network {network.name}')

    @classmethod
    def _from_cashaddr_string(cls, text, network):
        '''Construct from a cashaddress string.'''
        network = network or Bitcoin
        prefix = network.cashaddr_prefix
        if text.upper() == text:
            prefix = prefix.upper()
        if not text.startswith(prefix + ':'):
            text = ':'.join((prefix, text))
        addr_prefix, kind, hash160 = cashaddr.decode(text)
        assert prefix == addr_prefix

        if kind == cashaddr.PUBKEY_TYPE:
            return P2PKH_Address(hash160, network)
        return P2SH_Address(hash160, network)

    def network(self):
        return self._network

    def __str__(self):
        return self.to_string()


class P2PKH_Address(Address):

    KIND = 'pubkeyhash'

    def __init__(self, hash160, network):
        super().__init__(network)
        self._hash160 = _validate_hash160(hash160)

    def __eq__(self, other):
        return isinstance(other, P2PKH_Address) and self._hash160 == other._hash160

    def __hash__(self):
        return hash(self._hash160) + 2

    def to_string(self):
        return base58_encode_check(pack_byte(self._network.P2PKH_verbyte) + self._hash160)

    def hash160(self):
        return self._hash160

    def to_script_bytes(self):
        return b''.join((
            bytes([Ops.OP_DUP, Ops.OP_HASH160]),
            push_item(self._hash160),
            bytes([Ops.OP_EQUALVERIFY, Ops.OP_CHECKSIG]),
        ))

    def to_script(self):
        return Script(self.to_script_bytes())


class P2SH_Address(Address):

    def __init__(self, hash160, network):
        super().__init__(network)
        self._hash160 = _validate_hash160(hash160)

    def __eq__(self, other):
        return isinstance(other, P2SH_Address) and self._hash160 == other._hash160

    def __hash__(self):
        return hash(self._hash160) + 3

    def to_string(self):
        return base58_encode_check(pack_byte(self._network.P2SH_verbyte) + self._hash160)

    def hash160(self):
        return self._hash160

    def to_script_bytes(self):
        return b''.join((pack_byte(Ops.OP_HASH160), push_item(self._hash160),
                         pack_byte(Ops.OP_EQUAL)))

    def to_script(self):
        return Script(self.to_script_bytes())


class P2PK_Output:

    KIND = 'pubkey'

    def __init__(self, public_key, network):
        self.public_key = _to_public_key(public_key)
        self._network = network

    def __eq__(self, other):
        return isinstance(other, P2PK_Output) and self.public_key == other.public_key

    def __hash__(self):
        return hash(self.public_key) + 1

    def hash160(self):
        return self.public_key.hash160()

    def to_address(self):
        return self.public_key.to_address(network=self._network)

    def to_script_bytes(self):
        return push_item(self.public_key.to_bytes()) + pack_byte(Ops.OP_CHECKSIG)

    def to_script(self):
        return Script(self.to_script_bytes())


class P2MultiSig_Output:

    KIND = 'multisig'

    def __init__(self, public_keys, threshold):
        '''public_keys is an iterable.'''
        self.public_keys = tuple(_to_public_key(public_key) for public_key in public_keys)
        self.threshold = threshold
        n = len(self.public_keys)
        if not 1 <= threshold <= n:
            raise ValueError(f'threshold {threshold} is invalid with {n} public keys')

    def __eq__(self, other):
        return (isinstance(other, P2MultiSig_Output)
                and self.public_keys == other.public_keys
                and self.threshold == other.threshold)

    def __hash__(self):
        return hash(self.public_keys) + self.threshold

    def to_script_bytes(self):
        parts = [push_int(self.threshold)]
        parts.extend(push_item(public_key.to_bytes()) for public_key in self.public_keys)
        parts.append(push_int(len(self.public_keys)))
        parts.append(pack_byte(Ops.OP_CHECKMULTISIG))
        return b''.join(parts)

    def to_script(self):
        return Script(self.to_script_bytes())

    def hash160(self):
        return calc_hash160(self.to_script_bytes())

    def public_key_count(self):
        return len(self.public_keys)

    @classmethod
    def from_template(cls, *items):
        threshold, *public_keys, count = items
        n = len(public_keys)
        count = item_to_int(count)
        if count != n:
            raise ValueError(f'received {n} public keys but {count} as their count')
        return cls(public_keys, item_to_int(threshold))


class OP_RETURN_Output:
    '''This class indicates the script is an OP_RETURN script.'''

    KIND = 'op_return'

    def __eq__(self, other):
        return isinstance(other, OP_RETURN_Output)

    def __hash__(self):
        return 28

    def to_script_bytes(self):
        return pack_byte(Ops.OP_RETURN)

    def to_script(self):
        return Script(self.to_script_bytes())

    @classmethod
    def from_template(cls, *_items):
        return cls()


class Unknown_Output:

    KIND = 'unknown'

    def to_script_bytes(self):
        raise RuntimeError('no canonical script')

    def to_script(self):
        return Script(self.to_script_bytes())


def _validate_hash160(hash160):
    if not isinstance(hash160, bytes):
        raise TypeError('hash160 must be bytes')
    if len(hash160) != 20:
        raise ValueError('hash160 must be 20 bytes')
    return hash160


def _to_public_key(obj):
    '''Convert obj a PublicKey object.'''
    from .keys import PublicKey
    if isinstance(obj, PublicKey):
        return obj
    if isinstance(obj, str):
        return PublicKey.from_hex(obj)
    return PublicKey.from_bytes(obj)
