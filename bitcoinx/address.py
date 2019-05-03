# Copyright (c) 2019, Neil Booth
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

'''Bitcoin addresses and script classifications.'''

__all__ = (
    'Address', 'P2PKH_Address', 'P2SH_Address',
    'P2PK_Output', 'P2MultiSig_Output', 'OP_RETURN_Output', 'Unknown_Output',
    'P2PK_Input', 'P2PKH_Input', 'P2MultiSig_Input', 'P2SHMultiSig_Input', 'Unknown_Input',
    'classify_input_script', 'classify_output_script',
)

from abc import ABC, abstractmethod
import re

from bitcoinx import cashaddr
from .base58 import base58_decode_check, base58_encode_check
from .coin import Bitcoin, all_coins
from .packing import pack_byte
from .script import Script, Ops, push_item, push_int, item_to_int
from .signature import Signature


class Address(ABC):

    def __init__(self, coin=None):
        self._coin = coin or Bitcoin

    def __eq__(self, other):
        return str(self) == str(other)

    def __hash__(self):
        return hash(str(self))

    @abstractmethod
    def to_string(self, *, coin=None):
        pass

    @classmethod
    def from_string(cls, text, *, coin=None):
        '''Construct from an address string.'''
        if len(text) > 35:
            try:
                return cls._from_cashaddr_string(text, coin=coin)
            except ValueError as e:
                pass

        raw = base58_decode_check(text)

        if len(raw) != 21:
            raise ValueError(f'invalid address: {text}')

        verbyte, hash160 = raw[0], raw[1:]
        coins = all_coins if coin is None else [coin]
        for test in coins:
            if verbyte == test.P2PKH_verbyte:
                return P2PKH_Address(hash160, coin=test)
            if verbyte == test.P2SH_verbyte:
                return P2SH_Address(hash160, coin=test)

        raise ValueError(f'unknown version byte: {verbyte}')

    @classmethod
    def _from_cashaddr_string(cls, text, *, coin=None):
        '''Construct from a cashaddress string.'''
        coin = coin or Bitcoin
        prefix = coin.cashaddr_prefix
        if text.upper() == text:
            prefix = prefix.upper()
        if not text.startswith(prefix + ':'):
            text = ':'.join((prefix, text))
        addr_prefix, kind, hash160 = cashaddr.decode(text)
        assert prefix == addr_prefix

        if kind == cashaddr.PUBKEY_TYPE:
            return P2PKH_Address(hash160, coin=coin)
        return P2SH_Address(hash160, coin=coin)

    def coin(self):
        return self._coin

    def __str__(self):
        return self.to_string()


class P2PKH_Address(Address):

    def __init__(self, hash160, *, coin=None):
        super().__init__(coin)
        self._hash160 = _validate_hash160(hash160)

    def to_string(self, *, coin=None):
        coin = coin or self._coin
        return base58_encode_check(pack_byte(coin.P2PKH_verbyte) + self._hash160)

    def hash160(self):
        return self._hash160

    def to_script(self):
        return Script(b''.join((
            bytes([Ops.OP_DUP, Ops.OP_HASH160]),
            push_item(self._hash160),
            bytes([Ops.OP_EQUALVERIFY, Ops.OP_CHECKSIG]),
        )))


class P2SH_Address(Address):

    def __init__(self, hash160, *, coin=None):
        super().__init__(coin)
        self._hash160 = _validate_hash160(hash160)

    def to_string(self, *, coin=None):
        coin = coin or self._coin
        return base58_encode_check(pack_byte(coin.P2SH_verbyte) + self._hash160)

    def hash160(self):
        return self._hash160

    def to_script(self):
        return Script(b''.join((pack_byte(Ops.OP_HASH160), push_item(self._hash160),
                                pack_byte(Ops.OP_EQUAL))))


class P2PK_Output:

    def __init__(self, public_key):
        self.public_key = _to_public_key(public_key)

    def __eq__(self, other):
        return isinstance(other, P2PK_Output) and self.public_key == other.public_key

    def __hash__(self):
        return hash(self.public_key) + 1

    def to_script(self):
        return Script(push_item(self.public_key.to_bytes()) + pack_byte(Ops.OP_CHECKSIG))


class P2MultiSig_Output:

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

    def to_script(self):
        parts = [push_int(self.threshold)]
        parts.extend(push_item(public_key.to_bytes()) for public_key in self.public_keys)
        parts.append(push_int(len(self.public_keys)))
        parts.append(pack_byte(Ops.OP_CHECKMULTISIG))
        return Script(b''.join(parts))

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

    def __eq__(self, other):
        return isinstance(other, OP_RETURN_Output)

    def __hash__(self):
        return 28

    def to_script(self):
        return Script(pack_byte(Ops.OP_RETURN))

    @classmethod
    def from_template(cls, *items):
        return cls()


class Unknown_Output:

    def to_script(self):
        raise RuntimeError('no canonical script for Unknown_Output')


class InputBase(ABC):

    def is_complete(self):
        return self.signatures_required() == self.signatures_present()

    @abstractmethod
    def signatures_required(self):
        pass

    @abstractmethod
    def signatures_present(self):
        pass


class Unknown_Input(InputBase):

    def signatures_required(self):
        return 0

    def signatures_present(self):
        return 0


class P2PKH_Input(InputBase):

    def __init__(self, signature, public_key):
        self.signature = _to_signature(signature)
        self.public_key = _to_public_key(public_key)

    def to_script(self):
        return Script(push_item(self.signature.to_bytes())
                      + push_item(self.public_key.to_bytes()))

    def signatures_required(self):
        return 1

    def signatures_present(self):
        return int(self.signature.is_present())


class P2PK_Input(InputBase):

    def __init__(self, signature):
        self.signature = _to_signature(signature)

    def to_script(self):
        return Script(push_item(self.signature.to_bytes()))

    def signatures_required(self):
        return 1

    def signatures_present(self):
        return int(self.signature.is_present())


class P2MultiSig_Input(InputBase):

    def __init__(self, signatures):
        '''signatures is an iterable.'''
        self.signatures = [_to_signature(signature) for signature in signatures]
        if not self.signatures:
            raise ValueError('no signatures provided')

    def to_script(self):
        parts = [pack_byte(Ops.OP_0)]
        parts.extend(push_item(signature.to_bytes()) for signature in self.signatures)
        return Script(b''.join(parts))

    def signatures_required(self):
        return len(self.signatures)

    def signatures_present(self):
        return sum(signature.is_present() for signature in self.signatures)

    @classmethod
    def from_template(cls, *items):
        if not items or items[0] != b'':
            raise ValueError('scriptsig must have at least 2 items with the first empty')
        return cls(items[1:])


class P2SHMultiSig_Input(InputBase):

    def __init__(self, p2multisig_input, nested_script):
        if not isinstance(p2multisig_input, P2MultiSig_Input):
            raise TypeError('need a P2MultiSig_Input')
        if not isinstance(nested_script, P2MultiSig_Output):
            raise TypeError('need a P2MultiSig_Output')
        if p2multisig_input.signatures_required() > nested_script.public_key_count():
            raise ValueError('more signatures than public keys')
        self.p2multisig_input = p2multisig_input
        self.nested_script = nested_script

    def to_script(self):
        return self.p2multisig_input.to_script() << self.nested_script.to_script().to_bytes()

    def signatures_required(self):
        return self.p2multisig_input.signatures_required()

    def signatures_present(self):
        return self.p2multisig_input.signatures_present()

    @classmethod
    def from_template(cls, *items):
        if len(items) < 3:
            raise ValueError('requires at least 3 items')
        p2multisig_input = P2MultiSig_Input(items[1:-1])
        nested_script = classify_output_script(Script(items[-1]))
        return cls(p2multisig_input, nested_script)


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
    return PublicKey.from_bytes(obj)


def _to_signature(obj):
    '''Convert obj a Signature object.'''
    if isinstance(obj, Signature):
        return obj
    return Signature(obj)


def _classify_script(script, templates, unknown_class):
    our_template, items = script.to_template()

    for template, constructor in templates:
        if isinstance(template, bytes):
            if template != our_template:
                continue
        else:
            match = template.match(our_template)
            if not match:
                continue

        try:
            return constructor(*items)
        except (ValueError, TypeError):
            pass

    return unknown_class()


output_templates = (
    (bytes((Ops.OP_DUP, Ops.OP_HASH160, Ops.OP_PUSHDATA1, Ops.OP_EQUALVERIFY, Ops.OP_CHECKSIG)),
     P2PKH_Address),
    (bytes((Ops.OP_HASH160, Ops.OP_PUSHDATA1, Ops.OP_EQUAL)), P2SH_Address),
    (bytes((Ops.OP_PUSHDATA1, Ops.OP_CHECKSIG)), P2PK_Output),
    # Note this loses script ops other than pushdata
    (re.compile(pack_byte(Ops.OP_RETURN)), OP_RETURN_Output.from_template),
    (re.compile(pack_byte(Ops.OP_PUSHDATA1) + b'{3,}' + pack_byte(Ops.OP_CHECKMULTISIG) + b'$'),
     P2MultiSig_Output.from_template),
)


def classify_output_script(script):
    return _classify_script(script, output_templates, Unknown_Output)


input_templates = (
    (bytes((Ops.OP_PUSHDATA1, Ops.OP_PUSHDATA1)), P2PKH_Input),
    (bytes((Ops.OP_PUSHDATA1, )), P2PK_Input),
    (re.compile(pack_byte(Ops.OP_PUSHDATA1) + b'{3,}'), P2SHMultiSig_Input.from_template),
    (re.compile(pack_byte(Ops.OP_PUSHDATA1) + b'{2,}'), P2MultiSig_Input.from_template),
)


def classify_input_script(script):
    return _classify_script(script, input_templates, Unknown_Input)
