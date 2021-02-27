# Copyright (c) 2019-2021, Neil Booth
#
# All right reserved.
#
# Licensed under the the Open BSV License version 3; see LICENCE for details.
#

'''BIP32 implementation.'''

__all__ = (
    'BIP32PublicKey', 'BIP32PrivateKey', 'BIP32Derivation',
    'bip32_key_from_string', 'bip32_decompose_chain_string', 'bip32_is_valid_chain_string',
    'bip32_build_chain_string', 'bip32_validate_derivation',
)

from os import urandom
import re

import attr

from .base58 import base58_decode_check, base58_encode_check
from .hashes import hmac_sha512_halves, hash160
from .keys import PrivateKey, PublicKey
from .misc import cachedproperty
from .networks import Bitcoin, Network
from .packing import pack_be_uint32, unpack_be_uint32, pack_byte

HARDENED = 1 << 31
PART_REGEX = re.compile("([0-9]+)'?$")


@attr.s(slots=True, frozen=True, repr=False)
class BIP32Derivation:
    '''Metadata about a BIP32 derivation.'''
    chain_code = attr.ib()
    n = attr.ib()
    depth = attr.ib()
    parent_fingerprint = attr.ib()

    def extended_key(self, network, raw_serkey):
        '''Return the 78-byte extended key bytes.'''
        if len(raw_serkey) == 32:
            raw_serkey = b'\0' + raw_serkey
            ver_bytes = network.xprv_verbytes
        else:
            ver_bytes = network.xpub_verbytes

        assert len(raw_serkey) == 33

        return b''.join((
            ver_bytes,
            pack_byte(self.depth),
            self.parent_fingerprint,
            pack_be_uint32(self.n),
            self.chain_code,
            raw_serkey,
        ))

    def child(self, chain_code, n, parent_fingerprint):
        return BIP32Derivation(chain_code, n, self.depth + 1, parent_fingerprint)

    def __repr__(self):
        return (f'BIP32Derivation(chain_code=bytes.fromhex("{self.chain_code.hex()}"), '
                f'n={self.n}, depth={self.depth}, '
                f'parent_fingerprint=bytes.fromhex("{self.parent_fingerprint.hex()}"))')


class BIP32PrivateKey(PrivateKey):
    '''A BIP32 private key.

    Intended to be constructed in one of the following ways:
       - from a string via bip32_key_from_string()
       - the classmethod from_seed
       - from an existing instance with the child() function
    '''
    def __init__(self, secret, derivation, network):
        super().__init__(secret, True, network)
        self._derivation = derivation

    def _extended_key(self):
        '''Return a raw extended private key.'''
        return self._derivation.extended_key(self._network, self._secret)

    @classmethod
    def _from_parts(cls, privkey, chain_code, network):
        derivation = BIP32Derivation(chain_code, 0, 0, bytes(4))
        return cls(privkey, derivation, network)

    @classmethod
    def from_seed(cls, seed, network):
        # This hard-coded message string seems to be network-independent...
        privkey, chain_code = hmac_sha512_halves(b'Bitcoin seed', seed)
        return cls._from_parts(privkey, chain_code, network)

    @classmethod
    def from_random(cls, *, source=urandom):
        '''Return a random, valid PrivateKey.'''
        while True:
            try:
                data = source(64)
                return cls._from_parts(data[:32], data[32:], Bitcoin)
            except ValueError:
                pass

    @cachedproperty
    def public_key(self):
        '''Return the corresponding BIP32PublicKey object.'''
        return BIP32PublicKey(self._secp256k1_public_key(), self._derivation, self._network)

    def child(self, n):
        '''Return the derived child extended privkey at index N.'''
        if not 0 <= n < (1 << 32):
            raise ValueError(f'invalid BIP32 private key child number: {n}')

        if n >= HARDENED:
            serkey = b'\0' + self._secret
        else:
            serkey = self.public_key.to_bytes()

        msg = serkey + pack_be_uint32(n)
        L, R = hmac_sha512_halves(self._derivation.chain_code, msg)
        child_derivation = self._derivation.child(R, n, self.fingerprint())

        return BIP32PrivateKey(self.add(L).to_bytes(), child_derivation, self._network)

    def child_safe(self, n):
        '''Return a child but increment n if the child derivation is invalid.'''
        while True:
            try:
                return self.child(n)
            except ValueError:
                if not 0 <= n < (1 << 32):
                    raise
                n += 1
                if n & (HARDENED - 1) == 0:
                    raise ValueError('out of BIP32 derivations') from None

    def derivation(self):
        '''Return a BIP32 derivation object.'''
        return self._derivation

    def identifier(self):
        '''Return the key's identifier as 20 bytes.'''
        return self.public_key.identifier()

    def fingerprint(self):
        '''Return the key's fingerprint as 4 bytes.'''
        return self.public_key.fingerprint()

    def to_extended_key_string(self):
        '''Return an extended key as a base58 string.'''
        return base58_encode_check(self._extended_key())

    def __repr__(self):
        return f'BIP32PrivateKey("{str(self)}")'


class BIP32PublicKey(PublicKey):
    '''A BIP32 public key.

    Intended to be constructed in one of the following ways:
       - from a string via bip32_key_from_string()
       - from an existing instance with the child() function
       - from a BIP32PrivateKey via its public_key attribute
    '''

    def __init__(self, public_key, derivation, network):
        if isinstance(public_key, PublicKey):
            public_key = public_key._public_key
        super().__init__(public_key, True, network)
        self._derivation = derivation

    def _extended_key(self):
        '''Return a raw extended private key.'''
        return self._derivation.extended_key(self._network, self.to_bytes())

    def child(self, n):
        '''Return the derived child extended pubkey at index N.'''
        if not 0 <= n < HARDENED:
            raise ValueError(f'invalid BIP32 public key child number: {n}')

        msg = self.to_bytes() + pack_be_uint32(n)
        L, R = hmac_sha512_halves(self._derivation.chain_code, msg)
        child_derivation = self._derivation.child(R, n, self.fingerprint())

        return BIP32PublicKey(self.add(L), child_derivation, self._network)

    def child_safe(self, n):
        '''Return a child but increment n if the child derivation is invalid.'''
        while True:
            try:
                return self.child(n)
            except ValueError:
                if not 0 <= n < HARDENED:
                    raise
                n += 1

    def derivation(self):
        '''Return a BIP32 derivation object.'''
        return self._derivation

    def identifier(self):
        '''Return the key's identifier as 20 bytes.'''
        return hash160(self.to_bytes())

    def fingerprint(self):
        '''Return the key's fingerprint as 4 bytes.'''
        return self.identifier()[:4]

    def to_extended_key_string(self):
        '''Return an extended key as a base58 string.'''
        return base58_encode_check(self._extended_key())

    def __str__(self):
        return self.to_extended_key_string()

    def __repr__(self):
        return f'BIP32PublicKey("{self.to_extended_key_string()}")'


def _from_extended_key(ekey):
    '''Return a PubKey or PrivKey from an extended key raw bytes.'''
    if len(ekey) != 78:
        raise ValueError('extended key must have length 78')

    network, is_public_key = Network.lookup_xver_bytes(ekey[:4])
    n, = unpack_be_uint32(ekey[9:13])
    derivation = BIP32Derivation(ekey[13:45], n, ekey[4], ekey[5:9])
    if is_public_key:
        key = BIP32PublicKey(PublicKey.from_bytes(ekey[45:]), derivation, network)
    else:
        if ekey[45] != 0:
            raise ValueError(f'invalid extended private key prefix byte {ekey[45]}')
        key = BIP32PrivateKey(ekey[46:], derivation, network)

    return key


def bip32_key_from_string(ekey_str):
    '''Given an extended key string, such as

    xpub6BsnM1W2Y7qLMiuhi7f7dbAwQZ5Cz5gYJCRzTNainXzQXYjFwtuQXHd
    3qfi3t3KJtHxshXezfjft93w4UE7BGMtKwhqEHae3ZA7d823DVrL

    return a BIP32PubKey or BIP32PrivKey.
    '''
    return _from_extended_key(base58_decode_check(ekey_str))


def bip32_decompose_chain_string(chain_str):
    '''Given a chain string return a list of unsigned integers.

       For example:  m/1/2'/3'/0  -> [1, 0x80000002, 0x800000003, 0]
                     m            -> []

       The chain string must be 'm' or begin with 'm/'.
    '''
    if not isinstance(chain_str, str):
        raise TypeError(f'chain_str {chain_str} must be a string')

    parts = chain_str.split('/')
    if not parts or parts[0] != 'm':
        raise ValueError(f'invalid bip32 chain: {chain_str}')

    result = []
    for part in parts[1:]:
        match = PART_REGEX.match(part)
        if not match:
            raise ValueError(f'invalid bip32 chain: {chain_str}')
        value = int(match.groups()[0])
        if value >= HARDENED:
            raise ValueError(f'invalid bip32 chain: {chain_str}')
        if part[-1] == "'":
            value += HARDENED
        result.append(value)
    return result


def bip32_is_valid_chain_string(chain_str):
    '''Return True if chain_str is a valid BIP32 chain string.'''
    try:
        bip32_decompose_chain_string(chain_str)
        return True
    except ValueError:
        return False


def bip32_validate_derivation(derivation):
    '''Validate if derivation, an iterable of integers, is a valid BIP32 derivation.

    Returns the derivation as a list of integers.  Raises: ValueError, TypeError.
    '''
    result = list(derivation)
    for n in result:
        if not isinstance(n, int):
            raise TypeError('derivation must be a sequence of ints')
        if not 0 <= n < (1 << 32):
            raise ValueError(f'invalid child number: {n}')
    return result


def bip32_build_chain_string(derivation):
    '''Given an iterable of unsigned integers, return a chain string.  This is the inverse of
       the bip32_decompose_chain_string() function.

       For example:  [1, 0x80000002, 0x800000003, 0] -> m/1/2'/3'/0
                     []                              -> m
    '''
    def parts(derivation):
        yield 'm'
        for n in derivation:
            if n < HARDENED:
                yield str(n)
            else:
                yield str(n - HARDENED) + "'"

    return '/'.join(parts(bip32_validate_derivation(derivation)))
