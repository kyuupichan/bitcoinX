# Copyright (c) 2019-2021, Neil Booth
#
# All rights reserved.
#
# Licensed under the the Open BSV License version 3; see LICENCE for details.
#

'''Public and Private keys of various kinds.'''

__all__ = ('PrivateKey', 'PublicKey', )


from base64 import b64decode, b64encode
from binascii import Error as binascii_Error
from os import urandom

from electrumsv_secp256k1 import ffi, lib

from .address import P2PKH_Address, P2PK_Output
from .aes import aes_encrypt_with_iv, aes_decrypt_with_iv
from .base58 import base58_encode_check, base58_decode_check, is_minikey
from .consts import CURVE_ORDER
from .errors import DecryptionError, InvalidSignature
from .hashes import sha256, sha512, double_sha256, hash160 as calc_hash160, hmac_digest, _sha256
from .misc import be_bytes_to_int, int_to_be_bytes, CONTEXT, cachedproperty
from .networks import Bitcoin, Network
from .packing import pack_byte, pack_signed_message
from .signature import (
    sign_der, sign_recoverable, verify_der_signature, verify_recoverable_signature,
    public_key_from_recoverable_signature, to_message_signature, to_recoverable_signature,
)

EC_COMPRESSED = lib.SECP256K1_EC_COMPRESSED
EC_UNCOMPRESSED = lib.SECP256K1_EC_UNCOMPRESSED


def _to_32_bytes(value):
    if not isinstance(value, bytes):
        raise TypeError('value must have type bytes')
    if len(value) != 32:
        raise ValueError('value must be 32 bytes')
    return bytes(value)


def _message_hash(message, hasher):
    msg_hash = hasher(message) if hasher is not None else message
    if len(msg_hash) != 32:
        raise ValueError('hashed message must be 32 bytes')
    return msg_hash


class PrivateKey:

    def __init__(self, secret, compressed=True, network=None):
        '''Construct a PrivateKey from 32 big-endian bytes.

        compressed is passed on to the PublicKey constructor to indicate whether the
        public key should return an compressed serialization.

        A private key exists independently of any network.  However it is useful to have a
        default network for certain methods, such as to_WIF().  A PrivateKey may be created
        with an implicit network (e.g. if created from WIF), so in such cases we remember it.
        If there is no implicit network and client code does specify one, Bitcoin is used.
        '''
        if isinstance(secret, bytes):
            if len(secret) != 32:
                raise ValueError('private key must be 32 bytes')
            if not lib.secp256k1_ec_seckey_verify(CONTEXT, secret):
                raise ValueError('private key out of range')
            self._secret = secret
        elif repr(secret).startswith("<cdata 'unsigned char[32]'"):
            self._secret = bytes(ffi.buffer(secret))
        else:
            raise TypeError('private key must be bytes')
        self._compressed = compressed
        self._network = network or Bitcoin

    def _secp256k1_public_key(self):
        '''Construct a wrapped secp256k1 PublicKey.'''
        public_key = ffi.new('secp256k1_pubkey *')
        created = lib.secp256k1_ec_pubkey_create(CONTEXT, public_key, self._secret)
        # Only possible if client code has mucked with the private key's internals
        if not created:
            raise RuntimeError('invalid private key')
        return public_key

    # Public methods

    def __eq__(self, other):
        '''Return True if this PrivateKey is equal to another.'''
        return isinstance(other, PrivateKey) and self._secret == other._secret

    def __hash__(self):
        '''Hashable objects which compare equal must have the same hash value.'''
        return hash(self._secret)

    def __str__(self):
        '''Return a hash of the private key, out of an abundance of caution.
        To get a real string call to_hex() explicitly.'''
        return sha256(self._secret).hex()

    def network(self):
        '''The implied network.'''
        return self._network

    def is_compressed(self):
        '''Return true if the public key serializes to 33 bytes.'''
        return self._compressed

    @cachedproperty
    def public_key(self):
        '''Return a PublicKey corresponding to this private key.'''
        return PublicKey(self._secp256k1_public_key(), self._compressed, self._network)

    def to_int(self):
        '''Return the private key's representation as an integer.'''
        return be_bytes_to_int(self._secret)

    def to_hex(self):
        '''Return the private key's representation as a hexidecimal string.'''
        return self._secret.hex()

    def to_bytes(self):
        '''Return the private key's representation as bytes (32 bytes, big-endian).'''
        return self._secret

    @classmethod
    def from_int(cls, value):
        '''Contruct a PrivateKey from an unsigned integer.'''
        return cls(int_to_be_bytes(value, 32))

    @classmethod
    def from_arbitrary_bytes(cls, secret):
        return cls.from_int(be_bytes_to_int(secret) % CURVE_ORDER)

    @classmethod
    def from_hex(cls, hex_str):
        '''Contruct a PrivateKey from a hexadecimal string of 64 characters.

        There is no automatic padding.'''
        return cls(bytes.fromhex(hex_str))

    @classmethod
    def from_minikey(cls, minikey):
        '''Construct a PrivateKey from its Minikey encoding (used in Casascius coins).

        Minikeys used uncompressed public keys.'''
        if not is_minikey(minikey):
            raise ValueError('invalid minikey')
        return cls(sha256(minikey.encode()), False)

    @classmethod
    def from_random(cls, *, source=urandom):
        '''Return a random, valid PrivateKey.'''
        while True:
            try:
                return cls(source(32), True)
            except ValueError:
                pass

    @classmethod
    def from_WIF(cls, txt):
        '''Construct a PriveKey from WIF text.'''
        raw = base58_decode_check(txt)
        if len(raw) == 33 or len(raw) == 34 and raw[-1] == 0x01:
            return cls(raw[1:33], len(raw) == 34, Network.from_WIF_byte(raw[0]))
        raise ValueError('invalid WIF private key')

    @classmethod
    def from_text(cls, txt):
        '''Construct a PriveKey from text.  It should be either a minikey, hex, or WIF.'''
        if len(txt) == 64:
            return cls.from_hex(txt)
        if is_minikey(txt):
            return cls.from_minikey(txt)
        return cls.from_WIF(txt)

    def to_WIF(self, *, compressed=None, network=None):
        '''Return the WIF form of the private key for the given network.

        Set compressed to True to indicate the corresponding public key should be the
        compressed form.
        '''
        network = network or self._network
        payload = pack_byte(network.WIF_byte) + self._secret
        if (self._compressed if compressed is None else compressed):
            payload += b'\x01'
        return base58_encode_check(payload)

    def add(self, value):
        '''Return a new PrivateKey instance adding value to our secret.'''
        secret = ffi.new('unsigned char [32]', self._secret)
        if not lib.secp256k1_ec_privkey_tweak_add(CONTEXT, secret, _to_32_bytes(value)):
            raise ValueError('value or result out of range')
        return PrivateKey(secret, self._compressed, self._network)

    def multiply(self, value):
        '''Return a new PrivateKey instance multiplying value by our secret.'''
        secret = ffi.new('unsigned char [32]', self._secret)
        if not lib.secp256k1_ec_privkey_tweak_mul(CONTEXT, secret, _to_32_bytes(value)):
            raise ValueError('value or result out of range')
        return PrivateKey(secret, self._compressed, self._network)

    def sign(self, message, hasher=sha256):
        '''Sign a message (more correctly its hash) and return a DER-encoded signature.

        If the message is already hashed, set hasher to None.
        '''
        msg_hash = _message_hash(message, hasher)
        return sign_der(msg_hash, self._secret)

    def sign_recoverable(self, message, hasher=sha256):
        '''Sign a message (more correctly its hash) and return a 65-byte recoverable signature.
        This is a 64-byte compact signature with a recovery ID byte appended; and from
        which the public key can be immediately recovered.

        If the message is already hashed, set hasher to None.
        '''
        msg_hash = _message_hash(message, hasher)
        return sign_recoverable(msg_hash, self._secret)

    def sign_message(self, message, hasher=double_sha256):
        '''Sign a message compatibly with bitcoind (and ElectrumSV).

        message:     the message as bytes before being prefixed with SIGNED_MESSAGE_PREFIX.
                     If a string, it is first UTF-8 encoded to bytes before prefixing.
        hasher:      used to hash the message to 32 bytes.  Cannot be None as message cannot be
                     a hash.

        Returns a 65-byte signature.
        '''
        if hasher is None:
            raise ValueError('hasher cannot be None')
        message = pack_signed_message(message)
        recoverable_sig = self.sign_recoverable(message, hasher)
        # Compressed appears to be legacy and the signature is valid whether True or
        # False; in any case only the first byte (recid) of the signature changes.
        return to_message_signature(recoverable_sig, compressed=self._compressed)

    def sign_message_to_base64(self, message, hasher=double_sha256):
        '''As for sign_message, but return the result as a base64 ASCII string.'''
        return b64encode(self.sign_message(message, hasher)).decode()

    def shared_secret(self, public_key, message, hasher=sha256):
        '''Return a shared secret (as a public key) given their public key and a message.

        The deterministic key is formed by hashing the message; alternatively it can be
        passed in directly if hasher is None.
        '''
        deterministic_key = _message_hash(message, hasher)
        private_key2 = self.add(deterministic_key)
        public_key2 = public_key.add(deterministic_key)
        return public_key2.multiply(private_key2._secret)

    def ecdh_shared_secret(self, public_key):
        '''Return an Elliptic Curve Diffie-Helman shared secret (as a public key) given their
        public key.

        This is a degenerate form of shared_secret() where the deterministic key is zero.
        '''
        return public_key.multiply(self._secret)

    def decrypt_message(self, message, magic=b'BIE1'):
        '''Decrypt a message encrypted with PublicKey.encrypt_message().'''
        if isinstance(message, str):
            try:
                message = b64decode(message, validate=True)
            except binascii_Error:
                raise DecryptionError('invalid base64 encoding of encrypted message') from None
        mlen = len(magic)
        if len(message) < 81 + mlen:
            raise DecryptionError('message too short')
        if not message.startswith(magic):
            raise DecryptionError('bad magic')

        try:
            ephemeral_pubkey = PublicKey.from_bytes(message[mlen: mlen + 33])
        except ValueError as e:
            raise DecryptionError(f'invalid ephemeral public key: {e}') from None

        ciphertext = message[mlen + 33:-32]
        hmac = message[-32:]
        key = sha512(self.ecdh_shared_secret(ephemeral_pubkey).to_bytes())
        iv, key_e, key_m = key[0:16], key[16:32], key[32:]

        if hmac_digest(key_m, message[:-32], _sha256) != hmac:
            raise DecryptionError('bad HMAC')

        # Convert exceptions to DecryptionError as the aes library itself can raise
        try:
            return aes_decrypt_with_iv(key_e, iv, ciphertext)
        except Exception as e:
            raise DecryptionError(str(e)) from None


class PublicKey:

    def __init__(self, public_key, compressed, network=None):
        '''Construct a PublicKey.

        This function is not intended to be called directly by user code; use instead one
        of the "from_" class methods or using a PrivateKey's 'public_key' property.

        compressed is True if to_bytes() serializations yield public keys of 33 bytes.

        A public key exists independently of any network.  However it is useful to have a
        default network for certain methods, such as __str__().
        If there is no implicit network and client code does specify one, Bitcoin is used.
        '''
        if not repr(public_key).startswith("<cdata 'secp256k1_pubkey *'"):
            raise TypeError('PublicKey constructor requires a secp256k1_pubkey')
        self._public_key = public_key
        self._compressed = compressed
        self._network = network or Bitcoin

    # Public methods

    def __eq__(self, other):
        '''Return True if this PublicKey is equal to another.'''
        return (isinstance(other, PublicKey) and
                self.to_bytes(compressed=True) == other.to_bytes(compressed=True))

    def __hash__(self):
        '''Hashable objects which compare equal must have the same hash value.'''
        return hash(self.to_bytes(compressed=True))

    def __str__(self):
        return self.to_hex()

    def network(self):
        '''The implied network.'''
        return self._network

    def is_compressed(self):
        '''Return true if it serializes to 33 bytes.'''
        return self._compressed

    def to_bytes(self, *, compressed=None):
        '''Serialize a PublicKey to bytes.'''
        if (self._compressed if compressed is None else compressed):
            length, flag = 33, EC_COMPRESSED
        else:
            length, flag = 65, EC_UNCOMPRESSED
        result = ffi.new(f'unsigned char [{length}]')
        rlength = ffi.new('size_t *', length)

        lib.secp256k1_ec_pubkey_serialize(CONTEXT, result, rlength, self._public_key, flag)
        return bytes(ffi.buffer(result, length))

    @classmethod
    def from_bytes(cls, data):
        '''Construct a PublicKey from its serialized bytes.

        data should be bytes of length 33 or 65.'''
        public_key = ffi.new('secp256k1_pubkey *')
        if not lib.secp256k1_ec_pubkey_parse(CONTEXT, public_key, data, len(data)):
            raise ValueError('invalid public key')
        return cls(public_key, len(data) == 33)

    @classmethod
    def from_recoverable_signature(cls, recoverable_sig, message, hasher=sha256):
        '''Constuct a PublicKey from a recoverable signature and message (hash) that was
        signed.'''
        msg_hash = _message_hash(message, hasher)
        public_key = public_key_from_recoverable_signature(recoverable_sig, msg_hash)
        return cls(public_key, True)

    @classmethod
    def from_signed_message(cls, message_sig, message, hasher=double_sha256):
        '''Contruct a PublicKey from a message and its signature.

        message_sig: 65 bytes; if a string assumed base64-encoded.
        message:     the message as bytes before being prefixed with SIGNED_MESSAGE_PREFIX.
                     If a string, it is first UTF-8 encoded to bytes before prefixing.
        hasher:      used to hash the message to 32 bytes.  Cannot be None as message cannot be
                     a hash.
        '''
        if hasher is None:
            raise ValueError('hasher cannot be None')
        message = pack_signed_message(message)
        recoverable_sig = to_recoverable_signature(message_sig)
        return cls.from_recoverable_signature(recoverable_sig, message, hasher)

    def to_hex(self, *, compressed=None):
        '''Convert a PublicKey to a hexadecimal string.'''
        return self.to_bytes(compressed=compressed).hex()

    @classmethod
    def from_hex(cls, hex_str):
        '''Construct a PublicKey from a hexadecimal string.'''
        return cls.from_bytes(bytes.fromhex(hex_str))

    def to_point(self):
        '''Return the PublicKey as an (x, y) point on the curve.'''
        data = self.to_bytes(compressed=False)
        x = be_bytes_to_int(data[1:33])
        y = be_bytes_to_int(data[33:])
        return x, y

    @classmethod
    def from_point(cls, x, y):
        '''Construct a PublicKey from a (x, y) point on the curve.'''
        x_bytes = int_to_be_bytes(x, 32)
        y_bytes = int_to_be_bytes(y, 32)
        return cls.from_bytes(b''.join((b'\x04', x_bytes, y_bytes)))

    def to_address(self, *, compressed=None, network=None):
        '''Return the public key as a bitcoin P2PKH address.'''
        network = network or Bitcoin
        return P2PKH_Address(self.hash160(compressed=compressed), network)

    def add(self, value):
        '''Return a new PublicKey instance formed by adding value*G to this one.

        Preserves compressed / uncompressed serialization.'''
        public_key = ffi.new('secp256k1_pubkey *', self._public_key[0])
        if not lib.secp256k1_ec_pubkey_tweak_add(CONTEXT, public_key, _to_32_bytes(value)):
            raise ValueError('value or result out of range')
        return PublicKey(public_key, self._compressed, self._network)

    def multiply(self, value):
        '''Return a new PublicKey instance formed by multiplying this one by value (i.e. adding
        it to itself value times).

        Preserves compressed / uncompressed serialization.
        '''
        public_key = ffi.new('secp256k1_pubkey *', self._public_key[0])
        if not lib.secp256k1_ec_pubkey_tweak_mul(CONTEXT, public_key, _to_32_bytes(value)):
            raise ValueError('value or result out of range')
        return PublicKey(public_key, self._compressed, self._network)

    @classmethod
    def combine_keys(cls, public_keys):
        '''Return a new PublicKey equal to the sum of the given PublicKeys.

        The result takes its default compressed and network attributes from the first public key.
        '''
        lib_keys = [pk._public_key for pk in public_keys]
        if not lib_keys:
            raise ValueError('no public keys to combine')
        public_key = ffi.new('secp256k1_pubkey *')
        if not lib.secp256k1_ec_pubkey_combine(CONTEXT, public_key, lib_keys, len(lib_keys)):
            raise ValueError('the sum of the public keys is invalid')
        return cls(public_key, public_keys[0]._compressed, public_keys[0]._network)

    def verify_message(self, message_sig, message, hasher=double_sha256):
        '''Verify a message signed with bitcoind (and ElectrumSV).

        message_sig: 65 bytes; if a string assumed base64-encoded.
        message:     the message as bytes before being prefixed with SIGNED_MESSAGE_PREFIX.
                     If a string, it is first UTF-8 encoded to bytes before prefixing.
        hasher:      used to hash the message to 32 bytes.  Cannot be None as message cannot be
                     a hash.
        '''
        if hasher is None:
            raise ValueError('hasher cannot be None')
        message = pack_signed_message(message)
        recoverable_sig = to_recoverable_signature(message_sig)
        return self.verify_recoverable_signature(recoverable_sig, message, hasher)

    @classmethod
    def verify_message_and_address(cls, message_sig, message, address, *, hasher=double_sha256):
        '''As for verify_message, but also test it was signed by a private key of the given
        address.

        The network of the address is ignored; only its hash160 is extracted and compared
        against the two possibilities for the public key extracted from the signature.
        '''
        try:
            public_key = cls.from_signed_message(message_sig, message, hasher)
        except InvalidSignature:
            return False
        if isinstance(address, P2PKH_Address):
            hash160 = address.hash160()
        elif isinstance(address, str):
            hash160 = base58_decode_check(address)[1:]
        else:
            raise TypeError('address must be a string or address object')
        return (public_key.verify_message(message_sig, message, hasher) and
                any(hash160 == public_key.hash160(compressed=compressed)
                    for compressed in (True, False)))

    def verify_der_signature(self, der_sig, message, hasher=sha256):
        '''Verify a der-encoded signature.  Return True if good otherwise False.'''
        msg_hash = _message_hash(message, hasher)
        return verify_der_signature(der_sig, msg_hash, self._public_key)

    def verify_recoverable_signature(self, recoverable_sig, message, hasher=sha256):
        '''Verify a recoverable signature.  Return True if good otherwise False.'''
        msg_hash = _message_hash(message, hasher)
        return verify_recoverable_signature(recoverable_sig, msg_hash, self._public_key)

    def encrypt_message(self, message, magic=b'BIE1'):
        '''Encrypt a message using ECIES.  The message can be bytes or a string.

        String are converted to UTF-8 encoded bytes.  The result has type bytes.
        '''
        if isinstance(message, str):
            message = message.encode()
        ephemeral_key = PrivateKey.from_random()
        # pylint: disable=E1123
        key = sha512(ephemeral_key.ecdh_shared_secret(self).to_bytes(compressed=True))
        iv, key_e, key_m = key[0:16], key[16:32], key[32:]
        ciphertext = aes_encrypt_with_iv(key_e, iv, message)
        ephemeral_pubkey = ephemeral_key.public_key.to_bytes()
        encrypted_data = b''.join((magic, ephemeral_pubkey, ciphertext))
        return encrypted_data + hmac_digest(key_m, encrypted_data, _sha256)

    def encrypt_message_to_base64(self, message, magic=b'BIE1'):
        '''As for encrypt_message, but return the result as a base64 ASCII string.'''
        return b64encode(self.encrypt_message(message, magic)).decode()

    def hash160(self, *, compressed=None):
        '''Returns a P2PK script.'''
        return calc_hash160(self.to_bytes(compressed=compressed))

    def complement(self):
        '''Returns a compressed public key if uncompressed, or vice versa.'''
        return PublicKey(self._public_key, not self._compressed, self._network)

    def P2PK_script(self):
        '''Return a Script instance representing the P2PK script.'''
        return P2PK_Output(self, self._network).to_script()

    def P2PKH_script(self):
        '''Return a Script instance representing the P2PKH script.'''
        return self.to_address().to_script()
