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

'''Public and Private keys of various kinds.'''

__all__ = (
    'PrivateKey', 'PublicKey', 'CURVE_ORDER',
    'KeyException', 'InvalidSignatureError', 'DecryptionError',
    'der_signature_to_compact', 'compact_signature_to_der',
)

from base64 import b64decode, b64encode
from os import urandom

from electrumsv_secp256k1 import ffi, lib, create_context

from .aes import aes_encrypt_with_iv, aes_decrypt_with_iv
from .base58 import base58_encode_check, base58_decode_check, is_minikey
from .coin import Bitcoin, Coin
from .hashes import sha256, sha512, double_sha256, hash160, hmac_digest, _sha256
from .misc import be_bytes_to_int, int_to_be_bytes
from .packing import pack_byte, pack_varbytes
from .script import Script
from .util import cachedproperty


KEY_SIZE = 32
CURVE_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
CONTEXT = create_context()
CDATA_SIG_LENGTH = 64
MAX_SIG_LENGTH = 72
EC_COMPRESSED = lib.SECP256K1_EC_COMPRESSED
EC_UNCOMPRESSED = lib.SECP256K1_EC_UNCOMPRESSED
SIGNED_MESSAGE_PREFIX = pack_varbytes('Bitcoin Signed Message:\n'.encode())


class KeyException(Exception):
    pass


class InvalidSignatureError(KeyException):
    pass


class DecryptionError(KeyException):
    pass


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


def _serialize_der(signature):
    '''Return a DER-serialized signature; bytes of length at most 72.'''
    size = ffi.new('size_t *', MAX_SIG_LENGTH)
    data = ffi.new(f'unsigned char [{MAX_SIG_LENGTH}]')
    result = lib.secp256k1_ecdsa_signature_serialize_der(CONTEXT, data, size, signature)
    # Failure should never happen - MAX_SIG_LENGTH bytes is always enough
    assert result
    return bytes(ffi.buffer(data, size[0]))


def _serialize_recoverable(recover_sig, context):
    '''Return a 65-byte compact serialized signature.'''
    output = ffi.new(f'unsigned char [{CDATA_SIG_LENGTH}]')
    recid = ffi.new('int *')

    lib.secp256k1_ecdsa_recoverable_signature_serialize_compact(
        context, output, recid, recover_sig)

    # recid is 0, 1, 2 or 3.
    return bytes(ffi.buffer(output, CDATA_SIG_LENGTH)) + bytes([recid[0]])


def _deserialize_recoverable_sig(recover_sig_bytes):
    if len(recover_sig_bytes) != 65:
        raise InvalidSignatureError('invalid recoverable signature')
    recoverable_sig = ffi.new('secp256k1_ecdsa_recoverable_signature *')
    recid = recover_sig_bytes[-1]
    if not 0 <= recid <= 3:
        raise InvalidSignatureError('invalid recoverable signature')
    if not lib.secp256k1_ecdsa_recoverable_signature_parse_compact(
            CONTEXT, recoverable_sig, recover_sig_bytes, recid):
        raise InvalidSignatureError('invalid recoverable signature')
    return recoverable_sig


def _message_sig_to_recoverable_sig(message_sig):
    '''Return a recoverable signature from a message signature.'''
    if not isinstance(message_sig, bytes) or len(message_sig) != 65:
        raise InvalidSignatureError('message signature must be 65 bytes')
    if not 27 <= message_sig[0] < 35:
        raise InvalidSignatureError('invalid message signature format')
    return message_sig[1:] + pack_byte((message_sig[0] - 27) & 3)


def _recoverable_sig_to_message_sig(recoverable_sig, compressed):
    leading_byte = 27 + (4 if compressed else 0) + recoverable_sig[-1]
    return pack_byte(leading_byte) + recoverable_sig[:64]


def _recoverable_sig_to_cdata_sig(recoverable_sig):
    cdata_sig = ffi.new('secp256k1_ecdsa_signature *')
    rec_sig = _deserialize_recoverable_sig(recoverable_sig)
    # Always succeeds
    lib.secp256k1_ecdsa_recoverable_signature_convert(CONTEXT, cdata_sig, rec_sig)
    return cdata_sig


def _der_sig_to_cdata_sig(der_sig):
    cdata_sig = ffi.new('secp256k1_ecdsa_signature *')
    if not lib.secp256k1_ecdsa_signature_parse_der(CONTEXT, cdata_sig, der_sig, len(der_sig)):
        raise InvalidSignatureError('invalid DER-encoded signature')
    return cdata_sig


def _normalize_message_and_sig(message, message_sig):
    if isinstance(message, str):
        message = message.encode()
    if isinstance(message_sig, str):
        message_sig = b64decode(message_sig)
    return message, message_sig


def der_signature_to_compact(der_sig):
    '''Returns 64 bytes representing r and s as concatenated 32-byte big-endian numbers.'''
    cdata_sig = _der_sig_to_cdata_sig(der_sig)
    compact_sig = ffi.new('unsigned char [64]')
    lib.secp256k1_ecdsa_signature_serialize_compact(CONTEXT, compact_sig, cdata_sig)
    return bytes(ffi.buffer(compact_sig))


def compact_signature_to_der(compact_sig):
    if not (isinstance(compact_sig, bytes) and len(compact_sig) == 64):
        raise InvalidSignatureError('compact signature must be 64 bytes')
    cdata_sig = ffi.new('secp256k1_ecdsa_signature *')
    lib.secp256k1_ecdsa_signature_parse_compact(CONTEXT, cdata_sig, compact_sig)
    return _serialize_der(cdata_sig)


class PrivateKey:

    def __init__(self, secret, compressed=True, coin=None):
        '''Construct a PrivateKey from 32 big-endian bytes.

        compressed is passed on to the PublicKey constructor to indicate whether the
        public key should return an compressed serialization.

        A private key exists independently of any coin.  However it is useful to have a
        default coin for certain methods, such as to_WIF().  A PrivateKey may be created
        with an implicit coin (e.g. if created from WIF), so in such cases we remember it.
        If there is no implicit coin and client code does specify one, Bitcoin is used.
        '''
        if isinstance(secret, bytes):
            if len(secret) != KEY_SIZE:
                raise ValueError('private key must be 32 bytes')
            if not lib.secp256k1_ec_seckey_verify(CONTEXT, secret):
                raise ValueError('private key out of range')
            self._secret = secret
        elif repr(secret).startswith("<cdata 'unsigned char[32]'"):
            self._secret = bytes(ffi.buffer(secret))
        else:
            raise TypeError('private key must be bytes')
        self._compressed = compressed
        self._coin = coin or Bitcoin

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
        return self._secret == other._secret

    def __str__(self):
        '''Return a hash of the private key, out of an abundance of caution.
        To get a real string call to_hex() explicitly.'''
        return sha256(self._secret).hex()

    def coin(self):
        '''Returns an implied coin if there is one, otherwise Bitcoin.'''
        return self._coin

    def is_compressed(self):
        '''Return true if the public key serializes to 33 bytes.'''
        return self._compressed

    @cachedproperty
    def public_key(self):
        '''Return a PublicKey corresponding to this private key.'''
        return PublicKey(self._secp256k1_public_key(), self._compressed, self._coin)

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
            return cls(raw[1:33], len(raw) == 34, Coin.from_WIF_byte(raw[0]))
        raise ValueError('invalid WIF private key')

    def to_WIF(self, *, compressed=None, coin=None):
        '''Return the WIF form of the private key for the given coin.

        Set compressed to True to indicate the corresponding public key should be the
        compressed form.
        '''
        coin = coin or self._coin
        payload = pack_byte(coin.WIF_byte) + self._secret
        if (self._compressed if compressed is None else compressed):
            payload += pack_byte(0x01)
        return base58_encode_check(payload)

    def add(self, value):
        '''Return a new PrivateKey instance adding value to our secret.'''
        secret = ffi.new('unsigned char [32]', self._secret)
        if not lib.secp256k1_ec_privkey_tweak_add(CONTEXT, secret, _to_32_bytes(value)):
            raise ValueError('value or result out of range')
        return PrivateKey(secret, self._compressed, self._coin)

    def multiply(self, value):
        '''Return a new PrivateKey instance multiplying value by our secret.'''
        secret = ffi.new('unsigned char [32]', self._secret)
        if not lib.secp256k1_ec_privkey_tweak_mul(CONTEXT, secret, _to_32_bytes(value)):
            raise ValueError('value or result out of range')
        return PrivateKey(secret, self._compressed, self._coin)

    def sign(self, message, hasher=sha256):
        '''Sign a message (more correctly its hash, by default SHA256).'''
        msg_hash = _message_hash(message, hasher)
        signature = ffi.new('secp256k1_ecdsa_signature *')
        if not lib.secp256k1_ecdsa_sign(CONTEXT, signature, msg_hash, self._secret,
                                        ffi.NULL, ffi.NULL):
            raise ValueError('invalid private key')
        return _serialize_der(signature)

    def sign_recoverable(self, message, hasher=sha256):
        '''Sign a message (more correctly its hash, by default SHA256) so that the public key can
        be recovered from the signature.
        '''
        msg_hash = _message_hash(message, hasher)
        signature = ffi.new('secp256k1_ecdsa_recoverable_signature *')
        if not lib.secp256k1_ecdsa_sign_recoverable(CONTEXT, signature, msg_hash, self._secret,
                                                    ffi.NULL, ffi.NULL):
            raise ValueError('invalid private key')
        return _serialize_recoverable(signature, CONTEXT)

    def sign_message(self, message, hasher=double_sha256):
        '''Sign a message compatibly with bitcoind (and ElectrumSV).

        Compressed appears to be legacy and the signature is valid whether True or False;
        in any case only the first byte of the signature changes.

        If message is a string, it is UTF-8 encoded as bytes.  The result is bytes object
        of length 65.
        '''
        if isinstance(message, str):
            message = message.encode()
        msg_to_sign = SIGNED_MESSAGE_PREFIX + pack_varbytes(message)
        recoverable_sig = self.sign_recoverable(msg_to_sign, hasher)
        return _recoverable_sig_to_message_sig(recoverable_sig, compressed=self._compressed)

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
            message = b64decode(message)
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

        try:
            return aes_decrypt_with_iv(key_e, iv, ciphertext)
        except Exception as e:  # aes library can raise Exception, unfortunately
            raise DecryptionError(f'{e}') from None


class PublicKey:

    def __init__(self, public_key, compressed, coin=None):
        '''Construct a PublicKey.

        This function is not intended to be called directly by user code; use instead one
        of the "from_" class methods or using a PrivateKey's 'public_key' property.

        compressed is True if to_bytes() serializations yield public keys of 33 bytes.

        A public key exists independently of any coin.  However it is useful to have a
        default coin for certain methods, such as __str__().
        If there is no implicit coin and client code does specify one, Bitcoin is used.
        '''
        if not repr(public_key).startswith("<cdata 'secp256k1_pubkey *'"):
            raise TypeError('PublicKey constructor requires a secp256k1_pubkey')
        self._public_key = public_key
        self._compressed = compressed
        self._coin = coin or Bitcoin

    # Public methods

    def __eq__(self, other):
        '''Return True if this PublicKey is equal to another.'''
        return self.to_bytes(compressed=True) == other.to_bytes(compressed=True)

    def __str__(self):
        return self.to_hex()

    def coin(self):
        '''Returns an implied coin if there is one, otherwise Bitcoin.'''
        return self._coin

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
        recoverable_sig = _deserialize_recoverable_sig(recoverable_sig)
        public_key = ffi.new('secp256k1_pubkey *')
        if not lib.secp256k1_ecdsa_recover(CONTEXT, public_key, recoverable_sig, msg_hash):
            raise InvalidSignatureError('invalid recoverable signature')
        return cls(public_key, True)

    @classmethod
    def from_signed_message(cls, message_sig, message, hasher=double_sha256):
        '''Contruct a PublicKey from a message and its signature.'''
        message, message_sig = _normalize_message_and_sig(message, message_sig)
        message = SIGNED_MESSAGE_PREFIX + pack_varbytes(message)
        recoverable_sig = _message_sig_to_recoverable_sig(message_sig)
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

    def to_address(self, *, compressed=None, coin=None):
        '''Return the public key as a bitcoin P2PKH address.'''
        coin = coin or self.coin()
        data = self.to_bytes(compressed=compressed)
        return base58_encode_check(pack_byte(coin.P2PKH_verbyte) + hash160(data))

    def add(self, value):
        '''Return a new PublicKey instance formed by adding value*G to this one.

        Preserves compressed / uncompressed serialization.'''
        public_key = ffi.new('secp256k1_pubkey *', self._public_key[0])
        if not lib.secp256k1_ec_pubkey_tweak_add(CONTEXT, public_key, _to_32_bytes(value)):
            raise ValueError('value or result out of range')
        return PublicKey(public_key, self._compressed, self._coin)

    def multiply(self, value):
        '''Return a new PublicKey instance formed by multiplying this one by value (i.e. adding
        it to itself value times).

        Preserves compressed / uncompressed serialization.
        '''
        public_key = ffi.new('secp256k1_pubkey *', self._public_key[0])
        if not lib.secp256k1_ec_pubkey_tweak_mul(CONTEXT, public_key, _to_32_bytes(value)):
            raise ValueError('value or result out of range')
        return PublicKey(public_key, self._compressed, self._coin)

    @classmethod
    def combine_keys(cls, public_keys):
        '''Return a new PublicKey equal to the sum of the given PublicKeys.

        The result takes its default compressed and coin attributes from the first public key.
        '''
        lib_keys = [pk._public_key for pk in public_keys]
        if not lib_keys:
            raise ValueError('no public keys to combine')
        public_key = ffi.new('secp256k1_pubkey *')
        if not lib.secp256k1_ec_pubkey_combine(CONTEXT, public_key, lib_keys, len(lib_keys)):
            raise ValueError('the sum of the public keys is invalid')
        return cls(public_key, public_keys[0]._compressed, public_keys[0]._coin)

    def verify_message(self, message_sig, message, hasher=double_sha256):
        '''Verify a message signed with bitcoind (and ElectrumSV).

        If message is a string, it is UTF-8 encoded as bytes.  If message_sig is a string,
        it is assumed to be base64-encoded.
        '''
        message, message_sig = _normalize_message_and_sig(message, message_sig)
        recoverable_sig = _message_sig_to_recoverable_sig(message_sig)
        msg_to_sign = SIGNED_MESSAGE_PREFIX + pack_varbytes(message)
        return self.verify_signature(recoverable_sig, msg_to_sign, hasher)

    @classmethod
    def verify_message_and_address(cls, message_sig, message, address, *,
                                   hasher=double_sha256, coin=None):
        '''As for verify_message, but also test it was signed by a private key of the given
        address.
        '''
        message, message_sig = _normalize_message_and_sig(message, message_sig)
        try:
            public_key = cls.from_signed_message(message_sig, message, hasher)
        except InvalidSignatureError:
            return False
        return (public_key.verify_message(message_sig, message, hasher) and
                any(address == public_key.to_address(compressed=compressed, coin=coin)
                    for compressed in (True, False)))

    def verify_signature(self, signature, message, hasher=sha256):
        '''Verify a serialized signature.  Return True if good otherwise False.'''
        # Handle recoverable and der-encoded signatures
        if len(signature) == 65:
            cdata_sig = _recoverable_sig_to_cdata_sig(signature)
        else:
            cdata_sig = _der_sig_to_cdata_sig(signature)

        msg_hash = _message_hash(message, hasher)
        return bool(lib.secp256k1_ecdsa_verify(CONTEXT, cdata_sig, msg_hash, self._public_key))

    def encrypt_message(self, message, magic=b'BIE1'):
        '''Encrypt a message using ECIES.  The message can be bytes or a string.

        String are converted to UTF-8 encoded bytes.  The result has type bytes.
        '''
        if isinstance(message, str):
            message = message.encode()
        ephemeral_key = PrivateKey.from_random()
        key = sha512(ephemeral_key.ecdh_shared_secret(self).to_bytes(compressed=True))
        iv, key_e, key_m = key[0:16], key[16:32], key[32:]
        ciphertext = aes_encrypt_with_iv(key_e, iv, message)
        ephemeral_pubkey = ephemeral_key.public_key.to_bytes()
        encrypted_data = b''.join((magic, ephemeral_pubkey, ciphertext))
        return encrypted_data + hmac_digest(key_m, encrypted_data, _sha256)

    def encrypt_message_to_base64(self, message, magic=b'BIE1'):
        '''As for encrypt_message, but return the result as a base64 ASCII string.'''
        return b64encode(self.encrypt_message(message, magic)).decode()

    def P2PK_script(self, *, compressed=None):
        return Script.P2PK_script(self.to_bytes(compressed=compressed))

    def P2PKH_script(self, *, compressed=None):
        return Script.P2PKH_script(hash160(self.to_bytes(compressed=compressed)))
