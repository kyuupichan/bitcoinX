# Copyright (c) 2019-2024, Neil Booth
#
# All right reserved.
#
# Licensed under the the Open BSV License version 3; see LICENCE for details.
#

'''AES wrapper.'''

__all__ = (
    'aes_encrypt_with_iv', 'aes_decrypt_with_iv', 'aes_encrypt_authenticated',
    'aes_decrypt_authenticated'
)


from .errors import DecryptionError
from .hashes import _sha256, sha512, hmac_digest

from Cryptodome.Cipher import AES


def _append_PKCS7_padding(data):
    padlen = 16 - (len(data) % 16)
    return data + bytes([padlen]) * padlen


def _strip_PKCS7_padding(data):
    # Impossible if Cryptodomex is functioning properly - it would have raised ValueError in
    # aes_decrypt_with_iv().
    if not data or len(data) % 16:
        raise DecryptionError('bad length')
    # Check padding
    padlen = data[-1]
    if not 0 < padlen <= 16 or data[-padlen:] != bytes([padlen]) * padlen:
        # Impossible to distinguish between a bad password and corrupt ciphertext
        # If the caller used an HMAC it's the password; assume that
        raise DecryptionError('bad padding')

    return data[:-padlen]


def aes_encrypt_with_iv(key, iv, data):
    data = _append_PKCS7_padding(data)
    return AES.new(key, AES.MODE_CBC, iv).encrypt(data)


def aes_decrypt_with_iv(key, iv, data):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        data = cipher.decrypt(data)
    except ValueError:
        raise DecryptionError('bad length') from None
    return _strip_PKCS7_padding(data)


def aes_encrypt_authenticated(plaintext, password, prefix=b''):
    key = sha512(password)
    iv, key_e, key_m = key[0:16], key[16:32], key[32:]
    ciphertext = aes_encrypt_with_iv(key_e, iv, plaintext)
    unauth_result = b''.join((prefix, ciphertext))
    return unauth_result + hmac_digest(key_m, unauth_result, _sha256)


def aes_decrypt_authenticated(encoded_ciphertext, password, prefix=b''):
    plen = len(prefix)
    if encoded_ciphertext[:plen] != prefix:
        raise DecryptionError('corrupt ciphertext')

    ciphertext = encoded_ciphertext[plen:-32]
    hmac = encoded_ciphertext[-32:]
    key = sha512(password)
    iv, key_e, key_m = key[0:16], key[16:32], key[32:]

    if hmac_digest(key_m, encoded_ciphertext[:-32], _sha256) != hmac:
        raise DecryptionError('bad HMAC')

    return aes_decrypt_with_iv(key_e, iv, ciphertext)
