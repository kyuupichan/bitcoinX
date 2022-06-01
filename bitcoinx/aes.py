# Copyright (c) 2019-2021, Neil Booth
#
# All right reserved.
#
# Licensed under the the Open BSV License version 3; see LICENCE for details.
#

'''AES wrapper.'''

__all__ = (
    'aes_encrypt_with_iv', 'aes_decrypt_with_iv',
)


from .errors import DecryptionError

from Cryptodome.Cipher import AES


def _append_PKCS7_padding(data):
    padlen = 16 - (len(data) % 16)
    return data + bytes([padlen]) * padlen


def _strip_PKCS7_padding(data):
    if not data or len(data) % 16:
        raise DecryptionError('wrong length')
    padlen = data[-1]
    if not 0 < padlen <= 16:
        raise DecryptionError('invalid final padding byte')
    if data[-padlen:] != bytes([padlen]) * padlen:
        raise DecryptionError('inconsistent padding bytes')
    return data[:-padlen]


def aes_encrypt_with_iv(key, iv, data):
    data = _append_PKCS7_padding(data)
    return AES.new(key, AES.MODE_CBC, iv).encrypt(data)


def aes_decrypt_with_iv(key, iv, data):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = cipher.decrypt(data)
    return _strip_PKCS7_padding(data)
