# Copyright (c) 2019-2021, Neil Booth
#
# All right reserved.
#
# Licensed under the the Open BSV License version 3; see LICENCE for details.
#

'''AES wrapper.'''

__all__ = (
    'aes_encrypt_with_iv', 'aes_decrypt_with_iv', 'BadPaddingError',
)


from pyaes import AESModeOfOperationCBC, Decrypter, Encrypter, PADDING_NONE

try:
    from Cryptodome.Cipher import AES
except ImportError:
    AES = None


class BadPaddingError(Exception):
    pass


def _append_PKCS7_padding(data):
    padlen = 16 - (len(data) % 16)
    return data + bytes([padlen]) * padlen


def _strip_PKCS7_padding(data):
    if not data or len(data) % 16:
        raise BadPaddingError('wrong length')
    padlen = data[-1]
    if not 0 < padlen <= 16:
        raise BadPaddingError('invalid final padding byte')
    if data[-padlen:] != bytes([padlen]) * padlen:
        raise BadPaddingError('inconsistent padding bytes')
    return data[:-padlen]


def aes_encrypt_with_iv(key, iv, data):
    data = _append_PKCS7_padding(data)
    if AES:
        return AES.new(key, AES.MODE_CBC, iv).encrypt(data)

    aes_cbc = AESModeOfOperationCBC(key, iv=iv)
    aes = Encrypter(aes_cbc, padding=PADDING_NONE)
    return aes.feed(data) + aes.feed()  # empty aes.feed() flushes buffer


def aes_decrypt_with_iv(key, iv, data):
    if AES:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        data = cipher.decrypt(data)
    else:
        aes_cbc = AESModeOfOperationCBC(key, iv=iv)
        aes = Decrypter(aes_cbc, PADDING_NONE)
        data = aes.feed(data) + aes.feed()  # empty aes.feed() flushes buffer
    return _strip_PKCS7_padding(data)
