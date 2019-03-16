# Copyright (c) 2019, Neil Booth
# Copyright (C) 2018 The Electrum developers
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
#

'''AES wrapper.'''

__all__ = (
    'aes_encrypt_with_iv', 'aes_decrypt_with_iv', 'BadPaddingError',
)


from pyaes import AESModeOfOperationCBC, Decrypter, Encrypter, PADDING_NONE


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
    aes_cbc = AESModeOfOperationCBC(key, iv=iv)
    aes = Encrypter(aes_cbc, padding=PADDING_NONE)
    return aes.feed(data) + aes.feed()  # empty aes.feed() flushes buffer


def aes_decrypt_with_iv(key, iv, data):
    aes_cbc = AESModeOfOperationCBC(key, iv=iv)
    aes = Decrypter(aes_cbc, PADDING_NONE)
    data = aes.feed(data) + aes.feed()  # empty aes.feed() flushes buffer
    return _strip_PKCS7_padding(data)
