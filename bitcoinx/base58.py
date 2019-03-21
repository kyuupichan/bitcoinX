# Copyright (c) 2017-2019, Neil Booth
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Base58 encoding.'''

__all__ = (
    'base58_decode', 'base58_encode', 'base58_decode_check', 'base58_encode_check',
    'Base58Error', 'is_minikey',
)

from .hashes import double_sha256, sha256
from .misc import int_to_be_bytes, be_bytes_to_int


base58_chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
base58_cmap = {c: n for n, c in enumerate(base58_chars)}


class Base58Error(Exception):
    '''Exception used for Base58 errors.'''


def base58_decode(txt):
    """Decodes txt into a big-endian bytearray."""
    if not isinstance(txt, str):
        raise TypeError('a string is required')

    if not txt:
        raise Base58Error('string cannot be empty')

    cvalue = base58_cmap.get
    value = 0
    try:
        for c in txt:
            value = value * 58 + cvalue(c)
    except TypeError:
        raise Base58Error(f'invalid base 58 character "{c}"') from None

    result = int_to_be_bytes(value)

    # Prepend leading zero bytes if necessary
    count = 0
    for c in txt:
        if c != '1':
            break
        count += 1
    if count:
        result = bytes(count) + result

    return result


def base58_encode(be_bytes):
    '''Convert a big-endian bytearray into a base58 string.'''
    value = be_bytes_to_int(be_bytes)

    txt = ''
    while value:
        value, mod = divmod(value, 58)
        txt += base58_chars[mod]

    for byte in be_bytes:
        if byte != 0:
            break
        txt += '1'

    return txt[::-1]


def base58_decode_check(txt):
    '''Decode a Base58Check-encoded string to a payload.  The version prefixes it.'''
    be_bytes = base58_decode(txt)
    result, check = be_bytes[:-4], be_bytes[-4:]
    if check != double_sha256(result)[:4]:
        raise Base58Error(f'invalid base 58 checksum for {txt}')
    return result


def base58_encode_check(payload):
    '''Encode a payload bytearray (which includes the version byte(s)) into a Base58Check
    string.
    '''
    be_bytes = payload + double_sha256(payload)[:4]
    return base58_encode(be_bytes)


def is_minikey(text):
    # Minikeys are 22 or 30 characters.  A valid minikey must begin with an 'S', be in
    # base58, and when suffixed with '?' have its SHA256 hash begin with a zero byte.
    # They are widely used in Casascius physical bitcoins, where the address corresponded
    # to an uncompressed public key.
    return (len(text) in (22, 30)
            and text[0] == 'S'
            and all(c in base58_cmap for c in text)
            and sha256((text + '?').encode())[0] == 0x00)
