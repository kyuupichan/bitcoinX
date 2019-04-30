import pytest

from bitcoinx.signature import *


def test_exceptions():
    assert issubclass(InvalidSignatureError, ValueError)


# List of (der_sig, compact_sig)
serialization_testcases = [
    ('30450221008dc02fa531a9a704f5c01abdeb58930514651565b42abf94f6ad1565d0ad'
     '6785022027b1396f772c696629a4a09b01aed2416861aeaee05d0ff4a2e6fdfde73ec84d',
     '8dc02fa531a9a704f5c01abdeb58930514651565b42abf94f6ad1565d0ad6785'
     '27b1396f772c696629a4a09b01aed2416861aeaee05d0ff4a2e6fdfde73ec84d'),
]


@pytest.mark.parametrize("der_sig,compact_sig", serialization_testcases)
def test_der_signature_to_compact(der_sig, compact_sig):
    der_sig = bytes.fromhex(der_sig)
    assert der_signature_to_compact(der_sig) == bytes.fromhex(compact_sig)


@pytest.mark.parametrize("der_sig,compact_sig", serialization_testcases)
def test_compact_signature_to_der(der_sig, compact_sig):
    compact_sig = bytes.fromhex(compact_sig)
    assert compact_signature_to_der(compact_sig) == bytes.fromhex(der_sig)


def test_compact_signature_to_der_bad():
    with pytest.raises(InvalidSignatureError):
        compact_signature_to_der(bytes(63))
    with pytest.raises(InvalidSignatureError):
        compact_signature_to_der('a' * 64)
