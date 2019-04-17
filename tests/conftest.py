# Pytest looks here for fixtures

import pytest

from bitcoinx import aes


AES_params = [False]
try:
    from Cryptodome.Cipher import AES as Cryptodome_AES
    AES_params.append(True)
except ImportError:
    AES_params.append(pytest.param(True, marks=pytest.mark.skip))


# Run encryption / decryption tests with pyaes and with PyCryptodome
@pytest.fixture(params=AES_params)
def AES_impl(request):
    prior = aes.AES
    aes.AES = Cryptodome_AES if request.param else None
    try:
        yield aes.AES
    finally:
        aes.AES = prior
