import os

import pytest

from bitcoinx import aes

class TestAES:
    def _encrypt_decrypt(self):
        aeskey = os.urandom(32)
        aes_key = aeskey[:16]
        aes_iv = aeskey[16:]
        original_value = b"Now is the time for all good men to come to the aid of the party"
        encrypted_value = aes.aes_encrypt_with_iv(aes_key, aes_iv, original_value)
        value = aes.aes_decrypt_with_iv(aes_key, aes_iv, encrypted_value)
        assert value == original_value

    def test_encrypt_python(self):
        original_AES = aes.AES
        aes.AES = None
        try:
            self._encrypt_decrypt()
        finally:
            aes.AES = original_AES

    def test_encrypt_optimized(self):
        # This is set if pycryptodomex was found.
        if aes.AES is None:
            pytest.skip("pycryptodomex not installed")
        else:
            self._encrypt_decrypt()
