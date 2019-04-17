import os

from bitcoinx import aes


class TestAES:
    def test_encrypt_decrypt(self, AES_impl):
        aeskey = os.urandom(32)
        aes_key = aeskey[:16]
        aes_iv = aeskey[16:]
        original_values = [
            b"Now is the time for all good men to come to the aid of the party",
            b"The quick brown fox jumped over the lazy dog",
        ]
        for original_value in original_values:
            encrypted_value = aes.aes_encrypt_with_iv(aes_key, aes_iv, original_value)
            value = aes.aes_decrypt_with_iv(aes_key, aes_iv, encrypted_value)
            assert value == original_value
