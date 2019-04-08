import os

import pytest

from bitcoinx import Bitcoin, BitcoinTestnet, int_to_be_bytes
from bitcoinx.address import *
from bitcoinx.script import _P2PKH_Script, _P2SH_Script


class TestAddress:

    @pytest.mark.parametrize("string,kind,coin,equal", (
        ('1111111111111111111114oLvT2', P2PKH_Address, Bitcoin, P2PKH_Address(bytes(20))),
        ('mfWxJ45yp2SFn7UciZyNpvDKrzbi36LaVX', P2PKH_Address, BitcoinTestnet,
         P2PKH_Address(int_to_be_bytes(1, 20), coin=BitcoinTestnet)),
        ('31h1vYVSYuKP6AhS86fbRdMw9XHieotbST', P2SH_Address, Bitcoin, P2SH_Address(bytes(20))),
        ('2MsFDzHRUAMpjHxKyoEHU3aMCMsVtXMsfu8', P2SH_Address, BitcoinTestnet,
         P2SH_Address(int_to_be_bytes(1, 20), coin=BitcoinTestnet)),
    ))
    def test_from_string(self, string, kind, coin, equal):
        address = Address.from_string(string)
        assert isinstance(address, kind)
        assert address.coin() is coin
        assert address == equal

    def test_from_string_bad(self):
        # Too short
        with pytest.raises(ValueError):
            Address.from_string('111111111111111111117K4nzc')
        # Unknown version byte
        with pytest.raises(ValueError):
            Address.from_string('4d3RrygbPdAtMuFnDmzsN8T5fYKVUjFu7m')


class TestP2PKH_Address:

    def test_constructor(self):
        address = P2PKH_Address(bytes(20))
        assert address.to_string() == '1111111111111111111114oLvT2'

    def test_constructor_bad(self):
        with pytest.raises(TypeError):
            P2PKH_Address(bytearray(20))
        with pytest.raises(ValueError):
            P2PKH_Address(bytes(21))
        with pytest.raises(ValueError):
            P2PKH_Address(bytes(19))

    def test_coin(self):
        address = P2PKH_Address(bytes(20))
        assert address.coin() is Bitcoin

    def test_hash160(self):
        data = os.urandom(20)
        assert P2PKH_Address(data).hash160() is data

    def test_to_string(self):
        address = P2PKH_Address(int_to_be_bytes(1, 20))
        assert address.to_string() == '11111111111111111111BZbvjr'
        assert address.to_string(coin=BitcoinTestnet) == 'mfWxJ45yp2SFn7UciZyNpvDKrzbi36LaVX'

    def test_to_script(self):
        address = P2PKH_Address(bytes.fromhex('d63cc1e3b6009e31d03bd5f8046cbe0f7e37e8c0'))
        assert address == '1LXnPYpHTwQeWfBVnQZ4yDP23b57NwoyrP'
        S = address.to_script()
        assert S == bytes.fromhex('76a914d63cc1e3b6009e31d03bd5f8046cbe0f7e37e8c088ac')
        assert isinstance(S, _P2PKH_Script)

    def test_hashable(self):
        {P2PKH_Address(bytes(20))}

    def test_hash(self):
        addr = P2PKH_Address(os.urandom(20))
        assert hash(addr) == hash(str(addr))

    def test_eq(self):
        address = P2PKH_Address(int_to_be_bytes(1, 20))
        assert address == '11111111111111111111BZbvjr'
        assert address == P2PKH_Address(int_to_be_bytes(1, 20))


class TestP2SH_Address:

    def test_constructor(self):
        address = P2SH_Address(bytes(20))
        assert address.to_string() == '31h1vYVSYuKP6AhS86fbRdMw9XHieotbST'

    def test_constructor_bad(self):
        with pytest.raises(TypeError):
            P2SH_Address(bytearray(20))
        with pytest.raises(ValueError):
            P2SH_Address(bytes(21))
        with pytest.raises(ValueError):
            P2SH_Address(bytes(19))

    def test_coin(self):
        address = P2SH_Address(bytes(20))
        assert address.coin() is Bitcoin

    def test_hash160(self):
        data = os.urandom(20)
        assert P2SH_Address(data).hash160() is data

    def test_to_string(self):
        address = P2SH_Address(int_to_be_bytes(1, 20))
        assert address.to_string() == '31h1vYVSYuKP6AhS86fbRdMw9XHiiQ93Mb'
        assert address.to_string(coin=BitcoinTestnet) == '2MsFDzHRUAMpjHxKyoEHU3aMCMsVtXMsfu8'

    def test_to_script(self):
        address = P2SH_Address(bytes.fromhex('ca9f1c4998bf46f66af34d949d8a8f189b6675b5'))
        assert address == '3LAP2V4pNJhZ11gwAFUZsDnvXDcyeeaQM5'
        S = address.to_script()
        assert S == bytes.fromhex('a914ca9f1c4998bf46f66af34d949d8a8f189b6675b587')
        assert isinstance(S, _P2SH_Script)

    def test_hashable(self):
        {P2SH_Address(bytes(20))}

    def test_hash(self):
        addr = P2SH_Address(os.urandom(20))
        assert hash(addr) == hash(str(addr))

    def test_eq(self):
        address = P2SH_Address(int_to_be_bytes(1, 20))
        assert address == '31h1vYVSYuKP6AhS86fbRdMw9XHiiQ93Mb'
        assert address == P2SH_Address(int_to_be_bytes(1, 20))
