import pytest

from bitcoinx import pack_byte, be_bytes_to_int, Script
from bitcoinx.signature import *
from bitcoinx.signature import MISSING_SIG_BYTES


def test_exceptions():
    assert issubclass(InvalidSignatureError, ValueError)


# List of (der_sig, compact_sig)
serialization_testcases = [
    (bytes.fromhex('30450221008dc02fa531a9a704f5c01abdeb58930514651565b42abf94f6ad1565d0ad'
                   '6785022027b1396f772c696629a4a09b01aed2416861aeaee05d0ff4a2e6fdfde73ec84d'),
     bytes.fromhex('8dc02fa531a9a704f5c01abdeb58930514651565b42abf94f6ad1565d0ad6785'
                   '27b1396f772c696629a4a09b01aed2416861aeaee05d0ff4a2e6fdfde73ec84d')),
]


@pytest.mark.parametrize("der_sig,compact_sig", serialization_testcases)
def test_der_signature_to_compact(der_sig, compact_sig):
    assert der_signature_to_compact(der_sig) == compact_sig


@pytest.mark.parametrize("der_sig,compact_sig", serialization_testcases)
def test_compact_signature_to_der(der_sig, compact_sig):
    assert compact_signature_to_der(compact_sig) == der_sig


def test_compact_signature_to_der_bad():
    with pytest.raises(InvalidSignatureError):
        compact_signature_to_der(bytes(63))
    with pytest.raises(InvalidSignatureError):
        compact_signature_to_der('a' * 64)


class TestSigHash:

    def test_sighashes(self):
        assert SigHash.ALL == 0x01
        assert SigHash.NONE == 0x02
        assert SigHash.SINGLE == 0x03
        assert SigHash.FORKID == 0x40
        assert SigHash.ANYONE_CAN_PAY == 0x80

    @pytest.mark.parametrize("n", range(256))
    def test_attributes(self, n):
        s = SigHash(n)
        assert s.base == (n & 0x1f)
        assert isinstance(s.base, SigHash)
        assert s.anyone_can_pay is (n >= 128)

    @pytest.mark.parametrize("n, text", (
        (0, ""),
        (1, "ALL"),
        (2, "NONE"),
        (3, "SINGLE"),
        (0x40, "FORKID"),
        (0x41, "ALL|FORKID"),
        (0x42, "NONE|FORKID"),
        (0x43, "SINGLE|FORKID"),
        (0x80, "ANYONE_CAN_PAY"),
        (0x81, "ALL|ANYONE_CAN_PAY"),
        (0x82, "NONE|ANYONE_CAN_PAY"),
        (0x83, "SINGLE|ANYONE_CAN_PAY"),
    ))
    def test_to_string(self, n, text):
        assert SigHash(n).to_string() == text


defined_sighashes = {SigHash.ALL, SigHash.NONE, SigHash.SINGLE}
defined_sighashes.update(s | SigHash.ANYONE_CAN_PAY for s in list(defined_sighashes))
defined_sighashes.update(s | SigHash.FORKID for s in list(defined_sighashes))


class TestSignature:

    def test_constructor(self):
        s = Signature(MISSING_SIG_BYTES)
        assert not s.is_present()
        s = Signature(serialization_testcases[0][0] + pack_byte(0x41))
        assert s.is_present()

    def test_constructor_bad(self):
        with pytest.raises(InvalidSignatureError):
            Signature(b'\x30')

    def test_eq(self):
        assert Signature(MISSING_SIG_BYTES) == MISSING_SIG_BYTES
        assert Signature(MISSING_SIG_BYTES) == Script(MISSING_SIG_BYTES)
        assert Signature(MISSING_SIG_BYTES) == Signature(MISSING_SIG_BYTES)
        assert Signature(MISSING_SIG_BYTES) == bytearray(MISSING_SIG_BYTES)
        assert Signature(MISSING_SIG_BYTES) == memoryview(MISSING_SIG_BYTES)
        assert Signature(MISSING_SIG_BYTES) != 2.5

    def test_hashable(self):
        {Signature(MISSING_SIG_BYTES)}

    def test_hex(self):
        s = Signature.from_hex('ff')
        assert s.to_hex() == 'ff'

    def test_from_der_sig(self):
        der_sig = serialization_testcases[0][0]
        s = Signature.from_der_sig(der_sig, SigHash.ALL | SigHash.FORKID)
        assert s.der_signature == der_sig
        assert s.sighash == SigHash.ALL | SigHash.FORKID

    def test_MISSING(self):
        s = Signature.MISSING
        assert bytes(s) == MISSING_SIG_BYTES
        assert not s.is_present()

    def test_bytes(self):
        der_sig = serialization_testcases[0][0]
        raw = der_sig + pack_byte(SigHash.ALL | SigHash.FORKID)
        s = Signature(raw)
        assert bytes(s) == raw
        assert s.to_bytes() == raw

    @pytest.mark.parametrize("der_sig,compact_sig", serialization_testcases)
    def test_to_compact(self, der_sig, compact_sig):
        s = Signature(der_sig + pack_byte(SigHash.ALL))
        assert s.to_compact() == compact_sig

    @pytest.mark.parametrize("der_sig,compact_sig", serialization_testcases)
    def test_r_value(self, der_sig, compact_sig):
        s = Signature(der_sig + pack_byte(SigHash.ALL))
        assert s.r_value() == be_bytes_to_int(compact_sig[:32])

    @pytest.mark.parametrize("der_sig,compact_sig", serialization_testcases)
    def test_s_value(self, der_sig, compact_sig):
        s = Signature(der_sig + pack_byte(SigHash.ALL))
        assert s.s_value() == be_bytes_to_int(compact_sig[32:])

    def test_der_signature(self):
        s = Signature(MISSING_SIG_BYTES)
        with pytest.raises(InvalidSignatureError):
            s.der_signature
        der_sig = serialization_testcases[0][0]
        s = Signature(der_sig + pack_byte(0x41))
        assert s.der_signature == der_sig

    @pytest.mark.parametrize("sighash", (0, 1, 2, 3, 42, 189))
    def test_sighash(self, sighash):
        der_sig = serialization_testcases[0][0]
        s = Signature(der_sig + pack_byte(sighash))
        assert s.sighash == sighash

    def test_sighash_bad(self):
        s = Signature(MISSING_SIG_BYTES)
        with pytest.raises(InvalidSignatureError):
            s.sighash

    @pytest.mark.parametrize("sig, text", (
        ('304402207f5ba050adff0567df3dcdc70d5059c4b8b8d2afc961d7545778a79cd125f0b8022013b3e5a'
         '87f3fa84333f222dc32c2c75e630efb205a3c58010aab92ab4254531041',
         '304402207f5ba050adff0567df3dcdc70d5059c4b8b8d2afc961d7545778a79cd125f0b8022013b3e5a'
         '87f3fa84333f222dc32c2c75e630efb205a3c58010aab92ab42545310[ALL|FORKID]'),
    ))
    def test_to_string(self, sig, text):
        assert Signature.from_hex(sig).to_string() == text

    @pytest.mark.parametrize("sighash", range(300))
    def test_is_defined(self, sighash):
        assert SigHash(sighash).is_defined() is (sighash in defined_sighashes)

    @pytest.mark.parametrize("sighash", range(300))
    def test_has_forkid(self, sighash):
        assert SigHash(sighash).has_forkid() is bool(sighash & SigHash.FORKID)

    @pytest.mark.parametrize("hex_str,is_low", (
        ('3046022100820121109528efda8bb20ca28788639e5ba5b365e0a84f8bd85744321e7312c6022100a7c86a'
         '21446daa405306fe10d0a9906e37d1a2c6b6fdfaaf6700053058029bbe41', False),
        ('3045022100b135074e08cc93904a1712b2600d3cb01899a5b1cc7498caa4b8585bcf5f27e7022074ab5440'
         '45285baef0a63f0fb4c95e577dcbf5c969c0bf47c7da8e478909d66941', True),
        # R = S = 1
        ('300602010102010141', True),
        # R = S = 0
        ('300602010002010041', True),
        # R = 1, S = HALF_CURVE_ORDER
        ('302502010102207fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a041',
         True),
        # R = 1, S = HALF_CURVE_ORDER + 1
        ('302502010102207fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a141',
         False),
    ))
    def test_is_low_S(self, hex_str, is_low):
        raw_sig = bytes.fromhex(hex_str)
        assert Signature.is_strict_der_encoding(raw_sig)
        assert Signature.is_low_S(raw_sig) is is_low

    @pytest.mark.parametrize("hex_str", (
        # Bad Length
        '',
        '30' * 8,
        '30' * 74,
        # Not leading 0x30
        '310602010102010141',
        # Bad total length
        '300702010102010141',
        '300502010102010141',
        # Bad R length
        '300602610902010141',
        # Bad S length
        '300602010102020141',
        # R not integer
        '300601010002010041',
        # R length zero
        '300602000202010041',
        # R negative
        '300602018102010141',
        # R unnecessary leading zero
        '30070202000102010141',
        # S not ingeger
        '300602010001010041',
        # S length zero
        '300602020101020041',
        # S negative
        '300602010102019141',
        # S unnecessary leading zero
        '30070201010202007141',
    ))
    def test_is_not_strict_der_encoding(self, hex_str):
        raw_sig = bytes.fromhex(hex_str)
        assert Signature.is_strict_der_encoding(raw_sig) is False

    @pytest.mark.parametrize("hex_str", (
        # Test a zero value for R and S is accepted.
        '300602010002010041',
    ))
    def test_is_strict_der_encoding(self, hex_str):
        raw_sig = bytes.fromhex(hex_str)
        assert Signature.is_strict_der_encoding(raw_sig) is True
