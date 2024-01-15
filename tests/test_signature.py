import pytest
import random

from bitcoinx import (
    pack_byte, be_bytes_to_int, InvalidSignature, int_to_be_bytes, CURVE_ORDER,
)
from bitcoinx.signature import *


# List of (der_sig, compact_sig)
serialization_testcases = [
    (bytes.fromhex('30450221008dc02fa531a9a704f5c01abdeb58930514651565b42abf94f6ad1565d0ad'
                   '6785022027b1396f772c696629a4a09b01aed2416861aeaee05d0ff4a2e6fdfde73ec84d'),
     bytes.fromhex('8dc02fa531a9a704f5c01abdeb58930514651565b42abf94f6ad1565d0ad6785'
                   '27b1396f772c696629a4a09b01aed2416861aeaee05d0ff4a2e6fdfde73ec84d')),
    # R and S are CURVE_ORDER - 1
    (bytes.fromhex('3046022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364'
                   '140022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140'),
     bytes.fromhex('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140'
                   'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140')),
]


@pytest.mark.parametrize("der_sig,compact_sig", serialization_testcases)
def test_der_signature_to_compact(der_sig, compact_sig):
    assert der_signature_to_compact(der_sig) == compact_sig


@pytest.mark.parametrize("der_sig,compact_sig", serialization_testcases)
def test_compact_signature_to_der(der_sig, compact_sig):
    assert compact_signature_to_der(compact_sig) == der_sig


def test_der_signature_to_compact_no_overflow():
    der_sig = bytes.fromhex(
        '3046022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'
        '022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'
    )
    # Never overflows
    der_signature_to_compact(der_sig)


largest = int_to_be_bytes(CURVE_ORDER)
der_zeroes = bytes.fromhex('3006020100020100')


@pytest.mark.parametrize("raises, value", (
    (raises, value) for raises in (True, False) for value in (
        largest + bytes(32), bytes(32) + largest, largest * 2
    )
))
def test_compact_signature_to_der_overflow(raises, value):
    if raises:
        with pytest.raises(InvalidSignature):
            compact_signature_to_der(value, raise_on_overflow=True)
    else:
        assert compact_signature_to_der(value, raise_on_overflow=False) == der_zeroes
        assert compact_signature_to_der(value) == der_zeroes


def test_compact_signature_to_der_bad():
    with pytest.raises(InvalidSignature):
        compact_signature_to_der(bytes(63))
    with pytest.raises(InvalidSignature):
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
        (0xa3, "SINGLE|ANYONE_CAN_PAY|0x20"),
    ))
    def test_to_string(self, n, text):
        assert SigHash(n).to_string() == text

    @pytest.mark.parametrize("sighash", range(300))
    def test_is_defined(self, sighash):
        assert SigHash(sighash).is_defined() is (sighash in defined_sighashes)

    @pytest.mark.parametrize("sighash", range(300))
    def test_has_forkid(self, sighash):
        assert SigHash(sighash).has_forkid() is bool(sighash & SigHash.FORKID)


defined_sighashes = {SigHash.ALL, SigHash.NONE, SigHash.SINGLE}
defined_sighashes.update(s | SigHash.ANYONE_CAN_PAY for s in list(defined_sighashes))
defined_sighashes.update(s | SigHash.FORKID for s in list(defined_sighashes))

lax_der_testcases = [
    # Zero total length, zero R len, zero S len
    ('300002000200', '3006020100020100'),
    # 0x70 total length, R=2, S=3
    ('3070020102020103', '3006020102020103'),
    # 0x80 total length, R=2, S=3
    ('3080020102020103', '3006020102020103'),
    # 0x8101 total length, R=2, S=3
    ('308101020102020103', '3006020102020103'),
    # 0x80 total length, R=0002, S=0003
    ('30800202000202020003', '3006020102020103'),
    # 0x80 total length, Rlen=820002 R=0005, SLen=83000001 S=20
    ('3080028200020005028300000120', '3006020105020120'),
    # 0x70 total length, R=2, S=3  excess bytes
    ('3070020102020103deadbeef', '3006020102020103'),
    # R = TOO BIG, S=1  gives (0, 0)
    ('3046022170fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101',
     '3006020100020100'),
    # R = 1, S = TOO BIG, S=1  gives (0, 0)
    ('3046020101022170fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
     '3006020100020100'),
    # R = CURVE_ORDER, S=1  gives (0, 0)
    ('3046022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101',
     '3006020100020100'),
    # R = 1, S = CURVE_ORDER  gives (0, 0)
    ('3046020101022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
     '3006020100020100'),
    # R = 4, S = CURVE_ORDER - 1   gives (4, 1)
    ('3046020104022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140',
     '3006020104020101'),
]


class TestSignature:

    @pytest.mark.parametrize("der_sig,compact_sig", serialization_testcases)
    def test_parse_lax_to_compact(self, der_sig, compact_sig):
        assert Signature.parse_lax_to_compact(der_sig, force_low_S=False) == compact_sig

    @pytest.mark.parametrize("der_sig,compact_sig", serialization_testcases)
    def test_r_value(self, der_sig, compact_sig):
        assert Signature.r_value(der_sig) == be_bytes_to_int(compact_sig[:32])

    @pytest.mark.parametrize("der_sig,compact_sig", serialization_testcases)
    def test_s_value(self, der_sig, compact_sig):
        assert Signature.s_value(der_sig, force_low_S=False) == be_bytes_to_int(compact_sig[32:])

    @pytest.mark.parametrize("sig, text", (
        ('304402207f5ba050adff0567df3dcdc70d5059c4b8b8d2afc961d7545778a79cd125f0b8022013b3e5a'
         '87f3fa84333f222dc32c2c75e630efb205a3c58010aab92ab4254531041',
         '304402207f5ba050adff0567df3dcdc70d5059c4b8b8d2afc961d7545778a79cd125f0b8022013b3e5a'
         '87f3fa84333f222dc32c2c75e630efb205a3c58010aab92ab42545310[ALL|FORKID]'),
    ))
    def test_to_string(self, sig, text):
        assert Signature.to_string(bytes.fromhex(sig)) == text

    @pytest.mark.parametrize("hex_str, result", (
        # Bad Length
        ('', 0),
        ('30' * 8, 0),
        ('30' * 74, 0),
        # Not leading 0x30
        ('310602010102010141', 0),
        # Bad total length
        ('300702010102010141', 0),
        ('300502010102010141', 0),
        # Bad R length
        ('300602610902010141', 0),
        # Bad S length
        ('300602010102020141', 0),
        # R not integer
        ('300601010002010041', 0),
        # R length zero
        ('300602000202010041', 0),
        # R negative
        ('300602018102010141', 0),
        # R unnecessary leading zero
        ('30070202000102010141', 0),
        # S not ingeger
        ('300602010001010041', 0),
        # S length zero
        ('300602020101020041', 0),
        # S negative
        ('300602010102019141', 0),
        # S unnecessary leading zero
        ('30070201010202007141', 0),
        # Not low S
        ('3046022100820121109528efda8bb20ca28788639e5ba5b365e0a84f8bd85744321e7312c6022100a7c86a'
         '21446daa405306fe10d0a9906e37d1a2c6b6fdfaaf6700053058029bbe41', SigEncoding.STRICT_DER),
        ('3045022100b135074e08cc93904a1712b2600d3cb01899a5b1cc7498caa4b8585bcf5f27e7022074ab5440'
         '45285baef0a63f0fb4c95e577dcbf5c969c0bf47c7da8e478909d66941',
         SigEncoding.STRICT_DER | SigEncoding.LOW_S),
        # R = S = 1
        ('300602010102010141', SigEncoding.STRICT_DER | SigEncoding.LOW_S),
        # R = S = 0
        ('300602010002010041', SigEncoding.STRICT_DER | SigEncoding.LOW_S),
        # R = 1, S = HALF_CURVE_ORDER
        ('302502010102207fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a041',
         SigEncoding.STRICT_DER | SigEncoding.LOW_S),
        # R = 1, S = HALF_CURVE_ORDER + 1
        ('302502010102207fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a141',
         SigEncoding.STRICT_DER),
    ))
    def test_analyze_encoding(self, hex_str, result):
        raw_sig = bytes.fromhex(hex_str)
        assert Signature.analyze_encoding(raw_sig) == result

    @pytest.mark.parametrize("sig_hex", (
        # Too short
        '',
        # Not 0x30 at start
        '00',
        # Too short with -0 length byte
        '3080',
        # Too short with -1 length byte
        '3081',
        # R not integer
        '300001',
        # RLen not present
        '30000281',
        # R not present
        '30000220',
        # S not present
        '3000020108',
        # S not integer
        '300002010801',
        # SLen not present
        '300002010802',
        # SLen not present
        '30000201080281',
        # S not present
        '30000201080201',
        # S missing a byte
        '3000020108020201',
    ))
    def test_parse_lax_to_der_bad(self, sig_hex):
        with pytest.raises(InvalidSignature) as e:
            Signature.parse_lax_to_der(bytes.fromhex(sig_hex))
        assert 'invalid lax DER encoding' in str(e.value)

    @pytest.mark.parametrize("sig_hex, normalized", lax_der_testcases)
    def test_parse_lax_to_der_good(self, sig_hex, normalized):
        sig_bytes = bytes.fromhex(sig_hex)
        assert Signature.parse_lax_to_der(sig_bytes).hex() == normalized

    @pytest.mark.parametrize("sig_hex, normalized", lax_der_testcases)
    def test_split_and_normalize(self, sig_hex, normalized):
        sighash_byte = random.randrange(0, 256)
        sig_bytes = bytes.fromhex(sig_hex) + pack_byte(sighash_byte)
        normalized_sig, sighash = Signature.split_and_normalize(sig_bytes)
        assert (normalized_sig.hex(), sighash) == (normalized, SigHash(sighash_byte))
