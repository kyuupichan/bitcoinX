import random

import pytest

from bitcoinx import (
    PublicKey, SigHash, Bitcoin, BitcoinTestnet, JSONFlags, Script, OP_FALSE,
    InterpreterError
)

from bitcoinx.tx import LOCKTIME_THRESHOLD, Tx, TxInput, TxOutput

from .utils import read_tx, read_text_file, read_signature_hashes, read_json_tx


def test_tx_read():
    tx = read_tx('b59de025.txn')

    assert tx.version == 2
    assert len(tx.inputs) == 7
    assert len(tx.outputs) == 3
    assert tx.locktime == 0


def test_from_bytes():
    tx_bytes = bytes.fromhex(read_text_file('b59de025.txn'))
    tx = Tx.from_bytes(tx_bytes)
    assert tx.to_bytes() == tx_bytes


def test_from_hex():
    tx_hex = read_text_file('b59de025.txn')
    tx = Tx.from_hex(tx_hex)
    assert tx.to_hex() == tx_hex


def test_to_bytes_to_hex():
    tx_hex = read_text_file('b59de025.txn')
    tx = Tx.from_hex(tx_hex)
    assert tx.to_bytes() == bytes.fromhex(tx_hex)
    assert tx.to_hex() == tx_hex


def test_repr():
    tx = read_tx('afda808f.txn')
    assert repr(tx) == (
        'Tx(version=1, inputs=[TxInput(prev_hash="00000000000000000000000000000000000000000000'
        '00000000000000000000", prev_idx=4294967295, script_sig="0319c4082f626d67706f6f6c2e636f6d2'
        'f5473537148110d9e7fcc3cf74ee70c0200", sequence=4294967295)], outputs=[TxOutput(value='
        '1250005753, script_pubkey="76a914db1aea84aad494d9f5b253327da23c4e51266c9388ac")], '
        'locktime=0)'
    )


tx_testcases = ['503fd37f.txn']


@pytest.mark.parametrize("filename", tx_testcases)
def test_signature_hash(filename):
    tx, values, pk_scripts = read_json_tx(filename)
    correct_hashes = read_signature_hashes(filename.replace('.txn', '.sig_hashes'))

    n = 0
    for input_index, (value, pk_script, _txin) in enumerate(zip(values, pk_scripts, tx.inputs)):
        for sighash in range(256):
            sighash = SigHash(sighash)
            if sighash.has_forkid():
                signature_hash = tx.signature_hash(input_index, value, pk_script, sighash)
                assert signature_hash == correct_hashes[n]
            n += 1


def test_signature_hash_bad():
    tx, _, _ = read_json_tx('503fd37f.txn')

    with pytest.raises(IndexError):
        tx.signature_hash(-1, 5, b'', SigHash.ALL)
    with pytest.raises(IndexError):
        tx.signature_hash(2, 5, b'', SigHash.ALL)
    with pytest.raises(ValueError):
        tx.signature_hash(0, -1, b'', SigHash.ALL)
    with pytest.raises(TypeError):
        tx.signature_hash(0, 0, b'', 1)
    tx.signature_hash(0, 0, b'', SigHash.NONE)
    tx.signature_hash(1, 0, b'', SigHash(1))


@pytest.mark.parametrize("filename", tx_testcases)
def test_signatures(filename):
    tx, values, pk_scripts = read_json_tx(filename)

    for input_index, (value, pk_script, txin) in enumerate(zip(values, pk_scripts, tx.inputs)):
        signature, pubkey = txin.script_sig.ops()
        pubkey = PublicKey.from_bytes(pubkey)
        signature_hash = tx.signature_hash(input_index, value, pk_script, SigHash(signature[-1]))
        assert pubkey.verify_der_signature(signature[:-1], signature_hash, None)


class TestTx:

    def test_is_coinbase(self):
        tx = read_tx('afda808f.txn')
        assert tx.is_coinbase()
        assert not tx.is_extended()

    def test_are_inputs_final(self):
        tx = read_tx('b59de025.txn')
        assert not tx.is_extended()
        assert tx.are_inputs_final()
        tx.inputs[4].sequence += 1

    @pytest.mark.parametrize("nin, nout", ((1, 1), (1, 253), (253, 65536), (65536, 1)))
    def test_size(self, nin, nout):
        tx_in = TxInput(bytes(32), 0xffffffff, b'', 0xffffffff)
        tx_out = TxOutput(0, b'')
        tx = Tx(2, [tx_in] * nin, [tx_out] * nout, 0)
        assert tx.size() == len(tx.to_bytes())

    @pytest.mark.parametrize("locktime,inputs_final,height,timestamp,answer", (
        # Locktime 0 is always final
        (0, False, 0, 0, True),
        (0, False, 1, 1, True),
        (0, True, 0, 0, True),
        (0, True, 1, 1, True),
        # Locktime 1 is final only from block height 2
        (1, False, 0, 0, False),
        (1, False, 1, 0, False),
        (1, False, 2, 0, True),
        # If all inputs a final a tx is always final
        (1, True, 0, 0, True),
        (1, True, 1, 0, True),
        (1, True, 2, 0, True),
        # If < LOCKTIME_THRESHOLD, it's height-based
        (LOCKTIME_THRESHOLD - 1, False, LOCKTIME_THRESHOLD - 1, 0, False),
        (LOCKTIME_THRESHOLD - 1, False, LOCKTIME_THRESHOLD, 0, True),
        (LOCKTIME_THRESHOLD - 1, True, LOCKTIME_THRESHOLD - 1, 0, True),
        (LOCKTIME_THRESHOLD - 1, True, LOCKTIME_THRESHOLD, 0, True),
        # If >= LOCKTIME_THRESHOLD, it's time-based
        (LOCKTIME_THRESHOLD, False, LOCKTIME_THRESHOLD + 1, 0, False),
        (LOCKTIME_THRESHOLD, False, 0, LOCKTIME_THRESHOLD, False),
        (LOCKTIME_THRESHOLD, False, 0, LOCKTIME_THRESHOLD + 1, True),
        (LOCKTIME_THRESHOLD, True, LOCKTIME_THRESHOLD + 1, 0, True),
        (LOCKTIME_THRESHOLD, True, 0, LOCKTIME_THRESHOLD, True),
        (LOCKTIME_THRESHOLD, True, 0, LOCKTIME_THRESHOLD + 1, True),
    ))
    def test_is_final_for_block(self, locktime, inputs_final, height, timestamp, answer):
        tx = read_tx('b59de025.txn')
        tx.locktime = locktime
        if not inputs_final:
            tx.inputs[0].sequence = 0xfffffffe
        assert tx.is_final_for_block(height, timestamp) == answer

    def test_hash(self):
        tx = read_tx('b59de025.txn')
        assert tx.hex_hash() == 'b59de0255081f8032c521a1e70d9355876309a0c69e034db31c2ed387e9da809'

    def test_total_output(self):
        tx = read_tx('b59de025.txn')
        assert tx.total_output_value() == 59_999_999_818

    def test_total_input(self):
        coinbase = read_tx('afda808f.txn')
        assert coinbase.total_input_value() == coinbase.total_output_value()

        tx = read_tx('b59de025.txn')
        with pytest.raises(RuntimeError):
            tx.total_input_value()

    def test_fee(self):
        coinbase = read_tx('afda808f.txn')
        assert coinbase.fee() == 0

        tx = read_tx('b59de025.txn')
        with pytest.raises(RuntimeError):
            tx.fee()

    @staticmethod
    def read_extended_tx():
        tx = read_tx('9839fcf5d3406199dfbc88736768d7b9b8924a94f46247739829f0118ae31df6_ext.hex')
        assert tx.is_extended()
        assert tx.are_inputs_final()
        assert tx.fee() == 339
        return tx

    def test_to_hex_extended(self):
        tx = self.read_extended_tx()
        assert tx.to_hex_extended() == tx.to_bytes_extended().hex()

    def test_from_bytes_extended(self):
        tx = self.read_extended_tx()
        tx2 = Tx.from_bytes_extended(tx.to_bytes_extended())
        assert tx2.is_extended()
        assert tx2 == tx
        assert tx2.hash() == tx.hash()

    def test_verify_inputs(self):
        # Test the transaction signatures
        tx = self.read_extended_tx()
        tx.verify_inputs()

    def test_verify_inputs_fail(self):
        tx = self.read_extended_tx()
        tx.inputs[0].txo.value += 1
        with pytest.raises(InterpreterError):
            tx.verify_inputs()

    def test_verify_inputs_false(self):
        tx = self.read_extended_tx()
        tx.inputs[0].txo.script_pubkey = Script() << OP_FALSE
        tx.inputs[0].script_sig = Script()
        with pytest.raises(InterpreterError) as e:
            tx.verify_inputs()
        assert 'evaluates to false' in str(e.value)

    def test_verify_inputs_not_extended(self):
        # Test we require an extended tx to verify
        tx = read_tx('b59de025.txn')
        with pytest.raises(RuntimeError):
            tx.verify_inputs()

    def test_non_extended_streaming_of_extended(self):
        tx = self.read_extended_tx()
        tx2 = Tx.from_bytes(tx.to_bytes())
        assert not tx2.is_extended()
        assert tx2 != tx
        assert tx2.hex_hash() == tx.hex_hash()

    def test_extended_streaming_out(self):
        tx = self.read_extended_tx()
        tx2 = Tx.from_hex(tx.to_hex_extended())
        assert tx2.is_extended()
        assert tx2 == tx
        assert tx2.hex_hash() == tx.hex_hash()

    def test_extended_streaming_in(self):
        tx = self.read_extended_tx()
        tx2 = Tx.from_hex_extended(tx.to_hex_extended())
        assert tx2.is_extended()
        assert tx2 == tx
        assert tx2.hex_hash() == tx.hex_hash()

    def test_invalid_extended(self):
        tx = self.read_extended_tx()
        raw = bytearray(tx.to_bytes_extended())
        assert raw[4:10] == tx.EXTENDED_MARKER
        for n in range(4, 10):
            raw[n] = raw[n] + 1
            with pytest.raises(RuntimeError):
                Tx.from_bytes_extended(raw)
            raw[n] = raw[n] - 1
        assert raw[4:10] == tx.EXTENDED_MARKER

    @pytest.mark.parametrize("script,coin,json", (
        # Genesis tx
        (
            '01000000010000000000000000000000000000000000000000000000000000000000000000FFFFFFFF4'
            'D04FFFF001D0104455468652054696D65732030332F4A616E2F32303039204368616E63656C6C6F7220'
            '6F6E206272696E6B206F66207365636F6E64206261696C6F757420666F722062616E6B73FFFFFFFF010'
            '0F2052A01000000434104678AFDB0FE5548271967F1A67130B7105CD6A828E03909A67962E0EA1F61DE'
            'B649F6BC3F4CEF38C4F35504E51EC112DE5C384DF7BA0B8D578A4C702B6BF11D5FAC00000000',
            Bitcoin,
            {
                'version': 1,
                'nInputs': 1,
                'vin': [
                    {
                        'coinbase': '04ffff001d0104455468652054696d65732030332f4a616e2f323030392'
                        '04368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f'
                        '757420666f722062616e6b73',
                        'text': '\x04��\x00\x1d\x01\x04EThe Times 03/Jan/2009 Chancellor on '
                        'brink of second bailout for banks',
                        'sequence': 4294967295
                    }
                ],
                'nOutputs': 1,
                'vout': [
                    {
                        'value': 5000000000,
                        'script': {
                            'asm': '04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1'
                            'f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf'
                            '11d5f OP_CHECKSIG',
                            'hex': '4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0e'
                            'a1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6'
                            'bf11d5fac'
                        }
                    }
                ],
                'locktime': 0,
                'hash': '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'
            },
        ),
        (
            '0100000001e1337a3e268d53b9b292dab07a3fbf47a51aa155273362c5a9e7e3dfe64f006e000000006'
            'a47304402207f5ba050adff0567df3dcdc70d5059c4b8b8d2afc961d7545778a79cd125f0b8022013b3'
            'e5a87f3fa84333f222dc32c2c75e630efb205a3c58010aab92ab425453104121030b56f95f6d8d5f6b8'
            '4d4c7d6909423bd4b9cf189e9dd287fdea495582a3a5474feffffff01bd731f2c000000001976a914f6'
            '7000134f47d60523a36505830115fd52bc656e88ac2bc30800',
            Bitcoin,
            {
                'version': 1,
                'nInputs': 1,
                'vin': [
                    {
                        'hash': 'e1337a3e268d53b9b292dab07a3fbf47a51aa155273362c5a9e7e3dfe64f006e',
                        'idx': 0,
                        'script':
                        {
                            'asm': '304402207f5ba050adff0567df3dcdc70d5059c4b8b8d2afc961d7545778'
                            'a79cd125f0b8022013b3e5a87f3fa84333f222dc32c2c75e630efb205a3c58010aa'
                            'b92ab42545310[ALL|FORKID] 030b56f95f6d8d5f6b84d4c7d6909423bd4b9cf18'
                            '9e9dd287fdea495582a3a5474',
                            'hex': '47304402207f5ba050adff0567df3dcdc70d5059c4b8b8d2afc961d75457'
                            '78a79cd125f0b8022013b3e5a87f3fa84333f222dc32c2c75e630efb205a3c58010'
                            'aab92ab425453104121030b56f95f6d8d5f6b84d4c7d6909423bd4b9cf189e9dd28'
                            '7fdea495582a3a5474'
                        },
                        'sequence': 4294967294
                    }
                ],
                'nOutputs': 1,
                'vout': [
                    {
                        'value': 740258749,
                        'script':
                        {
                            'asm': 'OP_DUP OP_HASH160 f67000134f47d60523a36505830115fd52bc656e '
                            'OP_EQUALVERIFY OP_CHECKSIG',
                            'hex': '76a914f67000134f47d60523a36505830115fd52bc656e88ac'
                        }
                    }
                ],
                'locktime': 574251,
                'hash': '85d895859f19d8f0125f3a93af854a7b48c04cab8830f800cd5e4daaeb02dc00'
            },
        ),
        (
            '0100000001e1337a3e268d53b9b292dab07a3fbf47a51aa155273362c5a9e7e3dfe64f006e000000006'
            'a47304402207f5ba050adff0567df3dcdc70d5059c4b8b8d2afc961d7545778a79cd125f0b8022013b3'
            'e5a87f3fa84333f222dc32c2c75e630efb205a3c58010aab92ab425453104121030b56f95f6d8d5f6b8'
            '4d4c7d6909423bd4b9cf189e9dd287fdea495582a3a5474feffffff01bd731f2c000000001976a914f6'
            '7000134f47d60523a36505830115fd52bc656e88ac2bc30860',
            Bitcoin,
            {
                'version': 1,
                'nInputs': 1,
                'vin': [
                    {
                        'hash': 'e1337a3e268d53b9b292dab07a3fbf47a51aa155273362c5a9e7e3dfe64f006e',
                        'idx': 0,
                        'script':
                        {
                            'asm': '304402207f5ba050adff0567df3dcdc70d5059c4b8b8d2afc961d7545778'
                            'a79cd125f0b8022013b3e5a87f3fa84333f222dc32c2c75e630efb205a3c58010aa'
                            'b92ab42545310[ALL|FORKID] 030b56f95f6d8d5f6b84d4c7d6909423bd4b9cf18'
                            '9e9dd287fdea495582a3a5474',
                            'hex': '47304402207f5ba050adff0567df3dcdc70d5059c4b8b8d2afc961d75457'
                            '78a79cd125f0b8022013b3e5a87f3fa84333f222dc32c2c75e630efb205a3c58010'
                            'aab92ab425453104121030b56f95f6d8d5f6b84d4c7d6909423bd4b9cf189e9dd28'
                            '7fdea495582a3a5474'
                        },
                        'sequence': 4294967294
                    }
                ],
                'nOutputs': 1,
                'vout': [
                    {
                        'value': 740258749,
                        'script':
                        {
                            'asm': 'OP_DUP OP_HASH160 f67000134f47d60523a36505830115fd52bc656e '
                            'OP_EQUALVERIFY OP_CHECKSIG',
                            'hex': '76a914f67000134f47d60523a36505830115fd52bc656e88ac'
                        }
                    }
                ],
                'locktime': 1611186987,
                'hash': '9eaa6c0529a2d151eb4f0c7cfe99125c54b8908a0d3e8f66423f769bb553a816'
            },
        ),
    ), ids=['genesis', 'locktime block', 'locktime time'])
    def test_to_json(self, script, coin, json):
        flags = 0
        assert Tx.from_hex(script).to_json(flags, coin) == json
        json['size'] = len(script) // 2
        flags += JSONFlags.SIZE
        assert Tx.from_hex(script).to_json(flags, coin) == json
        if json['locktime'] == 0:
            json['locktimeMeaning'] = 'valid in any block'
        elif json['locktime'] < 500_000_000:
            json['locktimeMeaning'] = (f'valid in blocks with height greater than '
                                       f'{json["locktime"]:,d}')
        else:
            json['locktimeMeaning'] = (
                'valid in blocks with MTP greater than 2021-01-20 23:56:27 UTC'
            )
        flags += JSONFlags.LOCKTIME_MEANING
        assert Tx.from_hex(script).to_json(flags, coin) == json


class TestTxInput:

    def test_is_coinbase(self):
        txin = TxInput(bytes(32), 0xffffffff, b'', 0xffffffff)
        assert txin.is_coinbase()
        txin.prev_idx = 0
        assert not txin.is_coinbase()
        txin.prev_idx = 0xffffffff
        assert txin.is_coinbase()
        txin.prev_hash = bytes(31) + b'\1'
        assert not txin.is_coinbase()

    def test_is_final(self):
        txin = TxInput(bytes(32), 0xffffffff, b'', 0xffffffff)
        assert txin.is_final()
        txin.sequence -= 1
        assert not txin.is_final()

    def test_to_hex(self):
        tx = read_tx('afda808f.txn')
        assert tx.inputs[0].to_hex() == (
            '0000000000000000000000000000000000000000000000000000000000000000ffffffff220319'
            'c4082f626d67706f6f6c2e636f6d2f5473537148110d9e7fcc3cf74ee70c0200ffffffff'
        )

    @pytest.mark.parametrize("script_len", (0, 253, 65000, 120000))
    def test_size(self, script_len):
        txin = TxInput(bytes(32), 0xffffffff, b'', 0xffffffff)
        txin.script_sig = bytes(script_len)
        assert txin.size() == len(txin.to_bytes())

    @pytest.mark.parametrize("script,json", (
        # Genesis coinbase
        (
            '0000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff'
            '001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e'
            '206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff',
            {
                'coinbase': '04ffff001d0104455468652054696d65732030332f4a616e2f323030'
                '39204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261'
                '696c6f757420666f722062616e6b73',
                'text': '\x04��\x00\x1d\x01\x04EThe Times 03/Jan/2009 Chancellor on brink '
                'of second bailout for banks',
                'sequence': 4294967295,
            },
        ),
        # Another coinbase
        (
            '0000000000000000000000000000000000000000000000000000000000000000ffffffff41032b2'
            'c0a2f7461616c2e636f6d2f506c656173652070617920302e3520736174732f627974652c20696e'
            '666f407461616c2e636f6d6419c0bead6d55ff46be0400ffffffff',
            {
                'coinbase': '032b2c0a2f7461616c2e636f6d2f506c656173652070617920302e352073617'
                '4732f627974652c20696e666f407461616c2e636f6d6419c0bead6d55ff46be0400',
                'text': '\x03+,\n/taal.com/Please pay 0.5 sats/byte, info@taal.comd\x19���mU'
                '�F�\x04\x00',
                'sequence': 4294967295,
            }
        ),
        # A P2PK signature
        (
            'c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd37040000000048473044022'
            '04e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07'
            'de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff',
            {
                'hash': 'c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704',
                'idx': 0,
                'script': {
                    'asm': '304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8'
                    'cd410220181522ec8eca07de4860a4acdd12'
                    '909d831cc56cbbac4622082221a8768d1d09[ALL]',
                    'hex': '47304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5f'
                    'b8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901'
                },
                'sequence': 4294967295,
            },
        ),
    ), ids=['genesis', "coinbase", "p2pk"])
    def test_to_json(self, script, json):
        assert TxInput.from_hex(script).to_json(0, 0) == json
        assert TxInput.from_hex(script).to_json(JSONFlags.CLASSIFY_OUTPUT_SCRIPT, 0) == json
        assert TxInput.from_hex(script).to_json(JSONFlags.ENUMERATE_INPUTS, None) == json
        n = random.randrange(0, 100)
        json.update({'nInput': n})
        assert TxInput.from_hex(script).to_json(JSONFlags.ENUMERATE_INPUTS, n) == json

    def test_from_hex_extended(self):
        tx = TestTx.read_extended_tx()
        txin = tx.inputs[0]
        txin_hex = txin.to_hex_extended()
        assert TxInput.from_hex_extended(txin_hex) == txin


class TestTxOutput:

    def test_to_hex(self):
        tx = read_tx('afda808f.txn')
        assert tx.outputs[0].to_hex() == (
            'f992814a000000001976a914db1aea84aad494d9f5b253327da23c4e51266c9388ac'
        )

    @pytest.mark.parametrize("script_len", (0, 253, 65000, 120000))
    def test_size(self, script_len):
        output = TxOutput(0, b'')
        output.script_pubkey = bytes(script_len)
        assert output.size() == len(output.to_bytes())

    @pytest.mark.parametrize("script,json,coin,extra", (
        # Genesis P2PK output
        (
            '00f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1'
            'f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac',
            {
                'value': 5000000000,
                'script': {
                    'asm': '04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb64'
                    '9f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f OP_CHECKSIG',
                    'hex': '4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6'
                    '49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac'
                },
            },
            Bitcoin,
            {
                'type': 'pubkey',
                'pubkey': '04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6'
                '49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f',
                'address': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
            },
        ),
        # P2PKH output
        (
            '7dd8db00000000001976a9141207c3cd11e35de894c432e9907f2dcb1446855888ac',
            {
                'value': 14407805,
                'script': {
                    'asm': 'OP_DUP OP_HASH160 1207c3cd11e35de894c432e9907f2dcb14468558 '
                    'OP_EQUALVERIFY OP_CHECKSIG',
                    'hex': '76a9141207c3cd11e35de894c432e9907f2dcb1446855888ac',
                },
            },
            BitcoinTestnet,
            {
                'type': 'pubkeyhash',
                'address': 'mhAHm1zzjzuu61HhiQUyfjqqnewLQ3FM4s',
            },
        ),
    ), ids=['p2pk', 'p2pkh'])
    def test_to_json(self, script, coin, json, extra):
        assert TxOutput.from_hex(script).to_json(0, coin) == json
        assert TxOutput.from_hex(script).to_json(JSONFlags.ENUMERATE_OUTPUTS, coin) == json
        n = random.randrange(0, 100)
        json.update({'nOutput': n})
        assert TxOutput.from_hex(script).to_json(JSONFlags.ENUMERATE_OUTPUTS, coin, n) == json
        json['script'].update(extra)
        assert TxOutput.from_hex(script).to_json(JSONFlags.CLASSIFY_OUTPUT_SCRIPT |
                                                 JSONFlags.ENUMERATE_OUTPUTS, coin, n) == json
