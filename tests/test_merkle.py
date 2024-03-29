import json
from copy import deepcopy
from os import urandom

from random import randrange, sample, choice

import pytest

from bitcoinx import double_sha256, MerkleError, PackingError, hash_to_hex_str, hex_str_to_hash
from bitcoinx.merkle import BUMP, merkle_root, MerkleProof, merkle_path_length

from .utils import read_text_file


def generate_block(tx_count):
    return [urandom(32) for _ in range(tx_count)]


@pytest.mark.parametrize("tx_count, answer", (
    (1, 1),
    (2, 1),
    (3, 2),
    (4, 2),
    (5, 3),
    (25, 5),
    (32, 5),
    (33, 6),
    (1020, 10),
))
def test_merkle_path_length(tx_count, answer):
    assert merkle_path_length(tx_count) == answer


@pytest.mark.parametrize("tx_count", (0, -1))
def test_markle_path_length_bad(tx_count):
    with pytest.raises(ValueError):
        merkle_path_length(tx_count)


def test_merkle_root_empty():
    with pytest.raises(ValueError):
        merkle_root([])


def test_merkle_root_one():
    tx_hash = urandom(32)
    assert merkle_root([tx_hash]) == tx_hash
    assert merkle_root((tx_hash, )) == tx_hash


def test_merkle_root_two():
    hashes = [urandom(32), urandom(32)]
    assert merkle_root(hashes) == double_sha256(hashes[0] + hashes[1])


@pytest.mark.parametrize('tx_hashes, answer', (
    (('54247e57e4a1efdc9957c1546b77ff76d8c4007644f6ee2b4298659876712bfe',
      '7a840ee6cd354ed3c78eba768e8156ed7447f50969edadb0a2067699c776e5c6',
      'bd16637297daef8681158bf1117bfab39baaa4dd645349ff91553d06afc9a473'),
     '5160d7f550c185a0d533df7fbf0939a51adca07cc5befa5bb1e6e0f2ad2d7913'
     ),
    (('097f13a44278f01683518344cd84b109bf518b200c39c75f5925a17a067a2305',
      '06627c4a7ebed8ffc388352c32707a7d6a1d5ab774afa17849542cce5f402fad',
      '26e86e63729d2632006590615aefc43fd74a838b7641781979cb470e1fb470eb',
      '2f2d0469d02c962187be2202b06dc0c3c7ac5918be4b7f894d37cdd878cecbf3',
      '4e9c66a6c6ea6dab0219b39247fedc41834500558ccd8ae74ae1f34c81c70921',
      '6edcb74713e7279b5396a0ac17eb7a1d132791fdeff274e689d52155c4347018',
      'd562389baba0c9447f0a568e893d9934fc0dcda50cd52f0a9502dadeacd1b32c'),
     '5a0ac89d9427e27f31d8e9531e9e0aedc467ed9b2bd2a50d840ee20e48107e4d'
     ),
    (('0682e258c5ec43c4511482c9554d0bd473a660a53444eb2b78611870edbc90ae',
      '33402582ec79b44fe90c2e302c44ab3d550d5020ccb95cb0fcdbc4020b72cbbe',
      '8836e5dc968478d11fc7dd8d469a77fc4524eae7b9b0cf62f6b22c921731c43b',
      '913c36738a034568a33f641d3653d40706358124cf7e0d1c1c4893eac6bb4162'),
     '6a3aa0a0357eb7c169c688773f88f849d4dd1cca76792a84e5d90119a3527510',
     ),
))
def test_merkle_root(tx_hashes, answer):
    answer = hex_str_to_hash(answer)
    # Test a generator is accepted
    assert merkle_root(hex_str_to_hash(tx_hash) for tx_hash in tx_hashes) == answer
    # Test a tuple is accepted
    assert merkle_root(tuple(hex_str_to_hash(tx_hash) for tx_hash in tx_hashes)) == answer


def test_merkle_root_1():
    hashes = testcases[0]
    assert len(hashes) == 1
    assert merkle_root(hashes) == hashes[0]


def test_merkle_root_2():
    hashes = testcases[1]
    assert len(hashes) == 2
    assert merkle_root(hashes) == double_sha256(hashes[0] + hashes[1])


def test_merkle_root_3():
    hashes = testcases[2]
    assert len(hashes) == 3
    line = [double_sha256(hashes[0] + hashes[1]), double_sha256(hashes[2] + hashes[2])]
    assert merkle_root(hashes) == double_sha256(line[0] + line[1])


def test_merkle_root_4():
    hashes = testcases[3]
    assert len(hashes) == 4
    line = [double_sha256(hashes[0] + hashes[1]), double_sha256(hashes[2] + hashes[3])]
    assert merkle_root(hashes) == double_sha256(line[0] + line[1])


def test_merke_root_bad():
    with pytest.raises(ValueError):
        merkle_root([])


testcases = [generate_block(tx_count) for tx_count in range(1, 18)]


# Height 1_000, block of 13 transactions, proof of 7, path length 4
bump_a = (
    'fde803070249dad9c838e5614d66f8a13b02f78891fcea144e3d359b3bcf9e1a8c32c578bd033f38abe74cd74f8'
    'e3bdebcb76e8d1b51018dd28c88c61929c51157ec18c259eb04c3dab5fee61c4414478a32c176955a851357a18e'
    '6666ef9d490adddbaf5bcfa705776d78cc3649a83c0be6a9c4a260c07d3b481a50eb00b962398f631d21fa29270'
    '8d96aa35cff07dde174ff244eb8e598522e86fbba996a0da79362902c265f7bb10949b1064f0fd268cf87512e86'
    '5d24bbd25e56c92e0db189d07533dc6430b483810c633ccbcc35ce0c43dcb373635cab5c0c67e98b89be5571d51'
    'db489ba083e3ee003002420be80f197757398d4a1920cbc3c78ad94f5a66563d62f340115068c91d64f03cf3034'
    '247265fd996fd0ac62fc6dcce796e745e559b2df8a4766ea81d39fb68a05d89e21c9114b5c4a1b3576ccf5bbe3f'
    '5471daf041b52bbfcca5903ab8e84676f0000'
)


class TestMerkleProof:

    def random_merkle_proof(self):
        tx_hash = urandom(32)
        branch = [urandom(32) for _ in range(randrange(16))]
        offset = randrange(0, 1 << len(branch))
        return MerkleProof(tx_hash, offset, branch)

    def test_constructor_types(self):
        while True:
            m1 = self.random_merkle_proof()
            if len(m1.branch) > 5:
                break
        branch = m1.branch.copy()
        branch[2] = hash_to_hex_str(branch[2])
        m2 = MerkleProof(hash_to_hex_str(m1.tx_hash), m1.offset, branch)
        assert m1 == m1
        assert m1 == m2

    def test_constructor_bad_hashes(self):
        with pytest.raises(ValueError) as e:
            MerkleProof(bytes(31), 0, [])
        assert 'hash must be 32 bytes' == str(e.value)

        with pytest.raises(ValueError) as e:
            MerkleProof(bytes(32), 0, [bytes(5)])
        assert 'hash must be 32 bytes' == str(e.value)

    def test_constructor_bad_offset(self):
        branch = [bytes(32)] * 3
        with pytest.raises(ValueError) as e:
            MerkleProof(bytes(32), 8, branch)
        assert 'offset out of range' == str(e.value)

        with pytest.raises(ValueError) as e:
            MerkleProof(bytes(32), -1, branch)
        assert 'offset out of range' == str(e.value)

        MerkleProof(bytes(32), 7, branch)

    def test_constructor_bad_branch(self):
        with pytest.raises(ValueError) as e:
            MerkleProof(bytes(32), (1 << 32) - 1, [bytes(32)] * 33)
        assert 'branch too long' == str(e.value)

        MerkleProof(bytes(32), (1 << 32) - 1, [bytes(32)] * 32)

    @pytest.mark.parametrize('_exec_count', range(10))
    def test_to_from_json(self, _exec_count):
        m1 = self.random_merkle_proof()
        m2 = MerkleProof.from_json(m1.to_json())
        assert m1 == m2

    @pytest.mark.parametrize('_exec_count', range(10))
    def test_to_from_bytes(self, _exec_count):
        m1 = self.random_merkle_proof()
        m2 = MerkleProof.from_bytes(m1.to_bytes())
        assert m1 == m2

    def test_from_bytes_excess(self):
        m = self.random_merkle_proof()
        with pytest.raises(ValueError) as e:
            MerkleProof.from_bytes(m.to_bytes() + b'1')
        assert str(e.value) == 'excess bytes reading merkle proof'

    def test_root(self):
        row0 = [b'0' * 32, b'1' * 32, b'2' * 32, b'3' * 32]
        row1 = [double_sha256(row0[a] + row0[a + 1]) for a in (0, 2)]
        root = double_sha256(row1[0] + row1[1])
        for offset, tx_hash in enumerate(row0):
            m = MerkleProof(tx_hash, offset, [row0[offset ^ 1], row1[(offset // 2) ^ 1]])
            assert m.root() == root


class TestBUMP:

    @pytest.mark.parametrize("tx_hashes", [testcases[0]])
    def test_create(self, tx_hashes):
        count = randrange(len(tx_hashes) + 1)
        hashes_to_prove = sample(tx_hashes, count)
        proof = BUMP.create(tx_hashes, hashes_to_prove)

        assert isinstance(proof, BUMP)
        assert proof.root == merkle_root(tx_hashes)

        # Assert we don't have too many proofs
        proven_hashes = proof.tx_hashes()
        assert len(hashes_to_prove) <= len(proven_hashes) <= len(hashes_to_prove) * 2 + 1

        # Assert we have a proof for all hashes we were required to prove
        assert all(hash_to_prove in proven_hashes for hash_to_prove in hashes_to_prove)

    def test_create_fail(self):
        with pytest.raises(MerkleError) as e:
            BUMP.create([], [])
        assert 'tx_hashes cannot be empty' == str(e.value)

    def test_empty_path(self):
        with pytest.raises(MerkleError) as e:
            BUMP([])
        assert 'path cannot be empty' == str(e.value)

    @pytest.mark.parametrize("tx_hashes", testcases[1:])
    def test_duplicate_tx_hashes_rejected(self, tx_hashes):
        tx_hashes = tx_hashes.copy()
        first, second = sample(range(len(tx_hashes)), 2)
        tx_hashes[first] = tx_hashes[second]
        with pytest.raises(MerkleError) as e:
            BUMP.create(tx_hashes, tx_hashes)
        assert 'duplicate' in str(e.value)

    def test_create_missing_hash(self):
        tx_hashes = testcases[10]
        with pytest.raises(MerkleError) as e:
            BUMP.create(tx_hashes, [bytes(32)])
        assert 'present' in str(e.value)

    @pytest.mark.parametrize("tx_hashes", testcases)
    def test_create_all_txs(self, tx_hashes):
        proof = BUMP.create(tx_hashes, tx_hashes)
        assert proof.path[0] == {offset: tx_hash for offset, tx_hash in enumerate(tx_hashes)}
        assert all(not level for level in proof.path[1:])

    def test_level_map_fail(self):
        tx_hashes = testcases[6]
        proof = BUMP.create(tx_hashes, tx_hashes[:-1])
        value = proof.to_json(100)
        value['path'][0].append({'offset': 0, 'hash': bytes(32).hex()})
        with pytest.raises(MerkleError) as e:
            BUMP.from_json(value)
        assert 'conflicting leaves in path' in str(e.value)

    def test_eq(self):
        tx_hashes = testcases[6]
        proof = BUMP.create(tx_hashes, tx_hashes)
        proof2 = BUMP.create(tx_hashes, tx_hashes)
        tx_hashes = testcases[13]
        proof3 = BUMP.create(tx_hashes, tx_hashes)
        assert proof == proof2
        assert proof != proof3
        with pytest.raises(TypeError):
            assert proof == 3

        proof2.root = bytes(32)
        assert proof2 != proof
        proof2.root = proof.root
        assert proof2 == proof
        proof2.tx_count = proof2.tx_count + 1
        assert proof2 != proof
        proof2.tx_count = proof.tx_count
        assert proof == proof
        proof2.path.append({})
        assert proof2 != proof

    def test_tx_hashes(self):
        tx_hashes = testcases[10]
        # A single hash, and its sibling
        proof = BUMP.create(tx_hashes, [tx_hashes[1]])
        assert proof.tx_hashes() == {tx_hashes[0]: 0, tx_hashes[1]: 1, tx_hashes[10]: 10}
        proof = BUMP.create(tx_hashes, tx_hashes[:2])
        assert proof.tx_hashes() == {tx_hashes[0]: 0, tx_hashes[1]: 1, tx_hashes[10]: 10}
        # Test trailing singleton
        proof = BUMP.create(tx_hashes, [tx_hashes[-1]])
        assert proof.tx_hashes() == {tx_hashes[-1]: len(tx_hashes) - 1}

    @pytest.mark.parametrize("tx_hashes", testcases)
    def test_merge(self, tx_hashes):
        count = randrange(1, len(tx_hashes) + 1)
        hashes_to_prove = sample(tx_hashes, count)
        bump1 = BUMP.create(tx_hashes, hashes_to_prove)

        count = randrange(1, len(tx_hashes) + 1)
        hashes_to_prove = sample(tx_hashes, count)
        bump2 = BUMP.create(tx_hashes, hashes_to_prove)

        bump = bump1.merge(bump2)

        assert bump.root == bump1.root

        merged_hashes = bump1.tx_hashes()
        merged_hashes.update(bump2.tx_hashes())
        assert bump.tx_hashes() == merged_hashes

    def test_merge_all(self):
        tx_hashes = testcases[15]
        bumps = [BUMP.create(tx_hashes, [tx_hash]) for tx_hash in tx_hashes]
        bump = bumps[0]
        for other in bumps[1:]:
            bump = bump.merge(other)
        assert bump.root == merkle_root(tx_hashes)
        assert bump.tx_hashes() == {tx_hash: offset for offset, tx_hash in enumerate(tx_hashes)}
        assert all(not level for level in bump.path[1:])

    def test_merge_bad_type(self):
        height, bump = BUMP.from_bytes(bytes.fromhex(bump_a))
        with pytest.raises(TypeError):
            bump.merge(height)

    def test_merge_diff_blocks(self):
        bump1 = BUMP.create(testcases[5], [])
        bump2 = BUMP.create(testcases[6], [])
        with pytest.raises(MerkleError) as e:
            bump1.merge(bump2)
        assert 'different block' in str(e.value)

    @pytest.mark.parametrize("tx_hashes", testcases)
    def test_to_from_bytes(self, tx_hashes):
        # This also tests BUMP.read()
        count = randrange(1, len(tx_hashes) + 1)
        hashes_to_prove = sample(tx_hashes, count)
        bump = BUMP.create(tx_hashes, hashes_to_prove)

        height = 5 + (len(tx_hashes) - 1) * 50_000
        raw = bump.to_bytes(height)
        height2, bump2 = BUMP.from_bytes(raw)

        assert height == height2
        assert bump == bump2

    def test_read_short(self):
        tx_hashes = testcases[12]
        hashes_to_prove = tx_hashes[-1:]
        bump = BUMP.create(tx_hashes, hashes_to_prove)
        assert bump.path[-1]

        height = 5 + (len(tx_hashes) - 1) * 50_000
        raw = bump.to_bytes(height)
        with pytest.raises(PackingError) as e:
            BUMP.from_bytes(raw[:-1])
        assert 'hashes have length 32 bytes' == str(e.value)

    def test_to_bytes_height(self):
        tx_hashes = testcases[12]
        bump = BUMP.create(tx_hashes, sample(tx_hashes, 5))
        # This is OK
        bump.to_bytes(0)

        with pytest.raises(PackingError):
            bump.to_bytes(-1)

    def test_from_bytes_truncated(self):
        tx_hashes = testcases[6]
        bump = BUMP.create(tx_hashes, sample(tx_hashes, 2))
        raw = bump.to_bytes(1_000)

        for length in range(1, len(raw)):
            with pytest.raises(PackingError):
                BUMP.from_bytes(raw[:length])

    @pytest.mark.parametrize("depth", range(4))
    def test_negative_offset_rejected(self, depth):
        height, bump = BUMP.from_bytes(bytes.fromhex(bump_a))
        assert height == 1_000
        bump.path[depth][-1] = bytes(32)
        with pytest.raises(MerkleError) as e:
            BUMP(bump.path)
        assert 'extraneous leaves' in str(e.value)

    @pytest.mark.parametrize("depth", range(1, 4))
    def test_high_offset_rejected(self, depth):
        _, bump = BUMP.from_bytes(bytes.fromhex(bump_a))
        length = bump.tx_count
        for _ in range(depth):
            length = (length + 1) // 2
        bump.path[depth][length] = bytes(32)
        with pytest.raises(MerkleError) as e:
            BUMP(bump.path)
        assert 'extraneous leaves' in str(e.value)

    def fill_out_path(self, bump):
        from bitcoinx.merkle import uplift_level, iterate_path

        path = deepcopy(bump.path)

        # Fill in all redundant hashes
        uplift = {}
        for level, length in iterate_path(path, bump.tx_count):
            level.update(uplift)
            uplift = uplift_level(level, length)

        return path

    def test_redundant_hashes_ok(self):
        _, bump = BUMP.from_bytes(bytes.fromhex(bump_a))
        full_path = self.fill_out_path(bump)
        bump2 = BUMP(full_path)
        # Check duplicates removed
        assert bump2.path == bump.path

    @pytest.mark.parametrize("depth", range(1, 4))
    def test_conflicting_hashes_rejected(self, depth):
        _, bump = BUMP.from_bytes(bytes.fromhex(bump_a))
        full_path = self.fill_out_path(bump)
        redundant_offsets = set(full_path[depth].keys()).difference(bump.path[depth].keys())
        # Insert a bad hash at this offset
        offset = redundant_offsets.pop()
        bump.path[depth][offset] = bytes(32)
        with pytest.raises(MerkleError) as e:
            BUMP(bump.path)
        assert 'conflicting leaves' in str(e.value)

    @pytest.mark.parametrize("depth", range(4))
    def test_missing_leaves_rejected(self, depth):
        tx_hashes = testcases[16]
        hashes_to_prove = sample(tx_hashes, 5)
        bump = BUMP.create(tx_hashes, hashes_to_prove)
        path = bump.path
        offsets = sorted(path[depth].keys())
        if depth == 0:
            # Don't get rid of the tx that sets the count
            offsets.pop()
        if not offsets:
            return
        offset = choice(offsets)
        del path[depth][offset]
        with pytest.raises(MerkleError) as e:
            BUMP(path)
        assert 'missing leaves' in str(e.value)

    @pytest.mark.parametrize("depth", range(1, 4))
    def test_reject_phantoms(self, depth):
        from bitcoinx.merkle import next_level
        # Generate a block of sufficient txs that a phantom branch can be added to clash
        # at the given depth
        n = 1 << depth
        tx_count = 16 + n
        tx_hashes = generate_block(tx_count)
        rhs = tx_hashes[16:]
        hashes_to_prove = sample(tx_hashes, 5)
        bump = BUMP.create(tx_hashes, hashes_to_prove)

        # Now create a phantom branch by shifting all offsets of the last 4 up by n
        path = []
        half_way = 16
        length = tx_count
        for level in bump.path:
            level = {(offset + n if offset >= half_way else offset): hash_
                     for offset, hash_ in level.items()}
            if n == 1:
                level[length - 1] = rhs[0]
            path.append(level)
            half_way //= 2
            n //= 2
            length = (length + 1) // 2
            rhs = list(next_level(rhs))

        with pytest.raises(MerkleError) as e:
            BUMP(path)
        assert 'phantom' in str(e.value)

    def test_extraneous_leaves_rejected(self):
        tx_hashes = generate_block(32)
        bump = BUMP.create(tx_hashes, [tx_hashes[0]])
        bump.path[2][2] = bytes(32)
        with pytest.raises(MerkleError) as e:
            BUMP(bump.path)
        assert 'extraneous' in str(e.value)

    def test_short_path_rejected(self):
        _, bump = BUMP.from_bytes(bytes.fromhex(bump_a))
        path = bump.path
        path.pop()
        with pytest.raises(MerkleError) as e:
            BUMP(path)
        assert 'path length' in str(e.value)

        # Test also caught when converting from raw bytes
        raw = bump.to_bytes(1_000)
        with pytest.raises(PackingError) as e:
            BUMP.from_bytes(raw)
        assert 'truncated stream' in str(e.value)

    def test_long_path_rejected(self):
        _, bump = BUMP.from_bytes(bytes.fromhex(bump_a))
        path = bump.path
        path.append({})
        with pytest.raises(MerkleError) as e:
            BUMP(path)
        assert 'path length' in str(e.value)

        # Test also caught when converting from raw bytes
        raw = bump.to_bytes(1_000)
        with pytest.raises(PackingError) as e:
            BUMP.from_bytes(raw)
        assert 'excess bytes' in str(e.value)

    def test_to_json(self):
        answer = read_text_file('bump.json')
        height, bump = BUMP.from_bytes(bytes.fromhex(bump_a))
        data = bump.to_json(height)
        assert json.dumps(data) == answer

    def test_to_json_is_sorted(self):
        tx_hashes = testcases[1]
        bump = BUMP.create(tx_hashes, tx_hashes)
        level = bump.path[0]
        if sorted(level.keys()) == list(level.keys()):
            level = {offset: level[offset] for offset in reversed(level.keys())}
            bump.path[0] = level
        data = bump.to_json(1)
        assert data['path'][0][0]['offset'] == 0

    def test_from_json(self):
        orig_height, orig_bump = BUMP.from_bytes(bytes.fromhex(bump_a))
        text = read_text_file('bump.json')
        height, bump = BUMP.from_json(json.loads(text))
        assert height == orig_height
        assert bump == orig_bump

    @pytest.mark.parametrize("tx_hashes", testcases)
    def test_merkle_proof(self, tx_hashes):
        count = randrange(1, len(tx_hashes) + 1)
        hashes_to_prove = sample(tx_hashes, count)
        bump = BUMP.create(tx_hashes, hashes_to_prove)

        for tx_hash in hashes_to_prove:
            proof = bump.merkle_proof(tx_hash)
            assert proof.root() == bump.root

    def test_merkle_proof_fail(self):
        tx_hashes = testcases[10]
        bump = BUMP.create(tx_hashes, tx_hashes[:4])

        with pytest.raises(MerkleError) as e:
            bump.merkle_proof(bytes(32))
        assert str(e.value) == 'tx_hash is not in the bump'
