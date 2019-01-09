from os import urandom, path
import random

import pytest

from bitcoinx import Bitcoin, pack_le_uint32
from bitcoinx.chain import *


good_bits = [486604799, 472518933, 453281356, 436956491]
empty_header = bytes(80)


class TestChain(object):

    def test(self):
        base = Chain(None, -1, 0)
        assert base.height == -1

        N = 10
        headers = []
        for n in range(N * 2):
            raw_header = bytearray(urandom(80))
            raw_header[72:76] = pack_le_uint32(random.choice(good_bits))
            headers.append(Bitcoin.deserialized_header(raw_header, -1))
        indices = list(range(N * 2))
        random.shuffle(indices)

        for n, (header, index) in enumerate(zip(headers, indices)):
            if n < N:
                base._add_header(header, index)

        # Test public attributes
        assert base.height == N - 1
        assert base.work == sum(header.work() for header in headers[:N])
        assert base.tip == headers[N - 1]

        for n in range(base.height + 1):
            assert base._header_idx(n) == indices[n]

        for n in -1, N:
            with pytest.raises(MissingHeader):
                base._header_idx(n)

        # Build a fork chain
        common_height = 5
        work = sum(header.work() for header in headers[:common_height + 1])
        fork = Chain(base, common_height, work)
        for n, (header, index) in enumerate(zip(headers, indices)):
            if n >= N:
                fork._add_header(header, index)

        # Test public attributes
        assert fork.height == common_height + N
        assert fork.work == work + sum(header.work() for header in headers[N:])
        assert fork.tip == headers[-1]

        for n in range(fork.height + 1):
            if n <= common_height:
                assert fork._header_idx(n) == indices[n]
            else:
                assert fork._header_idx(n) == indices[N + (n - 1 - common_height)]

        for n in -1, 2 * N:
            with pytest.raises(MissingHeader):
                base._header_idx(n)

    def test_from_checkpoint(self):
        raw_header = bytes.fromhex(
            '000000203b0bc2a72e7313ac216e3c63314b8aec4be35374d66d2e0200000000000000009d14e99d'
            '7799f2d8b62b3c745aa94514da4c831193bd057a916e1f45183600b5d001f95b11fd02180d32952e'
        )
        checkpoint = CheckPoint(raw_header, height=557957, prev_work=0xd54c44dbdc491c25d097bf)
        header = Bitcoin.deserialized_header(checkpoint.raw_header, checkpoint.height)
        chain = Chain.from_checkpoint(checkpoint, Bitcoin)
        assert chain.height == checkpoint.height
        assert chain.tip == header
        assert chain.work == checkpoint.prev_work + header.work() == 0xd54c9a84f54e93d3d87015
        assert chain._parent == None
        assert chain._header_idxs[-1] == checkpoint.height


class TestHeaderStorage(object):

    def create_new(self, tmpdir):
        return HeaderStorage.create_new(path.join(tmpdir, 'hs'))

    def test_nonexistent_file(self, tmpdir):
        with pytest.raises(FileNotFoundError):
            HeaderStorage(path.join(tmpdir, 'no_such_file'))

    def test_create_new(self, tmpdir):
        hs = self.create_new(tmpdir)
        assert len(hs) == 0
        with pytest.raises(MissingHeader):
            hs[0]

    def test_open_or_create(self, tmpdir):
        file_name = path.join(tmpdir, 'hs')
        hs = HeaderStorage.open_or_create(file_name)
        assert len(hs) == 0
        raw_header = urandom(80)
        hs[1] = raw_header
        assert len(hs) == 2
        hs.close()
        hs = HeaderStorage.open_or_create(file_name)
        assert len(hs) == 2
        assert hs[1] == raw_header
        with pytest.raises(MissingHeader):
            hs[0]

    def test_bad_indices(self, tmpdir):
        hs = self.create_new(tmpdir)
        with pytest.raises(TypeError):
            hs['a']
        with pytest.raises(TypeError):
            hs[1:2]
        with pytest.raises(TypeError):
            hs['a'] = empty_header
        with pytest.raises(TypeError):
            hs[1:2] = empty_header

    def test_bad_header(self, tmpdir):
        hs = self.create_new(tmpdir)
        with pytest.raises(ValueError):
            hs[1] = bytes(85)
        with pytest.raises(TypeError):
            hs[1] = 'f' * 80

    def test_append(self, tmpdir):
        hs = self.create_new(tmpdir)
        raw_header = urandom(80)
        hs.append(raw_header)
        assert len(hs) == 1
        assert hs[0] == raw_header
        assert hs.raw_header(0) == raw_header
        with pytest.raises(MissingHeader):
            hs[1]

    def test_create_hole(self, tmpdir):
        N = random.randrange(20, 40)
        hs = self.create_new(tmpdir)
        raw_header = urandom(80)
        hs[N] = raw_header
        assert len(hs) == N + 1
        assert hs[N] == raw_header
        for idx in range(N):
            with pytest.raises(MissingHeader):
                hs[idx]
        with pytest.raises(MissingHeader):
            hs[N + 1]
        M = random.randrange(0, N)
        hs[M] = raw_header2 = urandom(80)
        for idx in range(N):
            if idx == M:
                assert hs[idx] == raw_header2
            else:
                with pytest.raises(MissingHeader):
                    hs[idx]

    def test_flush(self, tmpdir):
        # flush is likely needed on some OSes and not others.  It doesn't appear to be
        # needed on a Mac.
        hs = self.create_new(tmpdir)
        raw_header = urandom(80)
        hs[1] = raw_header
        hs.flush()
        with open(hs.file_name, 'rb') as f:
            assert f.read(4) == bytes([2, 0, 0, 0])


    def test_close(self, tmpdir):
        hs = self.create_new(tmpdir)
        raw_header = urandom(80)
        hs[1] = raw_header
        hs.close()
        with pytest.raises(ValueError):
            hs[1]
        with open(hs.file_name, 'rb') as f:
            assert f.read(4) == bytes([2, 0, 0, 0])
