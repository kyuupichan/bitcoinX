from io import BytesIO

import pytest

from bitcoinx.packing import *
from struct import error as struct_error

pack_cases = [
    ('pack_le_int32', -258, b'\xfe\xfe\xff\xff'),
    ('pack_le_int32', 258, b'\x02\x01\x00\x00'),
    ('pack_le_int64', -2345684275723, b'\xf5mR\xda\xdd\xfd\xff\xff'),
    ('pack_le_int64', 1234567890123456, b'\xc0\xba\x8a<\xd5b\x04\x00'),
    ('pack_le_uint16', 987, b'\xdb\x03'),
    ('pack_le_uint32', 4000000, b'\x00\t=\x00'),
    ('pack_le_uint64', 3615905184676284416, b'\x00\x88\x1f\x8a\x9bF.2'),
    ('pack_be_uint16', 12345, b'09'),
    ('pack_be_uint32', 123456789, b'\x07[\xcd\x15'),
    ('pack_byte', 144, b'\x90'),
    ('pack_port', 8333, b' \x8d'),
    ('pack_varint', 0, b'\x00'),
    ('pack_varint', 252, b'\xfc'),
    ('pack_varint', 253, b'\xfd\xfd\x00'),
    ('pack_varint', 31000, b'\xfd\x18y'),
    ('pack_varint', 65535, b'\xfd\xff\xff'),
    ('pack_varint', 65536, b'\xfe\x00\x00\x01\x00'),
    ('pack_varint', 1234567890, b'\xfe\xd2\x02\x96I'),
    ('pack_varint', 4294967295, b'\xfe\xff\xff\xff\xff'),
    ('pack_varint', 12345678901234567890, b'\xff\xd2\n\x1f\xeb\x8c\xa9T\xab'),
    ('pack_varint', 1 << 64 - 1, b'\xff\x00\x00\x00\x00\x00\x00\x00\x80'),
]


@pytest.mark.parametrize("pack_func,case,result", pack_cases)
def test_pack_funcs(pack_func, case, result):
    pack_func = globals()[pack_func]
    assert pack_func(case) == result


@pytest.mark.parametrize("pack_func",
                         [func for func in set(case[0] for case in pack_cases)
                          if not '_int' in func])
def test_pack_negative(pack_func):
    pack_func = globals()[pack_func]
    with pytest.raises(struct_error):
        pack_func(-127)


@pytest.mark.parametrize("pack_func", set(case[0] for case in pack_cases))
def test_oversized(pack_func):
    big = 1 << 64
    func = globals()[pack_func]
    with pytest.raises(struct_error):
        assert func(big)
    with pytest.raises(struct_error):
        assert func(-big)


@pytest.mark.parametrize("varbyte_len", (0, 252, 253, 254, 32757, 70000))
def test_pack_varbytes(varbyte_len):
    data = b'1' * varbyte_len
    assert pack_varbytes(data) == pack_varint(varbyte_len) + data


def unpack_cases():
    for func, case, result in pack_cases:
        unfunc = globals().get(f'un{func}')
        if unfunc:
            yield unfunc, result, case


@pytest.mark.parametrize("unpack_func,case,result", unpack_cases())
def test_unpack(unpack_func, case, result):
    value, = unpack_func(case)
    assert value == result


def unpack_from_cases():
    for func, case, result in pack_cases:
        unfunc = globals().get(f'un{func}_from')
        if unfunc:
            yield unfunc, result, case


@pytest.mark.parametrize("unpack_from_func,case,result", unpack_from_cases())
def test_unpack_from(unpack_from_func, case, result):
    value, = unpack_from_func(case, 0)
    assert value == result


def read_tests():
    for func, value, result in pack_cases:
        read_func_name = func.replace('pack_', 'read_')
        read_func = globals().get(read_func_name)
        if read_func:
            yield read_func, result, value
        else:
            print('skipping ', read_func_name)


@pytest.mark.parametrize("read_func,data,value", read_tests())
def test_read(read_func, data, value):
    io = BytesIO(data)
    assert read_func(io.read) == value


@pytest.mark.parametrize("varbyte_len", (0, 252, 253, 254, 32757, 70000))
def test_read_varbytes(varbyte_len):
    value = b'7' * varbyte_len
    data = pack_varbytes(value)
    io = BytesIO(data)
    assert read_varbytes(io.read) == value


@pytest.mark.parametrize("read_func,data,value", read_tests())
def test_read_short(read_func, data, value):
    io = BytesIO(data[:-1])
    with pytest.raises(struct_error):
        read_func(io.read)


@pytest.mark.parametrize("varbyte_len", (0, 252, 253, 254, 32757, 70000))
def test_read_varbytes_short(varbyte_len):
    value = b'7' * varbyte_len
    data = pack_varbytes(value)
    io = BytesIO(data[:-1])
    with pytest.raises(struct_error):
        read_varbytes(io.read)
