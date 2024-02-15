from io import BytesIO

import pytest

from bitcoinx.errors import PackingError
from bitcoinx.packing import (
    pack_le_uint64, pack_varint, varint_len, read_varbytes, read_le_int32, read_list,
    pack_varbytes, pack_list, unpack_header, pack_le_int32, pack_le_int64, pack_le_uint16,
    pack_be_uint32, pack_le_uint32, pack_be_uint16, pack_byte, pack_port, pack_be_uint64,
    unpack_le_int32, unpack_le_int32_from, unpack_le_int64, unpack_le_int64_from,
    unpack_le_uint16, unpack_le_uint16_from, unpack_le_uint32, unpack_le_uint32_from,
    unpack_le_uint64, unpack_le_uint64_from, read_le_int32, read_le_int64, read_le_uint16,
    read_le_uint32, read_le_uint64
)


pack_cases = [
    (pack_le_int32, -258, b'\xfe\xfe\xff\xff'),
    (pack_le_int32, 258, b'\x02\x01\x00\x00'),
    (pack_le_int64, -2345684275723, b'\xf5mR\xda\xdd\xfd\xff\xff'),
    (pack_le_int64, 1234567890123456, b'\xc0\xba\x8a<\xd5b\x04\x00'),
    (pack_le_uint16, 987, b'\xdb\x03'),
    (pack_le_uint32, 4000000, b'\x00\t=\x00'),
    (pack_le_uint64, 3615905184676284416, b'\x00\x88\x1f\x8a\x9bF.2'),
    (pack_be_uint16, 12345, b'09'),
    (pack_be_uint32, 123456789, b'\x07[\xcd\x15'),
    (pack_be_uint64, 1234567890123456, bytes(reversed(pack_le_uint64(1234567890123456)))),
    (pack_byte, 144, b'\x90'),
    (pack_port, 8333, b' \x8d'),
    (pack_varint, 0, b'\x00'),
    (pack_varint, 252, b'\xfc'),
    (pack_varint, 253, b'\xfd\xfd\x00'),
    (pack_varint, 31000, b'\xfd\x18y'),
    (pack_varint, 65535, b'\xfd\xff\xff'),
    (pack_varint, 65536, b'\xfe\x00\x00\x01\x00'),
    (pack_varint, 1234567890, b'\xfe\xd2\x02\x96I'),
    (pack_varint, 4294967295, b'\xfe\xff\xff\xff\xff'),
    (pack_varint, 12345678901234567890, b'\xff\xd2\n\x1f\xeb\x8c\xa9T\xab'),
    (pack_varint, 1 << 64 - 1, b'\xff\x00\x00\x00\x00\x00\x00\x00\x80'),
]

unpack_map = {
    pack_le_int32: (unpack_le_int32, unpack_le_int32_from, read_le_int32),
    pack_le_int64: (unpack_le_int64, unpack_le_int64_from, read_le_int64),
    pack_le_uint16: (unpack_le_uint16, unpack_le_uint16_from, read_le_uint16),
    pack_le_uint32: (unpack_le_uint32, unpack_le_uint32_from, read_le_uint32),
    pack_le_uint64: (unpack_le_uint64, unpack_le_uint64_from, read_le_uint64),
}


@pytest.mark.parametrize("pack_func,case,result", pack_cases)
def test_pack_funcs(pack_func, case, result):
    assert pack_func(case) == result


@pytest.mark.parametrize("value", [case[1] for case in pack_cases if case[0] is pack_varint])
def test_varint_len(value):
    assert varint_len(value) == len(pack_varint(value))


@pytest.mark.parametrize("value", (-1, 1 << 64))
def test_varint_len_bad(value):
    with pytest.raises(ValueError):
        varint_len(value)


@pytest.mark.parametrize("pack_func", (
    pack_le_uint16, pack_le_uint32, pack_le_uint64, pack_byte, pack_port,
    pack_be_uint16, pack_be_uint32, pack_be_uint64, pack_varint,
))
def test_pack_negative(pack_func):
    with pytest.raises(PackingError):
        pack_func(-127)


@pytest.mark.parametrize("pack_func", set(case[0] for case in pack_cases))
def test_oversized(pack_func):
    big = 1 << 64
    with pytest.raises(PackingError):
        assert pack_func(big)
    with pytest.raises(PackingError):
        assert pack_func(-big)


@pytest.mark.parametrize("varbyte_len", (0, 252, 253, 254, 32757, 70000))
def test_pack_varbytes(varbyte_len):
    data = b'1' * varbyte_len
    assert pack_varbytes(data) == pack_varint(varbyte_len) + data


def unpack_cases():
    for func, case, result in pack_cases:
        unfunc = unpack_map.get(func)
        if unfunc:
            yield unfunc[0], result, case


@pytest.mark.parametrize("unpack_func,case,result", unpack_cases())
def test_unpack(unpack_func, case, result):
    value, = unpack_func(case)
    assert value == result


def unpack_from_cases():
    for func, case, result in pack_cases:
        unfunc = unpack_map.get(func)
        if unfunc:
            yield unfunc[1], result, case


@pytest.mark.parametrize("unpack_from_func,case,result", unpack_from_cases())
def test_unpack_from(unpack_from_func, case, result):
    value, = unpack_from_func(case, 0)
    assert value == result


def read_tests():
    for func, value, result in pack_cases:
        read_func = unpack_map.get(func)
        if read_func:
            yield read_func[2], result, value


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


@pytest.mark.parametrize("read_func,data,_value", read_tests())
def test_read_short(read_func, data, _value):
    io = BytesIO(data[:-1])
    with pytest.raises(PackingError):
        read_func(io.read)


@pytest.mark.parametrize("varbyte_len", (0, 252, 253, 254, 32757, 70000))
def test_read_varbytes_short(varbyte_len):
    value = b'7' * varbyte_len
    data = pack_varbytes(value)
    io = BytesIO(data[:-1])
    with pytest.raises(PackingError):
        read_varbytes(io.read)


@pytest.mark.parametrize("header,answer", (
    (b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
     b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
     b'\x00\x00\x00\x00;\xa3\xed\xfdz{\x12\xb2z\xc7,>gv\x8fa\x7f\xc8\x1b'
     b'\xc3\x88\x8aQ2:\x9f\xb8\xaaK\x1e^J)\xab_I\xff\xff\x00\x1d\x1d\xac+|',
     (1, b'\0' * 32, b';\xa3\xed\xfdz{\x12\xb2z\xc7,>gv\x8fa\x7f\xc8\x1b'
      b'\xc3\x88\x8aQ2:\x9f\xb8\xaaK\x1e^J',
      1231006505, 486604799, 2083236893)),
    # Fake header to test signedness of integer fields
    (b'\xff\xff\xff\xff\x8d\xa1\xebr\xec\x00\x8e\xad\xaczv\xd2\xfb>\x16\xba'
     b'|$\x0c\xb7\x7f\xb0\x8b\x17v\xa80\x02n\xb6\xa8\xcc\x0fq\xcb\xbc\x01\xce'
     b'\xe9\xb3h\x96l\x8d\xb43H\x7f%\xc4\xe3\x1d7i\xd7\x8d\x18\xc6`\xe8g\xf8'
     b'\xb5\xa1\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff',
     (-1, b'\x8d\xa1\xebr\xec\x00\x8e\xad\xaczv\xd2\xfb>\x16\xba|$\x0c\xb7'
      b'\x7f\xb0\x8b\x17v\xa80\x02n\xb6\xa8\xcc', b'\x0fq\xcb\xbc\x01\xce'
      b'\xe9\xb3h\x96l\x8d\xb43H\x7f%\xc4\xe3\x1d7i\xd7\x8d\x18\xc6`\xe8'
      b'g\xf8\xb5\xa1', 4294967295, 4294967295, 4294967295)),
))
def test_unpack_header(header, answer):
    assert unpack_header(header) == answer


def test_pack_and_read_list():
    items = [1, 34598236, -23462436]
    p = pack_list(items, pack_le_int32)
    assert p == pack_varint(len(items)) + b''.join(pack_le_int32(item) for item in items)

    bio = BytesIO(p)
    assert read_list(bio.read, read_le_int32) == items
