import asyncio
import copy
import time
from io import BytesIO
from ipaddress import IPv4Address, IPv6Address
from os import urandom

import pytest

from bitcoinx import (
    Bitcoin, pack_varint, _version_str, double_sha256, pack_le_int32, pack_list,
)
from bitcoinx.errors import ProtocolError
from bitcoinx.net import *
from bitcoinx.net import ServicePacking


@pytest.mark.parametrize("hostname,answer", (
    ('', False),
    ('a', True),
    ('_', True),
    # Hyphens
    ('-b', False),
    ('a.-b', False),
    ('a-b', True),
    ('b-', False),
    ('b-.c', False),
    # Dots
    ('a.', True),
    ('a..', False),
    ('foo1.Foo', True),
    ('foo1..Foo', False),
    ('12Foo.Bar.Bax_', True),
    ('12Foo.Bar.Baz_12', True),
    # Numeric TLD
    ('foo1.123', False),
    ('foo1.d123', True),
    ('foo1.123d', True),
    # IP Addresses
    ('1.2.3.4', False),
    ('12::23', False),
    # 63 octets in part
    ('a.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.bar', True),
    # Over 63 octets in part
    ('a.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_1.bar', False),
    # Length
    (('a' * 62 + '.') * 4 + 'a', True),    # 253
    (('a' * 62 + '.') * 4 + 'ab', False),   # 254
))
def test_is_valid_hostname(hostname,answer):
    assert is_valid_hostname(hostname) == answer


@pytest.mark.parametrize("hostname", (2, b'1.2.3.4'))
def test_is_valid_hostname_bad(hostname):
    with pytest.raises(TypeError):
        is_valid_hostname(hostname)


@pytest.mark.parametrize("host,answer", (
    ('1.2.3.4', IPv4Address('1.2.3.4')),
    ('12:32::', IPv6Address('12:32::')),
    (IPv4Address('8.8.8.8'), IPv4Address('8.8.8.8')),
    (IPv6Address('::1'), IPv6Address('::1')),
    ('foo.bar.baz.', 'foo.bar.baz.'),
))
def test_classify_host(host, answer):
    assert classify_host(host) == answer


@pytest.mark.parametrize("host", (2, b'1.2.3.4'))
def test_classify_host_bad_type(host):
    with pytest.raises(TypeError):
        classify_host(host)


@pytest.mark.parametrize("host", ('', 'a..', 'b-', 'a' * 64))
def test_classify_host_bad(host):
    with pytest.raises(ValueError):
        classify_host(host)

@pytest.mark.parametrize("port,answer", (
    ('2', 2),
    (65535, 65535),
    (0, ValueError),
    (-1, ValueError),
    (65536, ValueError),
    (b'', TypeError),
    (2.0, TypeError),
    ('2a', ValueError),
))
def test_validate_port(port, answer):
    if isinstance(answer, type) and issubclass(answer, Exception):
        with pytest.raises(answer):
            validate_port(port)
    else:
        assert validate_port(port) == answer


@pytest.mark.parametrize("protocol,answer", (
    ('TCP', 'tcp'),
    ('http', 'http'),
    ('Ftp.-xbar+', 'ftp.-xbar+'),
    (b'', TypeError),
    (2, TypeError),
    ('', ValueError),
    ('a@b', ValueError),
    ('a:b', ValueError),
    ('[23]', ValueError),
))
def test_validate_protocol(protocol, answer):
    if isinstance(answer, type) and issubclass(answer, Exception):
        with pytest.raises(answer):
            validate_protocol(protocol)
    else:
        assert validate_protocol(protocol) == answer


class TestNetAddress:

    @pytest.mark.parametrize("host,port,answer,host_type",(
        ('foo.bar', '23', 'foo.bar:23', str),
        ('foo.bar', 23, 'foo.bar:23', str),
        ('foo.bar', 23.0, TypeError, None),
        ('::1', 15, '[::1]:15', IPv6Address),
        ('5.6.7.8', '23', '5.6.7.8:23', IPv4Address),
        ('5.6.7.8.9', '23', ValueError, None),
        ('[::1]', '23', ValueError, None),
        ('[::1]', 0, ValueError, None),
        ('[::1]', 65536, ValueError, None),
    ))
    def test_constructor(self, host,port,answer,host_type):
        if isinstance(answer, type) and issubclass(answer, Exception):
            with pytest.raises(answer):
                NetAddress(host, port)
        else:
            address = NetAddress(host, port)
            assert str(address) == answer
            assert isinstance(address.host, host_type)

    def test_eq(self):
        assert NetAddress('1.2.3.4', 23) == NetAddress('1.2.3.4', 23)
        assert NetAddress('1.2.3.4', 23) == NetAddress('1.2.3.4', '23')
        assert NetAddress('1.2.3.4', 23) != NetAddress('1.2.3.4', 24)
        assert NetAddress('1.2.3.4', 24) != NetAddress('1.2.3.5', 24)
        assert NetAddress('foo.bar', 24) != NetAddress('foo.baz', 24)

    def test_hashable(self):
        assert len({NetAddress('1.2.3.4', 23), NetAddress('1.2.3.4', '23')}) == 1

    @pytest.mark.parametrize("host,port,answer",(
        ('foo.bar', '23', "NetAddress('foo.bar:23')"),
        ('foo.bar', 23, "NetAddress('foo.bar:23')"),
        ('::1', 15, "NetAddress('[::1]:15')"),
        ('5.6.7.8', '23', "NetAddress('5.6.7.8:23')"),
    ))
    def test_repr(self, host, port, answer):
        assert repr(NetAddress(host, port)) == answer

    @pytest.mark.parametrize("string,default_func,answer",(
        ('foo.bar:23', None, NetAddress('foo.bar', 23)),
        (':23', NetAddress.default_host('localhost'), NetAddress('localhost', 23)),
        (':23', None, ValueError),
        (':23', NetAddress.default_port(23), ValueError),
        ('foo.bar', NetAddress.default_port(500), NetAddress('foo.bar', 500)),
        ('foo.bar:', NetAddress.default_port(500), NetAddress('foo.bar', 500)),
        ('foo.bar', NetAddress.default_port(500), NetAddress('foo.bar', 500)),
        (':', NetAddress.default_host_and_port('localhost', 80), NetAddress('localhost', 80)),
        ('::1:', None, ValueError),
        ('::1', None, ValueError),
        ('[::1:22', None, ValueError),
        ('[::1]:22', NetAddress.default_port(500), NetAddress('::1', 22)),
        ('[::1]:', NetAddress.default_port(500), NetAddress('::1', 500)),
        ('[::1]', NetAddress.default_port(500), NetAddress('::1', 500)),
        ('1.2.3.4:22', None, NetAddress('1.2.3.4', 22)),
        ('1.2.3.4:', NetAddress.default_port(500), NetAddress('1.2.3.4', 500)),
        ('1.2.3.4', NetAddress.default_port(500), NetAddress('1.2.3.4', 500)),
        ('localhost', NetAddress.default_port(500), NetAddress('localhost', 500)),
        ('1.2.3.4', NetAddress.default_host('localhost'), ValueError),
        (2, None, TypeError),
        (b'', None, TypeError),
    ))
    def test_from_string(self, string, default_func, answer):
        if isinstance(answer, type) and issubclass(answer, Exception):
            with pytest.raises(answer):
                NetAddress.from_string(string,default_func=default_func)
        else:
            assert NetAddress.from_string(string,default_func=default_func) == answer

    @pytest.mark.parametrize("item,answer",(
        ('1.2.3.4:23', NetAddress('1.2.3.4', 23)),
        ('[::1]:22', NetAddress('::1', 22)),
        (NetAddress('1.2.3.4', 23), NetAddress('1.2.3.4', 23)),
        (NetAddress.from_string('[::1]:22'), NetAddress('::1', 22)),
        ('foo.bar:23', ValueError),
        (NetAddress('foo.bar', 23), ValueError),
        (2, TypeError),
    ))
    def test_ensure_resolved(self, item, answer):
        if isinstance(answer, type) and issubclass(answer, Exception):
            with pytest.raises(answer):
                NetAddress.ensure_resolved(item)
        else:
            assert NetAddress.ensure_resolved(item) == answer

    @pytest.mark.parametrize("address,answer",(
        (NetAddress('foo.bar', 23), 'foo.bar:23'),
        (NetAddress('abcd::dbca', 40), '[abcd::dbca]:40'),
        (NetAddress('1.2.3.5', 50000), '1.2.3.5:50000'),
    ))
    def test_str(self, address, answer):
        assert str(address) == answer

    @pytest.mark.parametrize("attr", ('host', 'port'))
    def test_immutable(self, attr):
        address = NetAddress('foo.bar', 23)
        with pytest.raises(AttributeError):
            setattr(address, attr, 'foo')
        setattr(address, 'foo', '')

    @pytest.mark.parametrize("address,answer",(
        (NetAddress('abcd::dbca', 50), bytes.fromhex('abcd000000000000000000000000dbca')),
        (NetAddress('1.2.3.5', 50), bytes.fromhex('00000000000000000000ffff01020305')),
        (NetAddress('foo.bar', 50), TypeError('address must be resolved: foo.bar')),
    ))
    def test_pack_host(self, address, answer):
        if isinstance(answer, Exception):
            with pytest.raises(type(answer)) as e:
                address.pack_host()
            assert type(e.value) == type(answer) and str(e.value) == str(answer)
        else:
            assert address.pack_host() == answer

    @pytest.mark.parametrize("address,answer",(
        (NetAddress('abcd::dbca', 50), bytes.fromhex('abcd000000000000000000000000dbca0032')),
        (NetAddress('1.2.3.5', 40), bytes.fromhex('00000000000000000000ffff010203050028')),
        (NetAddress('foo.bar', 30), TypeError('address must be resolved: foo.bar')),
    ))
    def test_pack(self, address, answer):
        if isinstance(answer, Exception):
            with pytest.raises(type(answer)) as e:
                address.pack()
            assert type(e.value) == type(answer) and str(e.value) == str(answer)
        else:
            assert address.pack() == answer


def default_func(protocol, kind):
    if kind == ServicePart.PROTOCOL:
        return 'SSL'
    if kind == ServicePart.HOST:
        return {'ssl': 'ssl_host.tld', 'tcp': 'tcp_host.tld'}.get(protocol)
    return {'ssl': 443, 'tcp': '80', 'ws': 50001}.get(protocol)


class TestService:

    @pytest.mark.parametrize("protocol,address,answer", (
        ('tcp', 'domain.tld:8000', Service('tcp', NetAddress('domain.tld', 8000))),
        ('SSL', NetAddress('domain.tld', '23'), Service('ssl', NetAddress('domain.tld', 23))),
        ('SSL', '[::1]:80', Service('SSL', NetAddress('::1', 80))),
        ('ws', '1.2.3.4:80', Service('ws', NetAddress('1.2.3.4', 80))),
        (4, '1.2.3.4:80', TypeError),
        ('wss', '1.2.3.4:', ValueError),
    ))
    def test_constructor(self, protocol, address, answer):
        if isinstance(answer, type) and issubclass(answer, Exception):
            with pytest.raises(answer):
                Service(protocol, address)
        else:
            assert Service(protocol, address) == answer

    def test_eq(self):
        assert Service('http', '1.2.3.4:23') == Service(
            'HTTP', NetAddress(IPv4Address('1.2.3.4'), 23))
        assert Service('https', '1.2.3.4:23') != Service('http', '1.2.3.4:23')
        assert Service('https', '1.2.3.4:23') != Service('https', '1.2.3.4:22')

    def test_hashable(self):
        assert 1 == len({Service('http', '1.2.3.4:23'),
                         Service('HTTP', NetAddress(IPv4Address('1.2.3.4'), 23))})

    @pytest.mark.parametrize("protocol,address,answer", (
        ('TCP', 'foo.bar:23', 'tcp://foo.bar:23'),
        ('httpS', NetAddress('::1', 80), 'https://[::1]:80'),
        ('ws', NetAddress('1.2.3.4', '50000'), 'ws://1.2.3.4:50000'),
    ))
    def test_str(self, protocol, address, answer):
        assert str(Service(protocol, address)) == answer

    @pytest.mark.parametrize("protocol, address, answer", (
        ('TCP', 'foo.bar:23', "Service('tcp', 'foo.bar:23')"),
        ('httpS', NetAddress('::1', 80), "Service('https', '[::1]:80')"),
        ('ws', NetAddress('1.2.3.4', '50000'), "Service('ws', '1.2.3.4:50000')"),
    ))
    def test_repr(self, protocol, address, answer):
        assert repr(Service(protocol, address)) == answer

    def test_attributes(self):
        service = Service('HttpS', '[::1]:80')
        assert service.protocol == 'https'
        assert service.address == NetAddress('::1', 80)
        assert service.host == IPv6Address('::1')
        assert service.port == 80

    @pytest.mark.parametrize("service,default_func,answer", (
        ('HTTP://foo.BAR:80', None, Service('http', NetAddress('foo.BAR', 80))),
        ('ssl://[::1]:80', None, Service('ssl', '[::1]:80')),
        ('ssl://5.6.7.8:50001', None, Service('ssl', NetAddress('5.6.7.8', 50001))),
        ('ssl://foo.bar', None, ValueError),
        ('ssl://:80', None, ValueError),
        ('foo.bar:80', None, ValueError),
        ('foo.bar', None, ValueError),
        (2, None, TypeError),
        # With default funcs
        ('localhost:80', default_func, Service('ssl', 'localhost:80')),
        ('localhost', default_func, Service('ssl', 'localhost:443')),
        ('WS://domain.tld', default_func, Service('ws', 'domain.tld:50001')),
        # TCP has a default host and port
        ('tcp://localhost', default_func, Service('tcp', 'localhost:80')),
        ('tcp://:', default_func, Service('tcp', 'tcp_host.tld:80')),
        ('tcp://', default_func, Service('tcp', 'tcp_host.tld:80')),
        # As TCP has a default host and port it is interpreted as a protocol not a host
        ('tcp', default_func, Service('tcp', 'tcp_host.tld:80')),
        # WS has no default host
        ('ws://', default_func, ValueError),
        ('ws://:45', default_func, ValueError),
        ('ws://localhost', default_func, Service('ws', 'localhost:50001')),
        # WS alone is interpreted as a host name as WS protocol has no default host
        ('ws', default_func, Service('ssl', 'ws:443')),
        # Default everything
        ('', default_func, Service('ssl', 'ssl_host.tld:443')),
    ))
    def test_from_string(self, service, default_func, answer):
        if isinstance(answer, type) and issubclass(answer, Exception):
            with pytest.raises(answer):
                Service.from_string(service, default_func=default_func)
        else:
            assert Service.from_string(service, default_func=default_func) == answer

    @pytest.mark.parametrize("attr", ('host', 'port', 'address', 'protocol'))
    def test_immutable(self, attr):
        service = Service.from_string('https://foo.bar:8000')
        with pytest.raises(AttributeError):
            setattr(service, attr, '')
        setattr(service, 'foo', '')


pack_tests = (
    ('[1a00:23c6:cf86:6201:3cc8:85d1:c41f:9bf6]:8333', ServiceFlags.NODE_NONE,
     bytes(8) + b'\x1a\x00#\xc6\xcf\x86b\x01<\xc8\x85\xd1\xc4\x1f\x9b\xf6 \x8d'),
    ('1.2.3.4:56', ServiceFlags.NODE_NETWORK,
     b'\1' + bytes(17) + b'\xff\xff\1\2\3\4\0\x38'),
)

pack_ts_tests = (
    ('[1a00:23c6:cf86:6201:3cc8:85d1:c41f:9bf6]:8333', ServiceFlags.NODE_NETWORK,
     123456789,'15cd5b0701000000000000001a0023c6cf8662013cc885d1c41f9bf6208d'),
    ('100.101.102.103:104', ServiceFlags.NODE_NONE, 987654321,
     'b168de3a000000000000000000000000000000000000ffff646566670068'),
)

X_address = NetAddress.from_string('1.2.3.4:5678')
X_protoconf = Protoconf(2_000_000, [b'Default', b'BlockPriority'])
X_service = BitcoinService(
    services=ServiceFlags.NODE_NETWORK,
    address = X_address,
    protocol_version=80_000,
    user_agent='/foobar:1.0/',
    relay=False,
    timestamp=500_000,
    assoc_id=b'Default',
    start_height=5,
)


class TestServicePacking:

    @pytest.mark.parametrize('address,services,result', pack_tests)
    def test_pack(self, address, services, result):
        assert ServicePacking.pack(NetAddress.from_string(address), services) == result

    @pytest.mark.parametrize('address,services,ts,result', pack_ts_tests)
    def test_pack_with_timestamp(self, address, services, ts, result):
        addr = NetAddress.from_string(address)
        assert ServicePacking.pack_with_timestamp(addr, services, ts) == bytes.fromhex(result)

    @pytest.mark.parametrize('address,services,result', pack_tests)
    def test_unpack(self, address, services, result):
        assert ServicePacking.unpack(result) == (NetAddress.from_string(address), services)

    @pytest.mark.parametrize('address,services,result', pack_tests)
    def test_read(self, address, services, result):
        assert ServicePacking.read(BytesIO(result).read) == (
            NetAddress.from_string(address), services)

    @pytest.mark.parametrize('address,services,ts,result', pack_ts_tests)
    def test_read_with_timestamp(self, address, services, ts, result):
        read = BytesIO(bytes.fromhex(result)).read
        addr, srvcs, timestamp = ServicePacking.read_with_timestamp(read)
        assert ts == timestamp
        assert services == srvcs
        assert addr == NetAddress.from_string(address)

    def test_read_addrs(self):
        raw = bytearray()
        raw += pack_varint(len(pack_ts_tests))
        for address, _, ts, packed in pack_ts_tests:
            raw += bytes.fromhex(packed)
        result = ServicePacking.read_addrs(BytesIO(raw).read)
        assert len(result) == len(pack_ts_tests)
        for n, (addr, srvcs, ts) in enumerate(result):
            address, services, timestamp, packed = pack_ts_tests[n]
            assert addr == NetAddress.from_string(address)
            assert srvcs == services
            assert ts == timestamp


class TestBitcoinService:

    def test_eq(self):
        assert BitcoinService(address=NetAddress('1.2.3.4', 35),
                              services=ServiceFlags.NODE_NETWORK) == \
            BitcoinService(address='1.2.3.4:35', services=ServiceFlags.NODE_NETWORK)
        assert BitcoinService(address='1.2.3.4:35', services=ServiceFlags.NODE_NETWORK) != \
            BitcoinService(address='1.2.3.4:36', services=ServiceFlags.NODE_NETWORK)
        assert X_service == BitcoinService(address=X_address)

    def test_hashable(self):
        assert 1 == len({BitcoinService(address='1.2.3.5:35', services=ServiceFlags.NODE_NONE),
                         BitcoinService(address='1.2.3.5:35', services=ServiceFlags.NODE_NETWORK)})

    def test_str_repr(self):
        service = BitcoinService(address='1.2.3.4:5', services=1)
        assert repr(service) == str(service)

    def test_service_set(self):
        service = X_service
        assert service.address == X_address
        assert service.services == ServiceFlags.NODE_NETWORK
        assert service.protocol_version == 80_000
        assert service.user_agent == '/foobar:1.0/'
        assert service.relay is False
        assert service.timestamp == 500_000
        assert service.assoc_id == b'Default'
        assert service.start_height == 5

    def test_service_default(self):
        service = BitcoinService()
        assert service.address == NetAddress('::', 0, check_port=False)
        assert service.services == ServiceFlags.NODE_NONE
        assert service.protocol_version == 70_015
        assert service.user_agent == f'/bitcoinx/{_version_str}'
        assert service.relay is True
        assert service.timestamp is None
        assert service.assoc_id is None
        assert service.start_height == 0


protoconf_tests = [
    (2_000_000, [b'foo', b'bar'], '0280841e0007666f6f2c626172'),
]

class TestProtoconf:

    @pytest.mark.parametrize('max_payload', (Protoconf.LEGACY_MAX_PAYLOAD, 10_000_000))
    def test_max_inv_elements(self, max_payload):
        assert Protoconf(max_payload, b'').max_inv_elements() == (max_payload - 9) // (4 + 32)

    @pytest.mark.parametrize('max_payload, policies, result', protoconf_tests)
    def test_payload(self, max_payload, policies, result):
        assert Protoconf(max_payload, policies).payload() == bytes.fromhex(result)

    @pytest.mark.parametrize('max_payload, policies, result', protoconf_tests)
    def test_from_payload(self, max_payload, policies, result):
        pc = Protoconf.from_payload(bytes.fromhex(result))
        assert pc.max_payload == max_payload
        assert pc.stream_policies == policies

    @pytest.mark.parametrize('N', (0, 1))
    def test_bad_field_count(self, N):
        raw = bytearray(Protoconf(2_000_000, [b'Default']).payload())
        raw[0] = N
        with pytest.raises(ProtocolError):
            Protoconf.from_payload(raw)

    def test_bad_max_payload(self):
        raw = Protoconf(Protoconf.LEGACY_MAX_PAYLOAD - 1, [b'Default']).payload()
        with pytest.raises(ProtocolError):
            Protoconf.from_payload(raw)

    def test_logging(self, caplog):
        raw = bytearray(Protoconf(2_000_000, [b'Default']).payload())
        raw[0] = 3
        with caplog.at_level('WARNING'):
            Protoconf.from_payload(raw)
        assert 'unexpected field count' in caplog.text


class Dribble:
    '''Utility class for testing.'''

    def __init__(self, raw):
        self.raw = raw
        self.cursor = 0

    async def recv_exactly(self, size):
        result = self.raw[self.cursor: self.cursor + size]
        self.cursor += size
        return result

    @staticmethod
    def lengths(total):
        lengths = []
        cursor = 0
        while cursor < total:
            length = min(random.randrange(1, total // 2), total - cursor)
            lengths.append(length)
            cursor += length
        return lengths

    @staticmethod
    def parts(raw):
        parts = []
        start = 0
        for length in Dribble.lengths(len(raw)):
            parts.append(raw[start: start+length])
            start += length
        return parts


std_header_tests = [
    (b'1234', b'0123456789ab', b'', b'12340123456789ab\0\0\0\0]\xf6\xe0\xe2'),
    (Bitcoin.magic, MessageHeader.ADDR, b'foobar',
     b'\xe3\xe1\xf3\xe8addr\0\0\0\0\0\0\0\0\6\0\0\0?,|\xca'),
]

ext_header_tests = [
    (b'1234', b'command\0\0\0\0\0', 5,
     b'1234extmsg\0\0\0\0\0\0\xff\xff\xff\xff\0\0\0\0'
     b'command\0\0\0\0\0\5\0\0\0\0\0\0\0'),
    (Bitcoin.magic, MessageHeader.BLOCK, 8_000_000_000,
     b'\xe3\xe1\xf3\xe8extmsg\0\0\0\0\0\0\xff\xff\xff\xff\0\0\0\0'
     b'block\0\0\0\0\0\0\0\0P\xd6\xdc\1\0\0\0'),
]

ALL_COMMANDS = ('addr', 'authch', 'authresp', 'block', 'blocktxn', 'cmpctblock', 'createstrm',
                'datareftx', 'dsdetected', 'extmsg', 'feefilter', 'getaddr', 'getblocks',
                'getblocktxn', 'getdata', 'getheaders', 'gethdrsen', 'hdrsen', 'headers',
                'inv', 'mempool', 'notfound', 'ping', 'pong', 'protoconf', 'reject', 'reply',
                'revokemid', 'sendcmpct', 'sendheaders', 'sendhdrsen', 'streamack', 'tx',
                'verack', 'version')


class TestMessageHeader:

    def test_basics(self):
        assert MessageHeader.STD_HEADER_SIZE == 24
        assert MessageHeader.EXT_HEADER_SIZE == 44

    @pytest.mark.parametrize("command", ALL_COMMANDS)
    def test_commands(self, command):
        padding = 12 - len(command)
        assert getattr(MessageHeader, command.upper()) == command.encode() + bytes(padding)

    @pytest.mark.parametrize("magic, command, payload, answer", std_header_tests)
    def test_std_bytes(self, magic, command, payload, answer):
        assert MessageHeader.std_bytes(magic, command, payload) == answer

    @pytest.mark.parametrize("magic, command, payload_len, answer", ext_header_tests)
    def test_ext_bytes(self, magic, command, payload_len, answer):
        assert MessageHeader.ext_bytes(magic, command, payload_len) == answer

    @pytest.mark.parametrize("magic, command, payload, answer", std_header_tests)
    def test_from_stream_std(self, magic, command, payload, answer):
        async def main():
            dribble = Dribble(answer)
            header = await MessageHeader.from_stream(dribble.recv_exactly)
            assert header.magic == magic
            assert header.command_bytes == command
            assert header.payload_len == len(payload)
            assert header.checksum == double_sha256(payload)[:4]
            assert header.is_extended is False

        asyncio.run(main())

    @pytest.mark.parametrize("magic, command, payload_len, answer", ext_header_tests)
    def test_from_stream_ext(self, magic, command, payload_len, answer):
        async def main():
            dribble = Dribble(answer)
            header = await MessageHeader.from_stream(dribble.recv_exactly)
            assert header.magic == magic
            assert header.command_bytes == command
            assert header.payload_len == payload_len
            assert header.checksum == bytes(4)
            assert header.is_extended is True

        asyncio.run(main())

    @pytest.mark.parametrize("raw", (
        b'1234extmsg\0\0\0\0\0\0\xfe\xff\xff\xff\0\0\0\0command\0\0\0\0\0\5\0\0\0\0\0\0\0',
        b'4567extmsg\0\0\0\0\0\0\xff\xff\xff\xff\0\0\1\0command\0\0\0\0\0\5\0\0\0\0\0\0\0',
    ))
    def test_from_stream_ext_bad(self, raw):
        async def main():
            dribble = Dribble(raw)
            with pytest.raises(ProtocolError):
                await MessageHeader.from_stream(dribble.recv_exactly)

        asyncio.run(main())

    @pytest.mark.parametrize("command", ('addr', 'ping', 'sendheaders'))
    def test_str(self, command):
        command_bytes = getattr(MessageHeader, command.upper())
        header = MessageHeader(b'', command_bytes, 0, b'', False)
        assert str(header) == command


net_addresses = ['1.2.3.4', '4.3.2.1', '001:0db8:85a3:0000:0000:8a2e:0370:7334',
                 '2001:db8:85a3:8d3:1319:8a2e:370:7348']

def random_net_address():
    port = random.randrange(1024, 50000)
    address = random.choice(net_addresses)
    return NetAddress(address, port)


def random_service():
    address = random_net_address()
    return BitcoinService(address=address)


class TestNetworkProtocol:

    def test_pack_block_locator(self):
        def pack_hash(h):
            return h

        locator = [urandom(32) for _ in range(6)]
        hash_stop = urandom(32)
        protocol = 100
        answer = pack_le_int32(protocol) + pack_list(locator, pack_hash)

        assert NetworkProtocol.pack_block_locator(protocol, locator) == answer + bytes(32)
        assert NetworkProtocol.pack_block_locator(protocol, locator, None) == answer + bytes(32)
        assert NetworkProtocol.pack_block_locator(protocol, locator, hash_stop) \
            == answer + hash_stop

    def test_version_payload_bad_nonce(self):
        with pytest.raises(ValueError) as e:
            NetworkProtocol.version_payload(X_service, BitcoinService(), bytes(7))
        assert 'nonce must be 8 bytes' == str(e.value)

    def test_version_payload_theirs_default(self):
        nonce = b'1234beef'
        their_service = BitcoinService()
        payload = NetworkProtocol.version_payload(X_service, their_service, nonce)
        assert payload == bytes.fromhex(
            '80380100010000000000000020a1070000000000000000000000000000000000000000000000000000'
            '0000000000010000000000000000000000000000000000ffff01020304162e31323334626565660c2f'
            '666f6f6261723a312e302f05000000000744656661756c74')
        service = BitcoinService()
        service.address = X_service.address
        result = NetworkProtocol.read_version_payload(service, payload)
        assert service == X_service
        assert result == (their_service.address, their_service.services, nonce)

    def test_version_payload_theirs_X(self):
        nonce = b'1234beef'
        their_service = copy.copy(X_service)
        payload = NetworkProtocol.version_payload(X_service, their_service, nonce)
        assert payload == bytes.fromhex(
            '80380100010000000000000020a1070000000000010000000000000000000000000000000000ffff01'
            '020304162e010000000000000000000000000000000000ffff01020304162e31323334626565660c2f'
            '666f6f6261723a312e302f05000000000744656661756c74')
        service = BitcoinService()
        service.address = X_service.address
        result = NetworkProtocol.read_version_payload(service, payload)
        assert service == X_service
        assert result == (their_service.address, their_service.services, nonce)

    def test_version_payload_NetAddress(self):
        nonce = b'cabbages'
        address = NetAddress('1.2.3.4', 5)
        payload = NetworkProtocol.version_payload(X_service, address, nonce)
        assert payload == bytes.fromhex(
            '80380100010000000000000020a1070000000000000000000000000000000000000000000000ffff01'
            '0203040005010000000000000000000000000000000000ffff01020304162e63616262616765730c2f'
            '666f6f6261723a312e302f05000000000744656661756c74')
        service = BitcoinService(address=address)
        service_copy = copy.copy(service)
        result = NetworkProtocol.read_version_payload(service, payload)
        assert service == service_copy
        assert result == (address, ServiceFlags.NODE_NONE, nonce)

    def test_version_payload_timestamp_None(self):
        nonce = b'cabbages'
        service = copy.copy(X_service)
        service.timestamp = None
        payload = NetworkProtocol.version_payload(service, X_service, nonce)

        service2 = BitcoinService(address=service.address)
        result = NetworkProtocol.read_version_payload(service2, payload)
        assert 0 < time.time() - service2.timestamp < 5
        service.timestamp = service2.timestamp
        assert service == service2
        assert result == (X_service.address, X_service.services, nonce)

    def test_version_payload_timestamp_None(self):
        nonce = b'cabbages'
        service = copy.copy(X_service)
        service.assoc_id = None
        payload = NetworkProtocol.version_payload(service, X_service, nonce)

        service2 = BitcoinService(address=service.address)
        result = NetworkProtocol.read_version_payload(service2, payload)
        assert service2.assoc_id is None
        assert service == service2
        assert result == (X_service.address, X_service.services, nonce)

    def test_read_version_payload_undecodeable_user_agent(self):
        nonce = b'cabbages'
        service = copy.copy(X_service)
        service.user_agent = 'xxx'
        payload = NetworkProtocol.version_payload(service, X_service, nonce)
        # Non-UTF8 user agent
        payload = payload.replace(b'xxx', b'\xff' * 3)

        service2 = BitcoinService(address=service.address)
        result = NetworkProtocol.read_version_payload(service2, payload)
        assert service2.user_agent == '0xffffff'
        service2.user_agent = service.user_agent
        assert service == service2
        assert result == (X_service.address, X_service.services, nonce)

    def test_read_version_payload_no_relay(self):
        nonce = b'cabbages'
        service = BitcoinService()
        payload = NetworkProtocol.version_payload(service, X_service, nonce)

        service2 = BitcoinService(address=service.address)
        result = NetworkProtocol.read_version_payload(service2, payload[:-1])
        assert service2.assoc_id is None
        assert service2.relay is True
        assert service == service2
        assert result == (X_service.address, X_service.services, nonce)
