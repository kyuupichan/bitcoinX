import asyncio
import copy
import logging
import platform
import time
from io import BytesIO
from ipaddress import IPv4Address, IPv6Address
from os import urandom

import asqlite3
import pytest
import pytest_asyncio

from bitcoinx import (
    Bitcoin, BitcoinTestnet, pack_varint, _version_str, double_sha256, pack_le_int32, pack_list,
    Headers, all_networks, ProtocolError, PackingError, pack_le_uint32,
    NetAddress, BitcoinService, ServiceFlags, Protoconf, MessageHeader,
    Service, is_valid_hostname, validate_port, validate_protocol, classify_host,
    ServicePart, Node, Association, SimpleHeader
)
from bitcoinx.misc import chunks
from bitcoinx.net_protocol import (
    ServicePacking, BlockLocator, Stream, StreamKind, version_payload, read_version, _command,
    pack_headers_payload, read_headers, read_addrs, services_from_seeds,
)
from bitcoinx.aiolib import timeout_after, ignore_after, TaskGroup

from .utils import (
    run_test_with_headers, create_random_branch, insert_tree, first_mainnet_headers, in_caplog,
    print_caplog,
)


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
def test_is_valid_hostname(hostname, answer):
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

    @pytest.mark.parametrize("host,port,answer,host_type", (
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
    def test_constructor(self, host, port, answer, host_type):
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

    @pytest.mark.parametrize("host,port,answer", (
        ('foo.bar', '23', "NetAddress('foo.bar:23')"),
        ('foo.bar', 23, "NetAddress('foo.bar:23')"),
        ('::1', 15, "NetAddress('[::1]:15')"),
        ('5.6.7.8', '23', "NetAddress('5.6.7.8:23')"),
    ))
    def test_repr(self, host, port, answer):
        assert repr(NetAddress(host, port)) == answer

    @pytest.mark.parametrize("string,default_func,answer", (
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
                NetAddress.from_string(string, default_func=default_func)
        else:
            assert NetAddress.from_string(string, default_func=default_func) == answer

    @pytest.mark.parametrize("item,answer", (
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

    @pytest.mark.parametrize("address,answer", (
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

    @pytest.mark.parametrize("address,answer", (
        (NetAddress('abcd::dbca', 50), bytes.fromhex('abcd000000000000000000000000dbca')),
        (NetAddress('1.2.3.5', 50), bytes.fromhex('00000000000000000000ffff01020305')),
        (NetAddress('foo.bar', 50), TypeError('address must be resolved: foo.bar')),
    ))
    def test_pack_host(self, address, answer):
        if isinstance(answer, Exception):
            with pytest.raises(type(answer)) as e:
                address.pack_host()
            assert type(e.value) is type(answer) and str(e.value) == str(answer)
        else:
            assert address.pack_host() == answer

    @pytest.mark.parametrize("address,answer", (
        (NetAddress('abcd::dbca', 50), bytes.fromhex('abcd000000000000000000000000dbca0032')),
        (NetAddress('1.2.3.5', 40), bytes.fromhex('00000000000000000000ffff010203050028')),
        (NetAddress('foo.bar', 30), TypeError('address must be resolved: foo.bar')),
    ))
    def test_pack(self, address, answer):
        if isinstance(answer, Exception):
            with pytest.raises(type(answer)) as e:
                address.pack()
            assert type(e.value) is type(answer) and str(e.value) == str(answer)
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
     123456789, '15cd5b0701000000000000001a0023c6cf8662013cc885d1c41f9bf6208d'),
    ('100.101.102.103:104', ServiceFlags.NODE_NONE, 987654321,
     'b168de3a000000000000000000000000000000000000ffff646566670068'),
)

X_address = NetAddress.from_string('1.2.3.4:5678')
X_protoconf = Protoconf(2_000_000, ['Default', 'BlockPriority'])
X_service = BitcoinService(
    services=ServiceFlags.NODE_NETWORK,
    address=X_address,
    protocol_version=80_000,
    user_agent='/foobar:1.0/',
    relay=False,
    timestamp=500_000,
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
        result = read_addrs(BytesIO(raw).read)
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
        assert service.start_height == 5

    def test_service_default(self):
        service = BitcoinService()
        assert service.address == NetAddress('::', 0, check_port=False)
        assert service.services == ServiceFlags.NODE_NONE
        assert service.protocol_version in (70_015, 70_016)
        assert service.user_agent == f'/bitcoinx/{_version_str}'
        assert service.relay is True
        assert service.timestamp is None
        assert service.start_height == 0


protoconf_tests = [
    (2_000_000, ['foo', 'bar'], '0280841e0007666f6f2c626172'),
]


class TestProtoconfClass:

    @pytest.mark.parametrize('max_payload, policies, result', protoconf_tests)
    def test_payload(self, max_payload, policies, result):
        assert Protoconf(max_payload, policies).payload() == bytes.fromhex(result)

    @pytest.mark.parametrize('max_payload, policies, result', protoconf_tests)
    def test_from_payload(self, max_payload, policies, result):
        pc = Protoconf.read(BytesIO(bytes.fromhex(result)).read)
        assert pc.max_payload_length == max_payload
        assert pc.stream_policies == policies


class Dribble:
    '''Utility class for testing.'''

    def __init__(self, raw):
        self.raw = raw
        self.cursor = 0

    async def recv_exactly(self, size):
        result = self.raw[self.cursor: self.cursor + size]
        self.cursor += size
        return result


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

    @pytest.mark.parametrize("command", ALL_COMMANDS)
    def test_commands(self, command):
        padding = 12 - len(command)
        assert getattr(MessageHeader, command.upper()) == command.encode() + bytes(padding)

    @pytest.mark.parametrize("magic, command, payload, answer", std_header_tests)
    def test_std_bytes(self, magic, command, payload, answer):
        assert MessageHeader.std_bytes(magic, command, payload) == answer
        assert len(answer) == MessageHeader.STD_HEADER_SIZE

    @pytest.mark.parametrize("magic, command, payload_len, answer", ext_header_tests)
    def test_ext_bytes(self, magic, command, payload_len, answer):
        assert MessageHeader.ext_bytes(magic, command, payload_len) == answer
        assert len(answer) == MessageHeader.EXT_HEADER_SIZE

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
            with pytest.raises(ProtocolError) as e:
                await MessageHeader.from_stream(dribble.recv_exactly)
            assert 'protocol error: ill-formed extended message header' == str(e.value)

        asyncio.run(main())

    @pytest.mark.parametrize("command", ('addr', 'ping', 'sendheaders'))
    def test_str(self, command):
        command_bytes = getattr(MessageHeader, command.upper())
        header = MessageHeader(b'', command_bytes, 0, b'', False)
        assert str(header) == command


net_addresses = ['1.2.3.4', '4.3.2.1', '001:0db8:85a3:0000:0000:8a2e:0370:7334',
                 '2001:db8:85a3:8d3:1319:8a2e:370:7348']


class TestNetworkProtocol:

    @pytest.mark.parametrize("version, count, hash_stop", (
        (70_015, 5, False),
        (70_016, 20, True),
        (70_015, 0, True),
    ))
    def test_getheaders_payload(self, version, count, hash_stop):
        hash_stop = urandom(32) if hash_stop else None
        locator = BlockLocator(version, [urandom(32) for _ in range(count)], hash_stop)
        payload = locator.to_payload()
        assert BlockLocator.read(BytesIO(payload).read) == locator

    def test_getheaders_payload_short(self):
        locator = BlockLocator(700, [urandom(32)], urandom(31))
        payload = locator.to_payload()
        with pytest.raises(PackingError) as e:
            BlockLocator.read(BytesIO(payload).read)
        assert str(e.value) == 'could not read 32 bytes'

    def test_pack_getheaders_payload(self):
        def pack_hash(h):
            return h

        block_hashes = [urandom(32) for _ in range(6)]
        hash_stop = urandom(32)
        protocol = 100
        answer = pack_le_int32(protocol) + pack_list(block_hashes, pack_hash)

        assert BlockLocator(protocol, block_hashes, None).to_payload() == answer + bytes(32)
        assert BlockLocator(protocol, block_hashes, hash_stop).to_payload() == answer + hash_stop

    @pytest.mark.parametrize("count", (0, 10, 100, 2000))
    def test_headers_payload(self, count):
        headers = [SimpleHeader(urandom(80)) for _ in range(count)]
        payload = pack_headers_payload(headers)
        assert headers == read_headers(BytesIO(payload).read)

    def test_headers_payload_short(self):
        headers = [SimpleHeader(urandom(80)) for _ in range(5)]
        payload = pack_headers_payload(headers)
        with pytest.raises(PackingError):
            read_headers(BytesIO(payload[:-1]).read)

    def test_version_payload_bad_nonce(self):
        with pytest.raises(ValueError) as e:
            version_payload(X_service, BitcoinService(), bytes(7), None)
        assert 'nonce must be 8 bytes' == str(e.value)

    def test_version_payload_theirs_default(self):
        nonce = b'1234beef'
        remote_service = BitcoinService()
        payload = version_payload(X_service, remote_service, nonce, b'assoc_id')
        assert payload == bytes.fromhex(
            '80380100010000000000000020a1070000000000000000000000000000000000000000000000000000'
            '0000000000010000000000000000000000000000000000ffff01020304162e31323334626565660c2f'
            '666f6f6261723a312e302f0500000000086173736f635f6964')
        service = BitcoinService()
        service.address = X_service.address
        result = read_version(service, BytesIO(payload).read)
        assert service == X_service
        assert result == (remote_service.address, remote_service.services, nonce, b'assoc_id')

    def test_version_payload_theirs_X(self):
        nonce = b'1234beef'
        remote_service = copy.copy(X_service)
        payload = version_payload(X_service, remote_service, nonce, b'assoc_id')
        assert payload == bytes.fromhex(
            '80380100010000000000000020a1070000000000010000000000000000000000000000000000ffff01'
            '020304162e010000000000000000000000000000000000ffff01020304162e31323334626565660c2f'
            '666f6f6261723a312e302f0500000000086173736f635f6964')
        service = BitcoinService()
        service.address = X_service.address
        result = read_version(service, BytesIO(payload).read)
        assert service == X_service
        assert result == (remote_service.address, remote_service.services, nonce, b'assoc_id')

    def test_version_payload_NetAddress(self):
        nonce = b'cabbages'
        address = NetAddress('1.2.3.4', 5)
        payload = version_payload(X_service, address, nonce, b'assoc_id')
        assert payload == bytes.fromhex(
            '80380100010000000000000020a1070000000000000000000000000000000000000000000000ffff01'
            '0203040005010000000000000000000000000000000000ffff01020304162e63616262616765730c2f'
            '666f6f6261723a312e302f0500000000086173736f635f6964')
        service = BitcoinService(address=address)
        service_copy = copy.copy(service)
        result = read_version(service, BytesIO(payload).read)
        assert service == service_copy
        assert result == (address, ServiceFlags.NODE_NONE, nonce, b'assoc_id')

    def test_version_payload_timestamp_None(self):
        nonce = b'cabbages'
        service = copy.copy(X_service)
        service.timestamp = None
        payload = version_payload(service, X_service, nonce, b'assoc_id')

        service2 = BitcoinService(address=service.address)
        result = read_version(service2, BytesIO(payload).read)
        assert 0 < time.time() - service2.timestamp < 5
        service.timestamp = service2.timestamp
        assert service == service2
        assert result == (X_service.address, X_service.services, nonce, b'assoc_id')

    def test_version_payload_assoc_id_None(self):
        nonce = b'cabbages'
        assoc_id = b'assoc_id'
        service = copy.copy(X_service)
        payload = version_payload(service, X_service, nonce, assoc_id)

        service2 = BitcoinService(address=service.address)
        result = read_version(service, BytesIO(payload).read)
        assert service == service2
        assert result == (X_service.address, X_service.services, nonce, assoc_id)

    def test_read_version_payload_undecodeable_user_agent(self):
        nonce = b'cabbages'
        service = copy.copy(X_service)
        service.user_agent = 'xxx'
        payload = version_payload(service, X_service, nonce, b'assoc_id')
        # Non-UTF8 user agent
        payload = payload.replace(b'xxx', b'\xff' * 3)

        service2 = BitcoinService(address=service.address)
        result = read_version(service2, BytesIO(payload).read)
        assert service2.user_agent == '0xffffff'
        service2.user_agent = service.user_agent
        assert service == service2
        assert result == (X_service.address, X_service.services, nonce, b'assoc_id')

    def test_read_version_payload_no_relay(self):
        nonce = b'cabbages'
        service = BitcoinService()
        payload = version_payload(service, X_service, nonce, b'assoc_id')

        service2 = BitcoinService(address=service.address)
        result = read_version(service2, BytesIO(payload).read)
        assert service2.relay is True
        assert service == service2
        assert result == (X_service.address, X_service.services, nonce, b'assoc_id')


class TestBlockLocator:
    # FIXME: add more tests

    def test_from_headers(self):
        async def test(headers):
            count = 100
            branch = create_random_branch(headers.genesis_header, count)
            await insert_tree(headers, [(None, branch)])
            locator = await BlockLocator.from_block_hash(0, headers)
            assert len(locator) == 8
            assert locator.block_hashes[:-1] == [
                branch[-(1 << loc_pos)].hash for loc_pos in range(7)]
            assert locator.block_hashes[-1] == headers.genesis_header.hash

        run_test_with_headers(test)

    @pytest.mark.parametrize('network', all_networks)
    def test_block_locator_empty_headers(self, network):
        async def test(headers):
            locator = await BlockLocator.from_block_hash(0, headers)
            assert locator.block_hashes == [headers.genesis_header.hash]

        run_test_with_headers(test, network)


listen_host = IPv4Address('127.0.0.1')


@pytest_asyncio.fixture
async def listening_headers():
    async with asqlite3.connect(':memory:') as conn:
        headers = Headers(conn, Bitcoin)
        await headers.initialize()
        yield headers


@pytest.fixture
def listening_node(listening_headers):
    service = BitcoinService(address=NetAddress(listen_host, 5656))
    node = Node(service, listening_headers)
    yield node
    # assert not node.assocs


@pytest.fixture
def listening_node2(listening_headers):
    service = BitcoinService(address=NetAddress(listen_host, 5657))
    node = Node(service, listening_headers)
    yield node


async def listening_assoc(listening_node):
    await pause()
    for assoc in listening_node.assocs:
        if not assoc.is_outgoing:
            return assoc
    raise RuntimeError('no listening assocs')


@pytest_asyncio.fixture
async def client_headers():
    async with asqlite3.connect(':memory:') as conn:
        headers = Headers(conn, Bitcoin)
        await headers.initialize()
        yield headers


@pytest.fixture
def client_node(client_headers):
    node = Node(BitcoinService(), client_headers)
    yield node
    assert not node.assocs


async def achunks(payload, size):
    for chunk in chunks(payload, size):
        yield chunk


async def pause(secs=None):
    if secs is None:
        secs = 0.05 if platform.system() == 'Windows' else 0.01
    await asyncio.sleep(secs)


@pytest.mark.asyncio
@pytest.mark.parametrize('network', all_networks)
async def test_services_from_seeds(network):
    await services_from_seeds(network)


class ExcessClientAssociation(Association):

    def __init__(self, *args, **kwargs):
        self.excess_command = kwargs.pop('excess_command')
        super().__init__(*args, **kwargs)

    async def send_message(self, command, payload, *, force_extended=False):
        if command == self.excess_command:
            payload += b'x'
        await super().send_message(command, payload, force_extended=force_extended)


class CorruptClientAssociation(Association):

    def __init__(self, *args, **kwargs):
        self.excess_command = kwargs.pop('corrupt_command')
        super().__init__(*args, **kwargs)

    async def send_message(self, command, payload, *, force_extended=False):
        if command == self.excess_command:
            assert payload
            payload = payload[:-1]
        await super().send_message(command, payload, force_extended=force_extended)


class TestNode:

    @pytest.mark.asyncio
    async def test_simple_listen(self, listening_node):
        async with listening_node.listen():
            assert listening_node.service.address.host == listen_host
            assert listening_node.network is Bitcoin


class TestBasic:
    '''Basic connection handling tests.'''

    @pytest.mark.asyncio
    async def test_simple_connect(self, client_node, listening_node):
        async with listening_node.listen():
            async with client_node.connect(listening_node.service) as assoc:
                assert isinstance(assoc, Association)
                assert assoc.node is client_node
                assert assoc.remote_service is listening_node.service
                assert assoc.is_outgoing
                assert assoc.protoconf == Protoconf.default()

                listen_assoc = await listening_assoc(listening_node)
                assert isinstance(listen_assoc, Association)
                assert listen_assoc.node is listening_node
                assert listen_assoc.remote_service.address.host == listen_host
                assert not listen_assoc.is_outgoing
                assert listen_assoc.protoconf == Protoconf.default()
                await assoc.close()

    @pytest.mark.asyncio
    async def test_bad_magic(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                client_node.network = BitcoinTestnet
                async with client_node.connect(listening_node.service):
                    pass

        assert in_caplog(caplog, 'fatal protocol error: bad magic 0xf4e5f3f4 expected 0xe3e1f3e8')

    @pytest.mark.asyncio
    @pytest.mark.parametrize('force_extended', (False, True))
    async def test_bad_magic_later(self, client_node, listening_node, caplog, force_extended):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service) as assoc:
                    await assoc.verack_sent.wait()
                    command = MessageHeader.SENDHEADERS
                    payload = b''
                    header = MessageHeader.std_bytes(BitcoinTestnet.magic, command, payload)
                    stream = assoc.stream_for_message(command)
                    await stream.outgoing_messages.put((header, payload))
                    await pause()
                    await assoc.close()

        assert in_caplog(caplog, 'fatal protocol error: bad magic 0xf4e5f3f4 expected 0xe3e1f3e8')

    @pytest.mark.asyncio
    async def test_bad_checksum(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service) as assoc:
                    await assoc.verack_sent.wait()
                    command = MessageHeader.SENDHEADERS
                    payload = b''
                    header = MessageHeader.std_bytes(client_node.network.magic, command, payload)
                    # Mess up the checksum
                    header = bytearray(header)
                    header[-1] ^= 0x0f
                    stream = assoc.stream_for_message(command)
                    await stream.outgoing_messages.put((header, payload))
                    await pause()
                    await assoc.close()

        assert in_caplog(caplog, 'protocol error: bad checksum for sendheaders command')

    @pytest.mark.asyncio
    async def test_unhandled_command(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.WARNING):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service) as assoc:
                    await assoc.send_message(_command('zombie'), b'')
                    await pause()
                    await assoc.close()

        assert in_caplog(caplog, 'ignoring unhandled zombie message')

    @pytest.mark.asyncio
    async def test_client_bug(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                with pytest.raises(AttributeError):
                    async with client_node.connect(listening_node.service) as assoc:
                        await assoc.non_existent_member()
            await pause()

        assert in_caplog(caplog, 'connection closed remotely')

    @pytest.mark.asyncio
    async def test_listener_bug_pre_handshake(self, client_node, listening_node, caplog):
        class ListeningAssociation(Association):
            async def on_version(self, payload):
                await self.non_existent_member()

        with caplog.at_level(logging.ERROR):
            async with listening_node.listen(assoc_cls=ListeningAssociation):
                async with client_node.connect(listening_node.service):
                    pass

        assert in_caplog(caplog, "'ListeningAssociation' object has no attribute")

    @pytest.mark.asyncio
    async def test_listener_bug_post_handshake(self, client_node, listening_node, caplog):
        class ListeningAssociation(Association):
            async def on_protoconf(self, payload):
                await self.non_existent_member()

        with caplog.at_level(logging.ERROR):
            async with listening_node.listen(assoc_cls=ListeningAssociation):
                async with client_node.connect(listening_node.service):
                    pass

        assert in_caplog(caplog, "'ListeningAssociation' object has no attribute")


class TestHandshake:
    '''Covers VERSION, VERACK messages and the general handshake process.'''

    @pytest.mark.asyncio
    async def test_listener_waits_for_version_message(self, client_node, listening_node):
        class ClientAssociation(Association):
            async def activate_stream(self, stream):
                async with timeout_after(0.1):
                    await stream.recv_exactly(1)

        async with listening_node.listen():
            with pytest.raises(TimeoutError):
                async with client_node.connect(listening_node.service,
                                               assoc_cls=ClientAssociation):
                    pass

    @pytest.mark.asyncio
    async def test_client_sends_version_message(self, client_node, listening_node):
        class ListeningAssociation(Association):
            async def on_version(self, payload):
                await self.close()

        async with listening_node.listen(assoc_cls=ListeningAssociation):
            async with client_node.connect(listening_node.service):
                pass

    @pytest.mark.asyncio
    async def test_duplicate_version(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service,
                                               perform_handshake=False) as assoc:
                    await assoc.send_version()
                    with caplog.at_level(logging.WARNING):
                        await assoc.send_version()
                    assert in_caplog(caplog, 'version message already sent')
                    await pause()
                    assert not in_caplog(caplog, 'duplicate version message')

                    assoc.version_sent = False
                    await assoc.send_version()
                    await pause()
                    await assoc.close()

        assert in_caplog(caplog, 'protocol error: duplicate version message')

    @pytest.mark.asyncio
    async def test_send_verack_first(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service,
                                               perform_handshake=False) as assoc:
                    await assoc.send_verack()
                    await pause()
                    await assoc.close()

        assert in_caplog(caplog, 'protocol error: verack message received before version')

    @pytest.mark.asyncio
    async def test_send_verack_without_version(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service,
                                               perform_handshake=False) as assoc:
                    await assoc.send_version()
                    # Don't wait for an incoming version message....
                    await assoc.send_verack()
                    await pause()
                    await assoc.close()

        assert in_caplog(caplog, 'fatal protocol error: verack message received before '
                         'version message sent')

    @pytest.mark.asyncio
    @pytest.mark.parametrize('extended', (True, False))
    @pytest.mark.parametrize('first', (False, True))
    async def test_other_message_before_handshake_complete(self, client_node, listening_node,
                                                           caplog, extended, first):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service,
                                               perform_handshake=False) as assoc:
                    async def sendheaders():
                        # Don't use send_message to force the first message
                        command = MessageHeader.SENDHEADERS
                        payload = b''
                        if extended:
                            header = MessageHeader.ext_bytes(assoc.node.network.magic,
                                                             command, len(payload))
                        else:
                            header = MessageHeader.std_bytes(assoc.node.network.magic,
                                                             command, payload)
                        stream = assoc.stream_for_message(command)
                        await stream.outgoing_messages.put((header, payload))

                    if first:
                        await sendheaders()
                    else:
                        await assoc.send_version()
                        await sendheaders()
                    await pause()
                    await assoc.close()

        print_caplog(caplog)
        assert in_caplog(caplog, 'sendheaders message received before')

    @pytest.mark.asyncio
    async def test_corrupt_version(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service,
                                               assoc_cls=CorruptClientAssociation,
                                               corrupt_command=MessageHeader.VERSION,
                                               ) as assoc:
                    await pause()
                    await assoc.close()

        assert in_caplog(caplog, 'corrupt version message')

    @pytest.mark.asyncio
    async def test_excess_version(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.WARNING):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service,
                                               assoc_cls=ExcessClientAssociation,
                                               excess_command=MessageHeader.VERSION,
                                               ) as assoc:
                    await assoc.verack_sent.wait()
                    await assoc.close()

        assert in_caplog(caplog, 'extra bytes at end of version payload')

    @pytest.mark.asyncio
    async def test_self_connect(self, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                async with listening_node.connect(listening_node.service):
                    pass

        assert in_caplog(caplog, 'protocol error: connected to ourself')

    @pytest.mark.asyncio
    async def test_duplicate_verack(self, client_node, listening_node, caplog):
        class ClientAssociation(Association):
            async def send_verack(self):
                await super().send_verack()
                with caplog.at_level(logging.WARNING):
                    await super().send_verack()
                assert in_caplog(caplog, 'verack message already sent')
                await pause()
                assert not in_caplog(caplog, 'duplicate verack message')

                self.verack_sent.clear()
                await super().send_verack()
                await pause()
                await self.close()

        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service,
                                               assoc_cls=ClientAssociation):
                    pass

        assert in_caplog(caplog, 'protocol error: duplicate verack message')

    @pytest.mark.asyncio
    async def test_excess_verack(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.WARNING):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service,
                                               assoc_cls=ExcessClientAssociation,
                                               excess_command=MessageHeader.VERACK,
                                               ) as assoc:
                    await pause()
                    await assoc.close()

        assert in_caplog(caplog, 'extra bytes at end of verack payload')

    @pytest.mark.asyncio
    @pytest.mark.parametrize('slow', ('version', 'verack'))
    async def test_handshake_timeout(self, client_node, listening_node, slow):
        '''Test the handshake is only complete AFTER verack is received when verack is sent
        first.'''
        class ListeningAssociation(Association):
            async def send_version(self):
                if slow == 'version':
                    await pause(ClientAssociation.HANDSHAKE_TIMEOUT * 2)
                await super().send_version()

            async def send_verack(self):
                if slow == 'verack':
                    await pause(ClientAssociation.HANDSHAKE_TIMEOUT * 2)
                await super().send_verack()

        class ClientAssociation(Association):
            HANDSHAKE_TIMEOUT = 0.1

        async with listening_node.listen(assoc_cls=ListeningAssociation):
            with pytest.raises(ProtocolError) as e:
                async with client_node.connect(listening_node.service,
                                               assoc_cls=ClientAssociation) as assoc:
                    await pause(assoc.HANDSHAKE_TIMEOUT * 1.5)
            assert str(e.value) == 'fatal protocol error: handshake timed out'

    @pytest.mark.asyncio
    async def test_parallel_handling(self, client_node, listening_node, caplog):
        # Test commands are handled in parallel
        class ListenerAssociation(Association):
            async def on_parallel(self, payload):
                times.append(time.time())
                await asyncio.sleep(delay)

        times = []
        delay = 1.0
        async with listening_node.listen(assoc_cls=ListenerAssociation):
            async with client_node.connect(listening_node.service) as assoc:
                async with TaskGroup() as group:
                    await group.create_task(assoc.send_message(_command('parallel'), b''))
                    await group.create_task(assoc.send_message(_command('parallel'), b''))
                    await pause()
                    await group.cancel_remaining()
                await assoc.close()

        is_parallel = abs(times[0] - times[1]) < delay / 2
        assert is_parallel


class TestExtendedMessages:

    #
    # EXTMSG message tests
    #

    @pytest.mark.asyncio
    async def test_send_ext_message(self, client_node, listening_node):
        async with listening_node.listen():
            async with client_node.connect(listening_node.service,
                                           send_protoconf=False) as assoc:
                listener_assoc = await listening_assoc(listening_node)
                assert listener_assoc.their_protoconf is None
                assoc.our_protoconf = Protoconf(2_000_000, ['foo', 'bar'])
                payload = assoc.our_protoconf.payload()
                await assoc.send_message(MessageHeader.PROTOCONF, payload, force_extended=True)
                await pause()
                assert listener_assoc.their_protoconf == assoc.our_protoconf
                await assoc.close()

    @pytest.mark.asyncio
    async def test_cannot_send(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            listening_node.service.protocol_version = 70_015
            async with listening_node.listen():
                async with client_node.connect(listening_node.service,
                                               send_protoconf=False) as assoc:
                    await assoc.verack_sent.wait()
                    payload = Protoconf.default().payload()
                    assert not assoc.can_send_ext_messages
                    # We should not accept sending a large message
                    with pytest.raises(RuntimeError):
                        await assoc.send_message(MessageHeader.PROTOCONF, payload,
                                                 force_extended=True)
                    # Override the check
                    assoc.can_send_ext_messages = True
                    await assoc.send_message(MessageHeader.PROTOCONF, payload,
                                             force_extended=True)
                    pass

        assert in_caplog(caplog, 'ext message received but invalid')

    @pytest.mark.asyncio
    async def test_send_streaming(self, client_node, listening_node, caplog):
        class ListeningAssociation(Association):
            async def on_zombie_streaming(self, stream, size):
                parts = [chunk async for chunk in stream.recv_chunks(size)]
                self.zombie_payload = b''.join(parts)

            async def on_zombie(self, payload):
                self.zombie_payload2 = payload.payload

        payload = urandom(2000)
        with caplog.at_level(logging.WARNING):
            async with listening_node.listen(assoc_cls=ListeningAssociation):
                async with client_node.connect(listening_node.service) as assoc:
                    listener_assoc = await listening_assoc(listening_node)
                    listener_assoc.streaming_min_size = 200
                    await assoc.send_message(_command('zombie'),
                                             (achunks(payload, 100), len(payload)))
                    await assoc.send_message(_command('zombie'), payload)
                    await assoc.send_message(_command('ghoul'),
                                             (achunks(payload, 100), len(payload)))
                    await pause()
                    assert listener_assoc.zombie_payload == payload
                    assert listener_assoc.zombie_payload2 == payload
                    await assoc.close()

        assert in_caplog(caplog, 'ignoring unhandled extended ghoul messages')

    @pytest.mark.asyncio
    async def test_whole_assoc(self, client_node, listening_node):
        '''Test sending every message as extended, even the version message.'''
        class ClientAssociation(Association):
            async def send_message(self, command, payload, *, force_extended=False):
                await super().send_message(command, payload, force_extended=True)

        async with listening_node.listen():
            async with client_node.connect(listening_node.service,
                                           assoc_cls=ClientAssociation) as assoc:
                await pause(0.1)
                assert assoc.they_prefer_headers
                await assoc.close()


class TestGetAddr:
    '''ADDR and GETADDR tests.'''

    @pytest.mark.asyncio
    async def test_getaddr_roundtrip(self, client_node, listening_node):
        async def on_addr(payload):
            on_addr_event.set()

        on_addr_event = asyncio.Event()
        async with listening_node.listen():
            async with client_node.connect(listening_node.service) as assoc:
                assoc.on_addr = on_addr
                await assoc.send_getaddr()
                async with timeout_after(0.1):
                    await on_addr_event.wait()
                await assoc.close()

    @pytest.mark.asyncio
    async def test_getaddr_payload(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.WARNING):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service) as assoc:
                    await assoc.send_message(MessageHeader.GETADDR, b'0')
                    await pause()
                    await assoc.close()

        assert in_caplog(caplog, 'extra bytes at end of getaddr payload')


class TestProtoconf:

    @pytest.mark.asyncio
    async def test_protoconf_understood(self, client_node, listening_node):
        async with listening_node.listen():
            async with client_node.connect(listening_node.service,
                                           send_protoconf=False) as assoc:
                listener_assoc = await listening_assoc(listening_node)
                assert listener_assoc.their_protoconf is None
                assoc.protoconf.max_payload_length = 1024 * 1024 * 2
                assert assoc.protoconf.max_inv_elements() == 58254
                assoc.protoconf.max_payload_length = 1024 * 1024
                assert assoc.protoconf.max_inv_elements() == 29127
                await assoc.send_protoconf()
                await pause()
                assert listener_assoc.their_protoconf == assoc.protoconf
                await assoc.close()

    @pytest.mark.asyncio
    async def test_duplicate(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service,
                                               send_protoconf=False) as assoc:
                    await assoc.send_protoconf()
                    with caplog.at_level(logging.WARNING):
                        await assoc.send_protoconf()
                    await pause()
                    assert in_caplog(caplog, 'protoconf message already sent')
                    assert not in_caplog(caplog, 'duplicate protoconf')
                    # Force it
                    assoc.protoconf_sent = False
                    await assoc.send_protoconf()
                    await pause()
                    await assoc.close()

        assert in_caplog(caplog, 'duplicate protoconf')

    @pytest.mark.asyncio
    async def test_excess(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.WARNING):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service,
                                               assoc_cls=ExcessClientAssociation,
                                               send_protoconf=False,
                                               excess_command=MessageHeader.PROTOCONF,
                                               ) as assoc:
                    await assoc.send_protoconf()
                    await pause()
                    await assoc.close()

        assert in_caplog(caplog, 'extra bytes at end of protoconf payload')

    @pytest.mark.asyncio
    async def test_corrupt(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service,
                                               assoc_cls=CorruptClientAssociation,
                                               send_protoconf=False,
                                               corrupt_command=MessageHeader.PROTOCONF,
                                               ) as assoc:
                    await assoc.send_protoconf()
                    await pause()
                    await assoc.close()

        assert in_caplog(caplog, 'corrupt protoconf message')

    @pytest.mark.asyncio
    async def test_no_fields(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service,
                                               send_protoconf=False) as assoc:
                    await assoc.send_message(MessageHeader.PROTOCONF, b'\0')
                    await pause()
                    await assoc.close()

        assert in_caplog(caplog, 'fatal protocol error: protoconf message must have '
                         'at least one field')

    @pytest.mark.asyncio
    async def test_one_field(self, client_node, listening_node):
        async with listening_node.listen():
            async with client_node.connect(listening_node.service,
                                           send_protoconf=False) as assoc:
                protoconf = Protoconf(1024 * 1024, ['Default'])
                payload = pack_varint(1) + pack_le_uint32(protoconf.max_payload_length)
                await assoc.send_message(MessageHeader.PROTOCONF, payload)
                await pause()
                listener_assoc = await listening_assoc(listening_node)
                assert listener_assoc.their_protoconf == protoconf
                await assoc.close()

    @pytest.mark.asyncio
    async def test_too_many_fields(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.WARNING):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service,
                                               send_protoconf=False) as assoc:
                    payload = pack_varint(3) + assoc.protoconf.payload()[1:] + b'0'
                    await assoc.send_message(MessageHeader.PROTOCONF, payload)
                    await pause()
                    listener = await listening_assoc(listening_node)
                    # Assert still processed
                    assert listener.their_protoconf == assoc.protoconf
                    await assoc.close()

        assert in_caplog(caplog, 'protoconf message has field count of 3')

    @pytest.mark.asyncio
    async def test_bad_max_payload_length(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.WARNING):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service,
                                               send_protoconf=False) as assoc:
                    assoc.protoconf.max_payload_length = 1024 * 1024 - 1
                    await assoc.send_protoconf()
                    await pause()
                    await assoc.close()

        assert in_caplog(caplog, 'protoconf message has invalid max payload length of 1,048,575')

    @pytest.mark.asyncio
    async def test_oversized_protoconf_message(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                MAX = 1024 * 1024 - 10
                async with client_node.connect(listening_node.service,
                                               send_protoconf=False) as assoc:
                    assoc.protoconf.stream_policies = ['0' * MAX]
                    assert len(assoc.protoconf.payload()) == 1024 * 1024
                    await assoc.send_protoconf()
                    await pause()
                    await assoc.close()

                assert not in_caplog(caplog, 'oversized protoconf message')
                await pause()  # Wait for the listener to close the connection
                caplog.clear()

                async with client_node.connect(listening_node.service,
                                               send_protoconf=False) as assoc:
                    assoc.protoconf.stream_policies = ['0' * (MAX + 1)]
                    await assoc.send_protoconf()
                    await pause()

                assert in_caplog(caplog, 'fatal protocol error: oversized protoconf message')
                assert in_caplog(caplog, 'connection closed remotely')


class TestPing:
    '''PING and PONG tests.'''

    @pytest.mark.asyncio
    async def test_ping_interval(self, client_node, listening_node):
        class ClientAssociation(Association):
            PING_INTERVAL = 0.01

        class ListenerAssociation(Association):
            async def on_ping(self, payload):
                await super().on_ping(payload)
                nonlocal pings_received
                pings_received += 1

        pings_received = 0
        async with listening_node.listen(assoc_cls=ListenerAssociation):
            async with client_node.connect(listening_node.service) as assoc:
                await asyncio.sleep(0.04)
                await assoc.close()

            assert pings_received == 1
            pings_received = 0

            async with client_node.connect(listening_node.service,
                                           assoc_cls=ClientAssociation) as assoc:
                await asyncio.sleep(0.04)
                await assoc.close()

        assert pings_received >= 2

    @pytest.mark.asyncio
    async def test_ping_cutoff(self, client_node, listening_node, caplog):
        class ClientAssociation(Association):
            async def on_ping(self, payload):
                await asyncio.sleep(0.05)
                await super().on_ping(payload)

        class ListenerAssociation(Association):
            PING_CUTOFF = 0.02

        with caplog.at_level(logging.ERROR):
            async with listening_node.listen(assoc_cls=ListenerAssociation):
                async with client_node.connect(listening_node.service) as assoc:
                    await asyncio.sleep(0.04)
                    await assoc.close()

                assert not in_caplog(caplog, 'ping timeout')

                async with client_node.connect(listening_node.service,
                                               assoc_cls=ClientAssociation) as assoc:
                    pass

                assert in_caplog(caplog, 'ping timeout after 0.02s')

    @pytest.mark.asyncio
    async def test_unexpected_pong(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.WARNING):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service) as assoc:
                    await assoc.send_pong(urandom(8))
                    await pause()
                    await assoc.close()

            assert in_caplog(caplog, 'unexpected pong')

    @pytest.mark.asyncio
    @pytest.mark.parametrize('excess_command', (MessageHeader.PING, MessageHeader.PONG))
    async def test_excess(self, client_node, listening_node, caplog, excess_command):
        with caplog.at_level(logging.WARNING):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service,
                                               assoc_cls=ExcessClientAssociation,
                                               excess_command=excess_command,
                                               ) as assoc:
                    await assoc.verack_sent.wait()
                    await assoc.verack_received.wait()
                    await pause()
                    await assoc.close()

        command = excess_command.rstrip(b'\0').decode()
        assert in_caplog(caplog, f'extra bytes at end of {command} payload')

    @pytest.mark.asyncio
    @pytest.mark.parametrize('corrupt_command', (MessageHeader.PING, MessageHeader.PONG))
    async def test_corrupt(self, client_node, listening_node, caplog, corrupt_command):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service,
                                               assoc_cls=CorruptClientAssociation,
                                               corrupt_command=corrupt_command,
                                               ) as assoc:
                    await assoc.send_protoconf()
                    await pause()
                    await assoc.close()

        command = corrupt_command.rstrip(b'\0').decode()
        assert in_caplog(caplog, f'corrupt {command} message')


class TestSendHeaders:

    @pytest.mark.asyncio
    async def test_sendheaders_and_protoconf_are_sent(self, client_node, listening_node):
        async with listening_node.listen():
            async with client_node.connect(listening_node.service) as assoc:
                listener_assoc = await listening_assoc(listening_node)
                assert assoc.they_prefer_headers
                assert listener_assoc.they_prefer_headers
                assert assoc.their_protoconf
                assert listener_assoc.their_protoconf
                await assoc.close()

    @pytest.mark.asyncio
    async def test_understood(self, client_node, listening_node):
        async with listening_node.listen():
            async with client_node.connect(listening_node.service) as assoc:
                assoc.remote_service.protocol_version = 70_011
                await assoc.send_sendheaders()
                assert not assoc.sendheaders_sent
                await assoc.close()

    @pytest.mark.asyncio
    async def test_duplicate(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service) as assoc:
                    listener_assoc = await listening_assoc(listening_node)
                    await assoc.send_sendheaders()
                    await pause()
                    assert listener_assoc.they_prefer_headers

                    with caplog.at_level(logging.WARNING):
                        await assoc.send_sendheaders()
                    assert in_caplog(caplog, 'sendheaders message already sent')
                    await pause()
                    assert not in_caplog(caplog, 'protocol error: duplicate sendheaders message')

                    assoc.sendheaders_sent = False
                    await assoc.send_sendheaders()
                    await pause()
                    assert in_caplog(caplog, 'protocol error: duplicate sendheaders message')
                    await assoc.close()

    @pytest.mark.asyncio
    async def test_excess(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.WARNING):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service,
                                               assoc_cls=ExcessClientAssociation,
                                               excess_command=MessageHeader.SENDHEADERS,
                                               ) as assoc:
                    await assoc.verack_sent.wait()
                    await pause()
                    await assoc.close()

        assert in_caplog(caplog, 'extra bytes at end of sendheaders payload')


class TestGetHeaders:

    @pytest.mark.asyncio
    async def test_waits_for_prior(self, client_node, listening_node, caplog):
        # Test that concurrent getheaders requests wait on the prior one to complete
        class ListenerAssociation(Association):
            MAX_HEADERS = 25

            async def on_getheaders(self, payload):
                nonlocal secs
                await pause(secs)
                secs = 0
                await super().on_getheaders(payload)

        headers = first_mainnet_headers(ListenerAssociation.MAX_HEADERS * 2 + 1)[1:]
        await listening_node.headers.insert_header_chain(headers)
        secs = 0.2

        with caplog.at_level(logging.WARNING):
            async with listening_node.listen(assoc_cls=ListenerAssociation):
                async with client_node.connect(listening_node.service) as assoc:
                    request1 = await assoc.get_headers()
                    request2 = None
                    async with ignore_after(secs / 2):
                        request2 = await assoc.get_headers()
                    assert request2 is None
                    request2 = await assoc.get_headers()
                    await request2.wait()
                    assert request1.count == ListenerAssociation.MAX_HEADERS
                    assert request2.count == ListenerAssociation.MAX_HEADERS
                    await assoc.close()

    @pytest.mark.asyncio
    async def test_hash_stop_only(self, client_node, listening_node, caplog):
        simples = first_mainnet_headers(10)
        await listening_node.headers.insert_header_chain(simples[:5])

        with caplog.at_level(logging.INFO):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service) as assoc:
                    assoc.GETHEADERS_TIMEOUT = 0.1

                    # One known to the listener but doesn't join
                    locator = BlockLocator(1, [], simples[2].hash)
                    request = await assoc.get_headers(locator)
                    assert assoc.getheaders_request is request
                    await request.wait()
                    assert not assoc.getheaders_request
                    assert request.headers == [simples[2]]
                    assert request.count == 0

                    # One known to the listener but doesn't join
                    locator = BlockLocator(1, [], simples[1].hash)
                    request = await assoc.get_headers(locator)
                    assert assoc.getheaders_request is request
                    await request.wait()
                    assert not assoc.getheaders_request
                    assert request.headers == [simples[1]]
                    assert request.count == 1

                    # One not known to the listener; it should ignore the request
                    locator = BlockLocator(1, [], simples[5].hash)
                    request = await assoc.get_headers(locator)
                    assert assoc.getheaders_request is request
                    await request.wait()
                    assert request.count == -1
                    assert not request.headers

                    await assoc.close()

        assert in_caplog(caplog, 'ignoring getheaders for unknown block 000000009b7262315db')

    @pytest.mark.asyncio
    async def test_extend_chain(self, client_node, listening_node, caplog):
        # This tests all cases around correctly-functioning client and listener where they
        # are on different branches, listener on branch A and client on branch B.  They
        # are common for the first 3 mainnet headers, but the client forks to its own
        # branch to height 8, but the listener has mainnet to height 9 as the longest.
        # The listener knows all of branch B except the tip.
        simples = first_mainnet_headers(20)
        await listening_node.headers.insert_header_chain(simples[:10])

        client_branch = simples[:3]
        client_branch.extend(create_random_branch(client_branch[-1], 5))
        count, tip = await client_node.headers.insert_header_chain(client_branch, check_work=False)
        assert count == 7
        count, tip = await listening_node.headers.insert_header_chain(client_branch[:-1],
                                                                      check_work=False)
        assert count == 4
        client_chain = await client_node.headers.longest_chain()
        assert client_chain.tip.hash == client_branch[-1].hash

        with caplog.at_level(logging.INFO):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service) as assoc:
                    request = await assoc.get_headers()
                    await request.wait()
                    assert request.count == 7

                    client_chain = await client_node.headers.longest_chain()
                    listening_chain = await listening_node.headers.longest_chain()
                    assert client_chain.tip == listening_chain.tip

                    # Now extend the listener chain to height 19.  Test that hash_stop is
                    # honoured when the client provides it (how exactly the client knows
                    # the hash is another question....)
                    await listening_node.headers.insert_header_chain(simples[10:])
                    listening_chain = await listening_node.headers.longest_chain()
                    assert client_chain.tip != listening_chain.tip

                    to_height = 15
                    hash_stop = simples[to_height].hash
                    locator = await assoc.block_locator()
                    locator.hash_stop = hash_stop
                    request = await assoc.get_headers(locator)
                    await request.wait()
                    assert request.count == 6

                    client_chain = await client_node.headers.longest_chain()
                    assert client_chain.tip.height == to_height
                    header = await listening_node.headers.header_at_height(listening_chain,
                                                                           to_height)
                    assert header == client_chain.tip
                    assert not in_caplog(caplog, 'headers synchronized')

                    # The hash stop doesn't work now as we start after the tip...
                    locator = await assoc.block_locator()
                    locator.hash_stop = hash_stop
                    request = await assoc.get_headers(locator)
                    await request.wait()
                    assert request.count == 4
                    client_chain = await client_node.headers.longest_chain()
                    assert client_chain.tip == listening_chain.tip

                    assert not in_caplog(caplog, 'headers synchronized')

                    request = await assoc.get_headers()
                    await request.wait()
                    assert request.count == 0
                    assert in_caplog(caplog, 'headers synchronized to height 19')
                    await assoc.close()

    @pytest.mark.asyncio
    async def test_shorter(self, client_node, listening_node, caplog):
        # This tests all cases around correctly-functioning client and listener where they
        # are on different branches, branches A and B.  The listener is on branch A to
        # height 9, and the client on branch B which is longer.  The listener knows some of
        # branch B.
        simples = first_mainnet_headers(10)
        await listening_node.headers.insert_header_chain(simples)

        client_branch = simples[:3]
        client_branch.extend(create_random_branch(client_branch[-1], 10))
        await client_node.headers.insert_header_chain(client_branch, check_work=False)
        await listening_node.headers.insert_header_chain(client_branch[:-5], check_work=False)
        client_chain = await client_node.headers.longest_chain()
        assert client_chain.tip.hash == client_branch[-1].hash

        with caplog.at_level(logging.INFO):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service) as assoc:
                    request = await assoc.get_headers()
                    await request.wait()
                    assert not in_caplog(caplog, 'headers synchronized to height 9')
                    request = await assoc.get_headers()
                    await request.wait()
                    assert in_caplog(caplog, 'headers synchronized to height 9')

                    # Check neither chain has grown
                    client_chain = await client_node.headers.longest_chain()
                    listening_chain = await listening_node.headers.longest_chain()
                    assert client_chain.tip.hash == client_branch[-1].hash
                    assert listening_chain.tip.hash == simples[-1].hash

                    await assoc.close()

    @pytest.mark.asyncio
    async def test_not_a_chain(self, client_node, listening_node, caplog):
        '''The remote assoc sends, unrequested, 6 headers that do not form a chain.'''
        class ListenerAssociation(Association):
            async def on_getheaders(self, payload):
                branch = create_random_branch(Bitcoin.genesis_header, 5)
                branch.extend(create_random_branch(Bitcoin.genesis_header, 1))
                await self.send_message(MessageHeader.HEADERS, pack_headers_payload(branch))

        with caplog.at_level(logging.ERROR):
            async with listening_node.listen(assoc_cls=ListenerAssociation):
                async with client_node.connect(listening_node.service) as assoc:
                    assoc.GETHEADERS_TIMEOUT = 0.1
                    request = await assoc.get_headers()
                    await request.wait()
                    # Check the response was logged and viewed as a response to our request
                    assert in_caplog(caplog, 'protocol error: headers do not form a chain')
                    assert request.count == 0
                    assert request.headers
                    await assoc.close()

    @pytest.mark.asyncio
    async def test_separated(self, client_node, listening_node, caplog):
        class ListenerAssociation(Association):
            async def on_getheaders(self, payload):
                # Headers do not connect to genesis
                await self.send_message(MessageHeader.HEADERS, pack_headers_payload(simples[2:]))

        simples = first_mainnet_headers(10)
        with caplog.at_level(logging.WARNING):
            async with listening_node.listen(assoc_cls=ListenerAssociation):
                async with client_node.connect(listening_node.service) as assoc:
                    assoc.GETHEADERS_TIMEOUT = 0.1
                    request = await assoc.get_headers()
                    await request.wait()
                    # Check the response was logged and not viewed as a response to our
                    # request
                    assert in_caplog(caplog, 'ignoring 8 non-connecting headers')
                    assert request.count == -1
                    assert not request.headers
                    await assoc.close()

    @pytest.mark.asyncio
    async def test_bad_pow(self, client_node, listening_node, caplog):
        class ListenerAssociation(Association):
            async def on_getheaders(self, payload):
                await self.send_message(MessageHeader.HEADERS, pack_headers_payload(branch))

        print_caplog(caplog)
        branch = create_random_branch(Bitcoin.genesis_header, 2)
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen(assoc_cls=ListenerAssociation):
                async with client_node.connect(listening_node.service) as assoc:
                    request = await assoc.get_headers()
                    await request.wait()
                    # Check the response was logged AND viewed as a response to our request
                    assert in_caplog(caplog, 'hash value exceeds its target')
                    assert request.count == 0
                    assert request.headers == branch
                    await assoc.close()

    @pytest.mark.asyncio
    async def test_excess_getheaders(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.WARNING):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service,
                                               assoc_cls=ExcessClientAssociation,
                                               excess_command=MessageHeader.GETHEADERS,
                                               ) as assoc:
                    request = await assoc.get_headers()
                    await request.wait()
                    await assoc.close()

        assert in_caplog(caplog, 'extra bytes at end of getheaders payload')

    @pytest.mark.asyncio
    async def test_corrupt_getheaders(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service,
                                               assoc_cls=CorruptClientAssociation,
                                               corrupt_command=MessageHeader.GETHEADERS,
                                               ) as assoc:
                    await assoc.get_headers()
                    await pause()
                    await assoc.close()

        assert in_caplog(caplog, 'corrupt getheaders message')

    @pytest.mark.asyncio
    async def test_excess_headers(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.WARNING):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service,
                                               assoc_cls=ExcessClientAssociation,
                                               excess_command=MessageHeader.HEADERS,
                                               ) as assoc:
                    await assoc.send_headers([])
                    await pause()
                    await assoc.close()

        assert in_caplog(caplog, 'extra bytes at end of headers payload')

    @pytest.mark.asyncio
    async def test_corrupt_headers(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service,
                                               assoc_cls=CorruptClientAssociation,
                                               corrupt_command=MessageHeader.HEADERS,
                                               ) as assoc:
                    await assoc.send_headers([])
                    await pause()
                    await assoc.close()

        assert in_caplog(caplog, 'corrupt headers message')

    @pytest.mark.asyncio
    async def test_too_many_sent(self, client_node, listening_node, caplog):
        headers = first_mainnet_headers(10)[1:]
        await listening_node.headers.insert_header_chain(headers)

        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service) as assoc:
                    assoc.MAX_HEADERS = 5
                    request = await assoc.get_headers()
                    await request.wait()
                    # Check it is diagnosed AND recognised as a response to our request
                    assert in_caplog(caplog, 'headers message with 9 headers but limit is 5')
                    assert request.headers == headers
                    assert request.count == 0
                    await assoc.close()


class TestSyncHeaders:

    @pytest.mark.asyncio
    async def test_lock(self, client_node, listening_node, listening_node2):
        class ListenerAssociation(Association):
            async def on_getheaders(self, payload):
                nonlocal requests
                requests += 1
                await asyncio.sleep(1.0)

        async def create_client(lnode):
            async with client_node.connect(lnode.service) as assoc:

                async with ignore_after(0.1):
                    await assoc.sync_headers()
                await assoc.close()

        requests = 0
        async with listening_node.listen(assoc_cls=ListenerAssociation):
            async with listening_node2.listen(assoc_cls=ListenerAssociation):
                async with TaskGroup() as group:
                    group.create_task(create_client(listening_node))
                    group.create_task(create_client(listening_node2))

        assert requests == 1

    @pytest.mark.asyncio
    async def test_works(self, client_node, listening_node):
        # Test that the client syncs with the listening node, even when it's on a branch
        # whose length is greater than the atomic send limit, and the listener occasionally
        # sends a disconnected header
        class ListenerAssociation(Association):
            COUNT = 0
            MAX_HEADERS = 10

            async def on_getheaders(self, payload):
                await super().on_getheaders(payload)
                if self.COUNT % 3 == 0:
                    chain = await self.node.headers.longest_chain()
                    height = 95 + self.COUNT // 3
                    header = await self.node.headers.header_at_height(chain, height)
                    await self.send_headers([header])
                self.COUNT += 1

        # Client is on a branch of length 25 from genesis
        branch = create_random_branch(Bitcoin.genesis_header, 25)
        count, tip = await client_node.headers.insert_header_chain(branch, check_work=False)
        assert count == 25

        # Listening node has the first 101 mainnet heaaders, to height 100
        height = 100
        headers = first_mainnet_headers(height + 1)
        count, tip = await listening_node.headers.insert_header_chain(headers)
        assert count == height

        async with listening_node.listen(assoc_cls=ListenerAssociation):
            async with client_node.connect(listening_node.service) as assoc:
                assert await assoc.sync_headers()
                assert not await assoc.sync_headers()
                await assoc.close()

        assert await client_node.headers.height() == height


class TestStreams:
    '''Tests for CREATESTRM message and assoc_id negotiation.'''

    @pytest.mark.asyncio
    async def test_assoc_id_echoed(self, client_node, listening_node):
        async with listening_node.listen():
            assert listening_node.enable_multistreams
            async with client_node.connect(listening_node.service) as assoc:
                assert len(assoc.assoc_id) == 17
                await assoc.verack_received.wait()
                listener_assoc = await listening_assoc(listening_node)
                assert listener_assoc.assoc_id == assoc.assoc_id
                await assoc.close()

    @pytest.mark.asyncio
    async def test_assoc_id_echo_failure(self, client_node, listening_node, caplog):
        class ListenerAssociation(Association):
            async def version_payload(self):
                self.assoc_id = b'foobar'
                return await super().version_payload()

        async with listening_node.listen(assoc_cls=ListenerAssociation):
            with pytest.raises(ProtocolError) as e:
                async with client_node.connect(listening_node.service):
                    await pause()

        assert str(e.value) == 'fatal protocol error: version message has wrong assoc_id'

    @pytest.mark.asyncio
    async def test_remote_multistreams_disabled(self, client_node, listening_node):
        async with listening_node.listen():
            listening_node.enable_multistreams = False
            async with client_node.connect(listening_node.service) as assoc:
                await assoc.verack_received.wait()
                listener_assoc = await listening_assoc(listening_node)
                assert assoc.assoc_id is None
                assert listener_assoc.assoc_id is None
                await assoc.close()

    @pytest.mark.asyncio
    async def test_local_multistreams_disabled(self, client_node, listening_node):
        client_node.enable_multistreams = False
        async with listening_node.listen():
            async with client_node.connect(listening_node.service) as assoc:
                await assoc.verack_received.wait()
                listener_assoc = await listening_assoc(listening_node)
                assert assoc.assoc_id is None
                assert listener_assoc.assoc_id is None
                await assoc.close()

    @pytest.mark.asyncio
    async def test_multistream_works(self, client_node, listening_node, caplog):
        protoconf = Protoconf(2_000_000, ['Default', 'BlockPriority'])
        with caplog.at_level(logging.INFO):
            async with listening_node.listen(protoconf=protoconf):
                async with client_node.connect(listening_node.service,
                                               protoconf=protoconf) as assoc:
                    await assoc.verack_received.wait()
                    await pause(0.1)
                    assert len(assoc.streams) == 2

                    assert len(listening_node.assocs) == 1
                    lassoc = list(listening_node.assocs)[0]
                    assert len(lassoc.streams) == 2

                    # Test a fake block is sent on the second stream
                    sent_bytes = [stream.sent_bytes for stream in assoc.streams]
                    await assoc.send_message(MessageHeader.BLOCK, bytes(1000))
                    await pause(0.01)
                    assert assoc.streams[1].sent_bytes > sent_bytes[1] + 1000
                    assert assoc.streams[0].sent_bytes < sent_bytes[0] + 100

                    # Test a fake tx is sent on the first stream
                    sent_bytes = [stream.sent_bytes for stream in assoc.streams]
                    await assoc.send_message(MessageHeader.TX, bytes(1000))
                    await pause(0.01)
                    assert assoc.streams[1].sent_bytes == sent_bytes[1]
                    assert assoc.streams[0].sent_bytes > sent_bytes[0] + 1000

                    await assoc.close()

        assert in_caplog(caplog, 'common stream policies: [BlockPriority, Default]')
        assert in_caplog(caplog, 'implementing stream policy BlockPriority')
        assert in_caplog(caplog, 'streamack received, activating stream <StreamKind.DATA1: 1>')

    @pytest.mark.asyncio
    async def test_createstrm_no_common_assoc_id(self, client_node, listening_node):
        async with listening_node.listen():
            listening_node.enable_multistreams = False
            async with client_node.connect(listening_node.service) as assoc:
                await assoc.verack_received.wait()
                with pytest.raises(RuntimeError) as e:
                    await assoc.send_createstrm(assoc.streams[0])
                assert str(e.value) == 'common association ID is not established'
                await assoc.close()

    @pytest.mark.asyncio
    async def test_createstrm_GENERAL(self, client_node, listening_node):
        async with listening_node.listen():
            async with client_node.connect(listening_node.service) as assoc:
                await assoc.verack_received.wait()
                stream = Stream(None, None, StreamKind.GENERAL, 'policy')
                assoc.streams.append(stream)
                with pytest.raises(RuntimeError) as e:
                    await assoc.send_createstrm(stream)
                assoc.streams.pop()
                assert str(e.value) == 'send_createstrm: cannot use a GENERAL stream'
                await assoc.close()

    @pytest.mark.asyncio
    async def test_createstrm_active(self, client_node, listening_node):
        async with listening_node.listen():
            async with client_node.connect(listening_node.service) as assoc:
                await assoc.verack_received.wait()
                stream = Stream(None, None, StreamKind.DATA1, 'policy')
                stream.is_active = True
                assoc.streams.append(stream)
                with pytest.raises(RuntimeError) as e:
                    await assoc.send_createstrm(stream)
                assoc.streams.pop()
                assert str(e.value) == 'send_createstrm: stream is active'
                await assoc.close()

    @pytest.mark.asyncio
    async def test_createstrm_not_ours(self, client_node, listening_node):
        async with listening_node.listen():
            async with client_node.connect(listening_node.service) as assoc:
                await assoc.verack_received.wait()
                stream = Stream(None, None, StreamKind.DATA1, 'policy')
                with pytest.raises(RuntimeError) as e:
                    await assoc.send_createstrm(stream)
                assert str(e.value) == 'send_createstrm: stream is not ours'
                await assoc.close()

    @pytest.mark.asyncio
    async def test_createstrm_pending(self, client_node, listening_node):
        class ListenerAssociation(Association):
            async def on_createstrm(self, payload):
                await pause(0.1)

        async with listening_node.listen(assoc_cls=ListenerAssociation):
            async with client_node.connect(listening_node.service) as assoc:
                await assoc.verack_received.wait()
                await assoc.open_stream(StreamKind.DATA1, 'policy')
                stream = assoc.streams[1]
                await pause(0.02)
                with pytest.raises(RuntimeError) as e:
                    await assoc.send_createstrm(stream)
                assert str(e.value) == 'createstrm message already pending'
                await assoc.close()

    @pytest.mark.asyncio
    async def test_createstrm_after_version(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service) as assoc:
                    await assoc.verack_received.wait()
                    await assoc.send_message(MessageHeader.CREATESTRM, b'')
                    await pause()
                    assert in_caplog(caplog, 'received createstrm after version message')
                    assert in_caplog(caplog, 'connection closed remotely')

    @pytest.mark.asyncio
    async def test_createstrm_bad_assoc_id(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service) as assoc:
                    await assoc.verack_received.wait()
                    assoc.assoc_id = bytes(17)
                    await assoc.open_stream(StreamKind.DATA1, 'policy')
                    await pause()
                    assert in_caplog(caplog, 'received createstrm for unknown assoc_id')
                    assert in_caplog(caplog, 'connection closed remotely')

    @pytest.mark.asyncio
    async def test_streamack_no_common_assoc_id(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            listening_node.enable_multistreams = False
            async with listening_node.listen():
                async with client_node.connect(listening_node.service) as assoc:
                    await assoc.verack_received.wait()
                    assoc.assoc_id = assoc.random_assoc_id()
                    await assoc.send_streamack(StreamKind.DATA1)
                    await pause()
                    assert in_caplog(caplog, 'received streamack for unknown assoc_id')
                    assert in_caplog(caplog, 'connection closed remotely')

    @pytest.mark.asyncio
    async def test_unexpected_streamack(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service) as assoc:
                    await assoc.verack_received.wait()
                    await assoc.send_streamack(StreamKind.DATA1)
                    await pause()
                    assert in_caplog(caplog, 'fatal protocol error: unexpected streamack '
                                     'for stream kind <StreamKind.DATA1: 1>')
                    assert in_caplog(caplog, 'connection closed remotely')
