import asyncio
import copy
import logging
import platform
import sys
import time
from io import BytesIO
from ipaddress import IPv4Address, IPv6Address
from os import urandom

import asqlite3
import pytest
import pytest_asyncio

from bitcoinx import (
    Bitcoin, BitcoinTestnet, pack_varint, _version_str, double_sha256, pack_le_int32, pack_list,
    Headers, all_networks, ProtocolError, PackingError,
    NetAddress, BitcoinService, ServiceFlags, Protoconf, MessageHeader,
    Service, is_valid_hostname, validate_port, validate_protocol, classify_host,
    ServicePart, Node, Session, SimpleHeader
)
from bitcoinx.misc import chunks
from bitcoinx.net_protocol import (
    ServicePacking, BlockLocator, version_payload, read_version, _command,
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
X_protoconf = Protoconf(2_000_000, [b'Default', b'BlockPriority'])
X_service = BitcoinService(
    services=ServiceFlags.NODE_NETWORK,
    address=X_address,
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
        assert service.assoc_id == b'Default'
        assert service.start_height == 5

    def test_service_default(self):
        service = BitcoinService()
        assert service.address == NetAddress('::', 0, check_port=False)
        assert service.services == ServiceFlags.NODE_NONE
        assert service.protocol_version in (70_015, 70_016)
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
        pc = Protoconf.read(BytesIO(bytes.fromhex(result)).read)
        assert pc.max_payload == max_payload
        assert pc.stream_policies == policies

    @pytest.mark.parametrize('N', (0, 1))
    def test_bad_field_count(self, N):
        raw = bytearray(Protoconf(2_000_000, [b'Default']).payload())
        raw[0] = N
        with pytest.raises(ProtocolError):
            Protoconf.read(BytesIO(raw).read)

    def test_bad_max_payload(self):
        raw = Protoconf(Protoconf.LEGACY_MAX_PAYLOAD - 1, [b'Default']).payload()
        with pytest.raises(ProtocolError):
            Protoconf.read(BytesIO(raw).read)

    def test_logging(self, caplog):
        raw = bytearray(Protoconf(2_000_000, [b'Default']).payload())
        raw[0] = 3
        with caplog.at_level('WARNING'):
            Protoconf.read(BytesIO(raw).read)
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
            assert 'ill-formed extended message header' == str(e.value)

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
            version_payload(X_service, BitcoinService(), bytes(7))
        assert 'nonce must be 8 bytes' == str(e.value)

    def test_version_payload_theirs_default(self):
        nonce = b'1234beef'
        remote_service = BitcoinService()
        payload = version_payload(X_service, remote_service, nonce)
        assert payload == bytes.fromhex(
            '80380100010000000000000020a1070000000000000000000000000000000000000000000000000000'
            '0000000000010000000000000000000000000000000000ffff01020304162e31323334626565660c2f'
            '666f6f6261723a312e302f05000000000744656661756c74')
        service = BitcoinService()
        service.address = X_service.address
        result = read_version(service, BytesIO(payload).read)
        assert service == X_service
        assert result == (remote_service.address, remote_service.services, nonce)

    def test_version_payload_theirs_X(self):
        nonce = b'1234beef'
        remote_service = copy.copy(X_service)
        payload = version_payload(X_service, remote_service, nonce)
        assert payload == bytes.fromhex(
            '80380100010000000000000020a1070000000000010000000000000000000000000000000000ffff01'
            '020304162e010000000000000000000000000000000000ffff01020304162e31323334626565660c2f'
            '666f6f6261723a312e302f05000000000744656661756c74')
        service = BitcoinService()
        service.address = X_service.address
        result = read_version(service, BytesIO(payload).read)
        assert service == X_service
        assert result == (remote_service.address, remote_service.services, nonce)

    def test_version_payload_NetAddress(self):
        nonce = b'cabbages'
        address = NetAddress('1.2.3.4', 5)
        payload = version_payload(X_service, address, nonce)
        assert payload == bytes.fromhex(
            '80380100010000000000000020a1070000000000000000000000000000000000000000000000ffff01'
            '0203040005010000000000000000000000000000000000ffff01020304162e63616262616765730c2f'
            '666f6f6261723a312e302f05000000000744656661756c74')
        service = BitcoinService(address=address)
        service_copy = copy.copy(service)
        result = read_version(service, BytesIO(payload).read)
        assert service == service_copy
        assert result == (address, ServiceFlags.NODE_NONE, nonce)

    def test_version_payload_timestamp_None(self):
        nonce = b'cabbages'
        service = copy.copy(X_service)
        service.timestamp = None
        payload = version_payload(service, X_service, nonce)

        service2 = BitcoinService(address=service.address)
        result = read_version(service2, BytesIO(payload).read)
        assert 0 < time.time() - service2.timestamp < 5
        service.timestamp = service2.timestamp
        assert service == service2
        assert result == (X_service.address, X_service.services, nonce)

    def test_version_payload_assoc_id_None(self):
        nonce = b'cabbages'
        service = copy.copy(X_service)
        service.assoc_id = None
        payload = version_payload(service, X_service, nonce)

        service2 = BitcoinService(address=service.address)
        result = read_version(service, BytesIO(payload).read)
        assert service2.assoc_id is None
        assert service == service2
        assert result == (X_service.address, X_service.services, nonce)

    def test_read_version_payload_undecodeable_user_agent(self):
        nonce = b'cabbages'
        service = copy.copy(X_service)
        service.user_agent = 'xxx'
        payload = version_payload(service, X_service, nonce)
        # Non-UTF8 user agent
        payload = payload.replace(b'xxx', b'\xff' * 3)

        service2 = BitcoinService(address=service.address)
        result = read_version(service2, BytesIO(payload).read)
        assert service2.user_agent == '0xffffff'
        service2.user_agent = service.user_agent
        assert service == service2
        assert result == (X_service.address, X_service.services, nonce)

    def test_read_version_payload_no_relay(self):
        nonce = b'cabbages'
        service = BitcoinService()
        payload = version_payload(service, X_service, nonce)

        service2 = BitcoinService(address=service.address)
        result = read_version(service2, BytesIO(payload).read)
        assert service2.assoc_id is None
        assert service2.relay is True
        assert service == service2
        assert result == (X_service.address, X_service.services, nonce)


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
        headers = Headers(conn, 'main', Bitcoin)
        await headers.initialize()
        yield headers


@pytest.fixture
def listening_node(listening_headers):
    service = BitcoinService(address=NetAddress(listen_host, 5656))
    node = Node(service, listening_headers)
    yield node
    if sys.version_info >= (3, 12):
        assert not node.sessions
    else:
        assert all(not session.is_outgoing for session in node.sessions)


@pytest.fixture
def listening_node2(listening_headers):
    service = BitcoinService(address=NetAddress(listen_host, 5657))
    node = Node(service, listening_headers)
    yield node


async def listening_session(listening_node):
    await pause()
    for session in listening_node.sessions:
        if not session.is_outgoing:
            return session
    raise RuntimeError('no listening sessions')


@pytest_asyncio.fixture
async def client_headers():
    async with asqlite3.connect(':memory:') as conn:
        headers = Headers(conn, 'main', Bitcoin)
        await headers.initialize()
        yield headers


@pytest.fixture
def client_node(client_headers):
    node = Node(BitcoinService(), client_headers)
    yield node
    # assert not node.sessions


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


class TestNode:

    @pytest.mark.asyncio
    async def test_simple_listen(self, listening_node):
        async with listening_node.listen():
            assert listening_node.service.address.host == listen_host
            assert listening_node.network is Bitcoin


class TestSession:

    @pytest.mark.asyncio
    async def test_simple_connect(self, client_node, listening_node):
        async with listening_node.listen():
            async with client_node.connect(listening_node.service) as session:
                assert isinstance(session, Session)
                assert session.node is client_node
                assert session.remote_service is listening_node.service
                assert session.is_outgoing
                assert session.protoconf == Protoconf.default()

                listen_session = await listening_session(listening_node)
                assert isinstance(listen_session, Session)
                assert listen_session.node is listening_node
                assert listen_session.remote_service.address.host == listen_host
                assert not listen_session.is_outgoing
                assert listen_session.protoconf == Protoconf.default()
                await session.close()

    @pytest.mark.asyncio
    async def test_bad_magic(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                client_node.network = BitcoinTestnet
                with pytest.raises(ConnectionResetError):
                    async with client_node.connect(listening_node.service):
                        pass

        assert in_caplog(caplog, 'fatal protocol error: bad magic 0xf4e5f3f4 expected 0xe3e1f3e8')

    @pytest.mark.asyncio
    @pytest.mark.parametrize('force_extended', (False, True))
    async def test_bad_magic_later(self, client_node, listening_node, caplog, force_extended):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                with pytest.raises(ConnectionResetError):
                    async with client_node.connect(listening_node.service) as session:
                        await session.handshake_complete.wait()
                        payload = b''
                        header = MessageHeader.std_bytes(BitcoinTestnet.magic,
                                                         MessageHeader.SENDHEADERS, payload)
                        await session.connection.outgoing_messages.put((header, payload))
                        await pause()
                        await session.close()

        assert in_caplog(caplog, 'fatal protocol error: bad magic 0xf4e5f3f4 expected 0xe3e1f3e8')

    @pytest.mark.asyncio
    async def test_bad_checksum(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service) as session:
                    # So it is not a disconnection
                    await session.handshake_complete.wait()
                    payload = b''
                    header = MessageHeader.std_bytes(client_node.network.magic,
                                                     MessageHeader.SENDHEADERS, payload)
                    # Mess up the checksum
                    header = bytearray(header)
                    header[-1] ^= 0x0f
                    await session.connection.outgoing_messages.put((header, payload))
                    await pause()
                    await session.close()

        assert in_caplog(caplog, 'protocol error: bad checksum for sendheaders command')

    @pytest.mark.asyncio
    async def test_unhandled_command(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.DEBUG):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service) as session:
                    await session.send_message(_command('zombie'), b'')
                    await pause()
                    await session.close()

        assert in_caplog(caplog, 'ignoring unhandled zombie message')

    #
    # VERSION message tests
    #

    @pytest.mark.asyncio
    async def test_listener_waits_for_version_message(self, client_node, listening_node):
        class ClientSession(Session):
            async def setup_session(self):
                async with timeout_after(0.1):
                    await self.connection.recv_exactly(1)

        async with listening_node.listen():
            with pytest.raises(TimeoutError):
                async with client_node.connect(listening_node.service, session_cls=ClientSession):
                    pass

    @pytest.mark.asyncio
    async def test_client_sends_version_message(self, client_node, listening_node):
        class ListeningSession(Session):
            async def on_version(self, payload):
                await self.close()

        async with listening_node.listen(session_cls=ListeningSession):
            with pytest.raises(ConnectionResetError):
                async with client_node.connect(listening_node.service):
                    pass

    @pytest.mark.asyncio
    async def test_duplicate_version(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service,
                                               perform_handshake=False) as session:
                    await session.send_version()
                    with caplog.at_level(logging.WARNING):
                        await session.send_version()
                    assert in_caplog(caplog, 'version message already sent')
                    await pause()
                    assert not in_caplog(caplog, 'duplicate version message')

                    session.version_sent = False
                    await session.send_version()
                    await pause()
                    await session.close()

        assert in_caplog(caplog, 'protocol error: duplicate version message')

    @pytest.mark.asyncio
    async def test_send_verack_first(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                with pytest.raises(ConnectionResetError):
                    async with client_node.connect(listening_node.service,
                                                   perform_handshake=False) as session:
                        await session.send_verack()

        assert in_caplog(caplog, 'verack message received before version message sent')

    @pytest.mark.asyncio
    async def test_send_other_first(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                with pytest.raises(ConnectionResetError):
                    async with client_node.connect(listening_node.service,
                                                   perform_handshake=False) as session:
                        # Don't use send_message to force the first message
                        command = MessageHeader.SENDHEADERS
                        payload = b''
                        header = MessageHeader.std_bytes(session.node.network.magic,
                                                         command, payload)
                        await session.connection.outgoing_messages.put((header, payload))

        assert in_caplog(caplog, 'sendheaders command received before handshake finished')

    @pytest.mark.asyncio
    async def test_send_corrupt_version_message(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                with pytest.raises(ConnectionResetError):
                    async with client_node.connect(listening_node.service,
                                                   perform_handshake=False) as session:
                        await session.send_message(MessageHeader.VERSION, bytes(10))

        assert in_caplog(caplog, 'corrupt version message')

    @pytest.mark.asyncio
    async def test_send_long_version_message(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.WARNING):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service,
                                               perform_handshake=False) as session:
                    await session.send_message(MessageHeader.VERSION,
                                               await session.version_payload() + bytes(2))
                    await pause()
                    await session.close()

        assert in_caplog(caplog, 'extra bytes at end of version payload')

    @pytest.mark.asyncio
    async def test_self_connect(self, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                with pytest.raises(ConnectionResetError):
                    async with listening_node.connect(listening_node.service):
                        pass

        assert in_caplog(caplog, 'protocol error: connected to ourself')
        assert in_caplog(caplog, 'connection closed remotely')

    #
    # VERACK / handshake tests
    #

    @pytest.mark.asyncio
    async def test_duplicate_verack(self, client_node, listening_node, caplog):
        class ClientSession(Session):
            async def send_verack(self):
                await super().send_verack()
                await super().send_verack()
                await pause()
                await self.close()

        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service, session_cls=ClientSession):
                    pass

        assert in_caplog(caplog, 'protocol error: duplicate verack message')

    @pytest.mark.asyncio
    async def test_verack_payload(self, client_node, listening_node, caplog):
        class ClientSession(Session):
            async def send_verack(self):
                await self.send_message(MessageHeader.VERACK, b'0')
                await pause()
                await self.close()

        with caplog.at_level(logging.WARNING):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service, session_cls=ClientSession):
                    pass

        assert in_caplog(caplog, 'extra bytes at end of verack payload')

    @pytest.mark.asyncio
    async def test_hc_verack_received_first(self, client_node, listening_node):
        '''Test the handshake is only complete AFTER verack is sent when verack is received
        first.'''
        class ClientSession(Session):
            async def on_verack(self, payload):
                await super().on_verack(payload)
                received_event.set()

            async def send_verack(self):
                try:
                    await received_event.wait()
                    assert not self.handshake_complete.is_set()
                    await super().send_verack()
                    assert self.handshake_complete.is_set()
                finally:
                    finished_event.set()

        received_event = asyncio.Event()
        finished_event = asyncio.Event()

        # Test verack received before handshake is complete when verack is received
        async with listening_node.listen():
            async with client_node.connect(listening_node.service,
                                           session_cls=ClientSession) as session:
                await finished_event.wait()
                await session.close()

    @pytest.mark.asyncio
    async def test_hc_verack_sent_first(self, client_node, listening_node):
        '''Test the handshake is only complete AFTER verack is received when verack is sent
        first.'''
        class ClientSession(Session):
            async def on_verack(self, payload):
                try:
                    await sent_event.wait()
                    assert not self.handshake_complete.is_set()
                    await super().on_verack(payload)
                    assert self.handshake_complete.is_set()
                finally:
                    finished_event.set()

            async def send_verack(self):
                await super().send_verack()
                sent_event.set()

        sent_event = asyncio.Event()
        finished_event = asyncio.Event()

        # Test verack received before handshake is complete when verack is received
        async with listening_node.listen():
            async with client_node.connect(listening_node.service,
                                           session_cls=ClientSession) as session:
                await finished_event.wait()
                await session.close()

    @pytest.mark.asyncio
    @pytest.mark.parametrize('slow', ('version', 'verack'))
    async def test_handshake_timeout(self, client_node, listening_node, slow):
        '''Test the handshake is only complete AFTER verack is received when verack is sent
        first.'''
        class ListeningSession(Session):
            async def send_version(self):
                if slow == 'version':
                    await pause(ClientSession.HANDSHAKE_TIMEOUT * 2)
                await super().send_version()

            async def send_verack(self):
                if slow == 'verack':
                    await pause(ClientSession.HANDSHAKE_TIMEOUT * 2)
                await super().send_verack()

        class ClientSession(Session):
            HANDSHAKE_TIMEOUT = 0.1

        async with listening_node.listen(session_cls=ListeningSession):
            with pytest.raises(TimeoutError):
                async with client_node.connect(listening_node.service,
                                               session_cls=ClientSession) as session:
                    await pause(session.HANDSHAKE_TIMEOUT * 1.5)
            await pause()

    #
    # PROTOCONF message tests
    #

    @pytest.mark.asyncio
    async def test_protoconf_understood(self, client_node, listening_node):
        async with listening_node.listen():
            async with client_node.connect(listening_node.service,
                                           send_protoconf=False) as session:
                listener_session = await listening_session(listening_node)
                assert listener_session.their_protoconf is None
                await session.send_protoconf()
                await pause()
                assert listener_session.their_protoconf == session.protoconf
                await session.close()

    @pytest.mark.asyncio
    @pytest.mark.parametrize('force', (True, False))
    async def test_duplicate_protoconf(self, client_node, listening_node, caplog, force):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service,
                                               send_protoconf=False) as session:
                    await session.send_protoconf()
                    if force:
                        session.protoconf_sent = False
                    await session.send_protoconf()
                    await pause()
                    await session.close()

        assert in_caplog(caplog, 'duplicate protoconf') is force

    #
    # EXTMSG message tests
    #

    @pytest.mark.asyncio
    async def test_send_protoconf_as_ext_message(self, client_node, listening_node):
        async with listening_node.listen():
            async with client_node.connect(listening_node.service,
                                           send_protoconf=False) as session:
                listener_session = await listening_session(listening_node)
                assert listener_session.their_protoconf is None
                session.our_protoconf = Protoconf(2_000_000, [b'foo', b'bar'])
                payload = session.our_protoconf.payload()
                await session.send_message(MessageHeader.PROTOCONF, payload, force_extended=True)
                await pause()
                assert listener_session.their_protoconf == session.our_protoconf
                await session.close()

    @pytest.mark.asyncio
    async def test_cannot_send_ext_message(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            listening_node.service.protocol_version = 70_015
            async with listening_node.listen():
                with pytest.raises(ConnectionResetError):
                    async with client_node.connect(listening_node.service,
                                                   send_protoconf=False) as session:
                        await session.handshake_complete.wait()
                        payload = Protoconf.default().payload()
                        assert not session.can_send_ext_messages
                        # We should not accept sending a large message
                        with pytest.raises(RuntimeError):
                            await session.send_message(MessageHeader.PROTOCONF, payload,
                                                       force_extended=True)
                        # Override the check
                        session.can_send_ext_messages = True
                        await session.send_message(MessageHeader.PROTOCONF, payload,
                                                   force_extended=True)
                        pass

        assert in_caplog(caplog, 'ext message received but invalid', count=2)

    @pytest.mark.asyncio
    async def test_send_streaming_message(self, client_node, listening_node, caplog):
        class ListeningSession(Session):
            async def on_zombie_large(self, connection, size):
                parts = [chunk async for chunk in connection.recv_chunks(size)]
                self.zombie_payload = b''.join(parts)

            async def on_zombie(self, payload):
                self.zombie_payload2 = payload.payload

        payload = urandom(2000)
        with caplog.at_level(logging.WARNING):
            async with listening_node.listen(session_cls=ListeningSession):
                async with client_node.connect(listening_node.service) as session:
                    listener_session = await listening_session(listening_node)
                    listener_session.streaming_min_size = 200
                    await session.send_message(_command('zombie'),
                                               (achunks(payload, 100), len(payload)))
                    await session.send_message(_command('zombie'), payload)
                    await session.send_message(_command('ghoul'),
                                               (achunks(payload, 100), len(payload)))
                    await pause()
                    assert listener_session.zombie_payload == payload
                    assert listener_session.zombie_payload2 == payload
                    await session.close()

        assert in_caplog(caplog, 'ignoring unhandled extended ghoul messages')

    @pytest.mark.asyncio
    async def test_whole_session_extended(self, client_node, listening_node):
        '''Test sending every message as extended, even the version message.'''
        class ClientSession(Session):
            async def send_message(self, command, payload, *, force_extended=False):
                await super().send_message(command, payload, force_extended=True)

        async with listening_node.listen():
            async with client_node.connect(listening_node.service,
                                           session_cls=ClientSession) as session:
                await pause(0.1)
                assert session.they_prefer_headers
                await session.close()

    #
    # SENDHEADERS message tests
    #

    @pytest.mark.asyncio
    async def test_sendheaders_and_protoconf_are_sent(self, client_node, listening_node):
        async with listening_node.listen():
            async with client_node.connect(listening_node.service) as session:
                listener_session = await listening_session(listening_node)
                assert session.they_prefer_headers
                assert listener_session.they_prefer_headers
                assert session.their_protoconf
                assert listener_session.their_protoconf
                await session.close()

    @pytest.mark.asyncio
    async def test_sendheaders_understood(self, client_node, listening_node):
        async with listening_node.listen():
            async with client_node.connect(listening_node.service) as session:
                session.remote_service.protocol_version = 70_011
                await session.send_sendheaders()
                assert not session.sendheaders_sent
                await session.close()
            await pause()

    @pytest.mark.asyncio
    async def test_duplicate_sendheaders(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service) as session:
                    listener_session = await listening_session(listening_node)
                    await session.send_sendheaders()
                    await pause()
                    assert listener_session.they_prefer_headers

                    with caplog.at_level(logging.WARNING):
                        await session.send_sendheaders()
                    assert in_caplog(caplog, 'sendheaders message already sent')
                    await pause()
                    assert not in_caplog(caplog, 'protocol error: duplicate sendheaders message')

                    session.sendheaders_sent = False
                    await session.send_sendheaders()
                    await pause()
                    assert in_caplog(caplog, 'protocol error: duplicate sendheaders message')
                    await session.close()

    @pytest.mark.asyncio
    async def test_sendheaders_payload(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.WARNING):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service) as session:
                    await session.send_message(MessageHeader.SENDHEADERS, b'0')
                    await pause()
                    await session.close()

        assert in_caplog(caplog, 'extra bytes at end of sendheaders payload')

    #
    # ADDR / GETADDR message tests
    #

    @pytest.mark.asyncio
    async def test_getaddr_roundtrip(self, client_node, listening_node):
        async def on_addr(payload):
            on_addr_event.set()

        on_addr_event = asyncio.Event()
        async with listening_node.listen():
            async with client_node.connect(listening_node.service) as session:
                session.on_addr = on_addr
                await session.send_getaddr()
                async with timeout_after(0.1):
                    await on_addr_event.wait()
                await session.close()

    @pytest.mark.asyncio
    async def test_getaddr_payload(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.WARNING):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service) as session:
                    await session.send_message(MessageHeader.GETADDR, b'0')
                    await pause()
                    await session.close()

        assert in_caplog(caplog, 'extra bytes at end of getaddr payload')

    #
    # PING / PONG message tests
    #

    @pytest.mark.asyncio
    async def test_ping_interval(self, client_node, listening_node):
        class ClientSession(Session):
            PING_INTERVAL = 0.01

        class ListenerSession(Session):
            async def on_ping(self, payload):
                await super().on_ping(payload)
                nonlocal pings_received
                pings_received += 1

        pings_received = 0
        async with listening_node.listen(session_cls=ListenerSession):
            async with client_node.connect(listening_node.service) as session:
                await asyncio.sleep(0.04)
                await session.close()

            assert pings_received == 1
            pings_received = 0

            async with client_node.connect(listening_node.service,
                                           session_cls=ClientSession) as session:
                await asyncio.sleep(0.04)
                await session.close()

        assert pings_received >= 2

    @pytest.mark.asyncio
    async def test_ping_cutoff(self, client_node, listening_node, caplog):
        class ClientSession(Session):
            async def on_ping(self, payload):
                await asyncio.sleep(0.05)
                await super().on_ping(payload)

        class ListenerSession(Session):
            PING_CUTOFF = 0.02

        with caplog.at_level(logging.ERROR):
            async with listening_node.listen(session_cls=ListenerSession):
                async with client_node.connect(listening_node.service) as session:
                    await asyncio.sleep(0.04)
                    await session.close()

                assert not in_caplog(caplog, 'ping timeout')

                with pytest.raises(ConnectionResetError):
                    async with client_node.connect(listening_node.service,
                                                   session_cls=ClientSession) as session:
                        pass

                assert in_caplog(caplog, 'ping timeout after 0.02s')

    @pytest.mark.asyncio
    async def test_unexpected_pong(self, client_node, listening_node, caplog):
        with caplog.at_level(logging.WARNING):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service) as session:
                    await session.send_pong(urandom(8))
                    await pause()
                    await session.close()

            assert in_caplog(caplog, 'unexpected pong')

    @pytest.mark.asyncio
    async def test_parallel_handling(self, client_node, listening_node, caplog):
        # Test commands are handled in parallel
        class ListenerSession(Session):
            async def on_parallel(self, payload):
                times.append(time.time())
                await asyncio.sleep(delay)

        times = []
        delay = 1.0
        async with listening_node.listen(session_cls=ListenerSession):
            async with client_node.connect(listening_node.service) as session:
                async with TaskGroup() as group:
                    await group.create_task(session.send_message(_command('parallel'), b''))
                    await group.create_task(session.send_message(_command('parallel'), b''))
                    await pause()
                    await group.cancel_remaining()
                await session.close()

        is_parallel = abs(times[0] - times[1]) < delay / 2
        assert is_parallel


class TestGetHeaders:

    #
    # GETHEADERS / HEADERS message tests
    #

    @pytest.mark.asyncio
    async def test_waits_for_prior(self, client_node, listening_node, caplog):
        # Test that concurrent getheaders requests wait on the prior one to complete
        class ListenerSession(Session):
            MAX_HEADERS = 25

            async def on_getheaders(self, payload):
                nonlocal secs
                await pause(secs)
                secs = 0
                await super().on_getheaders(payload)

        headers = first_mainnet_headers(ListenerSession.MAX_HEADERS * 2 + 1)[1:]
        await listening_node.headers.insert_headers(headers)
        secs = 0.2

        with caplog.at_level(logging.WARNING):
            async with listening_node.listen(session_cls=ListenerSession):
                async with client_node.connect(listening_node.service) as session:
                    request1 = await session.get_headers()
                    request2 = None
                    async with ignore_after(secs / 2):
                        request2 = await session.get_headers()
                    assert request2 is None
                    request2 = await session.get_headers()
                    await request2.wait()
                    assert request1.count == ListenerSession.MAX_HEADERS
                    assert request2.count == ListenerSession.MAX_HEADERS
                    await session.close()

    @pytest.mark.asyncio
    async def test_hash_stop_only(self, client_node, listening_node, caplog):
        simples = first_mainnet_headers(10)
        await listening_node.headers.insert_headers(simples[:5])

        with caplog.at_level(logging.INFO):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service) as session:
                    session.GETHEADERS_TIMEOUT = 0.1

                    # One known to the listener but doesn't join
                    locator = BlockLocator(1, [], simples[2].hash)
                    request = await session.get_headers(locator)
                    assert session.getheaders_request is request
                    await request.wait()
                    assert not session.getheaders_request
                    assert request.headers == [simples[2]]
                    assert request.count == 0

                    # One known to the listener but doesn't join
                    locator = BlockLocator(1, [], simples[1].hash)
                    request = await session.get_headers(locator)
                    assert session.getheaders_request is request
                    await request.wait()
                    assert not session.getheaders_request
                    assert request.headers == [simples[1]]
                    assert request.count == 1

                    # One not known to the listener; it should ignore the request
                    locator = BlockLocator(1, [], simples[5].hash)
                    request = await session.get_headers(locator)
                    assert session.getheaders_request is request
                    await request.wait()
                    assert request.count == -1
                    assert not request.headers

                    await session.close()

        assert in_caplog(caplog, 'ignoring getheaders for unknown block 000000009b7262315db')

    @pytest.mark.asyncio
    async def test_extend_chain(self, client_node, listening_node, caplog):
        # This tests all cases around correctly-functioning client and listener where they
        # are on different branches, listener on branch A and client on branch B.  They
        # are common for the first 3 mainnet headers, but the client forks to its own
        # branch to height 8, but the listener has mainnet to height 9 as the longest.
        # The listener knows all of branch B except the tip.
        simples = first_mainnet_headers(20)
        await listening_node.headers.insert_headers(simples[:10])

        client_branch = simples[:3]
        client_branch.extend(create_random_branch(client_branch[-1], 5))
        await client_node.headers.insert_headers(client_branch, check_work=False)
        await listening_node.headers.insert_headers(client_branch[:-1], check_work=False)
        client_chain = await client_node.headers.longest_chain()
        assert client_chain.tip.hash == client_branch[-1].hash

        with caplog.at_level(logging.INFO):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service) as session:
                    request = await session.get_headers()
                    await request.wait()
                    assert request.count == 7

                    client_chain = await client_node.headers.longest_chain()
                    listening_chain = await listening_node.headers.longest_chain()
                    assert client_chain.tip == listening_chain.tip

                    # Now extend the listener chain to height 19.  Test that hash_stop is
                    # honoured when the client provides it (how exactly the client knows
                    # the hash is another question....)
                    await listening_node.headers.insert_headers(simples[10:])
                    listening_chain = await listening_node.headers.longest_chain()
                    assert client_chain.tip != listening_chain.tip

                    to_height = 15
                    hash_stop = simples[to_height].hash
                    locator = await session.block_locator()
                    locator.hash_stop = hash_stop
                    request = await session.get_headers(locator)
                    await request.wait()
                    assert request.count == 6

                    client_chain = await client_node.headers.longest_chain()
                    assert client_chain.tip.height == to_height
                    header = await listening_node.headers.header_at_height(listening_chain,
                                                                           to_height)
                    assert header == client_chain.tip
                    assert not in_caplog(caplog, 'headers synchronized')

                    # The hash stop doesn't work now as we start after the tip...
                    locator = await session.block_locator()
                    locator.hash_stop = hash_stop
                    request = await session.get_headers(locator)
                    await request.wait()
                    assert request.count == 4
                    client_chain = await client_node.headers.longest_chain()
                    assert client_chain.tip == listening_chain.tip

                    assert not in_caplog(caplog, 'headers synchronized')

                    request = await session.get_headers()
                    await request.wait()
                    assert request.count == 0
                    assert in_caplog(caplog, 'headers synchronized to height 19')
                    await session.close()

    @pytest.mark.asyncio
    async def test_shorter(self, client_node, listening_node, caplog):
        # This tests all cases around correctly-functioning client and listener where they
        # are on different branches, branches A and B.  The listener is on branch A to
        # height 9, and the client on branch B which is longer.  The listener knows some of
        # branch B.
        simples = first_mainnet_headers(10)
        await listening_node.headers.insert_headers(simples)

        client_branch = simples[:3]
        client_branch.extend(create_random_branch(client_branch[-1], 10))
        await client_node.headers.insert_headers(client_branch, check_work=False)
        await listening_node.headers.insert_headers(client_branch[:-5], check_work=False)
        client_chain = await client_node.headers.longest_chain()
        assert client_chain.tip.hash == client_branch[-1].hash

        with caplog.at_level(logging.INFO):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service) as session:
                    request = await session.get_headers()
                    await request.wait()
                    assert not in_caplog(caplog, 'headers synchronized to height 9')
                    request = await session.get_headers()
                    await request.wait()
                    assert in_caplog(caplog, 'headers synchronized to height 9')

                    # Check neither chain has grown
                    client_chain = await client_node.headers.longest_chain()
                    listening_chain = await listening_node.headers.longest_chain()
                    assert client_chain.tip.hash == client_branch[-1].hash
                    assert listening_chain.tip.hash == simples[-1].hash

                    await session.close()

    @pytest.mark.asyncio
    async def test_not_a_chain(self, client_node, listening_node, caplog):
        '''The remote session sends, unrequested, 6 headers that do not form a chain.'''
        class ListenerSession(Session):
            async def on_getheaders(self, payload):
                branch = create_random_branch(Bitcoin.genesis_header, 5)
                branch.extend(create_random_branch(Bitcoin.genesis_header, 1))
                await self.send_message(MessageHeader.HEADERS, pack_headers_payload(branch))

        with caplog.at_level(logging.ERROR):
            async with listening_node.listen(session_cls=ListenerSession):
                async with client_node.connect(listening_node.service) as session:
                    session.GETHEADERS_TIMEOUT = 0.1
                    request = await session.get_headers()
                    await request.wait()
                    # Check the response was logged and not viewed as a response to our
                    # request
                    assert in_caplog(caplog, 'received headers that do not form a chain')
                    assert request.count == -1
                    assert not request.headers
                    await session.close()

    @pytest.mark.asyncio
    async def test_separated(self, client_node, listening_node, caplog):
        class ListenerSession(Session):
            async def on_getheaders(self, payload):
                # Headers do not connect to genesis
                await self.send_message(MessageHeader.HEADERS, pack_headers_payload(simples[2:]))

        simples = first_mainnet_headers(10)
        with caplog.at_level(logging.WARNING):
            async with listening_node.listen(session_cls=ListenerSession):
                async with client_node.connect(listening_node.service) as session:
                    session.GETHEADERS_TIMEOUT = 0.1
                    request = await session.get_headers()
                    await request.wait()
                    # Check the response was logged and not viewed as a response to our
                    # request
                    assert in_caplog(caplog, 'ignoring 8 non-connecting headers')
                    assert request.count == -1
                    assert not request.headers
                    await session.close()

    @pytest.mark.asyncio
    async def test_bad_pow(self, client_node, listening_node, caplog):
        class ListenerSession(Session):
            async def on_getheaders(self, payload):
                await self.send_message(MessageHeader.HEADERS, pack_headers_payload(branch))

        print_caplog(caplog)
        branch = create_random_branch(Bitcoin.genesis_header, 2)
        with caplog.at_level(logging.ERROR):
            async with listening_node.listen(session_cls=ListenerSession):
                async with client_node.connect(listening_node.service) as session:
                    request = await session.get_headers()
                    await request.wait()
                    # Check the response was logged AND viewed as a response to our request
                    assert in_caplog(caplog, 'hash value exceeds its target')
                    assert request.count == 0
                    assert request.headers == branch
                    await session.close()

    @pytest.mark.asyncio
    async def test_request_too_long(self, client_node, listening_node, caplog):
        class ListenerSession(Session):
            async def on_getheaders(self, payload):
                await self.send_message(MessageHeader.HEADERS,
                                        pack_headers_payload(headers) + b'1')

        headers = first_mainnet_headers(3)[1:]
        with caplog.at_level(logging.WARNING):
            async with listening_node.listen(session_cls=ListenerSession):
                async with client_node.connect(listening_node.service) as session:
                    request = await session.get_headers()
                    await request.wait()
                    assert in_caplog(caplog, 'extra bytes at end of headers payload')
                    assert request.count == 2
                    assert request.headers == headers
                    await session.close()

    @pytest.mark.asyncio
    async def test_too_many_sent(self, client_node, listening_node, caplog):
        headers = first_mainnet_headers(10)[1:]
        await listening_node.headers.insert_headers(headers)

        with caplog.at_level(logging.ERROR):
            async with listening_node.listen():
                async with client_node.connect(listening_node.service) as session:
                    session.MAX_HEADERS = 5
                    request = await session.get_headers()
                    await request.wait()
                    # Check it is diagnosed AND recognised as a response to our request
                    assert in_caplog(caplog, 'headers message with 9 headers but limit is 5')
                    assert request.headers == headers
                    assert request.count == 0
                    await session.close()


class TestSyncHeaders:

    @pytest.mark.asyncio
    async def test_lock(self, client_node, listening_node, listening_node2):
        class ListenerSession(Session):
            async def on_getheaders(self, payload):
                nonlocal requests
                requests += 1
                await asyncio.sleep(0.04)
                await self.close()

        async def create_client(lnode):
            async with client_node.connect(lnode.service) as session:

                async with ignore_after(0.02):
                    await session.sync_headers()
                await session.close()

        requests = 0
        async with listening_node.listen(session_cls=ListenerSession):
            async with listening_node2.listen(session_cls=ListenerSession):
                async with TaskGroup() as group:
                    group.create_task(create_client(listening_node))
                    group.create_task(create_client(listening_node2))

        assert requests == 1

    @pytest.mark.asyncio
    async def test_works(self, client_node, listening_node):
        # Test that the client syncs with the listening node, even when it's on a branch
        # whose length is greater than the atomic send limit, and the listener occasionally
        # sends a disconnected header
        class ListenerSession(Session):
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
        assert await client_node.headers.insert_headers(branch, check_work=False) == 25

        # Listening node has the first 101 mainnet heaaders, to height 100
        height = 100
        headers = first_mainnet_headers(height + 1)
        assert await listening_node.headers.insert_headers(headers) == height

        async with listening_node.listen(session_cls=ListenerSession):
            async with client_node.connect(listening_node.service) as session:
                assert await session.sync_headers()
                assert not await session.sync_headers()
                await session.close()

        assert await client_node.headers.height() == height
