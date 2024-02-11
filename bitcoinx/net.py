# Copyright (c) 2024, Neil Booth
#
# All rights reserved.
#


import logging
import re
import time
from dataclasses import dataclass
from enum import IntEnum, IntFlag
from functools import partial
from io import BytesIO
from ipaddress import ip_address, IPv4Address, IPv6Address
from struct import Struct, error as struct_error
from typing import List

from .errors import ProtocolError
from .hashes import double_sha256
from .packing import (
    pack_byte, pack_le_int32, pack_le_uint32, pack_le_int64, pack_le_uint64, pack_varint,
    pack_varbytes, pack_port, unpack_port,
    read_varbytes, read_varint, read_le_int32, read_le_uint32, read_le_uint64, read_le_int64,
    read_list
)


__all__ = (
    'is_valid_hostname', 'classify_host', 'validate_port', 'validate_protocol',
    'NetAddress', 'Service', 'ServicePart', 'NetworkProtocol',
    'BitcoinService', 'ServiceFlags', 'Protoconf', 'MessageHeader',
)


class ServicePart(IntEnum):
    PROTOCOL = 0
    HOST = 1
    PORT = 2


class NetAddress:

    def __init__(self, host, port, check_port=True):
        '''Construct a NetAddress from a host and a port.

        Host is classified and port is an integer.'''
        self._host = classify_host(host)
        self._port = validate_port(port) if check_port else int(port)

    def __eq__(self, other):
        # pylint: disable=protected-access
        return (isinstance(other, NetAddress) and
                self._host == other._host and self._port == other._port)

    def __hash__(self):
        return hash((self._host, self._port))

    @classmethod
    def from_string(cls, string, *, check_port=True, default_func=None):
        '''Construct a NetAddress from a string and return a (host, port) pair.

        If either (or both) is missing and default_func is provided, it is called with
        ServicePart.HOST or ServicePart.PORT to get a default.
        '''
        def split_address(string):
            if string.startswith('['):
                end = string.find(']')
                if end != -1:
                    if len(string) == end + 1:
                        return string[1:end], ''
                    if string[end + 1] == ':':
                        return string[1:end], string[end+2:]
            colon = string.find(':')
            if colon == -1:
                return string, ''
            return string[:colon], string[colon + 1:]

        if not isinstance(string, str):
            raise TypeError(f'address must be a string: {string}')
        host, port = split_address(string)
        if default_func:
            host = host or default_func(ServicePart.HOST)
            port = port or default_func(ServicePart.PORT)
            if not host or not port:
                raise ValueError(f'invalid address string: {string}')
        return cls(host, port, check_port=check_port)

    @classmethod
    def ensure_resolved(cls, address):
        '''If address is a string, convert it to a NetAddress.  Enforces the result be an IP
        address.'''
        if not isinstance(address, cls):
            address = cls.from_string(address)
        if not isinstance(address.host, (IPv4Address, IPv6Address)):
            raise ValueError(f'a resolved IP address is required, not {address.host}')
        return address

    @property
    def host(self):
        return self._host

    @property
    def port(self):
        return self._port

    def __str__(self):
        if isinstance(self._host, IPv6Address):
            return f'[{self._host}]:{self._port}'
        return f'{self.host}:{self.port}'

    def __repr__(self):
        return f"NetAddress('{self}')"

    @classmethod
    def default_host_and_port(cls, host, port):
        def func(kind):
            return host if kind == ServicePart.HOST else port
        return func

    @classmethod
    def default_host(cls, host):
        return cls.default_host_and_port(host, None)

    @classmethod
    def default_port(cls, port):
        return cls.default_host_and_port(None, port)

    def pack_host(self):
        '''Return the host as a 16-byte IPv6 address.'''
        if isinstance(self._host, IPv4Address):
            # An IPv4-mapped IPv6 address
            return b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff' + self._host.packed
        if isinstance(self._host, IPv6Address):
            return self._host.packed
        raise TypeError(f'address must be resolved: {self._host}')

    def pack(self):
        return self.pack_host() + pack_port(self._port)


class Service:
    '''A validated protocol, address pair.'''

    def __init__(self, protocol, address):
        '''Construct a service from a protocol string and a NetAddress object,'''
        self._protocol = validate_protocol(protocol)
        if not isinstance(address, NetAddress):
            address = NetAddress.from_string(address)
        self._address = address

    def __eq__(self, other):
        # pylint: disable=protected-access
        return (isinstance(other, Service) and
                self._protocol == other._protocol and self._address == other._address)

    def __hash__(self):
        return hash((self._protocol, self._address))

    @property
    def protocol(self):
        return self._protocol

    @property
    def address(self):
        return self._address

    @property
    def host(self):
        return self._address.host

    @property
    def port(self):
        return self._address.port

    @classmethod
    def from_string(cls, string, *, default_func=None):
        '''Construct a Service from a string.

        If default_func is provided and any ServicePart is missing, it is called with
        default_func(protocol, part) to obtain the missing part.
        '''
        if not isinstance(string, str):
            raise TypeError(f'service must be a string: {string}')

        parts = string.split('://', 1)
        if len(parts) == 2:
            protocol, address = parts
        else:
            item, = parts
            protocol = None
            if default_func:
                if default_func(item, ServicePart.HOST) and default_func(item, ServicePart.PORT):
                    protocol, address = item, ''
                else:
                    protocol, address = default_func(None, ServicePart.PROTOCOL), item
            if not protocol:
                raise ValueError(f'invalid service string: {string}')

        if default_func:
            default_func = partial(default_func, protocol.lower())
        address = NetAddress.from_string(address, default_func=default_func)
        return cls(protocol, address)

    def __str__(self):
        return f'{self._protocol}://{self._address}'

    def __repr__(self):
        return f"Service({self._protocol!r}, '{self._address}')"


# See http://stackoverflow.com/questions/2532053/validate-a-hostname-string
# Note underscores are valid in domain names, but strictly invalid in host
# names.  We ignore that distinction.
PROTOCOL_REGEX = re.compile('[A-Za-z][A-Za-z0-9+-.]+$')
LABEL_REGEX = re.compile('^[a-z0-9_]([a-z0-9-_]{0,61}[a-z0-9_])?$', re.IGNORECASE)
NUMERIC_REGEX = re.compile('[0-9]+$')


def is_valid_hostname(hostname):
    '''Return True if hostname is valid, otherwise False.'''
    if not isinstance(hostname, str):
        raise TypeError('hostname must be a string')
    # strip exactly one dot from the right, if present
    if hostname and hostname[-1] == ".":
        hostname = hostname[:-1]
    if not hostname or len(hostname) > 253:
        return False
    labels = hostname.split('.')
    # the TLD must be not all-numeric
    if re.match(NUMERIC_REGEX, labels[-1]):
        return False
    return all(LABEL_REGEX.match(label) for label in labels)


def classify_host(host):
    '''Host is an IPv4Address, IPv6Address or a string.

    If an IPv4Address or IPv6Address return it.  Otherwise convert the string to an
    IPv4Address or IPv6Address object if possible and return it.  Otherwise return the
    original string if it is a valid hostname.

    Raise ValueError if a string cannot be interpreted as an IP address and it is not
    a valid hostname.
    '''
    if isinstance(host, (IPv4Address, IPv6Address)):
        return host
    if is_valid_hostname(host):
        return host
    return ip_address(host)


def validate_port(port):
    '''Validate port and return it as an integer.

    A string, or its representation as an integer, is accepted.'''
    if not isinstance(port, (str, int)):
        raise TypeError(f'port must be an integer or string: {port}')
    if isinstance(port, str) and port.isdigit():
        port = int(port)
    if isinstance(port, int) and 0 < port <= 65535:
        return port
    raise ValueError(f'invalid port: {port}')


def validate_protocol(protocol):
    '''Validate a protocol, a string, and return it in lower case.'''
    if not re.match(PROTOCOL_REGEX, protocol):
        raise ValueError(f'invalid protocol: {protocol}')
    return protocol.lower()


#
# Constants and classes implementing the Bitcoin network protocol
#

ZERO_NONCE = bytes(8)

# Standard and extended message headers
std_header_struct = Struct('<4s12sI4s')
std_pack = std_header_struct.pack
std_unpack = std_header_struct.unpack
ext_header_struct = Struct('<4s12sI4s12sQ')
ext_pack = ext_header_struct.pack
ext_extra_struct = Struct('<12sQ')
ext_extra_unpack = ext_extra_struct.unpack
empty_checksum = bytes(4)


class InventoryKind(IntEnum):
    ERROR = 0
    TX = 1
    BLOCK = 2
    # The following occur only in getdata messages.  Invs always use TX or BLOCK.
    FILTERED_BLOCK = 3
    COMPACT_BLOCK = 4


@dataclass
class MessageHeader:
    '''The header of a network protocol message.'''

    # Extended headers were introduced in the BSV 1.0.10 node software.
    COMMAND_LEN = 12
    STD_HEADER_SIZE = std_header_struct.size
    EXT_HEADER_SIZE = ext_header_struct.size

    magic: bytes
    command_bytes: bytes
    payload_len: int
    checksum: bytes
    is_extended: bool

    @classmethod
    async def from_stream(cls, recv_exactly):
        raw_std = await recv_exactly(cls.STD_HEADER_SIZE)
        magic, command_bytes, payload_len, checksum = std_unpack(raw_std)
        is_extended = False
        if command_bytes == cls.EXTMSG:
            if checksum != empty_checksum or payload_len != 0xffffffff:
                raise ProtocolError('ill-formed extended message header')
            raw_ext = await recv_exactly(cls.EXT_HEADER_SIZE - cls.STD_HEADER_SIZE)
            command_bytes, payload_len = ext_extra_unpack(raw_ext)
            is_extended = True
        return cls(magic, command_bytes, payload_len, checksum, is_extended)

    def command(self):
        '''The command as text, e.g. addr '''
        command = self.command_bytes.rstrip(b'\0')
        return command.decode() if command.isascii() else '0x' + command.hex()

    def __str__(self):
        return self.command()

    @staticmethod
    def payload_checksum(payload):
        return double_sha256(payload)[:4]

    @classmethod
    def std_bytes(cls, magic, command, payload):
        return std_pack(magic, command, len(payload), cls.payload_checksum(payload))

    @classmethod
    def ext_bytes(cls, magic, command, payload_len):
        return ext_pack(magic, cls.EXTMSG, 0xffffffff, empty_checksum, command, payload_len)


def _command(text):
    return text.encode().ljust(MessageHeader.COMMAND_LEN, b'\0')


# List these explicitly because pylint is dumb
MessageHeader.ADDR = _command('addr')
MessageHeader.AUTHCH = _command('authch')
MessageHeader.AUTHRESP = _command('authresp')
MessageHeader.BLOCK = _command('block')
MessageHeader.BLOCKTXN = _command('blocktxn')
MessageHeader.CMPCTBLOCK = _command('cmpctblock')
MessageHeader.CREATESTRM = _command('createstrm')
MessageHeader.DATAREFTX = _command('datareftx')
MessageHeader.DSDETECTED = _command('dsdetected')
MessageHeader.EXTMSG = _command('extmsg')
MessageHeader.FEEFILTER = _command('feefilter')
MessageHeader.GETADDR = _command('getaddr')
MessageHeader.GETBLOCKS = _command('getblocks')
MessageHeader.GETBLOCKTXN = _command('getblocktxn')
MessageHeader.GETDATA = _command('getdata')
MessageHeader.GETHEADERS = _command('getheaders')
MessageHeader.GETHDRSEN = _command('gethdrsen')
MessageHeader.HDRSEN = _command('hdrsen')
MessageHeader.HEADERS = _command('headers')
MessageHeader.INV = _command('inv')
MessageHeader.MEMPOOL = _command('mempool')
MessageHeader.NOTFOUND = _command('notfound')
MessageHeader.PING = _command('ping')
MessageHeader.PONG = _command('pong')
MessageHeader.PROTOCONF = _command('protoconf')
MessageHeader.REJECT = _command('reject')
MessageHeader.REPLY = _command('reply')
MessageHeader.REVOKEMID = _command('revokemid')
MessageHeader.SENDCMPCT = _command('sendcmpct')
MessageHeader.SENDHEADERS = _command('sendheaders')
MessageHeader.SENDHDRSEN = _command('sendhdrsen')
MessageHeader.STREAMACK = _command('streamack')
MessageHeader.TX = _command('tx')
MessageHeader.VERACK = _command('verack')
MessageHeader.VERSION = _command('version')


class ServiceFlags(IntFlag):
    NODE_NONE = 0
    NODE_NETWORK = 1 << 0
    # All other flags are obsolete


class ServicePacking:
    struct = Struct('<Q16s2s')

    @classmethod
    def pack(cls, address, services):
        '''Return the address and service flags as an encoded service.

        No timestamp is prefixed; this is used in for the version message.
        '''
        return pack_le_uint64(services) + address.pack()

    @classmethod
    def pack_with_timestamp(cls, address, services, timestamp):
        '''Return an encoded service with a 4-byte timestamp prefix.'''
        return pack_le_uint32(timestamp) + cls.pack(address, services)

    @classmethod
    def unpack(cls, raw):
        '''Given the final 26 bytes (no leading timestamp) of a protocol-encoded
        internet address return a (NetAddress, services) pair.'''
        services, address, raw_port = cls.struct.unpack(raw)
        address = ip_address(address)
        if address.ipv4_mapped:
            address = address.ipv4_mapped
        port, = unpack_port(raw_port)
        return (NetAddress(address, port, check_port=False), ServiceFlags(services))

    @classmethod
    def read(cls, read):
        '''Reads 26 bytes from a raw byte stream, returns a (NetAddress, services) pair.'''
        return cls.unpack(read(cls.struct.size))

    @classmethod
    def read_with_timestamp(cls, read):
        '''Read a timestamp-prefixed net_addr (4 + 26 bytes); return a
        (NetAddress, services, timestamp) tuple.'''
        timestamp = read_le_uint32(read)
        address, services = cls.read(read)
        return (address, services, timestamp)

    @classmethod
    def read_addrs(cls, read):
        '''Return a lits of (NetAddress, services, timestamp) triples from an addr
        message payload.'''
        count = read_varint(read)
        read_with_timestamp = cls.read_with_timestamp
        return [read_with_timestamp(read) for _ in range(count)]


class BitcoinService:
    '''Represents a bitcoin network service.

    Stores various details obtained from the version message.  Comparison and hashing is
    only done on the (resolved) network address.
    '''

    def __init__(self, *,
                 address=None,
                 services=ServiceFlags.NODE_NONE,
                 user_agent=None,
                 protocol_version=None,
                 start_height=0,
                 relay=True,
                 timestamp=None,
                 assoc_id=None):
        from bitcoinx import _version_str

        self.address = (NetAddress('::', 0, check_port=False) if address is None else
                        NetAddress.ensure_resolved(address))
        self.services = ServiceFlags(services)
        self.user_agent = user_agent or f'/bitcoinx/{_version_str}'
        self.protocol_version = protocol_version or 70015
        self.start_height = start_height
        self.relay = relay
        self.timestamp = timestamp
        self.assoc_id = assoc_id

    def __eq__(self, other):
        return self.address == other.address

    def __hash__(self):
        return hash(self.address)

    def pack(self):
        '''Return the address and service flags as an encoded service.'''
        return ServicePacking.pack(self.address, self.services)

    def pack_with_timestamp(self, timestamp):
        '''Return an encoded service with a 4-byte timestamp prefix.'''
        return ServicePacking.pack_with_timestamp(self.address, self.services, timestamp)

    def __str__(self):
        return repr(self)

    def __repr__(self):
        return (
            f'BitcoinService({self.address}, services={self.services!r}, '
            f'user_agent={self.user_agent!r}, protocol_version={self.protocol_version}, '
            f'start_height={self.start_height:,d} relay={self.relay} '
            f'timestamp={self.timestamp}, assoc_id={self.assoc_id!r})'
        )


@dataclass
class Protoconf:
    LEGACY_MAX_PAYLOAD = 1024 * 1024

    max_payload: int
    stream_policies: List[bytes]

    def max_inv_elements(self):
        return (self.max_payload - 9) // (4 + 32)

    def payload(self):
        field_count = 2
        return b''.join((
            pack_varint(field_count),
            pack_le_uint32(self.max_payload),
            pack_varbytes(b','.join(self.stream_policies)),
        ))

    @classmethod
    def default(cls):
        return cls(5_000_000, [b'Default'])

    @classmethod
    def from_payload(cls, payload, logger=None):
        logger = logger or logging
        read = BytesIO(payload).read

        field_count = read_varint(read)
        if field_count < 2:
            raise ProtocolError('bad field count {field_count} in protoconf message')
        if field_count != 2:
            logger.warning('unexpected field count {field_count:,d} in protoconf message')

        max_payload = read_le_uint32(read)
        if max_payload < Protoconf.LEGACY_MAX_PAYLOAD:
            raise ProtocolError(f'invalid max payload {max_payload:,d} in protconf message')

        stream_policies = read_varbytes(read)
        return Protoconf(max_payload, stream_policies.split(b','))


class NetworkProtocol:

    @classmethod
    def random_nonce(cls):
        '''A nonce suitable for a PING or VERSION messages.'''
        # bitcoind doesn't like zero nonces
        while True:
            nonce = urandom(8)
            if nonce != ZERO_NONCE:
                return nonce

    @classmethod
    def version_payload(cls, service, their_service, nonce):
        '''Create a version message payload.

        If self.timestamp is None, then the current time is used.
        their_service is a NetAddress or BitcoinService.
        '''
        if len(nonce) != 8:
            raise ValueError('nonce must be 8 bytes')

        if isinstance(their_service, NetAddress):
            their_service_packed = ServicePacking.pack(their_service, ServiceFlags.NODE_NONE)
        else:
            their_service_packed = their_service.pack()

        timestamp = int(time.time()) if service.timestamp is None else service.timestamp
        assoc_id = b'' if service.assoc_id is None else pack_varbytes(service.assoc_id)

        return b''.join((
            pack_le_int32(service.protocol_version),
            pack_le_uint64(service.services),
            pack_le_int64(timestamp),
            their_service_packed,
            service.pack(),   # In practice this is ignored by receiver
            nonce,
            pack_varbytes(service.user_agent.encode()),
            pack_le_int32(service.start_height),
            pack_byte(service.relay),
            assoc_id,
        ))

    @classmethod
    def read_version_payload(cls, service, payload):
        '''Read a version payload and update member variables of service (except address).  Return
        a tuple (our_address, our_services, nonce) in the payload.
        '''
        read = BytesIO(payload).read
        service.protocol_version = read_le_uint32(read)
        service.services = read_le_uint64(read)
        service.timestamp = read_le_int64(read)
        our_address, our_services = ServicePacking.read(read)
        ServicePacking.read(read)   # Ignore
        nonce = read(8)

        user_agent = read_varbytes(read)
        try:
            service.user_agent = user_agent.decode()
        except UnicodeDecodeError:
            service.user_agent = '0x' + user_agent.hex()

        service.start_height = read_le_int32(read)
        # Relay is optional, defaulting to True
        service.relay = read(1) != b'\0'
        # Association ID is optional.  We set it to None if not provided.
        try:
            service.assoc_id = read_varbytes(read)
        except struct_error:
            service.assoc_id = None

        return (our_address, our_services, nonce)

    @classmethod
    def pack_block_locator(cls, protocol_version, locator, hash_stop=None):
        parts = [pack_le_int32(protocol_version), pack_varint(len(locator))]
        parts.extend(locator)
        parts.append(hash_stop or bytes(32))
        return b''.join(parts)

    # @classmethod
    # def unpack_headers(payload):
    #     def read_one(read):
    #         raw_header = read(80)
    #         # A stupid tx count which seems to always be zero...
    #         read_varint(read)
    #         return raw_header

    #     read = BytesIO(payload).read
    #     return read_list(read, read_one)
