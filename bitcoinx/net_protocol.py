# Copyright (c) 2024, Neil Booth
#
# All rights reserved.
#

'''Implementation of (parts of) the Bitcoin network protocol.'''

import asyncio
import logging
import os
import sys
import time
from asyncio import Event, Queue, open_connection
from dataclasses import dataclass
from enum import IntEnum, IntFlag
from io import BytesIO
from ipaddress import ip_address
from struct import Struct
from typing import List

from .asyncio_compat import TaskGroup, ExceptionGroup, timeout
from .errors import (
    ProtocolError, ForceDisconnectError, PackingError, MissingHeader,
)
from .hashes import double_sha256, hash_to_hex_str
from .headers import SimpleHeader
from .net import NetAddress
from .packing import (
    pack_byte, pack_le_int32, pack_le_uint32, pack_le_int64, pack_le_uint64, pack_varint,
    pack_varbytes, unpack_port,
    read_varbytes, read_varint, read_le_int32, read_le_uint32, read_le_uint64, read_le_int64,
    pack_list, read_list,
)


__all__ = (
    'BitcoinService', 'ServiceFlags', 'Protoconf', 'MessageHeader', 'Node', 'Session',
)

#
# Constants and classes implementing the Bitcoin network protocol
#

ZERO_NONCE = bytes(8)
LARGE_MESSAGES_PROTOCOL_VERSION = 70016

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
    only done on the (resolved) network address.  start_height is the height at the time
    a connection waas made.
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
        self.protocol_version = protocol_version or LARGE_MESSAGES_PROTOCOL_VERSION
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

#
# Network Protocol
#


def random_nonce():
    '''A nonce suitable for a PING or VERSION messages.'''
    # bitcoind doesn't like zero nonces
    while True:
        nonce = os.urandom(8)
        if nonce != ZERO_NONCE:
            return nonce


def read_version_payload(service, payload):
    '''Read a version payload and update member variables of service (except address).  Return
     a tuple (our_address, our_services, nonce) in the payload.

     This is not a constructor because there is no reliable source for the address.
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
    except PackingError:
        service.assoc_id = None

    if read(1) != b'':
        logging.info('extra bytes at end of version payload')

    return (our_address, our_services, nonce)


def version_payload(service, remote_service, nonce):
    '''Create a version message payload.

    If self.timestamp is None, then the current time is used.
        remote_service is a NetAddress or BitcoinService.
    '''
    if len(nonce) != 8:
        raise ValueError('nonce must be 8 bytes')

    if isinstance(remote_service, NetAddress):
        remote_service_packed = ServicePacking.pack(remote_service, ServiceFlags.NODE_NONE)
    else:
        remote_service_packed = remote_service.pack()

    timestamp = int(time.time()) if service.timestamp is None else service.timestamp
    assoc_id = b'' if service.assoc_id is None else pack_varbytes(service.assoc_id)

    return b''.join((
        pack_le_int32(service.protocol_version),
        pack_le_uint64(service.services),
        pack_le_int64(timestamp),
        remote_service_packed,
        service.pack(),   # In practice this is ignored by receiver
        nonce,
        pack_varbytes(service.user_agent.encode()),
        pack_le_int32(service.start_height),
        pack_byte(service.relay),
        assoc_id,
    ))


def pack_headers_payload(headers: List[SimpleHeader]):
    zero = pack_varint(0)
    return pack_list(headers, lambda header: header.raw + zero)


def unpack_headers_payload(payload):
    def read_one(read):
        raw_header = read(80)
        # A stupid tx count which the reference client sets to zero...
        read_varint(read)
        return SimpleHeader(raw_header)

    read = BytesIO(payload).read
    try:
        result = read_list(read, read_one)
    except PackingError:
        raise ProtocolError('truncated headers payload')
    if read(1) != b'':
        logging.info('extra bytes at end of headers payload')
    return result


class BlockLocator:
    '''A block locator is a list of block hashes starting from the chain tip back to the
    genesis block, that become increasingly sparse.  It also includes an optional
    hash_stop to indicate where to stop.

    As a payload it is used in the getblocks and getheaders messages.
    '''
    def __init__(self, version, block_hashes, hash_stop=None):
        self.version = version
        self.block_hashes = block_hashes
        self.hash_stop = hash_stop or bytes(32)

    def __len__(self):
        return len(self.block_hashes)

    def __eq__(self, other):
        return (isinstance(other, BlockLocator) and self.version == other.version
                and self.block_hashes == other.block_hashes and self.hash_stop == other.hash_stop)

    @classmethod
    async def from_block_hash(cls, version, headers, block_hash=None, *, hash_stop=None):
        '''Returns a block locator for the longest chain containing the block hash.  If None, the
        genesis block hash is used.
        '''
        def block_heights(height, stop=0, step=-1):
            while height > stop:
                yield height
                height += step
                step += step
            yield stop

        chain = await headers.longest_chain(block_hash)
        block_hashes = [(await headers.header_at_height(chain, height)).hash
                        for height in block_heights(chain.tip.height)]
        return cls(version, block_hashes, hash_stop)

    def to_payload(self):
        def parts():
            yield pack_le_int32(self.version)
            yield pack_list(self.block_hashes, lambda block_hash: block_hash)
            yield self.hash_stop

        return b''.join(parts())

    @classmethod
    def from_payload(cls, payload):
        def read_one(read):
            return read(32)

        read = BytesIO(payload).read
        version = read_le_uint32(read)
        locator = read_list(read, read_one)
        hash_stop = read(32)
        if len(hash_stop) != 32:
            raise ProtocolError('truncated getheaders payload')
        if read(1) != b'':
            logging.info('extra bytes at end of getheaders payload')

        return cls(version, locator, hash_stop)

    async def fetch_locator_headers(self, headers, limit):
        result = []
        if self.block_hashes:
            first_height = 1
            chain = await headers.longest_chain()
            for block_hash in self.block_hashes:
                header = await headers.header_from_hash(block_hash)
                if not header:
                    continue

                try:
                    chain_header = await headers.header_at_height(chain, header.height)
                except MissingHeader:
                    continue

                if header == chain_header:
                    first_height = header.height + 1
                    break

            stop_height = min(chain.tip.height + 1, first_height + limit)
            result = []
            for height in range(first_height, stop_height):
                header = await headers.header_at_height(chain, height)
                result.append(header)
                if header.hash == self.hash_stop:
                    break
        else:
            header = await headers.header_from_hash(self.hash_stop)
            if header:
                result.append(header)

        return result

    async def headers_payload(self, headers, limit):
        '''Return the payload for a "headers" message in reply to "getheaders".'''
        return pack_headers_payload(await self.fetch_locator_headers(headers, limit))

    def validate_headers(self, headers):
        # headers is a list of SimpleHeader objects
        if not self.block_hashes:
            if self.version == 0:
                raise ProtocolError('received unsolicited headers')
            if len(headers) != 1 or headers[0].hash != self.hash_stop:
                raise ProtocolError('did not receive the single header requested')
            return

        # Check that the first header branches from an entry in the locator, and that the
        # rest form a chain.
        prev_hash = None
        for n, header in enumerate(headers):
            if n:
                if header.prev_hash != prev_hash:
                    raise ProtocolError('received headers do not form a chain')
            else:
                if header.prev_hash not in self.block_hashes:
                    raise ProtocolError('received headers are detached from the block locator')
            prev_hash = header.hash


BlockLocator.NULL = BlockLocator(0, [], None)


class Connection:
    '''A single network connection.  Each connection has its own outgoing message queue
    because a Session decides which connection an outgoing message is sent on.
    '''

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.outgoing_messages = Queue()

    async def close(self):
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except (BrokenPipeError, ConnectionResetError):   # CRE happens on Windows it seems
            pass

    async def send(self, data):
        self.writer.write(data)
        await self.writer.drain()

    async def recv_exactly(self, nbytes):
        return await self.reader.readexactly(nbytes)

    async def recv_chunks(self, size, chunk_size=None):
        '''Read size bytes, returning it in chunks.  An asynchronous iterator.'''
        chunk_size = chunk_size or 1_000_000
        while size > 0:
            recv_size = min(size, chunk_size)
            chunk = await self.recv_exactly(recv_size)
            yield chunk
            size -= recv_size

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()


class Node:
    '''A node talks on a single network, e.g., mainnet.  Connections to peers are represented
    by a Session, which references the Node to manage unified state.
    '''

    def __init__(self, service, network, headers):
        self.service = service
        self.network = network
        self.headers = headers
        self.outgoing_sessions = set()
        self.incoming_sessions = set()

    async def height(self):
        chain = await self.headers.longest_chain()
        return chain.tip.height

    def random_nonce(self):
        while True:
            nonce = random_nonce()
            if not self.is_our_nonce(nonce):
                return nonce

    def is_our_nonce(self, nonce):
        return any(nonce == session.nonce for session in self.outgoing_sessions)

    async def connect(self, service, *, session_cls=None, **kwargs):
        '''Establish an outgoing connection to a service (a BitcoinService instance).  When
        connected, call session_cls (a callable) and await its member funciont
        maintain_connection().
        '''
        session_cls = session_cls or Session
        reader, writer = await open_connection(str(service.address.host), service.address.port)
        async with Connection(reader, writer) as connection:
            session = session_cls(self, service, connection, True, **kwargs)
            await self.run_session(session)

    def listen(self, *, session_cls=None):
        '''Listen for incoming connections, and for each incoming connection call session_cls (a
        callable) and then await its member function maintain_connection().
        '''
        async def on_client(reader, writer):
            try:
                async with Connection(reader, writer) as connection:
                    host, port = writer.transport.get_extra_info('peername')
                    remote = BitcoinService(address=NetAddress(host, port))
                    session = (session_cls or Session)(self, remote, connection, False)
                    await self.run_session(session)
            except Exception as e:
                logging.exception(f'error handling incoming connection: {e}')

        host = str(self.service.address.host)
        port = self.service.address.port
        return Listener(asyncio.start_server(on_client, host, port))

    async def run_session(self, session):
        '''Establish an outgoing connection to a service (a BitcoinService instance).  When
        connected, call session_cls (a callable) and await its member funciont
        maintain_connection().
        '''
        sessions = self.outgoing_sessions if session.is_outgoing else self.incoming_sessions
        sessions.add(session)
        try:
            await session.maintain_connection(session.connection)
        finally:
            sessions.remove(session)


class Listener:
    '''A helper for Node.listen() to ensure sessions are cleaned up properly.'''

    def __init__(self, start_server):
        self.start_server = start_server
        self.server = None

    async def __aenter__(self):
        self.server = await self.start_server

    async def __aexit__(self, *args):
        self.server.close()
        await self.server.wait_closed()
        if sys.version_info < (3, 11):
            await asyncio.sleep(0.001)


class SessionLogger(logging.LoggerAdapter):

    '''Prepends a connection identifier to a logging message.'''
    def process(self, msg, kwargs):
        remote_address = self.extra.get('remote_address', 'unknown')
        return f'[{remote_address}] {msg}', kwargs


class Session:
    '''Represents a single logical connection (an association) to a peer.  A logical
    connection can consist of multiple separate streams connection to a peer.  The sesion
    determines on which connection a message is sent, and tracks state across the
    associated connections.

    If a client wishes to maintain several associations with the same address, it must be
    done with separate Session objects.
    '''
    MAX_HEADERS = 2000

    def __init__(self, node, remote_service, connection, is_outgoing, *, on_handshake=None):
        self.node = node
        self.remote_service = remote_service
        # The main connection.  For now, the only one.
        self.connection = connection
        self.is_outgoing = is_outgoing
        self.protoconf = Protoconf.default()
        self._on_handshake = on_handshake or self.__class__.on_handshake
        self.streaming_min_size = 10_000_000

        # State
        self.version_sent = False
        self.version_received = Event()
        self.verack_received = Event()
        self.headers_received = Event()
        self.headers_synced = False
        self.protoconf_sent = False
        self.their_protoconf = None
        self.nonce = self.node.random_nonce()
        self.can_send_large_messages = False
        self.their_tip = node.headers.genesis_header
        self.getheaders_locator = BlockLocator.NULL

        # Logging
        logger = logging.getLogger('Session')
        context = {'remote_address': f'{remote_service.address}'}
        self.logger = SessionLogger(logger, context)
        self.debug = logger.isEnabledFor(logging.DEBUG)

    async def send_messages_loop(self, connection):
        '''Handle sending the queue of messages.  This sends all messages except the initial
        version / verack handshake.
        '''
        send = self.connection.send
        while True:
            header, payload = await connection.outgoing_messages.get()
            if len(header) == MessageHeader.STD_HEADER_SIZE:
                if len(payload) + len(header) <= 536:
                    await send(header + payload)
                else:
                    await send(header)
                    await send(payload)
            else:
                await send(header)
                async for part in payload:
                    await send(part)

    async def recv_messages_loop(self, connection):
        '''Read messages from a stream and pass them to handlers for processing.'''
        while True:
            header = 'incoming'
            try:
                header = await MessageHeader.from_stream(connection.recv_exactly)
                await self.handle_message(connection, header)
            except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
                self.logger.error('connection closed remotely')
                raise ConnectionResetError('connection closed remotely') from None
            except ForceDisconnectError:
                raise
            except ProtocolError as e:
                self.logger.error(f'protocol error: {e}')
            except Exception:
                self.logger.exception(f'unexpected error handling {header} message')
                raise

    async def maintain_connection(self, connection):
        '''Maintains a connection.'''
        try:
            async with TaskGroup() as group:
                group.create_task(self.recv_messages_loop(connection))
                group.create_task(self.perform_handshake(connection))
                await self.verack_received.wait()
                group.create_task(self.send_messages_loop(connection))
                await self._on_handshake(self, group)
        except ExceptionGroup as e:
            raise e.exceptions[0] from None

    async def on_handshake(self, group):
        # For now we simply send a protoconf message
        group.create_task(self.send_protoconf())

    async def _send_unqueued(self, connection, command, payload):
        '''Send a command without queueing.  For use with handshake negotiation.'''
        self.logger.debug(f'sending unqueued {command} message')
        header = MessageHeader.std_bytes(self.node.network.magic, command, payload)
        await connection.send(header + payload)

    def log_service_details(self, serv, headline):
        self.logger.info(headline)
        self.logger.info(f'    user_agent={serv.user_agent} services={serv.services!r}')
        self.logger.info(f'    protocol={serv.protocol_version} height={serv.start_height:,d}  '
                         f'relay={serv.relay} timestamp={serv.timestamp} assoc_id={serv.assoc_id}')

    async def version_payload(self):
        # Send version message with our current height
        our_service = self.node.service
        our_service.start_height = await self.node.height()
        self.log_service_details(our_service, 'sending version message:')
        return version_payload(our_service, self.remote_service.address, self.nonce)

    async def send_version_message(self, connection):
        payload = await self.version_payload()
        await self._send_unqueued(connection, MessageHeader.VERSION, payload)
        self.version_sent = True

    async def send_verack_message(self, connection):
        await self._send_unqueued(connection, MessageHeader.VERACK, b'')

    async def perform_handshake(self, connection):
        '''Perform the initial handshake.  Send version and verack messages, and wait until a
        verack is received back.'''
        if self.is_outgoing:
            await self.send_version_message(connection)
            # Outoing connections wait now
            await self.version_received.wait()
        else:
            # Incoming connections wait for version message first
            await self.version_received.wait()
            await self.send_version_message(connection)

        # Send verack.  The handhsake is complete once verack is received
        await self.send_verack_message(connection)
        await self.verack_received.wait()

    def connection_for_command(self, _command):
        return self.connection

    async def send_message(self, command, payload):
        '''Send a command and its payload.'''
        connection = self.connection_for_command(command)
        header = MessageHeader.std_bytes(self.node.network.magic, command, payload)
        await connection.outgoing_messages.put((header, payload))

    async def send_large_message(self, command, payload_len, payload_func):
        '''Send a command as an extended message with its payload.'''
        if not self.can_send_large_messages:
            raise RuntimeError('large messages cannot be sent')
        connection = self.connection_for_command(command)
        header = MessageHeader.ext_bytes(self.node.network.magic, command, payload_len)
        await connection.outgoing_messages.put((header, payload_func))

    async def handle_message(self, connection, header):
        if self.debug:
            self.logger.debug(f'<- {header} payload {header.payload_len:,d} bytes')

        magic = self.node.network.magic
        if header.magic != magic:
            raise ForceDisconnectError(f'bad magic: got 0x{header.magic.hex()} '
                                       f'expected 0x{magic.hex()}')

        if not self.verack_received.is_set():
            if header.command_bytes not in (MessageHeader.VERSION, MessageHeader.VERACK):
                raise ProtocolError(f'{header} command received before handshake finished')

        if header.is_extended and await self.handle_large_message(connection, header):
            return

        command = header.command()
        payload = await connection.recv_exactly(header.payload_len)
        handler = getattr(self, f'on_{command}', None)
        if not handler:
            if self.debug:
                self.logger.debug(f'ignoring unhandled {command} command')
            return

        if not header.is_extended and header.payload_checksum(payload) != header.checksum:
            # Maybe force disconnect if we get too many bad checksums in a short time
            error = ProtocolError if self.verack_received.is_set() else ForceDisconnectError
            raise error(f'bad checksum for {header} command')

        await handler(payload)

    async def handle_large_message(self, connection, header):
        if self.node.service.protocol_version < LARGE_MESSAGES_PROTOCOL_VERSION:
            raise ForceDisconnectError('large message received but invalid')

        # If the payload is small read it all in - just as for standard messages
        if header.payload_len < self.streaming_min_size:
            return False

        command = header.command()
        size = header.payload_len
        handler = getattr(self, f'on_{command}_large', None)
        if not handler:
            self.logger.warning(f'ignoring large {command} with payload of {size:,d} bytes')
            async for _chunk in connection.recv_chunks(size):
                pass
        else:
            await handler(connection, size)
        return True

    # Call to request various things from the peer

    async def get_addr(self):
        '''Call to request network nodes from the peer.'''

    async def get_data(self, items):
        '''Request various items from the peer.'''

    async def get_block(self, block_hash):
        '''Call to request the block with the given hash.'''

    async def sync_headers(self, timeout_secs):
        self.headers_synced = False
        while not self.headers_synced:
            await self.get_headers()
            try:
                async with timeout(timeout_secs):
                    await self.headers_received.wait()
            except asyncio.TimeoutError:
                logging.error(f'timeout syncing headers after {timeout}s')
                break

    async def block_locator(self):
        return await BlockLocator.from_block_hash(self.node.service.protocol_version,
                                                  self.node.headers, self.their_tip.hash)

    async def get_headers(self, locator=None):
        '''Send a request to get headers for the given locator.  If not provided,
        uses self.locator().
        '''
        if locator is None:
            locator = await self.block_locator()
        if self.debug:
            self.logger.debug(f'requesting headers; locator has {len(locator)} entries')
        await self.send_message(MessageHeader.GETHEADERS, locator.to_payload())
        self.getheaders_locator = locator
        self.headers_received.clear()

    # Callbacks when certain messages are received.

    async def on_addr(self, services):
        '''Called when an addr message is received.'''

    async def on_block(self, raw):
        '''Called when a block is received.'''

    async def on_headers(self, payload):
        '''Handle getting a bunch of headers.'''
        locator = self.getheaders_locator
        self.getheaders_locator = BlockLocator.NULL
        # So we abandon a sync in case of any kind of error
        self.headers_synced = True
        try:
            simple_headers = unpack_headers_payload(payload)
            locator.validate_headers(simple_headers)

            count = len(simple_headers)
            if count > self.MAX_HEADERS:
                self.logger.warning(f'protocol violation: {count:,d} headers received')

            if simple_headers:
                await self.node.headers.insert_headers(simple_headers)
                self.their_tip = simple_headers[-1]
            if count < self.MAX_HEADERS:
                self.logger.info(f'headers synchronized to height {self.their_tip.height}')
            else:
                self.headers_synced = False
        finally:
            self.headers_received.set()

    async def on_getheaders(self, payload):
        locator = BlockLocator.from_payload(payload)
        headers_payload = await locator.headers_payload(self.node.headers, self.MAX_HEADERS)
        # Ignore if there are no block hashes and the hash_stop block is missing
        if locator.block_hashes or len(headers_payload) > 1:
            await self.send_message(MessageHeader.HEADERS, headers_payload)
        else:
            self.logger.info('ignoring getheaders for unknown block '
                             f'{hash_to_hex_str(locator.hash_stop)}')

    async def on_inv(self, items):
        '''Called when an inv message is received advertising availability of various objects.'''

    async def on_tx(self, raw):
        '''Called when a tx is received.'''

    async def on_version(self, payload):
        '''Called when a version message is received.   remote_service has been updated as
        they report it (except the address is unchanged).'''
        if self.version_received.is_set():
            raise ProtocolError('duplicate version message')
        self.version_received.set()
        try:
            _, _, nonce = read_version_payload(self.remote_service, payload)
        except PackingError:
            raise ForceDisconnectError('corrupt version message')
        if self.node.is_our_nonce(nonce):
            raise ForceDisconnectError('connected to ourself')
        self.log_service_details(self.remote_service, 'received version message:')
        self.can_send_large_messages = (self.remote_service.protocol_version
                                        >= LARGE_MESSAGES_PROTOCOL_VERSION)

    async def on_verack(self, payload):
        if not self.version_sent:
            raise ProtocolError('verack message received before version message sent')
        if self.verack_received.is_set():
            raise ProtocolError('duplicate verack message')
        self.verack_received.set()
        if payload:
            self.logger.info('verack message has payload')

    async def on_protoconf(self, payload):
        '''Called when a protoconf message is received.'''
        if self.their_protoconf:
            raise ProtocolError('duplicate protoconf message received')
        self.their_protoconf = Protoconf.from_payload(payload, self.logger)

    async def send_protoconf(self):
        if self.protoconf_sent:
            self.logger.warning('protoconf message already sent')
            return
        self.protoconf_sent = True
        await self.send_message(MessageHeader.PROTOCONF, self.protoconf.payload())
