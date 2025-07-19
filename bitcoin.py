import asyncio
import ipaddress
import socket
import struct
import time
from asyncio import StreamReader, StreamWriter
from datetime import datetime
from enum import Enum
from hashlib import sha256

from settings import Settings
from storage import Storage

user_agent_local = '/Cthulhu:0/'
IP_UNKNOWN = bytes([0] * 10 + [255, 255, 127, 0, 0, 1])


class BitcoinNetwork(Enum):
    MAINNET = 'f9beb4d9'
    TESTNET = '0b110907'
    REGTEST = 'fabfb5da'

    def as_bytes(self) -> bytes:
        return bytes.fromhex(self.value)


class BrokenProtocolException(Exception):
    pass


class Header:
    format = '<4s12sI4s'
    size = struct.calcsize(format)

    def __init__(self, network: bytes, command: str, payload_size: int, checksum: bytes):
        self.network = network
        self.command = command
        self.payload_size = payload_size
        self.checksum = checksum

    @classmethod
    def checksum(cls, payload: bytes) -> bytes:
        return sha256(sha256(payload).digest()).digest()[:4]

    @classmethod
    def encode(cls, command: str, payload: bytes) -> bytes:
        settings = Settings()
        checksum = cls.checksum(payload)
        return struct.pack(cls.format, settings.network, command.encode('ascii'), len(payload), checksum)

    @classmethod
    def decode(cls, data: bytes):
        settings = Settings()
        network, raw_command, payload_size, checksum = struct.unpack(cls.format, data)
        if network != settings.network:
            raise BrokenProtocolException(f'network {network.hex()}')
        command = raw_command.decode('ascii').rstrip('\0')
        return Header(network, command, payload_size, checksum)

    def __str__(self) -> str:
        return f'Header {self.command} {self.payload_size} {self.checksum.hex()}'


class CompactSize:

    @classmethod
    def encode(cls, value: int) -> bytes:
        if value <= 0xfc:
            return struct.pack('B', value)
        elif value <= 0xffff:
            return b'\xfd' + struct.pack('<H', value)
        elif value <= 0xffffffff:
            return b'\xfe' + struct.pack('<I', value)
        else:
            return b'\xff' + struct.pack('<Q', value)

    @classmethod
    def decode(cls, data: bytes, offset: int = 0) -> tuple[int, int]:
        """Return: (value, bytes_consumed)"""
        first = data[offset]

        if first < 0xfd:
            # 1 byte
            return first, 1
        elif first == 0xfd:
            # 3 first: 0xfd + 2 byte little endian
            value = struct.unpack('<H', data[offset+1:offset+3])[0]
            return value, 3
        elif first == 0xfe:
            # 5 bytes: 0xfe + 4 byte little endian
            value = struct.unpack('<I', data[offset+1:offset+5])[0]
            return value, 5
        else:
            # 9 bytes: 0xff + 8 byte little endian
            value = struct.unpack('<Q', data[offset+1:offset+9])[0]
            return value, 9


class Version:
    command = 'version'
    format = '<iQqQ16sHQ16sHQziB'
    format_simple = '<iQqQ16sHQ16sHQ B iB'

    @classmethod
    def encode_simple(cls):
        # https://developer.bitcoin.org/reference/p2p_networking.html#version
        protocol_version = 70015  # int32_t i; Bitcoin Core 0.13.2 (Jan 2017)
        services = 0  # uint64_t Q
        timestamp = int(time.time())  # int64_t q
        addr_recv_services = 0  # uint64_t Q; we can send 0
        addr_recv_ip = IP_UNKNOWN  # char[16] 16s
        addr_recv_port = 0  # uint16_t H
        addr_trans_services = services  # uint64_t Q
        addr_trans_ip = IP_UNKNOWN  # char[16] 16s
        addr_trans_port = 0  # uint16_t H
        nonce = 0  # uint64_t Q; with 0 is ignored
        user_agent_bytes = 0  # compactSize uint, 0x00 B to skip the user agent
        # skip user_agent because user_agent_bytes == 0
        start_height = 0  # int32_t i
        relay = 0  # bool B
        data = struct.pack(cls.format_simple, protocol_version, services, timestamp, addr_recv_services,
                           addr_recv_ip, addr_recv_port, addr_trans_services, addr_trans_ip, addr_trans_port, nonce,
                           user_agent_bytes, start_height, relay)
        return data

    @classmethod
    def encode(cls):
        # https://developer.bitcoin.org/reference/p2p_networking.html#version
        protocol_version = 70015  # int32_t i; Bitcoin Core 0.13.2 (Jan 2017)
        services = 0  # uint64_t Q
        timestamp = int(time.time())  # int64_t q
        addr_recv_services = 0  # uint64_t Q; we can send 0
        addr_recv_ip = IP_UNKNOWN  # char[16] 16s
        addr_recv_port = 0  # uint16_t H
        addr_trans_services = services  # uint64_t Q
        addr_trans_ip = IP_UNKNOWN  # char[16] 16s
        addr_trans_port = 0  # uint16_t H
        nonce = 0  # uint64_t Q; with 0 is ignored
        # user_agent z
        start_height = 904877  # int32_t i
        relay = 0  # bool B

        data0 = struct.pack(cls.format.split('z')[0], protocol_version, services, timestamp, addr_recv_services,
                           addr_recv_ip, addr_recv_port, addr_trans_services, addr_trans_ip, addr_trans_port, nonce)
        data_user_agent = CompactSize.encode(len(user_agent_local)) + user_agent_local.encode('utf-8')
        data1 = struct.pack(cls.format[0] + cls.format.split('z')[1], start_height, relay)
        return data0 + data_user_agent + data1

    @classmethod
    def decode(cls, data: bytes):
        fixed_size_format = cls.format.split('z')[0]
        fixed_size = struct.calcsize(fixed_size_format)
        fields = struct.unpack(fixed_size_format, data[:fixed_size])
        protocol_version = fields[0]
        services = fields[1]
        timestamp = fields[2]
        addr_recv_services = fields[3]
        addr_recv_ip = fields[4]
        addr_recv_port = fields[5]
        addr_trans_services = fields[6]
        addr_trans_ip = fields[7]
        addr_trans_port = fields[8]
        nonce = fields[9]
        user_agent_bytes, bytes_consumed = CompactSize.decode(data, fixed_size)
        offset = fixed_size + bytes_consumed
        user_agent = data[offset:offset + user_agent_bytes].decode('utf-8')
        offset += user_agent_bytes
        start_height, relay = struct.unpack('<iB', data[offset:])
        print('protocol_version', protocol_version)
        print('services', cls.decode_services(services))
        print('timestamp', datetime.fromtimestamp(timestamp))
        print('addr_recv_services', addr_recv_services)
        print('addr_recv_ip port', addr_recv_ip, addr_recv_port)
        print('addr_trans_services', addr_trans_services)
        print('addr_trans_ip port', addr_trans_ip, addr_trans_port)
        print('nonce', nonce)
        print('user_agent', user_agent)
        print('start_height', start_height)
        print('relay', relay)

    @staticmethod
    def decode_services(value: int) -> str:
        services = [
            (1 << 0, 'NETWORK'),
            (1 << 2, 'BLOOM'),
            (1 << 3, 'WITNESS'),
            (1 << 6, 'COMPACT_FILTERS'),
            (1 << 10, 'NETWORK_LIMITED'),
            (1 << 11, 'P2P_V2'),
        ]
        enabled = []
        for code, label in services:
            if value & code:
                enabled.append(label)
        return ' '.join(enabled)


class SendCmpct:
    command = 'sendcmpct'
    format = '<BQ'

    @classmethod
    def decode(cls, data: bytes) -> tuple[int, int]:
        u1, u2 = struct.unpack(cls.format, data)
        return u1, u2


class FeeFilter:
    """uint64_t Q The fee rate (in satoshis per kilobyte) below which transactions should not be relayed to this peer"""
    command = 'feefilter'
    format = '<Q'


    @classmethod
    def decode(cls, data: bytes) -> int:
        fee_rate, = struct.unpack(cls.format, data)
        return fee_rate


class Ping:
    command = 'ping'
    format = '<Q'

    @classmethod
    def encode(cls, value: int) -> bytes:
        return struct.pack(cls.format, value)

    @classmethod
    def decode(cls, data: bytes) -> int:
        nonce, = struct.unpack(cls.format, data)
        return nonce


class Addr:
    command = 'addr'
    addr_format = '<IQ16s'
    port_format = '>H'
    # uint32 uint64_t char[16] uint16_t

    def __init__(self, timestamp: int, services: int, address: str, port: int, is_ipv4: bool):
        self.timestamp = timestamp  # the last time they connected to that node
        self.services = services
        self.address = address
        self.port = port
        self.is_ipv4 = is_ipv4

    def __str__(self):
        return (f'{self.address}:{self.port} ({Version.decode_services(self.services)}) '
                f'{datetime.fromtimestamp(self.timestamp)}')

    def __repr__(self):
        return f'Addr({str(self)})'

    @property
    def addr_str(self) -> str:
        return f'{self.address}:{self.port}'

    @classmethod
    def decode(cls, data: bytes) -> list['Addr']:
        out = []
        n_addr, bytes_consumed = CompactSize.decode(data)
        addr_raw_size = struct.calcsize(cls.addr_format)
        port_raw_size = struct.calcsize(cls.port_format)
        offset = bytes_consumed
        for _ in range(n_addr):
            timestamp, services, ip = struct.unpack_from(cls.addr_format, data, offset)
            offset += addr_raw_size
            port, = struct.unpack_from(cls.port_format, data, offset)
            offset += port_raw_size
            address, is_ipv4 = cls.parse_net_addr(ip)
            out.append(cls(timestamp, services, address, port, is_ipv4))
        return out

    @staticmethod
    def parse_net_addr(ip_data: bytes) -> tuple[str, bool]:
        """
        Convert 16-byte Bitcoin net_addr IP into human-readable IP string.
        """
        ip = ipaddress.IPv6Address(ip_data)

        # Check if it's IPv4-mapped IPv6
        if ip.ipv4_mapped:
            return str(ip.ipv4_mapped), True  # Return IPv4-style string
        else:
            return str(ip), False  # Return full IPv6 string

async def send_getaddr(writer: StreamWriter) -> None:
    getaddr_header = Header.encode('getaddr', b'')
    # sock.send(getaddr_header)
    writer.write(getaddr_header)
    await writer.drain()



async def send_verack(writer: StreamWriter) -> None:
    verack_header = Header.encode('verack', b'')
    # sock.send(verack_header)
    writer.write(verack_header)
    await writer.drain()


def send_ping(sock: socket.socket, nonce: int) -> None:
    ping_payload = Ping.encode(nonce)
    ping_header = Header.encode('ping', ping_payload)
    sock.send(ping_header + ping_payload)


async def receive_bytes(reader: StreamReader, size: int) -> bytes:
    count = 0
    buffer = bytearray()
    while count < size:
        # data = sock.recv(size - count)
        data = await reader.read(size - count)
        if not data:
            raise ConnectionResetError(
                f'The connection was closed by the peer after receiving {count} of {size} bytes.')
        count += len(data)
        buffer.extend(data)
    return bytes(buffer)


async def network_loop(host: str, port: int, log_prefix: str, timeout: int = 10) -> tuple[int | None, list[Addr]]:
    """
    Wait for the feefilter message and return the fee rate value.
    We should download addresses from the peer.
    After 2' close the socket.
    """
    t0 = time.time()
    fee_rate = None
    addrs = []
    version_payload = Version.encode()
    version_header = Header.encode('version', version_payload)

    try:
        print(log_prefix, f'Connecting to ~:{port}...')

        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        print(log_prefix, 'Connected!')

        writer.write(version_header + version_payload)
        await writer.drain()

        try:
            while True:
                if time.time() - t0 > 120:
                    return fee_rate, addrs
                raw_header = await receive_bytes(reader, Header.size)
                header = Header.decode(raw_header)
                print(log_prefix, 'received header of', header.command)

                raw_payload = await receive_bytes(reader, header.payload_size)
                if header.checksum != Header.checksum(raw_payload):
                    print(log_prefix, header.checksum.hex(), Header.checksum(raw_payload).hex())
                    print(log_prefix, len(raw_payload))
                    raise BrokenProtocolException('Wrong checksum')
                match header.command:
                    case 'version':
                        await send_verack(writer)
                    case 'feefilter':
                        fee_rate = FeeFilter.decode(raw_payload)
                        print(log_prefix, 'feefilter', fee_rate)
                        await send_getaddr(writer)
                    case 'addr':
                        addrs = Addr.decode(raw_payload)
                        writer.close()
                        await writer.wait_closed()
                        return fee_rate, addrs
                    case 'verack' | 'sendheaders' | 'inv' | 'alert' | 'sendcmpct' | 'ping':
                        pass
                    case _:
                        raise BrokenProtocolException(f'unknown command {header.command}')

        except socket.timeout:
            print(log_prefix, 'Timeout - no data received')
            return None, []
        except ConnectionResetError:
            print(log_prefix, 'Connection reset by server')
            return None, []
        except struct.error as ex:
            if ex.args[0].startswith('unpack requires a buffer of'):
                print(log_prefix, 'Invalid data:', ex)
                return None, []
            raise
    except ConnectionRefusedError:
        print(log_prefix, f'Connection refused to ~:{port}')
    except socket.timeout:
        print(log_prefix, f'Connection timeout to ~:{port}')
    except OSError as ex:
        print(log_prefix, f'Fail connection to ~:{port}')
        print(log_prefix, ex)
    except BrokenProtocolException as ex:
        print(log_prefix, ex)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
            print(log_prefix, 'Socket closed')
        except:
            pass
    return None, []


def host_port(addr: str) -> tuple[str, int]:
    host, port_str = addr.split(':')
    port = int(port_str)
    return host, port


def char_id(routine_id: int) -> str:
    if routine_id < 10:
        base = '0'
        offset = 0
    else:
        base = 'A'
        offset = -10
    return chr(ord(base) + routine_id + offset)


async def nodes_loop(routine_id: int) -> None:
    s = Storage()
    while True:
        addr_str, last_seen = s.last_seen_pop()
        first_seen = s.first_seen_get(addr_str)
        if not addr_str:
            print('nodes_loop No addresses to explore')
            break
        h, p = host_port(addr_str)
        log_prefix = f'{char_id(routine_id)} {h:15}'
        print(log_prefix, readable_timestamp(first_seen)[:13], '→', readable_timestamp(last_seen)[:13])
        fee_rate, addresses = await network_loop(h, p, log_prefix)
        if fee_rate is not None:
            s.result_push(addr_str, dict(fee_rate=fee_rate, timestamp=int(time.time())))

        # storage: processed
        addr_ts = {addr.addr_str: addr.timestamp for addr in addresses
                   if addr.is_ipv4 and not s.processed_is(addr.addr_str)}
        s.processed_add(*addr_ts.keys())

        # storage: timestamps
        s.last_seen_add(addr_ts)
        s.first_seen_set(addr_ts)


def readable_timestamp(timestamp: int) -> str:
    return str(datetime.fromtimestamp(timestamp))
