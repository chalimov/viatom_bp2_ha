"""Viatom BP2 BLE protocol handler.

This module implements the Lepu BLE protocol used by Viatom BP2/BP2A/BP2W
blood pressure monitors. The protocol is reverse-engineered from the
viatom-develop/LepuDemo Android SDK.

Protocol frame format:
  [Header(1)] [Cmd(1)] [~Cmd(1)] [SeqNo(2)] [Length(2)] [Payload(N)] [CRC8(1)]

Header: 0xA5
Cmd: command type byte
~Cmd: bitwise NOT of Cmd
SeqNo: 2-byte little-endian sequence number
Length: 2-byte little-endian payload length
Payload: variable length data
CRC8: CRC-8/MAXIM of payload bytes
"""

from __future__ import annotations

import struct
import time
import logging
from dataclasses import dataclass
from itertools import count
from typing import Callable

_LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CRC-8 / MAXIM (polynomial 0x31, init 0x00, refin=True, refout=True)
# ---------------------------------------------------------------------------
_CRC8_TABLE = [0] * 256

def _init_crc8_table() -> None:
    poly = 0x8C  # reversed 0x31
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
        _CRC8_TABLE[i] = crc

_init_crc8_table()


def crc8(data: bytes) -> int:
    """Calculate CRC-8/MAXIM over data."""
    crc = 0x00
    for b in data:
        crc = _CRC8_TABLE[crc ^ b]
    return crc


# ---------------------------------------------------------------------------
# Data classes for parsed results
# ---------------------------------------------------------------------------
@dataclass
class BpResult:
    """A single blood pressure measurement."""
    systolic: int = 0
    diastolic: int = 0
    pulse: int = 0
    mean_arterial_pressure: int = 0
    timestamp: int = 0  # unix seconds
    irregular_heartbeat: bool = False

    @property
    def timestamp_str(self) -> str:
        if self.timestamp > 0:
            return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp))
        return ""


@dataclass
class DeviceInfo:
    """BP2 device information."""
    hw_version: str = ""
    fw_version: str = ""
    serial_number: str = ""
    battery_level: int = 0
    battery_status: int = 0
    device_status: int = 0


@dataclass
class RtData:
    """Real-time data from BP2."""
    device_status: int = 0
    battery_status: int = 0
    battery_level: int = 0
    systolic: int = 0
    diastolic: int = 0
    pulse: int = 0
    mean_arterial_pressure: int = 0
    measuring: bool = False
    result_ready: bool = False
    cuff_pressure: int = 0


# ---------------------------------------------------------------------------
# Packet builder / parser
# ---------------------------------------------------------------------------
class LepuPacket:
    """Represents a single Lepu protocol packet."""

    HEADER = 0xA5

    def __init__(self, cmd: int, payload: bytes = b"", seq: int = 0):
        self.cmd = cmd
        self.payload = payload
        self.seq = seq

    def encode(self) -> bytes:
        """Encode the packet to bytes for transmission."""
        cmd_inv = (~self.cmd) & 0xFF
        length = len(self.payload)
        # Header + Cmd + ~Cmd + SeqNo(2) + Length(2) + Payload + CRC8
        header = struct.pack(
            "<BBBHH",
            self.HEADER,
            self.cmd,
            cmd_inv,
            self.seq & 0xFFFF,
            length,
        )
        if length > 0:
            crc = crc8(self.payload)
        else:
            crc = 0
        return header + self.payload + bytes([crc])

    @classmethod
    def decode(cls, data: bytes) -> LepuPacket | None:
        """Decode bytes into a LepuPacket. Returns None if invalid."""
        if len(data) < 8:  # minimum: header(1)+cmd(1)+~cmd(1)+seq(2)+len(2)+crc(1)
            return None
        if data[0] != cls.HEADER:
            _LOGGER.debug("Invalid header: 0x%02X", data[0])
            return None
        cmd = data[1]
        cmd_inv = data[2]
        if cmd_inv != (~cmd & 0xFF):
            _LOGGER.debug("Cmd/~Cmd mismatch: 0x%02X vs 0x%02X", cmd, cmd_inv)
            return None
        seq = struct.unpack_from("<H", data, 3)[0]
        length = struct.unpack_from("<H", data, 5)[0]
        if len(data) < 7 + length + 1:
            _LOGGER.debug("Packet too short: expected %d, got %d", 7 + length + 1, len(data))
            return None
        payload = data[7 : 7 + length]
        received_crc = data[7 + length]
        if length > 0:
            calc_crc = crc8(payload)
            if calc_crc != received_crc:
                _LOGGER.debug("CRC mismatch: calc=0x%02X recv=0x%02X", calc_crc, received_crc)
                return None
        pkt = cls(cmd, payload, seq)
        return pkt


# ---------------------------------------------------------------------------
# Response parsers
# ---------------------------------------------------------------------------
def parse_device_info(payload: bytes) -> DeviceInfo:
    """Parse device info response payload."""
    info = DeviceInfo()
    try:
        if len(payload) >= 20:
            # Typical Lepu info response:
            # bytes 0-5: hw version string
            # bytes 6-11: fw version string
            # bytes 12-19: serial number
            info.hw_version = payload[0:6].decode("ascii", errors="replace").strip("\x00")
            info.fw_version = payload[6:12].decode("ascii", errors="replace").strip("\x00")
            info.serial_number = payload[12:20].decode("ascii", errors="replace").strip("\x00")
        if len(payload) >= 22:
            info.battery_level = payload[20]
            info.battery_status = payload[21]
    except Exception as e:
        _LOGGER.warning("Failed to parse device info: %s", e)
    return info


def parse_rt_data(payload: bytes) -> RtData:
    """Parse real-time data notification payload.

    This is sent continuously while the device is active.
    The exact format varies by firmware version. The layout below
    is based on analysis of the LepuDemo SDK's RtData class.
    """
    rt = RtData()
    try:
        if len(payload) >= 1:
            rt.device_status = payload[0]
        if len(payload) >= 2:
            rt.battery_status = payload[1]
        if len(payload) >= 3:
            rt.battery_level = payload[2]
        if len(payload) >= 5:
            rt.cuff_pressure = struct.unpack_from("<H", payload, 3)[0]
        # When device_status == 5 (STATUS_BP_MEASURE_END), the result follows
        if rt.device_status == 5 and len(payload) >= 15:
            rt.result_ready = True
            rt.systolic = struct.unpack_from("<H", payload, 5)[0]
            rt.diastolic = struct.unpack_from("<H", payload, 7)[0]
            rt.mean_arterial_pressure = struct.unpack_from("<H", payload, 9)[0]
            rt.pulse = struct.unpack_from("<H", payload, 11)[0]
            # byte 13: flags (bit 0 = irregular heartbeat)
            if len(payload) >= 14:
                rt.measuring = False
        elif rt.device_status == 4:
            rt.measuring = True
    except Exception as e:
        _LOGGER.warning("Failed to parse rt data: %s (payload hex: %s)", e, payload.hex())
    return rt


def parse_bp_file(payload: bytes) -> list[BpResult]:
    """Parse a BP file downloaded from device storage.

    BP files contain one or more BP records. The Lepu SDK BpFile format
    uses a 4-byte header followed by variable-length records.

    Two record formats are attempted (auto-detected by payload size):
      Format A (12 bytes): timestamp(4) + systolic(2) + diastolic(2) + pulse(2) + MAP(1) + flags(1)
      Format B (8 bytes):  timestamp(4) + systolic(1) + diastolic(1) + pulse(1) + flags(1)

    Note: The exact record format may need adjustment based on sniffed data.
    Update this parser once you've captured actual BLE traffic.
    """
    results: list[BpResult] = []
    try:
        # Skip file header (first 4 bytes typically contain file type + record count)
        if len(payload) < 4:
            return results
        file_type = payload[0]
        if file_type != 1:  # 1 = BP file, 2 = ECG file
            _LOGGER.debug("Not a BP file (type=%d), skipping", file_type)
            return results
        record_count = payload[1]
        data_len = len(payload) - 4
        offset = 4  # skip header

        # Auto-detect record size: try 12-byte format first (supports >255 mmHg)
        if record_count > 0 and data_len >= record_count * 12:
            record_size = 12
        elif record_count > 0 and data_len >= record_count * 8:
            record_size = 8
        else:
            # Fallback: try to infer from total data length
            record_size = 12 if data_len % 12 == 0 else 8

        _LOGGER.debug(
            "BP file: type=%d records=%d data_len=%d record_size=%d",
            file_type, record_count, data_len, record_size,
        )

        for i in range(record_count):
            if offset + record_size > len(payload):
                break
            record = payload[offset : offset + record_size]
            ts = struct.unpack_from("<I", record, 0)[0]

            if record_size == 12:
                # 2-byte fields — supports full 0-300 mmHg range
                bp = BpResult(
                    timestamp=ts,
                    systolic=struct.unpack_from("<H", record, 4)[0],
                    diastolic=struct.unpack_from("<H", record, 6)[0],
                    pulse=struct.unpack_from("<H", record, 8)[0],
                    mean_arterial_pressure=record[10],
                    irregular_heartbeat=bool(record[11] & 0x01),
                )
            else:
                # 1-byte fields (legacy or compact format)
                bp = BpResult(
                    timestamp=ts,
                    systolic=record[4],
                    diastolic=record[5],
                    pulse=record[6],
                    irregular_heartbeat=bool(record[7] & 0x01),
                )

            # Calculate MAP if not provided or zero
            if bp.mean_arterial_pressure == 0 and bp.systolic > 0 and bp.diastolic > 0:
                bp.mean_arterial_pressure = bp.diastolic + (bp.systolic - bp.diastolic) // 3
            results.append(bp)
            offset += record_size
    except Exception as e:
        _LOGGER.warning("Failed to parse BP file: %s (payload hex: %s)", e, payload.hex())
    return results


def parse_file_list(payload: bytes) -> list[str]:
    """Parse file list response.

    Returns list of filenames stored on the device.
    Filenames are null-terminated strings.
    """
    files: list[str] = []
    try:
        if len(payload) < 2:
            return files
        file_count = struct.unpack_from("<H", payload, 0)[0]
        offset = 2
        for _ in range(file_count):
            # Find null terminator
            end = payload.find(0x00, offset)
            if end < 0:
                end = len(payload)
            name = payload[offset:end].decode("ascii", errors="replace")
            if name:
                files.append(name)
            offset = end + 1
            if offset >= len(payload):
                break
    except Exception as e:
        _LOGGER.warning("Failed to parse file list: %s", e)
    return files


# ---------------------------------------------------------------------------
# Command builders
# ---------------------------------------------------------------------------
_seq_iter = count(1)


def _next_seq() -> int:
    """Return the next sequence number (wraps at 0xFFFF)."""
    return next(_seq_iter) & 0xFFFF


def build_get_info() -> bytes:
    """Build GET_INFO command."""
    return LepuPacket(cmd=0x14, seq=_next_seq()).encode()


def build_sync_time() -> bytes:
    """Build SYNC_TIME command with current UTC timestamp."""
    ts = int(time.time())
    payload = struct.pack("<I", ts)
    return LepuPacket(cmd=0x0C, payload=payload, seq=_next_seq()).encode()


def build_get_file_list() -> bytes:
    """Build GET_FILE_LIST command."""
    return LepuPacket(cmd=0x18, seq=_next_seq()).encode()


def build_read_file_start(filename: str) -> bytes:
    """Build READ_FILE_START command."""
    payload = filename.encode("ascii") + b"\x00"
    return LepuPacket(cmd=0x1A, payload=payload, seq=_next_seq()).encode()


def build_read_file_data(offset: int) -> bytes:
    """Build READ_FILE_DATA command for a given offset."""
    payload = struct.pack("<I", offset)
    return LepuPacket(cmd=0x1C, payload=payload, seq=_next_seq()).encode()


def build_read_file_end() -> bytes:
    """Build READ_FILE_END command."""
    return LepuPacket(cmd=0x1E, seq=_next_seq()).encode()


# ---------------------------------------------------------------------------
# Packet reassembler (for notifications that arrive in chunks)
# ---------------------------------------------------------------------------
class PacketReassembler:
    """Reassembles fragmented BLE notifications into complete Lepu packets."""

    def __init__(self):
        self._buffer = bytearray()
        self.on_packet: Callable[[LepuPacket], None] | None = None

    def feed(self, data: bytes) -> None:
        """Feed raw notification data. Complete packets are dispatched."""
        self._buffer.extend(data)
        self._try_parse()

    def _try_parse(self) -> None:
        """Try to extract complete packets from the buffer."""
        while len(self._buffer) >= 8:
            # Find header byte
            idx = self._buffer.find(bytes([LepuPacket.HEADER]))
            if idx < 0:
                self._buffer.clear()
                return
            if idx > 0:
                _LOGGER.debug("Skipping %d bytes before header", idx)
                self._buffer = self._buffer[idx:]

            if len(self._buffer) < 7:
                return

            # Validate cmd/~cmd before trusting this as a real header
            cmd = self._buffer[1]
            cmd_inv = self._buffer[2]
            if cmd_inv != (~cmd & 0xFF):
                # Not a real packet header — skip this 0xA5 byte and search again
                _LOGGER.debug(
                    "False header at buffer start (cmd=0x%02X ~cmd=0x%02X), skipping",
                    cmd, cmd_inv,
                )
                self._buffer = self._buffer[1:]
                continue

            length = struct.unpack_from("<H", self._buffer, 5)[0]
            total_len = 7 + length + 1  # header(7) + payload + crc(1)

            # Sanity check: reject absurdly large packets (max BLE MTU is ~512)
            if length > 1024:
                _LOGGER.debug("Implausible payload length %d, skipping byte", length)
                self._buffer = self._buffer[1:]
                continue

            if len(self._buffer) < total_len:
                return  # wait for more data

            packet_bytes = bytes(self._buffer[:total_len])
            self._buffer = self._buffer[total_len:]

            pkt = LepuPacket.decode(packet_bytes)
            if pkt and self.on_packet:
                self.on_packet(pkt)
            elif pkt is None:
                _LOGGER.debug(
                    "Failed to decode packet: %s", packet_bytes.hex()
                )

    def reset(self) -> None:
        """Clear the reassembly buffer."""
        self._buffer.clear()
