"""Viatom BP2W BLE protocol handler.

This module implements the Lepu BLE protocol V2 used by Viatom LP-BP2W
blood pressure monitors. The protocol was reverse-engineered from
HCI snoop log captures of the official ViHealth Android app.

Protocol frame format:
  [Header(1)] [Cmd(1)] [~Cmd(1)] [SeqLo(1)] [SeqHi(1)] [LenLo(1)] [LenHi(1)] [Payload(N)] [CRC8(1)]

Header: 0xA5
Cmd: command type byte
~Cmd: bitwise NOT of Cmd
SeqLo: TX/RX flag (0x00=TX, 0x01=RX)
SeqHi: command counter (increments per command sent)
Length: 2-byte little-endian payload length
Payload: variable length data
CRC8: CRC-8/MAXIM over payload bytes (0x00 if no payload)

Key differences from protocol V1:
  - CMD_SYNC_TIME = 0xC0 (not 0x0C), uses structured datetime payload
  - CMD_GET_INFO = 0x00 (not 0x14)
  - CMD_GET_DEVICE_INFO = 0xE1 (new)
  - CMD_GET_CONFIG = 0x33 (not 0x20)
  - CMD_GET_BATTERY = 0x30 (new)
  - CMD_READ_FILE_START = 0xF2 (not 0x1A), uses 20-byte padded filename
  - CMD_READ_FILE_DATA = 0xF3 (not 0x1C)
  - CMD_READ_FILE_END = 0xF4 (not 0x1E)
  - CMD_RT_DATA = 0x08 (not 0x16), pushed by device
  - Writes MUST use write-without-response (WRITE_CMD, not WRITE_REQ)
  - Seq number: byte3 = 0x00 for TX / 0x01 for RX, byte4 = counter
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
            return time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp)
            )
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
    """Real-time data from BP2 (CMD 0x08).

    Pushed by the device continuously while active.
    Payload is 32 bytes; layout reverse-engineered from HCI snoop.
    """

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
# Protocol V2 command codes (from HCI snoop of ViHealth app)
# ---------------------------------------------------------------------------
CMD_GET_INFO = 0x00
CMD_RT_DATA = 0x08
CMD_GET_BATTERY = 0x30
CMD_GET_CONFIG = 0x33
CMD_SYNC_TIME = 0xC0
CMD_GET_DEVICE_INFO = 0xE1
CMD_READ_FILE_START = 0xF2
CMD_READ_FILE_DATA = 0xF3
CMD_READ_FILE_END = 0xF4

# Device status codes
STATUS_READY = 3
STATUS_BP_MEASURING = 4
STATUS_BP_MEASURE_END = 5

# Known filenames on the device
FILE_USER_LIST = "user.list"
FILE_BP_LIST = "bp2nibp.list"


# ---------------------------------------------------------------------------
# Packet builder / parser
# ---------------------------------------------------------------------------
class LepuPacket:
    """Represents a single Lepu protocol V2 packet."""

    HEADER = 0xA5

    def __init__(self, cmd: int, payload: bytes = b"", seq: int = 0):
        self.cmd = cmd
        self.payload = payload
        self.seq = seq

    def encode(self) -> bytes:
        """Encode the packet to bytes for transmission."""
        cmd_inv = (~self.cmd) & 0xFF
        length = len(self.payload)
        # Header + Cmd + ~Cmd + SeqLo + SeqHi + LenLo + LenHi + Payload + CRC8
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
        if len(data) < 8:
            return None
        if data[0] != cls.HEADER:
            _LOGGER.debug("Invalid header: 0x%02X", data[0])
            return None
        cmd = data[1]
        cmd_inv = data[2]
        if cmd_inv != (~cmd & 0xFF):
            _LOGGER.debug(
                "Cmd/~Cmd mismatch: 0x%02X vs 0x%02X", cmd, cmd_inv
            )
            return None
        seq = struct.unpack_from("<H", data, 3)[0]
        length = struct.unpack_from("<H", data, 5)[0]
        if len(data) < 7 + length + 1:
            _LOGGER.debug(
                "Packet too short: expected %d, got %d",
                7 + length + 1,
                len(data),
            )
            return None
        payload = data[7 : 7 + length]
        received_crc = data[7 + length]
        if length > 0:
            calc_crc = crc8(payload)
            if calc_crc != received_crc:
                _LOGGER.debug(
                    "CRC mismatch: calc=0x%02X recv=0x%02X",
                    calc_crc,
                    received_crc,
                )
                return None
        return cls(cmd, payload, seq)


# ---------------------------------------------------------------------------
# Response parsers
# ---------------------------------------------------------------------------
def parse_device_info(payload: bytes) -> DeviceInfo:
    """Parse GET_INFO (CMD 0x00) response payload.

    The response is 40 bytes. Exact layout based on HCI snoop analysis.
    """
    info = DeviceInfo()
    try:
        if len(payload) >= 20:
            info.hw_version = (
                payload[0:6].decode("ascii", errors="replace").strip("\x00")
            )
            info.fw_version = (
                payload[6:12].decode("ascii", errors="replace").strip("\x00")
            )
            info.serial_number = (
                payload[12:20].decode("ascii", errors="replace").strip("\x00")
            )
        if len(payload) >= 22:
            info.battery_level = payload[20]
            info.battery_status = payload[21]
    except Exception as e:
        _LOGGER.warning("Failed to parse device info: %s", e)
    return info


def parse_rt_data(payload: bytes) -> RtData:
    """Parse real-time data (CMD 0x08) notification payload.

    This is pushed by the device continuously while active.
    Payload is 32 bytes. Layout from HCI snoop analysis:
      byte 0: device_status (3=READY, 4=MEASURING, 5=MEASURE_END)
      byte 1: battery_status
      byte 2: battery_level (percentage)
      bytes 3+: varies by device_status
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
        # When device_status == STATUS_BP_MEASURE_END, the result follows
        if rt.device_status == STATUS_BP_MEASURE_END and len(payload) >= 13:
            rt.result_ready = True
            rt.systolic = struct.unpack_from("<H", payload, 5)[0]
            rt.diastolic = struct.unpack_from("<H", payload, 7)[0]
            rt.mean_arterial_pressure = struct.unpack_from("<H", payload, 9)[0]
            rt.pulse = struct.unpack_from("<H", payload, 11)[0]
            rt.measuring = False
        elif rt.device_status == STATUS_BP_MEASURING:
            rt.measuring = True
    except Exception as e:
        _LOGGER.warning(
            "Failed to parse rt data: %s (payload hex: %s)",
            e,
            payload.hex(),
        )
    return rt


def parse_bp_file(payload: bytes) -> list[BpResult]:
    """Parse BP measurement data from the bp2nibp.list file.

    The file format (from HCI snoop analysis) contains measurement records.
    Each record contains BP readings with 2-byte LE fields for values that
    can exceed 255 (systolic, diastolic, pulse, MAP), plus timestamp and flags.

    Observed record structure in the file data:
      - Records separated by padding/header bytes
      - Each record: systolic(2) + diastolic(2) + pulse(2) + MAP(2) + flags + padding + timestamp(4)
    """
    results: list[BpResult] = []
    try:
        if len(payload) < 8:
            return results

        _LOGGER.debug(
            "Parsing BP file: %d bytes, first 40 hex: %s",
            len(payload),
            payload[:40].hex(),
        )

        # The file starts with a small header, then contains records.
        # From sniffing we see patterns like:
        #   72003e004b004000 00000000 00000000 0000000000 66b40f69 d7530300 01 ...
        #   sys=114 dia=62 pulse=75 MAP=64 ... timestamp ... flags
        # Records appear to be ~40 bytes each based on file size vs record count.
        # We scan for plausible BP readings (2-byte LE values in valid ranges).

        # Strategy: scan the raw bytes for 4 consecutive uint16 LE values
        # that look like BP readings (systolic: 60-250, diastolic: 30-150,
        # pulse: 30-200, MAP: 30-200).
        offset = 0
        while offset + 8 <= len(payload):
            sys_val = struct.unpack_from("<H", payload, offset)[0]
            dia_val = struct.unpack_from("<H", payload, offset + 2)[0]
            pulse_val = struct.unpack_from("<H", payload, offset + 4)[0]
            map_val = struct.unpack_from("<H", payload, offset + 6)[0]

            if (
                60 <= sys_val <= 250
                and 30 <= dia_val <= 150
                and 30 <= pulse_val <= 200
                and 30 <= map_val <= 200
                and dia_val < sys_val
            ):
                # Look for a 4-byte unix timestamp nearby (within next 20 bytes)
                ts = 0
                for ts_off in range(offset + 8, min(offset + 28, len(payload) - 3)):
                    candidate = struct.unpack_from("<I", payload, ts_off)[0]
                    # Valid unix timestamp: between 2020 and 2040
                    if 1577836800 <= candidate <= 2208988800:
                        ts = candidate
                        break

                bp = BpResult(
                    systolic=sys_val,
                    diastolic=dia_val,
                    pulse=pulse_val,
                    mean_arterial_pressure=map_val,
                    timestamp=ts,
                )
                # Calculate MAP if not provided
                if bp.mean_arterial_pressure == 0 and bp.systolic > 0:
                    bp.mean_arterial_pressure = (
                        bp.diastolic + (bp.systolic - bp.diastolic) // 3
                    )
                results.append(bp)
                _LOGGER.debug(
                    "Found BP record at offset %d: %d/%d pulse=%d MAP=%d ts=%s",
                    offset,
                    sys_val,
                    dia_val,
                    pulse_val,
                    map_val,
                    bp.timestamp_str,
                )
                # Skip past this record to avoid duplicate detection
                offset += 20
            else:
                offset += 2  # scan in 2-byte steps
    except Exception as e:
        _LOGGER.warning(
            "Failed to parse BP file: %s (payload len: %d)", e, len(payload)
        )
    return results


def parse_battery(payload: bytes) -> tuple[int, int]:
    """Parse GET_BATTERY (CMD 0x30) response.

    Returns (battery_level, battery_status).
    From HCI snoop: 4-byte payload, byte 1 appears to be battery level.
    """
    level = 0
    status = 0
    try:
        if len(payload) >= 2:
            status = payload[0]
            level = payload[1]
        if len(payload) >= 4:
            _LOGGER.debug(
                "Battery payload: %s (level=%d%% status=%d)",
                payload.hex(),
                level,
                status,
            )
    except Exception as e:
        _LOGGER.warning("Failed to parse battery: %s", e)
    return level, status


# ---------------------------------------------------------------------------
# Command builders (Protocol V2)
# ---------------------------------------------------------------------------
_seq_counter = count(0)


def _next_seq() -> int:
    """Return the next sequence number.

    Format: byte3 = 0x00 (TX flag), byte4 = counter.
    As a LE uint16: counter << 8.
    """
    counter = next(_seq_counter) & 0xFF
    return counter << 8  # SeqHi = counter, SeqLo = 0x00 (TX)


def build_sync_time() -> bytes:
    """Build SYNC_TIME command (CMD 0xC0).

    Payload: year(2 LE) + month(1) + day(1) + hour(1) + min(1) + sec(1) + extra(1)
    """
    now = time.localtime()
    payload = struct.pack(
        "<HBBBBBB",
        now.tm_year,
        now.tm_mon,
        now.tm_mday,
        now.tm_hour,
        now.tm_min,
        now.tm_sec,
        0x14,  # observed constant in sniff (possibly timezone or weekday)
    )
    # Sync time uses a special seq with counter=0xFE
    return LepuPacket(cmd=CMD_SYNC_TIME, payload=payload, seq=0xFE00).encode()


def build_get_info() -> bytes:
    """Build GET_INFO command (CMD 0x00)."""
    return LepuPacket(cmd=CMD_GET_INFO, seq=_next_seq()).encode()


def build_get_device_info() -> bytes:
    """Build GET_DEVICE_INFO command (CMD 0xE1)."""
    return LepuPacket(cmd=CMD_GET_DEVICE_INFO, seq=_next_seq()).encode()


def build_get_config() -> bytes:
    """Build GET_CONFIG command (CMD 0x33)."""
    return LepuPacket(cmd=CMD_GET_CONFIG, seq=_next_seq()).encode()


def build_get_battery() -> bytes:
    """Build GET_BATTERY command (CMD 0x30)."""
    return LepuPacket(cmd=CMD_GET_BATTERY, seq=_next_seq()).encode()


def build_read_file_start(filename: str) -> bytes:
    """Build READ_FILE_START command (CMD 0xF2).

    Payload: 20-byte null-padded filename.
    Response: 4-byte LE file size.
    """
    name_bytes = filename.encode("ascii")[:20]
    payload = name_bytes + b"\x00" * (20 - len(name_bytes))
    return LepuPacket(
        cmd=CMD_READ_FILE_START, payload=payload, seq=_next_seq()
    ).encode()


def build_read_file_data(offset: int) -> bytes:
    """Build READ_FILE_DATA command (CMD 0xF3) for a given byte offset."""
    payload = struct.pack("<I", offset)
    return LepuPacket(
        cmd=CMD_READ_FILE_DATA, payload=payload, seq=_next_seq()
    ).encode()


def build_read_file_end() -> bytes:
    """Build READ_FILE_END command (CMD 0xF4)."""
    return LepuPacket(cmd=CMD_READ_FILE_END, seq=_next_seq()).encode()


# ---------------------------------------------------------------------------
# Packet reassembler (for notifications that arrive in chunks)
# ---------------------------------------------------------------------------
class PacketReassembler:
    """Reassembles fragmented BLE notifications into complete Lepu packets.

    BLE notifications are limited by MTU (typically 20 bytes). A single Lepu
    packet may span multiple notifications. This class buffers incoming data
    and dispatches complete packets.
    """

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
                _LOGGER.debug(
                    "False header (cmd=0x%02X ~cmd=0x%02X), skipping",
                    cmd,
                    cmd_inv,
                )
                self._buffer = self._buffer[1:]
                continue

            length = struct.unpack_from("<H", self._buffer, 5)[0]
            total_len = 7 + length + 1  # header(7) + payload + crc(1)

            # Sanity: reject absurdly large packets
            if length > 2048:
                _LOGGER.debug(
                    "Implausible payload length %d, skipping byte", length
                )
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
