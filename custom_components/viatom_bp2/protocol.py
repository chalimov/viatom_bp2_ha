"""Viatom BP2W BLE protocol handler.

This module implements the Lepu BLE protocol V2 used by Viatom LP-BP2W
blood pressure monitors. The protocol was reverse-engineered from the
LepuDemo SDK (blepro AAR) and verified with direct BLE testing.

Protocol frame format:
  [Header(1)] [Cmd(1)] [~Cmd(1)] [0x00(1)] [SeqNo(1)] [LenLo(1)] [LenHi(1)] [Payload(N)] [CRC8(1)]

Header: 0xA5
Cmd: command type byte
~Cmd: bitwise NOT of Cmd
Byte 3: always 0x00 for TX, 0x01 for RX
Byte 4: sequence counter (increments per command sent)
Length: 2-byte little-endian payload length
Payload: variable length data
CRC8: CRC-8/CCITT over ALL preceding bytes (bytes[0..N-2])

CRITICAL: CRC is CRC-8/CCITT (poly 0x07), NOT CRC-8/MAXIM!
This was the root cause of all previous communication failures.
The CRC is computed over the ENTIRE packet (header through payload),
not just the payload alone.
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
# CRC-8/CCITT (polynomial 0x07) — from BleCRC.java in LepuBle SDK
# ---------------------------------------------------------------------------
_CRC8_TABLE = [
    0x00, 0x07, 0x0E, 0x09, 0x1C, 0x1B, 0x12, 0x15,
    0x38, 0x3F, 0x36, 0x31, 0x24, 0x23, 0x2A, 0x2D,
    0x70, 0x77, 0x7E, 0x79, 0x6C, 0x6B, 0x62, 0x65,
    0x48, 0x4F, 0x46, 0x41, 0x54, 0x53, 0x5A, 0x5D,
    0xE0, 0xE7, 0xEE, 0xE9, 0xFC, 0xFB, 0xF2, 0xF5,
    0xD8, 0xDF, 0xD6, 0xD1, 0xC4, 0xC3, 0xCA, 0xCD,
    0x90, 0x97, 0x9E, 0x99, 0x8C, 0x8B, 0x82, 0x85,
    0xA8, 0xAF, 0xA6, 0xA1, 0xB4, 0xB3, 0xBA, 0xBD,
    0xC7, 0xC0, 0xC9, 0xCE, 0xDB, 0xDC, 0xD5, 0xD2,
    0xFF, 0xF8, 0xF1, 0xF6, 0xE3, 0xE4, 0xED, 0xEA,
    0xB7, 0xB0, 0xB9, 0xBE, 0xAB, 0xAC, 0xA5, 0xA2,
    0x8F, 0x88, 0x81, 0x86, 0x93, 0x94, 0x9D, 0x9A,
    0x27, 0x20, 0x29, 0x2E, 0x3B, 0x3C, 0x35, 0x32,
    0x1F, 0x18, 0x11, 0x16, 0x03, 0x04, 0x0D, 0x0A,
    0x57, 0x50, 0x59, 0x5E, 0x4B, 0x4C, 0x45, 0x42,
    0x6F, 0x68, 0x61, 0x66, 0x73, 0x74, 0x7D, 0x7A,
    0x89, 0x8E, 0x87, 0x80, 0x95, 0x92, 0x9B, 0x9C,
    0xB1, 0xB6, 0xBF, 0xB8, 0xAD, 0xAA, 0xA3, 0xA4,
    0xF9, 0xFE, 0xF7, 0xF0, 0xE5, 0xE2, 0xEB, 0xEC,
    0xC1, 0xC6, 0xCF, 0xC8, 0xDD, 0xDA, 0xD3, 0xD4,
    0x69, 0x6E, 0x67, 0x60, 0x75, 0x72, 0x7B, 0x7C,
    0x51, 0x56, 0x5F, 0x58, 0x4D, 0x4A, 0x43, 0x44,
    0x19, 0x1E, 0x17, 0x10, 0x05, 0x02, 0x0B, 0x0C,
    0x21, 0x26, 0x2F, 0x28, 0x3D, 0x3A, 0x33, 0x34,
    0x4E, 0x49, 0x40, 0x47, 0x52, 0x55, 0x5C, 0x5B,
    0x76, 0x71, 0x78, 0x7F, 0x6A, 0x6D, 0x64, 0x63,
    0x3E, 0x39, 0x30, 0x37, 0x22, 0x25, 0x2C, 0x2B,
    0x06, 0x01, 0x08, 0x0F, 0x1A, 0x1D, 0x14, 0x13,
    0xAE, 0xA9, 0xA0, 0xA7, 0xB2, 0xB5, 0xBC, 0xBB,
    0x96, 0x91, 0x98, 0x9F, 0x8A, 0x8D, 0x84, 0x83,
    0xDE, 0xD9, 0xD0, 0xD7, 0xC2, 0xC5, 0xCC, 0xCB,
    0xE6, 0xE1, 0xE8, 0xEF, 0xFA, 0xFD, 0xF4, 0xF3,
]


def crc8(data: bytes) -> int:
    """Calculate CRC-8/CCITT over data.

    This is used over bytes[0..N-2] of the packet (everything except
    the CRC byte itself).
    """
    crc = 0
    for b in data:
        crc = _CRC8_TABLE[0xFF & (crc ^ b)]
    return crc


# ---------------------------------------------------------------------------
# Data classes for parsed results
# ---------------------------------------------------------------------------
@dataclass
class BpResult:
    """A single blood pressure measurement."""

    systolic: int = 0
    diastolic: int = 0
    mean_arterial_pressure: int = 0  # MAP (mmHg) — SDK misleadingly labels "pulse"
    heart_rate: int = 0  # HR (bpm) — shown on device screen
    pulse_pressure: int = 0  # PP = systolic - diastolic (calculated, not stored)
    timestamp: int = 0  # unix seconds
    user_id: int = 0  # multi-user support: identifies which user took measurement
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
    """BP2 device information from CMD 0xE1 (GET_DEVICE_INFO).

    Response layout (60 bytes from probe log):
      byte 0: hardware_version major
      bytes 1-2: unknown
      byte 3: software_version major
      byte 4: software_version minor
      bytes 5-7: unknown
      byte 8: model_str_len
      bytes 9..9+model_str_len: model string (ASCII)
      then: firmware date bytes, serial number, etc.

    Actual hex from device:
      42 00 01 01 01 00 00 01 00  33323132303031 31
      05 00 00 22 86 03 01 ea 07 03 07 17 06 37 02 01
      00 00 00 00 0a 32353233433030383132 00...
    """

    hw_version: str = ""
    fw_version: str = ""
    serial_number: str = ""
    model: str = ""
    battery_level: int = 0
    battery_status: int = 0
    device_status: int = 0


@dataclass
class RtData:
    """Real-time data from BP2 (CMD 0x08).

    Pushed by the device continuously while active.
    """

    device_status: int = 0
    battery_status: int = 0
    battery_level: int = 0
    systolic: int = 0
    diastolic: int = 0
    mean_arterial_pressure: int = 0  # MAP (mmHg)
    heart_rate: int = 0  # HR (bpm) — SDK misleadingly labels "pulse"
    measuring: bool = False
    result_ready: bool = False
    cuff_pressure: int = 0


# ---------------------------------------------------------------------------
# Protocol V2 command codes
#
# Two command sets work on LP-BP2W:
#   1. LP-BP2W specific (from iffb.class in blepro AAR)
#   2. Standard BP2 (from UniversalBleCmd.java in LepuBle)
# Both verified working with direct BLE probe.
#
# SAFETY CLASSIFICATION (verified by direct device testing):
#   SAFE    — device screen does not change, user is not disturbed
#   VISUAL  — device shows a transfer icon, but auto-resolves on disconnect
#   DANGER  — triggers cuff inflation (starts BP measurement!)
# ---------------------------------------------------------------------------

# LP-BP2W specific commands (from decompiled iffb.class)
CMD_GET_INFO = 0x00           # SAFE — LP-BP2W GET_INFO (returns 40-byte device info)
CMD_GET_CONFIG = 0x06         # SAFE — returns device config
CMD_RT_DATA = 0x08            # Real-time data (BP measurement in progress)

# Standard BP2 commands (from UniversalBleCmd.java — also work on LP-BP2W)
CMD_GET_DEVICE_INFO = 0xE1    # SAFE — returns 60-byte info w/ serial
CMD_SYNC_TIME = 0xEC          # SAFE — sync time
CMD_READ_FILE_START = 0xF2    # VISUAL — shows transfer icon, starts file read
CMD_READ_FILE_DATA = 0xF3     # VISUAL — file data chunk (part of transfer)
CMD_READ_FILE_END = 0xF4      # VISUAL — ends file transfer, icon disappears
CMD_GET_LP_CONFIG = 0x33      # SAFE — 4 bytes

# Device status codes (from Bp2BleInterface.kt)
STATUS_BP_MEASURING = 0       # RT data type 0 = BP measuring
STATUS_BP_MEASURE_END = 1     # RT data type 1 = BP end (result available)

# Known filenames on the device
FILE_BP_LIST = "bp2nibp.list"

# --- Unused / dangerous commands (kept for protocol documentation only) ---
# DANGER — DO NOT USE on LP-BP2W! These start a BP measurement (cuff inflates):
_CMD_FACTORY_RESET = 0x04      # DANGER — factory reset!
_CMD_SWITCH_STATE = 0x09       # DANGER — starts BP measurement on LP-BP2W!
_CMD_START_MEASUREMENT = 0x0A  # DANGER — starts BP measurement on LP-BP2W!
_CMD_RESET = 0xE2              # DANGER — device reset
_CMD_FACTORY_RESET_STD = 0xE3  # DANGER — factory reset
_CMD_DANGER_DEVICE_OFF = 0x24  # DANGER — device off + cuff inflation
_CMD_DANGER_INFLATE = 0x39     # DANGER — cuff inflation + BLE disconnect
# Untested / unused safe commands:
_CMD_GET_FILE_LIST = 0x11      # LP-BP2W file list
_CMD_LP_READ_FILE_START = 0x12 # LP-BP2W file read start
_CMD_LP_READ_FILE_DATA = 0x13  # LP-BP2W file read data
_CMD_READ_FILE_LIST = 0xF1     # Standard file list
_FILE_ECG_LIST = "bp2ecg.list"

# ---------------------------------------------------------------------------
# Device states (CMD 0x00 byte[39] / CMD 0x06 byte[0])
#
# Polling CMD 0x00 is SAFE — no screen change, no transfer icon.
# This is the preferred method to detect new measurement results.
#
# Single measurement lifecycle:  3 -> 4 -> 5 -> 3
# Triple measurement lifecycle:  3 -> 15 -> 16 -> 15 -> 16 -> 15 -> 17 -> 3
# ---------------------------------------------------------------------------
DEVICE_STATE_IDLE = 3            # Home screen, no measurement
DEVICE_STATE_MEASURING = 4       # Single: cuff inflated, taking reading
DEVICE_STATE_RESULT = 5          # Single: result on screen (until user dismisses)
DEVICE_STATE_TRIPLE_MEAS = 15    # Triple: cuff inflated for one of 3 readings
DEVICE_STATE_TRIPLE_PAUSE = 16   # Triple: rest between sequential readings
DEVICE_STATE_TRIPLE_RESULT = 17  # Triple: averaged result on screen

# Sets for logic
DEVICE_STATES_RESULT = {DEVICE_STATE_RESULT, DEVICE_STATE_TRIPLE_RESULT}
DEVICE_STATES_BUSY = {DEVICE_STATE_MEASURING, DEVICE_STATE_TRIPLE_MEAS, DEVICE_STATE_TRIPLE_PAUSE}


# ---------------------------------------------------------------------------
# Packet builder / parser
# ---------------------------------------------------------------------------
class LepuPacket:
    """Represents a single Lepu protocol V2 packet.

    Wire format:
      [0]     0xA5 header
      [1]     cmd
      [2]     ~cmd (bitwise NOT)
      [3]     0x00 (TX) or 0x01 (RX)
      [4]     sequence counter
      [5]     length low byte
      [6]     length high byte
      [7..N-2] payload
      [N-1]   CRC-8/CCITT over bytes[0..N-2]
    """

    HEADER = 0xA5

    def __init__(self, cmd: int, payload: bytes = b"", seq: int = 0):
        self.cmd = cmd
        self.payload = payload
        self.seq = seq  # sequence counter (0-255)

    def encode(self) -> bytes:
        """Encode the packet to bytes for transmission."""
        cmd_inv = (~self.cmd) & 0xFF
        length = len(self.payload)
        # Build packet without CRC
        pkt = bytearray()
        pkt.append(self.HEADER)             # [0] header
        pkt.append(self.cmd & 0xFF)         # [1] command
        pkt.append(cmd_inv)                 # [2] ~command
        pkt.append(0x00)                    # [3] TX flag (always 0x00)
        pkt.append(self.seq & 0xFF)         # [4] sequence counter
        pkt.append(length & 0xFF)           # [5] length low
        pkt.append((length >> 8) & 0xFF)    # [6] length high
        pkt.extend(self.payload)            # [7..7+len-1] payload
        # CRC over ALL bytes so far (everything except the CRC byte itself)
        pkt.append(crc8(bytes(pkt)))
        return bytes(pkt)

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
        # Bytes [3] = TX/RX flag, [4] = seq counter
        seq = data[4]
        length = data[5] | (data[6] << 8)
        total_len = 7 + length + 1
        if len(data) < total_len:
            _LOGGER.debug(
                "Packet too short: expected %d, got %d", total_len, len(data)
            )
            return None
        payload = data[7 : 7 + length]
        received_crc = data[7 + length]
        # CRC over bytes[0..N-2] (all bytes except the CRC byte)
        calc_crc = crc8(data[: 7 + length])
        if calc_crc != received_crc:
            _LOGGER.debug(
                "CRC mismatch: calc=0x%02X recv=0x%02X", calc_crc, received_crc
            )
            return None
        return cls(cmd, payload, seq)


# ---------------------------------------------------------------------------
# Response parsers
# ---------------------------------------------------------------------------
def parse_device_info_v1(payload: bytes) -> DeviceInfo:
    """Parse LP-BP2W GET_INFO (CMD 0x00) response payload.

    The response is 40 bytes. This contains raw device registers including
    timestamps, counters, and status bytes. The exact layout is not fully
    documented but includes battery level.

    From probe log (40 bytes):
      10db11006ac21100 d4190000 c8004005 3a68cd03 6d67c800
      01 01 00 d7530300 14000000 00000000 03
    """
    info = DeviceInfo()
    try:
        if len(payload) >= 40:
            # Battery level appears to be around byte 24-25 based on
            # the values changing between probe runs (c8=200 -> %, or
            # the byte at offset 24 = 0x01 = charging status)
            # For now extract what we can confirm
            info.battery_level = payload[24]  # observed as 0x01 or status byte
            info.battery_status = payload[25]
        _LOGGER.debug(
            "CMD 0x00 raw (40b): %s", payload.hex()
        )
    except Exception as e:
        _LOGGER.warning("Failed to parse device info v1: %s", e)
    return info


def parse_device_info(payload: bytes) -> DeviceInfo:
    """Parse standard GET_DEVICE_INFO (CMD 0xE1) response payload.

    This is the preferred command — returns structured info including
    model string, serial number, firmware version, etc.

    Verified layout from probe log (60 bytes):
      [0]     0x42  hardware version (66)
      [1-2]   status/unknown
      [3]     software version major
      [4]     software version minor
      [5-8]   unknown
      [9-16]  model string (8 bytes ASCII): "32120011"
      [17]    sub-version / build (0x05)
      [18-19] padding
      [20-23] unknown (CRC or ID)
      [24-25] device clock year (uint16 LE) — NOT firmware build date
      [26]    device clock month
      [27]    device clock day
      [28]    device clock hour
      [29]    device clock minute
      [30]    device clock second
      [31-36] unknown/padding
      [37]    serial number length (0x0A = 10)
      [38-47] serial number ASCII: "2523C00812"
      [48-59] padding (zeros)
    """
    info = DeviceInfo()
    try:
        if len(payload) < 17:
            return info

        info.hw_version = str(payload[0])

        # Software version
        sw_major = payload[3]
        sw_minor = payload[4]
        info.fw_version = f"{sw_major}.{sw_minor}"

        # Model string: fixed 8 bytes at offset 9
        info.model = (
            payload[9:17]
            .decode("ascii", errors="replace")
            .strip("\x00")
        )

        # Serial number: length at byte 37, string at bytes 38+
        if len(payload) >= 38:
            sn_len = payload[37]
            if 0 < sn_len <= 20 and 38 + sn_len <= len(payload):
                info.serial_number = (
                    payload[38 : 38 + sn_len]
                    .decode("ascii", errors="replace")
                    .strip("\x00")
                )

        _LOGGER.debug(
            "Device info: hw=%s fw=%s model=%s sn=%s",
            info.hw_version,
            info.fw_version,
            info.model,
            info.serial_number,
        )
    except Exception as e:
        _LOGGER.warning("Failed to parse device info: %s", e)
    return info


def parse_rt_data(payload: bytes) -> RtData:
    """Parse real-time data (CMD 0x08) notification payload.

    Based on Bp2BleInterface.kt and Bp2BleCmd.java:
      byte 0: data type (0=BP measuring, 1=BP end, 2=ECG measuring, 3=ECG end)
      byte 1: battery_status
      byte 2: battery_level (percentage)
      bytes 3+: varies by data type

    For BP measuring (type 0):
      bytes 3-4: cuff pressure (uint16 LE)

    For BP end (type 1):
      bytes 3-4: systolic (uint16 LE)
      bytes 5-6: diastolic (uint16 LE)
      bytes 7-8: MAP — mean arterial pressure (uint16 LE, mmHg)
      bytes 9-10: HR — heart rate (uint16 LE, bpm) — SDK labels "pulse"
    """
    rt = RtData()
    try:
        if len(payload) >= 1:
            rt.device_status = payload[0]
        if len(payload) >= 2:
            rt.battery_status = payload[1]
        if len(payload) >= 3:
            rt.battery_level = payload[2]

        # Type 0: BP measuring — cuff pressure follows
        if rt.device_status == 0 and len(payload) >= 5:
            rt.measuring = True
            rt.cuff_pressure = struct.unpack_from("<H", payload, 3)[0]

        # Type 1: BP measurement complete — results follow
        elif rt.device_status == 1 and len(payload) >= 11:
            rt.result_ready = True
            rt.measuring = False
            rt.systolic = struct.unpack_from("<H", payload, 3)[0]
            rt.diastolic = struct.unpack_from("<H", payload, 5)[0]
            rt.mean_arterial_pressure = struct.unpack_from("<H", payload, 7)[0]
            rt.heart_rate = struct.unpack_from("<H", payload, 9)[0]

    except Exception as e:
        _LOGGER.warning(
            "Failed to parse rt data: %s (payload hex: %s)",
            e,
            payload.hex(),
        )
    return rt


def parse_bp_file(payload: bytes) -> list[BpResult]:
    """Parse BP measurement data from the bp2nibp.list file.

    File format (verified from device dump — LP-BP2W):
      Header: 10 bytes (byte 0: version?, byte 1: user count?, rest zeros)
      Records: 37 bytes each, starting at offset 10

    Record layout (37 bytes):
      [0-3]   timestamp (uint32 LE, unix seconds)
      [4-7]   user_id (uint32 LE) — identifies which user took measurement
      [8]     status_flag (0x00 or 0x01)
      [9-12]  reserved (zeros)
      [13-14] systolic (uint16 LE, mmHg)
      [15-16] diastolic (uint16 LE, mmHg)
      [17-18] MAP — mean arterial pressure (uint16 LE, mmHg)
              SDK misleadingly labels this "pulse"
      [19-20] HR — heart rate (uint16 LE, bpm), shown on device screen
      [21-36] padding (zeros)

    Pulse Pressure (PP = systolic - diastolic) is calculated, not stored.
    Records are stored in circular buffer order (not necessarily chronological).
    """
    HEADER_SIZE = 10
    RECORD_SIZE = 37

    results: list[BpResult] = []
    try:
        if len(payload) < HEADER_SIZE + RECORD_SIZE:
            _LOGGER.debug(
                "BP file too short: %d bytes (need at least %d)",
                len(payload),
                HEADER_SIZE + RECORD_SIZE,
            )
            return results

        _LOGGER.debug(
            "Parsing BP file: %d bytes, header: %s",
            len(payload),
            payload[:HEADER_SIZE].hex(),
        )

        record_data = payload[HEADER_SIZE:]
        num_records = len(record_data) // RECORD_SIZE

        for i in range(num_records):
            rec = record_data[i * RECORD_SIZE : (i + 1) * RECORD_SIZE]

            timestamp = struct.unpack_from("<I", rec, 0)[0]
            user_id = struct.unpack_from("<I", rec, 4)[0]
            status_flag = rec[8]
            systolic = struct.unpack_from("<H", rec, 13)[0]
            diastolic = struct.unpack_from("<H", rec, 15)[0]
            map_val = struct.unpack_from("<H", rec, 17)[0]   # MAP (mmHg)
            heart_rate = struct.unpack_from("<H", rec, 19)[0]  # HR (bpm)

            # Skip obviously invalid records (empty slots or corrupt data)
            if systolic == 0 or diastolic == 0:
                continue
            if not (40 <= systolic <= 300) or not (20 <= diastolic <= 250):
                _LOGGER.debug(
                    "Implausible BP %d/%d in record %d, skipping",
                    systolic, diastolic, i,
                )
                continue
            if not (20 <= heart_rate <= 300):
                _LOGGER.debug(
                    "Implausible HR %d in record %d, skipping",
                    heart_rate, i,
                )
                continue

            bp = BpResult(
                systolic=systolic,
                diastolic=diastolic,
                mean_arterial_pressure=map_val,
                heart_rate=heart_rate,
                pulse_pressure=systolic - diastolic,
                timestamp=timestamp,
                user_id=user_id,
                irregular_heartbeat=(status_flag == 1),
            )
            results.append(bp)
            _LOGGER.debug(
                "BP record %d: %d/%d MAP=%d HR=%d PP=%d user=%d ts=%s flag=%d",
                i,
                systolic,
                diastolic,
                map_val,
                heart_rate,
                systolic - diastolic,
                user_id,
                bp.timestamp_str,
                status_flag,
            )

        _LOGGER.info("Parsed %d BP records from %d bytes", len(results), len(payload))

    except Exception as e:
        _LOGGER.warning(
            "Failed to parse BP file: %s (payload len: %d)", e, len(payload)
        )
    return results


# ---------------------------------------------------------------------------
# Command builders (Protocol V2)
# ---------------------------------------------------------------------------
_seq_counter = count(1)


def _next_seq() -> int:
    """Return the next sequence number (0-255, wrapping)."""
    return next(_seq_counter) % 256


def build_sync_time(now: time.struct_time | None = None) -> bytes:
    """Build SYNC_TIME command (CMD 0xEC).

    Payload: year(2 LE) + month(1) + day(1) + hour(1) + min(1) + sec(1)

    Pass a struct_time in the user's local timezone. If None, falls back
    to the system's local time (caller should prefer HA's dt_util.now()).
    """
    if now is None:
        now = time.localtime()
    payload = struct.pack(
        "<HBBBBB",
        now.tm_year,
        now.tm_mon,
        now.tm_mday,
        now.tm_hour,
        now.tm_min,
        now.tm_sec,
    )
    return LepuPacket(cmd=CMD_SYNC_TIME, payload=payload, seq=_next_seq()).encode()


def build_get_device_info() -> bytes:
    """Build standard GET_DEVICE_INFO command (CMD 0xE1).

    Returns 60-byte structured info with model, serial, firmware.
    This is the preferred info command.
    """
    return LepuPacket(cmd=CMD_GET_DEVICE_INFO, seq=_next_seq()).encode()


def build_get_config() -> bytes:
    """Build GET_CONFIG command (CMD 0x06)."""
    return LepuPacket(cmd=CMD_GET_CONFIG, seq=_next_seq()).encode()


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

    _MAX_BUFFER = 4096

    def feed(self, data: bytes) -> None:
        """Feed raw notification data. Complete packets are dispatched."""
        self._buffer.extend(data)
        if len(self._buffer) > self._MAX_BUFFER:
            _LOGGER.warning(
                "Reassembler buffer overflow (%d bytes), clearing",
                len(self._buffer),
            )
            self._buffer.clear()
            return
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

            length = self._buffer[5] | (self._buffer[6] << 8)
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
