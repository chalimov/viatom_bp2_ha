"""
BP2 Deep User Name Hunt

The device shows "VS" and "AS" but all 256 commands were scanned
without finding the names. This script tries:

1. Enumerate ALL BLE services/characteristics (names might be in a readable char)
2. Try commands with user_id (218071 = 0x000353B7) as 4-byte LE payload
3. Download bp2ecg.list (never tried before)
4. Try GET_CONFIG (0x06) with 2-byte and 4-byte payloads
5. Try multi-step: send user_id via one command, then read via another

All raw data logged to tools/user_name_deep.log
"""

import asyncio
import sys
import struct
import os
from datetime import datetime

from bleak import BleakClient

SERVICE_UUID = "14839ac4-7d7e-415c-9a42-167340cf2339"
WRITE_UUID = "8b00ace7-eb0b-49b0-bbe9-9aee0a26e1a3"
NOTIFY_UUID = "0734594a-a8e7-4b1a-a6b1-cd5243059a57"
DEFAULT_ADDRESS = "46:22:4E:7C:B4:D8"

KNOWN_USER_ID = 218071  # 0x000353B7

LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "user_name_deep.log")

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
    crc = 0
    for b in data:
        crc = _CRC8_TABLE[0xFF & (crc ^ b)]
    return crc

_seq = 0

def build_packet(cmd: int, payload: bytes = b"") -> bytes:
    global _seq
    _seq = (_seq + 1) % 255
    cmd_inv = (~cmd) & 0xFF
    length = len(payload)
    pkt = bytearray([0xA5, cmd & 0xFF, cmd_inv, 0x00, _seq,
                      length & 0xFF, (length >> 8) & 0xFF])
    pkt.extend(payload)
    pkt.append(crc8(bytes(pkt)))
    return bytes(pkt)

def decode_packet(data: bytes):
    if len(data) < 8 or data[0] != 0xA5:
        return None
    cmd = data[1]
    if data[2] != (~cmd & 0xFF):
        return None
    length = data[5] | (data[6] << 8)
    if len(data) < 7 + length + 1:
        return None
    payload = data[7:7 + length]
    expected_crc = crc8(data[:7 + length])
    if data[7 + length] != expected_crc:
        return None
    return cmd, payload

class Reassembler:
    def __init__(self):
        self.buf = bytearray()
        self.packets = []

    def feed(self, data: bytes):
        self.buf.extend(data)
        self._try_parse()

    def _try_parse(self):
        while len(self.buf) >= 8:
            idx = self.buf.find(b'\xA5')
            if idx < 0:
                self.buf.clear()
                return
            if idx > 0:
                self.buf = self.buf[idx:]
            if len(self.buf) < 7:
                return
            cmd = self.buf[1]
            if self.buf[2] != (~cmd & 0xFF):
                self.buf = self.buf[1:]
                continue
            length = self.buf[5] | (self.buf[6] << 8)
            total = 7 + length + 1
            if length > 2048:
                self.buf = self.buf[1:]
                continue
            if len(self.buf) < total:
                return
            pkt_bytes = bytes(self.buf[:total])
            self.buf = self.buf[total:]
            result = decode_packet(pkt_bytes)
            if result:
                self.packets.append(result)


def has_ascii_text(data: bytes, min_run: int = 2) -> list:
    runs = []
    current = []
    for b in data:
        if 32 <= b < 127:
            current.append(chr(b))
        else:
            if len(current) >= min_run:
                runs.append("".join(current))
            current = []
    if len(current) >= min_run:
        runs.append("".join(current))
    return runs


def hex_dump(payload: bytes) -> str:
    lines = []
    for offset in range(0, len(payload), 16):
        chunk = payload[offset:offset+16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"    {offset:04x}: {hex_str:<48s} {ascii_str}")
    return "\n".join(lines)


async def send_and_wait(client, reassembler, cmd, payload=b"", wait=0.5):
    """Send a command and return list of (resp_cmd, resp_payload) tuples."""
    reassembler.packets.clear()
    await client.write_gatt_char(WRITE_UUID, build_packet(cmd, payload))
    await asyncio.sleep(wait)
    return list(reassembler.packets)


async def download_file(client, reassembler, filename: str, log_fn) -> bytes:
    """Download a file from the device using FILE_START/FILE_DATA/FILE_END."""
    # FILE_START (0xF2) with filename
    name_bytes = filename.encode("ascii")
    padded = name_bytes + b"\x00" * (16 - len(name_bytes))
    # offset 0, payload: filename(16) + offset(4)
    file_payload = padded + struct.pack("<I", 0)

    responses = await send_and_wait(client, reassembler, 0xF2, file_payload, wait=1.0)
    if not responses:
        return b""

    resp_cmd, resp_data = responses[0]
    if len(resp_data) < 4:
        return b""

    file_size = struct.unpack("<I", resp_data[:4])[0]
    if file_size == 0:
        return b""

    log_fn(f"  File size: {file_size} bytes")

    # Read data chunks
    file_data = bytearray()
    for _ in range(500):  # safety limit
        responses = await send_and_wait(client, reassembler, 0xF3, b"", wait=0.3)
        if not responses:
            break
        for rc, rd in responses:
            if rc == 0xF3 and len(rd) > 0:
                file_data.extend(rd)
        if len(file_data) >= file_size:
            break

    # FILE_END
    await send_and_wait(client, reassembler, 0xF4, b"", wait=0.3)

    return bytes(file_data[:file_size])


async def main():
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ADDRESS

    logf = open(LOG_PATH, "w", encoding="utf-8")
    def log(msg: str):
        logf.write(msg + "\n")
        logf.flush()

    log(f"=== BP2 Deep User Name Hunt ===")
    log(f"Date: {datetime.now().isoformat()}")
    log(f"Target: {target}")
    log(f"Known user_id: {KNOWN_USER_ID} (0x{KNOWN_USER_ID:08X})")
    log("")

    print(f"BP2 Deep User Name Hunt — log: {LOG_PATH}")
    print(f"Target: {target}")
    print()

    reassembler = Reassembler()

    def notification_handler(sender, data: bytearray):
        reassembler.feed(bytes(data))

    client = BleakClient(target)

    for attempt in range(3):
        try:
            print(f"Connecting (attempt {attempt + 1}/3)...", end=" ", flush=True)
            await client.connect()
            print("OK")
            break
        except Exception as e:
            print(f"FAIL ({e})")
            log(f"Connection attempt {attempt+1} failed: {e}")
            if attempt < 2:
                await asyncio.sleep(3)
            else:
                print("Could not connect. Exiting.")
                logf.close()
                return

    try:
        await asyncio.sleep(2)

        for sub_attempt in range(3):
            try:
                await client.start_notify(NOTIFY_UUID, notification_handler)
                break
            except Exception as e:
                if sub_attempt < 2:
                    print(f"  Subscribe retry {sub_attempt+1}...")
                    log(f"Subscribe attempt {sub_attempt+1} failed: {e}")
                    try:
                        await client.disconnect()
                    except Exception:
                        pass
                    await asyncio.sleep(2)
                    await client.connect()
                    await asyncio.sleep(2)
                else:
                    print(f"  Subscribe failed. Exiting.")
                    logf.close()
                    return

        await asyncio.sleep(0.5)
        names_found = []

        def check_for_names(label, data):
            ascii_runs = has_ascii_text(data)
            has_name = any("VS" in r or "AS" in r for r in ascii_runs)
            if has_name:
                names_found.append((label, data))
                print(f"  *** {label}: FOUND NAME! ascii={ascii_runs} ***")
            return ascii_runs, has_name

        # =============================================
        # TEST 1: Enumerate ALL BLE services & characteristics
        # =============================================
        print("Test 1: Enumerating BLE services & characteristics...")
        log("=" * 60)
        log("TEST 1: BLE Service/Characteristic Enumeration")
        log("=" * 60)

        for service in client.services:
            log(f"\nService: {service.uuid} — {service.description}")
            for char in service.characteristics:
                props = ", ".join(char.properties)
                log(f"  Char: {char.uuid} [{props}] — {char.description}")

                # Try to read any readable characteristic
                if "read" in char.properties:
                    try:
                        value = await client.read_gatt_char(char.uuid)
                        ascii_runs = has_ascii_text(value)
                        log(f"    Value ({len(value)} bytes): {value.hex()}")
                        if ascii_runs:
                            log(f"    ASCII: {ascii_runs}")
                        log(hex_dump(value))

                        check_for_names(f"BLE char {char.uuid}", value)
                    except Exception as e:
                        log(f"    Read error: {e}")

                # Check descriptors
                for desc in char.descriptors:
                    try:
                        value = await client.read_gatt_descriptor(desc.handle)
                        log(f"    Descriptor {desc.uuid} ({len(value)} bytes): {value.hex()}")
                        if has_ascii_text(value):
                            log(f"      ASCII: {has_ascii_text(value)}")
                    except Exception as e:
                        log(f"    Descriptor {desc.uuid} read error: {e}")

        svc_list = list(client.services)
        char_count = sum(len(list(s.characteristics)) for s in svc_list)
        print(f"  Found {len(svc_list)} services, {char_count} characteristics")

        # =============================================
        # TEST 2: Commands with user_id as 4-byte LE payload
        # =============================================
        print("Test 2: Commands with user_id payload...")
        log(f"\n{'='*60}")
        log(f"TEST 2: Commands with user_id (0x{KNOWN_USER_ID:08X}) as payload")
        log("=" * 60)

        uid_bytes = struct.pack("<I", KNOWN_USER_ID)
        # Try safe commands that had responses in previous scans
        safe_cmds = [0x00, 0x06, 0x08, 0x0B, 0x0C, 0x0D, 0x21, 0x22, 0x23, 0x26, 0x28, 0x33]

        for cmd in safe_cmds:
            responses = await send_and_wait(client, reassembler, cmd, uid_bytes)
            if responses:
                for resp_cmd, payload in responses:
                    ascii_runs = has_ascii_text(payload)
                    log(f"CMD 0x{cmd:02X}+uid → resp 0x{resp_cmd:02X}, {len(payload)} bytes")
                    if ascii_runs:
                        log(f"  ASCII: {ascii_runs}")
                    log(hex_dump(payload))
                    log("")
                    check_for_names(f"CMD 0x{cmd:02X}+uid", payload)
            else:
                log(f"CMD 0x{cmd:02X}+uid — no response\n")

        print(f"  Tested {len(safe_cmds)} commands with user_id payload")

        # =============================================
        # TEST 3: Try user_id as 2-byte payload (low 2 bytes)
        # =============================================
        print("Test 3: Commands with 2-byte user index payloads...")
        log(f"\n{'='*60}")
        log(f"TEST 3: Commands with 2-byte payloads")
        log("=" * 60)

        # The device might use a shorter user index
        two_byte_payloads = [
            b"\x01\x00",  # user 1
            b"\x02\x00",  # user 2
            b"\x00\x01",  # user 1 (big endian)
            b"\x00\x02",  # user 2 (big endian)
        ]

        for cmd in [0x00, 0x06, 0x08, 0x0D]:
            for pl in two_byte_payloads:
                responses = await send_and_wait(client, reassembler, cmd, pl)
                if responses:
                    for resp_cmd, payload in responses:
                        ascii_runs = has_ascii_text(payload)
                        log(f"CMD 0x{cmd:02X}+{pl.hex()} → resp 0x{resp_cmd:02X}, {len(payload)} bytes")
                        if ascii_runs:
                            log(f"  ASCII: {ascii_runs}")
                        log(hex_dump(payload))
                        log("")
                        check_for_names(f"CMD 0x{cmd:02X}+{pl.hex()}", payload)
                else:
                    log(f"CMD 0x{cmd:02X}+{pl.hex()} — no response\n")

        print(f"  Done")

        # =============================================
        # TEST 4: Download bp2ecg.list
        # =============================================
        print("Test 4: Downloading bp2ecg.list...")
        log(f"\n{'='*60}")
        log(f"TEST 4: Download bp2ecg.list")
        log("=" * 60)

        try:
            ecg_data = await download_file(client, reassembler, "bp2ecg.list", log)
            if ecg_data:
                log(f"Downloaded {len(ecg_data)} bytes")
                log(hex_dump(ecg_data[:256]))  # first 256 bytes
                ascii_runs = has_ascii_text(ecg_data[:256])
                if ascii_runs:
                    log(f"ASCII in first 256 bytes: {ascii_runs}")
                check_for_names("bp2ecg.list", ecg_data)
                print(f"  Got {len(ecg_data)} bytes")
            else:
                log("No data returned (empty file or timeout)")
                print(f"  Empty or timeout")
        except Exception as e:
            log(f"Download error: {e}")
            print(f"  Error: {e}")

        # =============================================
        # TEST 5: Try writing to writable characteristics
        # =============================================
        print("Test 5: Looking for writable characteristics beyond command channel...")
        log(f"\n{'='*60}")
        log(f"TEST 5: Other writable characteristics")
        log("=" * 60)

        for service in client.services:
            for char in service.characteristics:
                if char.uuid.lower() == WRITE_UUID.lower():
                    continue  # skip command channel
                if "write" in char.properties or "write-without-response" in char.properties:
                    log(f"  Writable char: {char.uuid} [{', '.join(char.properties)}]")
                    # Don't actually write to unknown chars — just log them
                    print(f"  Found writable: {char.uuid}")

        # =============================================
        # TEST 6: Try GET_CONFIG with multi-byte structured payloads
        # =============================================
        print("Test 6: GET_CONFIG with structured payloads...")
        log(f"\n{'='*60}")
        log(f"TEST 6: GET_CONFIG (0x06) with various payloads")
        log("=" * 60)

        # Try different "config section" requests
        structured_payloads = [
            b"\x01",          # section 1
            b"\x02",          # section 2
            b"\x03",          # section 3
            b"\x04",          # section 4
            b"\x05",          # section 5
            b"\x01\x01",      # section 1, subsection 1
            b"\x01\x02",      # section 1, subsection 2
            b"\x02\x01",      # section 2, subsection 1
            b"\x02\x02",      # section 2, subsection 2
        ]

        for pl in structured_payloads:
            responses = await send_and_wait(client, reassembler, 0x06, pl)
            if responses:
                for resp_cmd, payload in responses:
                    ascii_runs = has_ascii_text(payload)
                    log(f"CMD 0x06+{pl.hex()} → resp 0x{resp_cmd:02X}, {len(payload)} bytes")
                    if ascii_runs:
                        log(f"  ASCII: {ascii_runs}")
                    log(hex_dump(payload))
                    log("")
                    check_for_names(f"0x06+{pl.hex()}", payload)
            else:
                log(f"CMD 0x06+{pl.hex()} — no response\n")

        print(f"  Done")

        # =============================================
        # SUMMARY
        # =============================================
        print(f"\n{'='*50}")
        if names_found:
            print(f"  FOUND {len(names_found)} RESPONSE(S) WITH USER NAMES!")
            for label, data in names_found:
                print(f"    {label}: {has_ascii_text(data)}")
        else:
            print(f"  User names NOT found in any of the tested methods")
        print(f"  Full details in: {LOG_PATH}")
        print(f"{'='*50}")

        log(f"\n{'='*60}")
        log(f"FINAL SUMMARY")
        log(f"{'='*60}")
        log(f"Names found: {len(names_found)}")
        if names_found:
            for label, data in names_found:
                log(f"  {label}: {has_ascii_text(data)}")
                log(hex_dump(data))

    finally:
        try:
            await client.disconnect()
        except Exception:
            pass

    logf.close()
    print(f"\nDone.")


if __name__ == "__main__":
    asyncio.run(main())
