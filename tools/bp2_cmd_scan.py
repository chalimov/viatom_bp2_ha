"""
BP2 Command Scanner — Scan all safe command codes to find user names.

The device shows user names "VS" and "AS" on screen, so they must be
stored somewhere. This script sends every command code (0x00-0xFF)
EXCEPT the known dangerous ones, and looks for responses containing
ASCII text that could be user names.

DANGER LIST (NEVER send):
  0x04 = FACTORY_RESET
  0x09 = START_MEASUREMENT (cuff inflate)
  0x0A = START_MEASUREMENT (cuff inflate)
  0xE2 = DEVICE_RESET
  0xE3 = FACTORY_RESET
"""

import asyncio
import sys
import struct
import time

from bleak import BleakClient

WRITE_UUID = "8b00ace7-eb0b-49b0-bbe9-9aee0a26e1a3"
NOTIFY_UUID = "0734594a-a8e7-4b1a-a6b1-cd5243059a57"
DEFAULT_ADDRESS = "46:22:4E:7C:B4:D8"

# Commands that are DANGEROUS — skip these
DANGER_CMDS = {0x04, 0x09, 0x0A, 0xE2, 0xE3}

# Commands we already know — still scan them but mark as known
KNOWN_CMDS = {
    0x00: "GET_INFO",
    0x06: "GET_CONFIG",
    0x08: "RT_DATA",
    0x0B: "unknown(empty)",
    0x0C: "unknown(empty)",
    0x0D: "unknown(2b)",
    0x11: "LP_FILE_LIST(empty)",
    0x30: "GET_BATTERY",
    0x31: "RT_STATE(garbage)",
    0xE1: "GET_DEVICE_INFO",
    0xEC: "SYNC_TIME",
    0xF1: "READ_FILE_LIST",
    0xF2: "READ_FILE_START",
    0xF3: "READ_FILE_DATA",
    0xF4: "READ_FILE_END",
}

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


def has_ascii_text(data: bytes, min_run: int = 2) -> str:
    """Find runs of printable ASCII in binary data."""
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


async def main():
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ADDRESS

    print(f"=== BP2 Full Command Scan ===")
    print(f"Target: {target}")
    print(f"Scanning 0x00-0xFF, skipping DANGER: {[f'0x{c:02X}' for c in sorted(DANGER_CMDS)]}")
    print()

    reassembler = Reassembler()

    def notification_handler(sender, data: bytearray):
        reassembler.feed(bytes(data))

    client = BleakClient(target)

    for attempt in range(3):
        try:
            print(f"Connecting (attempt {attempt + 1}/3)...")
            await client.connect()
            break
        except Exception as e:
            print(f"  Failed: {e}")
            if attempt < 2:
                await asyncio.sleep(3)
            else:
                print("Could not connect.")
                return

    print(f"Connected\n")

    try:
        await asyncio.sleep(2)

        # Subscribe with retry
        for sub_attempt in range(3):
            try:
                await client.start_notify(NOTIFY_UUID, notification_handler)
                break
            except Exception as e:
                if sub_attempt < 2:
                    print(f"  Subscribe attempt {sub_attempt+1} failed: {e}, reconnecting...")
                    try:
                        await client.disconnect()
                    except Exception:
                        pass
                    await asyncio.sleep(2)
                    await client.connect()
                    await asyncio.sleep(2)
                else:
                    print(f"  Subscribe failed: {e}")
                    return

        await asyncio.sleep(0.5)

        # Track interesting findings
        interesting = []
        responded = []

        for cmd_code in range(0x00, 0x100):
            if cmd_code in DANGER_CMDS:
                continue

            # Skip file transfer commands that need special payloads
            if cmd_code in (0xF2, 0xF3, 0xF4):
                continue

            reassembler.packets.clear()

            try:
                await client.write_gatt_char(WRITE_UUID, build_packet(cmd_code))
            except Exception as e:
                print(f"  0x{cmd_code:02X}: write failed ({e})")
                break

            await asyncio.sleep(0.5)

            if reassembler.packets:
                for resp_cmd, payload in reassembler.packets:
                    known = KNOWN_CMDS.get(cmd_code, "")
                    size_str = f"{len(payload)}b"
                    hex_str = payload.hex() if len(payload) <= 60 else payload[:60].hex() + "..."
                    ascii_runs = has_ascii_text(payload)

                    responded.append(cmd_code)

                    # Check for user names
                    has_name = False
                    for run in ascii_runs:
                        if "VS" in run or "AS" in run or "vs" in run or "as" in run:
                            has_name = True

                    # Print all responses that have data
                    if len(payload) > 0:
                        marker = " *** HAS NAME ***" if has_name else ""
                        known_str = f" [{known}]" if known else ""
                        ascii_str = f" ascii={ascii_runs}" if ascii_runs else ""
                        print(f"  0x{cmd_code:02X} → 0x{resp_cmd:02X} {size_str:>5s}{known_str}: {hex_str}{ascii_str}{marker}")

                        if has_name or (len(payload) > 4 and ascii_runs):
                            interesting.append((cmd_code, resp_cmd, payload))

        print(f"\n{'='*60}")
        print(f"SUMMARY")
        print(f"{'='*60}")
        print(f"Commands that responded: {len(responded)}")
        print(f"Responded codes: {[f'0x{c:02X}' for c in responded]}")

        if interesting:
            print(f"\nINTERESTING RESPONSES ({len(interesting)}):")
            for cmd_code, resp_cmd, payload in interesting:
                print(f"\n  CMD 0x{cmd_code:02X} → 0x{resp_cmd:02X}, {len(payload)} bytes:")
                # Full hex dump
                for offset in range(0, len(payload), 16):
                    chunk = payload[offset:offset+16]
                    hex_str = " ".join(f"{b:02x}" for b in chunk)
                    ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                    print(f"    {offset:04x}: {hex_str:<48s} {ascii_str}")
        else:
            print(f"\nNo responses containing user names found.")
            print(f"Names may be stored in a way that requires a specific payload/parameter.")

    finally:
        try:
            await client.disconnect()
        except Exception:
            pass

    print(f"\nDone.")


if __name__ == "__main__":
    asyncio.run(main())
