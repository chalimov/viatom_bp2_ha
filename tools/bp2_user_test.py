"""
BP2 User + Records Fetch — Downloads user.list and bp2nibp.list,
hex-dumps user.list to understand its format, and shows user_id
from each BP record.

Uses ONLY safe commands. One-shot script.
"""

import asyncio
import sys
import struct
import time

from bleak import BleakClient

WRITE_UUID = "8b00ace7-eb0b-49b0-bbe9-9aee0a26e1a3"
NOTIFY_UUID = "0734594a-a8e7-4b1a-a6b1-cd5243059a57"
DEFAULT_ADDRESS = "46:22:4E:7C:B4:D8"

# CRC-8/CCITT table (poly 0x07)
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


def hex_dump(data: bytes, prefix: str = "  "):
    """Pretty hex dump with ASCII."""
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset+16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"{prefix}{offset:04x}: {hex_str:<48s} {ascii_str}")


async def download_file(client, reassembler, filename: str) -> bytes:
    """Download a file from the device. Returns file data or empty bytes."""
    file_data = bytearray()
    file_size = 0
    file_started = asyncio.Event()
    file_done = asyncio.Event()

    # Save the old packet list and use a fresh one
    old_packets = reassembler.packets[:]
    reassembler.packets.clear()

    fn = filename.encode("ascii")
    fn_padded = fn + b"\x00" * (20 - len(fn))
    await client.write_gatt_char(WRITE_UUID, build_packet(0xF2, fn_padded))

    # Poll for responses
    deadline = time.time() + 30
    while time.time() < deadline:
        await asyncio.sleep(0.1)

        while reassembler.packets:
            cmd, payload = reassembler.packets.pop(0)

            if cmd == 0xF2:  # FILE_START
                if len(payload) >= 4:
                    file_size = struct.unpack_from("<I", payload, 0)[0]
                    print(f"  {filename}: size = {file_size} bytes")
                    file_started.set()
                    if file_size > 0:
                        file_data.clear()
                        await client.write_gatt_char(
                            WRITE_UUID,
                            build_packet(0xF3, struct.pack("<I", 0))
                        )
                    else:
                        file_done.set()

            elif cmd == 0xF3:  # FILE_DATA
                file_data.extend(payload)
                if len(file_data) < file_size:
                    await client.write_gatt_char(
                        WRITE_UUID,
                        build_packet(0xF3, struct.pack("<I", len(file_data)))
                    )
                else:
                    await client.write_gatt_char(
                        WRITE_UUID,
                        build_packet(0xF4)
                    )

            elif cmd == 0xF4:  # FILE_END
                file_done.set()

        if file_done.is_set():
            break

        if file_started.is_set() and file_size == 0:
            break

    # Restore old packets
    reassembler.packets = old_packets + reassembler.packets

    if not file_started.is_set():
        print(f"  {filename}: no response (file may not exist)")
        return b""

    return bytes(file_data)


async def main():
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ADDRESS

    print(f"=== BP2 User + Records Test ===")
    print(f"Target: {target}")
    print()

    reassembler = Reassembler()

    def notification_handler(sender, data: bytearray):
        reassembler.feed(bytes(data))

    client = BleakClient(target)

    # Connect
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

    print(f"Connected")
    try:
        await asyncio.sleep(2)

        # Subscribe
        for attempt in range(3):
            try:
                await client.start_notify(NOTIFY_UUID, notification_handler)
                break
            except Exception as e:
                if attempt < 2:
                    await asyncio.sleep(1)
                else:
                    print(f"Could not subscribe: {e}")
                    return

        await asyncio.sleep(0.5)

        # --- Download user.list ---
        print(f"\n--- Downloading user.list ---")
        user_data = await download_file(client, reassembler, "user.list")

        if user_data:
            print(f"\n  user.list hex dump ({len(user_data)} bytes):")
            hex_dump(user_data)

            # Try to interpret: header might be similar to bp2nibp.list
            print(f"\n  First 10 bytes (possible header): {user_data[:10].hex()}")
            if len(user_data) > 10:
                print(f"  Remaining data ({len(user_data) - 10} bytes): {user_data[10:].hex()}")

            # Try various record sizes to find patterns
            for rec_size in [4, 8, 10, 16, 20, 24, 32, 37, 40]:
                if len(user_data) > 10 and (len(user_data) - 10) % rec_size == 0:
                    n = (len(user_data) - 10) // rec_size
                    if n > 0 and n <= 10:
                        print(f"  Possible: {n} records of {rec_size} bytes each (with 10-byte header)")
        else:
            print(f"  user.list: empty or not available")

        # --- Also try GET_CONFIG (0x06) for current user ---
        print(f"\n--- GET_CONFIG (0x06) ---")
        reassembler.packets.clear()
        await client.write_gatt_char(WRITE_UUID, build_packet(0x06))
        await asyncio.sleep(2)
        if reassembler.packets:
            for cmd, payload in reassembler.packets:
                print(f"  Response CMD 0x{cmd:02X}, {len(payload)} bytes:")
                hex_dump(payload)
            reassembler.packets.clear()
        else:
            print(f"  No response")

        # --- Download bp2nibp.list and show user_id per record ---
        print(f"\n--- Downloading bp2nibp.list ---")
        bp_data = await download_file(client, reassembler, "bp2nibp.list")

        if bp_data:
            HEADER = 10
            RECORD = 37
            print(f"\n  BP file header (10 bytes): {bp_data[:HEADER].hex()}")

            rec_data = bp_data[HEADER:]
            n = len(rec_data) // RECORD
            print(f"  {n} records of {RECORD} bytes each")
            print()

            # Show last 5 records with user_id and full raw hex
            start = max(0, n - 5)
            print(f"  Last {n - start} records with user_id:")
            print(f"  {'#':>3}  {'Date/Time':<20} {'UID':>5} {'SYS':>4} {'DIA':>4} {'PUL':>4} {'HR':>4} {'st':>3}  raw_hex")
            print(f"  {'-'*3}  {'-'*20} {'-'*5} {'-'*4} {'-'*4} {'-'*4} {'-'*4} {'-'*3}  {'-'*20}")

            for i in range(start, n):
                r = rec_data[i * RECORD:(i + 1) * RECORD]
                ts = struct.unpack_from("<I", r, 0)[0]
                user_id = struct.unpack_from("<I", r, 4)[0]
                status = r[8]
                systolic = struct.unpack_from("<H", r, 13)[0]
                diastolic = struct.unpack_from("<H", r, 15)[0]
                pulse = struct.unpack_from("<H", r, 17)[0]
                hr = struct.unpack_from("<H", r, 19)[0]

                ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts > 0 else "?"

                if systolic == 0 or diastolic == 0:
                    continue

                print(f"  {i+1:3d}  {ts_str:<20} {user_id:5d} {systolic:4d} {diastolic:4d} {pulse:4d} {hr:4d} {status:3d}  {r.hex()}")

            # Show unique user_ids
            user_ids = set()
            for i in range(n):
                r = rec_data[i * RECORD:(i + 1) * RECORD]
                systolic = struct.unpack_from("<H", r, 13)[0]
                if systolic > 0:
                    uid = struct.unpack_from("<I", r, 4)[0]
                    user_ids.add(uid)
            print(f"\n  Unique user_ids found: {sorted(user_ids)}")

    finally:
        try:
            await client.disconnect()
        except Exception:
            pass

    print(f"\nDone.")


if __name__ == "__main__":
    asyncio.run(main())
