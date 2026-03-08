"""
BP2 User ID Collector — fetch all user_ids from device.

Reads CMD 0x00 (active user info), CMD 0x08 (RT data),
and downloads bp2nibp.list to extract all user_ids.

Switch to each user on the device before running, or take
a measurement with the new user so their ID appears in records.

Log: tools/user_ids.log
"""

import asyncio
import sys
import struct
import os
from datetime import datetime

from bleak import BleakClient

WRITE_UUID = "8b00ace7-eb0b-49b0-bbe9-9aee0a26e1a3"
NOTIFY_UUID = "0734594a-a8e7-4b1a-a6b1-cd5243059a57"
DEFAULT_ADDRESS = "46:22:4E:7C:B4:D8"

LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "user_ids.log")

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

def hex_dump(data: bytes) -> str:
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset+16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"    {offset:04x}: {hex_str:<48s} {ascii_str}")
    return "\n".join(lines)

async def send_and_wait(client, reassembler, cmd, payload=b"", wait=0.5):
    reassembler.packets.clear()
    await client.write_gatt_char(WRITE_UUID, build_packet(cmd, payload))
    await asyncio.sleep(wait)
    return list(reassembler.packets)

async def download_file(client, reassembler, filename: str) -> bytes:
    name_bytes = filename.encode("ascii")
    padded = name_bytes + b"\x00" * (20 - len(name_bytes))
    responses = await send_and_wait(client, reassembler, 0xF2, padded, wait=2.0)
    if not responses:
        return b""
    resp_cmd, resp_data = responses[0]
    if len(resp_data) < 4:
        return b""
    file_size = struct.unpack("<I", resp_data[:4])[0]
    if file_size == 0:
        return b""

    file_data = bytearray()
    # Request first chunk at offset 0
    offset = 0
    for _ in range(500):
        try:
            responses = await send_and_wait(
                client, reassembler, 0xF3,
                struct.pack("<I", offset), wait=0.5
            )
        except Exception:
            break
        if not responses:
            break
        for rc, rd in responses:
            if rc == 0xF3 and len(rd) > 0:
                file_data.extend(rd)
                offset = len(file_data)
        if len(file_data) >= file_size:
            break
    try:
        await send_and_wait(client, reassembler, 0xF4, b"", wait=0.3)
    except Exception:
        pass
    return bytes(file_data[:file_size])


async def main():
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ADDRESS

    logf = open(LOG_PATH, "w", encoding="utf-8")
    def log(msg: str):
        logf.write(msg + "\n")
        logf.flush()

    log(f"=== BP2 User ID Collector ===")
    log(f"Date: {datetime.now().isoformat()}")
    print(f"BP2 User ID Collector — log: {LOG_PATH}")

    reassembler = Reassembler()
    def notification_handler(sender, data: bytearray):
        reassembler.feed(bytes(data))

    client = BleakClient(target)
    for attempt in range(3):
        try:
            print(f"Connecting (attempt {attempt+1}/3)...", end=" ", flush=True)
            await client.connect()
            print("OK")
            break
        except Exception as e:
            print(f"FAIL ({e})")
            if attempt < 2:
                await asyncio.sleep(3)
            else:
                print("Could not connect.")
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
                    try: await client.disconnect()
                    except: pass
                    await asyncio.sleep(2)
                    await client.connect()
                    await asyncio.sleep(2)
                else:
                    print("Subscribe failed.")
                    logf.close()
                    return
        await asyncio.sleep(0.5)

        # 1. CMD 0x00 — active user info (40 bytes)
        print("Reading CMD 0x00 (device info with active user)...")
        responses = await send_and_wait(client, reassembler, 0x00)
        if responses:
            cmd, payload = responses[0]
            log(f"CMD 0x00 response ({len(payload)} bytes):")
            log(hex_dump(payload))

            # Search for any uint32 in the 200k-999k range (likely user IDs)
            print(f"  Raw ({len(payload)} bytes): {payload.hex()}")
            found_ids = []
            for i in range(len(payload) - 3):
                val = struct.unpack_from("<I", payload, i)[0]
                if 100000 < val < 10000000:  # plausible user ID range
                    found_ids.append((i, val))
            if found_ids:
                for offset, uid in found_ids:
                    le_bytes = struct.pack("<I", uid)
                    print(f"  Possible user_id at offset {offset}: {uid} (0x{uid:08X}) LE={le_bytes.hex()}")
                    log(f"  Possible user_id at offset {offset}: {uid} (0x{uid:08X})")

        # 2. CMD 0x08 — RT data (also contains user info)
        print("Reading CMD 0x08 (RT data)...")
        responses = await send_and_wait(client, reassembler, 0x08)
        if responses:
            cmd, payload = responses[0]
            log(f"\nCMD 0x08 response ({len(payload)} bytes):")
            log(hex_dump(payload))
            print(f"  Raw ({len(payload)} bytes): {payload.hex()}")
            for i in range(len(payload) - 3):
                val = struct.unpack_from("<I", payload, i)[0]
                if 100000 < val < 10000000:
                    le_bytes = struct.pack("<I", val)
                    print(f"  Possible user_id at offset {i}: {val} (0x{val:08X}) LE={le_bytes.hex()}")

        # 3. Download BP records
        print("Downloading bp2nibp.list...")
        bp_data = await download_file(client, reassembler, "bp2nibp.list")
        if bp_data:
            log(f"\nbp2nibp.list: {len(bp_data)} bytes")
            log(f"Header (10 bytes): {bp_data[:10].hex()}")

            HEADER = 10
            REC_SIZE = 37
            record_data = bp_data[HEADER:]
            num_records = len(record_data) // REC_SIZE

            user_ids = {}  # uid → count
            for i in range(num_records):
                rec = record_data[i*REC_SIZE:(i+1)*REC_SIZE]
                if len(rec) < 21:
                    break
                ts = struct.unpack_from("<I", rec, 0)[0]
                uid = struct.unpack_from("<I", rec, 4)[0]
                sys_bp = struct.unpack_from("<H", rec, 13)[0]
                dia_bp = struct.unpack_from("<H", rec, 15)[0]
                pulse = struct.unpack_from("<H", rec, 17)[0]
                hr = struct.unpack_from("<H", rec, 19)[0]

                if sys_bp == 0 and dia_bp == 0:
                    continue

                if uid not in user_ids:
                    user_ids[uid] = 0
                user_ids[uid] += 1

                log(f"  Record {i}: uid={uid} sys={sys_bp} dia={dia_bp} pulse={pulse} hr={hr}")

            print(f"  {num_records} records, {len(user_ids)} unique user_id(s)")
            print()

            # === KEY OUTPUT ===
            print(f"{'='*60}")
            print(f"  USER ID SUMMARY")
            print(f"{'='*60}")
            for uid, count in sorted(user_ids.items()):
                le = struct.pack("<I", uid)
                be = struct.pack(">I", uid)
                print(f"  ID: {uid:>10d}  hex: 0x{uid:08X}  LE: {le.hex()}  records: {count}")

                # Decode attempts
                # 1. Raw bytes as ASCII
                ascii_chars = []
                for b in le:
                    if 32 <= b < 127:
                        ascii_chars.append(chr(b))
                    else:
                        ascii_chars.append(f'[{b:02X}]')
                print(f"         LE ASCII: {''.join(ascii_chars)}")

                for b in be:
                    if 32 <= b < 127:
                        ascii_chars_be = []
                        ascii_chars_be.append(chr(b))
                    else:
                        ascii_chars_be = [f'[{b:02X}]']

                # 2. Byte[2] as "slot"
                print(f"         slot(byte[2]): {le[2]}  name_16(bytes[0:2]): 0x{le[0]:02X}{le[1]:02X} = {le[0] | (le[1]<<8)}")

                log(f"\nUser {uid}: count={count}, LE={le.hex()}, BE={be.hex()}")

            print(f"{'='*60}")
        else:
            print("  No BP data (empty or timeout — is device measuring?)")

    finally:
        try:
            await client.disconnect()
        except:
            pass

    logf.close()
    print("\nDone.")

if __name__ == "__main__":
    asyncio.run(main())
