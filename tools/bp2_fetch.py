"""
BP2 Silent Fetch — Connects to LP-BP2W, downloads BP records, disconnects.
Uses ONLY safe commands. Device shows a brief transfer icon during download,
which auto-resolves on disconnect. No cuff inflation, no BLE mode.

SAFE commands:    GET_BATTERY (0x30), GET_DEVICE_INFO (0xE1),
                  SYNC_TIME (0xEC), READ_FILE_LIST (0xF1)
VISUAL commands:  READ_FILE_START (0xF2), READ_FILE_DATA (0xF3),
                  READ_FILE_END (0xF4) — show transfer icon briefly
DANGER — NEVER:   0x09 (SWITCH_STATE), 0x0A (START_MEASUREMENT)

Usage:
    python bp2_fetch.py [DEVICE_ADDRESS]

Steps:
    1. Turn on BP2, take a measurement, wait for results on screen
    2. Run this script
    3. Script fetches data silently, device shows brief transfer icon
    4. Script prints all BP records including the new one
"""

import asyncio
import sys
import struct
import time

from bleak import BleakClient

# BLE UUIDs for LP-BP2W
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
    """Decode a Lepu packet. Returns (cmd, payload) or None."""
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


# ---------------------------------------------------------------------------
# Reassembler for multi-notification packets
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# BP file parser (37-byte records)
# ---------------------------------------------------------------------------
def parse_bp_records(data: bytes):
    """Parse bp2nibp.list file: 10-byte header + N x 37-byte records."""
    HEADER = 10
    RECORD = 37
    records = []
    if len(data) < HEADER + RECORD:
        return records
    rec_data = data[HEADER:]
    n = len(rec_data) // RECORD
    for i in range(n):
        r = rec_data[i * RECORD:(i + 1) * RECORD]
        ts = struct.unpack_from("<I", r, 0)[0]
        systolic = struct.unpack_from("<H", r, 13)[0]
        diastolic = struct.unpack_from("<H", r, 15)[0]
        pulse = struct.unpack_from("<H", r, 17)[0]
        map_val = struct.unpack_from("<H", r, 19)[0]
        status = r[8]
        if systolic == 0 or diastolic == 0 or pulse == 0:
            continue
        ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts > 0 else "?"
        records.append({
            "timestamp": ts,
            "time_str": ts_str,
            "systolic": systolic,
            "diastolic": diastolic,
            "pulse": pulse,
            "map": map_val,
            "status": status,
        })
    return records


# ---------------------------------------------------------------------------
# Main fetch logic
# ---------------------------------------------------------------------------
async def main():
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ADDRESS

    print(f"=== BP2 Silent Fetch ===")
    print(f"Target: {target}")
    print()

    reassembler = Reassembler()
    file_data = bytearray()
    file_size = 0
    file_done = asyncio.Event()
    battery_info = {}
    device_info_raw = None

    async def write_cmd(client, cmd_bytes):
        await client.write_gatt_char(WRITE_UUID, cmd_bytes)

    def notification_handler(sender, data: bytearray):
        nonlocal file_size, device_info_raw
        reassembler.feed(bytes(data))

        # Process any complete packets
        while reassembler.packets:
            cmd, payload = reassembler.packets.pop(0)

            if cmd == 0x30:  # GET_BATTERY response
                if len(payload) >= 4:
                    voltage = struct.unpack_from("<H", payload, 2)[0]
                    pct = max(0, min(100, (voltage - 3000) * 100 // 1200)) if 2500 <= voltage <= 4300 else 0
                    battery_info["voltage_mv"] = voltage
                    battery_info["percent"] = pct
                    print(f"  Battery: {pct}% ({voltage} mV)")

            elif cmd == 0xE1:  # GET_DEVICE_INFO response
                device_info_raw = payload
                model = payload[9:17].decode("ascii", errors="replace").strip("\x00") if len(payload) >= 17 else "?"
                fw = f"{payload[3]}.{payload[4]}" if len(payload) >= 5 else "?"
                sn = ""
                if len(payload) >= 38:
                    sn_len = payload[37]
                    if 0 < sn_len <= 20 and 38 + sn_len <= len(payload):
                        sn = payload[38:38 + sn_len].decode("ascii", errors="replace").strip("\x00")
                print(f"  Device: model={model} fw={fw} sn={sn}")

            elif cmd == 0xEC:  # SYNC_TIME ACK
                print(f"  Time synced")

            elif cmd == 0xF2:  # FILE_START response
                if len(payload) >= 4:
                    file_size = struct.unpack_from("<I", payload, 0)[0]
                    print(f"  File size: {file_size} bytes")
                    if file_size > 0:
                        file_data.clear()
                        # Request first chunk
                        asyncio.get_event_loop().call_soon_threadsafe(
                            asyncio.ensure_future,
                            write_cmd(client_ref[0], build_packet(0xF3, struct.pack("<I", 0)))
                        )
                    else:
                        file_done.set()

            elif cmd == 0xF3:  # FILE_DATA response
                file_data.extend(payload)
                if len(file_data) < file_size:
                    asyncio.get_event_loop().call_soon_threadsafe(
                        asyncio.ensure_future,
                        write_cmd(client_ref[0], build_packet(0xF3, struct.pack("<I", len(file_data))))
                    )
                else:
                    # Request file end
                    asyncio.get_event_loop().call_soon_threadsafe(
                        asyncio.ensure_future,
                        write_cmd(client_ref[0], build_packet(0xF4))
                    )

            elif cmd == 0xF4:  # FILE_END response
                file_done.set()

    # Connect
    client = BleakClient(target)
    client_ref = [client]
    t_start = time.time()

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

    print(f"Connected (MTU={client.mtu_size})")

    try:
        await asyncio.sleep(2)

        # Subscribe notifications
        for attempt in range(3):
            try:
                await client.start_notify(NOTIFY_UUID, notification_handler)
                break
            except Exception as e:
                if attempt < 2:
                    await asyncio.sleep(2)
                else:
                    print(f"Could not subscribe: {e}")
                    return

        await asyncio.sleep(0.5)

        # Step 1: GET_BATTERY (SAFE)
        print(f"\n--- Step 1: GET_BATTERY ---")
        await write_cmd(client, build_packet(0x30))
        await asyncio.sleep(1)

        # Step 2: GET_DEVICE_INFO (SAFE)
        print(f"--- Step 2: GET_DEVICE_INFO ---")
        await write_cmd(client, build_packet(0xE1))
        await asyncio.sleep(1)

        # Step 3: SYNC_TIME (SAFE)
        print(f"--- Step 3: SYNC_TIME ---")
        now = time.localtime()
        time_payload = struct.pack("<HBBBBB",
            now.tm_year, now.tm_mon, now.tm_mday,
            now.tm_hour, now.tm_min, now.tm_sec)
        await write_cmd(client, build_packet(0xEC, time_payload))
        await asyncio.sleep(1)

        # Step 4: Download BP file (VISUAL — transfer icon)
        print(f"\n--- Step 4: Downloading bp2nibp.list ---")
        fn = b"bp2nibp.list"
        fn_padded = fn + b"\x00" * (20 - len(fn))
        await write_cmd(client, build_packet(0xF2, fn_padded))

        try:
            await asyncio.wait_for(file_done.wait(), timeout=30)
        except asyncio.TimeoutError:
            print(f"  Download timed out (got {len(file_data)}/{file_size} bytes)")

        t_end = time.time()
        print(f"\nDownload complete: {len(file_data)} bytes in {t_end - t_start:.1f}s total")

    finally:
        try:
            await client.disconnect()
        except Exception:
            pass

    print(f"Disconnected.\n")

    # Parse and display records
    if file_data:
        records = parse_bp_records(bytes(file_data))
        # Sort by timestamp
        records.sort(key=lambda r: r["timestamp"])

        print(f"{'='*65}")
        print(f"  BP RECORDS: {len(records)} measurements")
        print(f"{'='*65}")
        print(f"  {'#':>3}  {'Date/Time':<20} {'SYS':>4} {'DIA':>4} {'PUL':>4} {'MAP':>4}")
        print(f"  {'-'*3}  {'-'*20} {'-'*4} {'-'*4} {'-'*4} {'-'*4}")

        for i, r in enumerate(records):
            print(f"  {i+1:3d}  {r['time_str']:<20} {r['systolic']:4d} {r['diastolic']:4d} {r['pulse']:4d} {r['map']:4d}")

        if records:
            newest = records[-1]
            print(f"\n  LATEST: {newest['systolic']}/{newest['diastolic']} mmHg, "
                  f"pulse {newest['pulse']} bpm @ {newest['time_str']}")

            oldest = records[0]
            print(f"  RANGE:  {oldest['time_str']} to {newest['time_str']}")

        if battery_info:
            print(f"  BATTERY: {battery_info['percent']}% ({battery_info['voltage_mv']} mV)")
    else:
        print("No data downloaded.")


if __name__ == "__main__":
    asyncio.run(main())
