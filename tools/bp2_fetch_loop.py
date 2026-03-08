"""
BP2 Cycling Fetch v3 — Emulates HA coordinator behavior.

Continuously polls the LP-BP2W device: connects, fetches BP records,
disconnects, and repeats.

SAFE commands:    GET_BATTERY (0x30), SYNC_TIME (0xEC)
VISUAL commands:  READ_FILE_START (0xF2), READ_FILE_DATA (0xF3),
                  READ_FILE_END (0xF4) — show transfer icon briefly
DANGER — NEVER:   0x09 (SWITCH_STATE), 0x0A (START_MEASUREMENT)

v3 changes (from v1):
  - Renamed MAP→HR (device shows heart rate there, not mean arterial pressure)
  - Removed RT_STATE (0x31) — returns garbage on LP-BP2W, not usable
  - Removed BleakScanner pre-scan — after a failed connection on Windows,
    the BLE stack gets stuck and scanner can never find the device again.
    Now just tries to connect directly every cycle.
  - Do NOT pass timeout= to BleakClient constructor (breaks WinRT)
  - Keep 2s post-connect stabilization (shorter causes connection drops)
  - Don't check is_connected aggressively — just try operations

Usage:
    python bp2_fetch_loop.py [DEVICE_ADDRESS] [--interval SECONDS]
    python bp2_fetch_loop.py --once          # single cycle test
"""

import asyncio
import sys
import struct
import time
import argparse
import signal

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


def parse_bp_records(data: bytes):
    """Parse bp2nibp.list file: 10-byte header + N x 37-byte records.

    Record layout (37 bytes):
      [0-3]   timestamp (uint32 LE, unix seconds)
      [4-7]   user_id (uint32 LE) — identifies which user took the measurement
      [8]     status flag (0 or 1)
      [9-12]  reserved (zeros)
      [13-14] systolic (uint16 LE, mmHg)
      [15-16] diastolic (uint16 LE, mmHg)
      [17-18] pulse rate (uint16 LE, bpm)
      [19-20] heart rate (uint16 LE, bpm) — displayed as HR on device
      [21-36] padding (zeros)
    """
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
        user_id = struct.unpack_from("<I", r, 4)[0]
        systolic = struct.unpack_from("<H", r, 13)[0]
        diastolic = struct.unpack_from("<H", r, 15)[0]
        pulse = struct.unpack_from("<H", r, 17)[0]
        hr = struct.unpack_from("<H", r, 19)[0]
        status = r[8]
        if systolic == 0 or diastolic == 0 or pulse == 0:
            continue
        ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts > 0 else "?"
        records.append({
            "timestamp": ts,
            "time_str": ts_str,
            "user_id": user_id,
            "systolic": systolic,
            "diastolic": diastolic,
            "pulse": pulse,
            "hr": hr,
            "status": status,
        })
    return records


def log(msg):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")


# ---------------------------------------------------------------------------
# Single fetch cycle — connect, fetch, disconnect
# ---------------------------------------------------------------------------
async def fetch_cycle(target: str, known_records: set) -> tuple:
    """
    One fetch cycle: connect directly, download BP file, disconnect.

    Returns (success, new_records, battery_info).
    """
    reassembler = Reassembler()
    file_data = bytearray()
    file_size = 0
    file_started = asyncio.Event()
    file_done = asyncio.Event()
    battery_info = {}
    battery_received = asyncio.Event()
    client_ref = [None]

    async def write_cmd(cmd_bytes):
        c = client_ref[0]
        if c and c.is_connected:
            await c.write_gatt_char(WRITE_UUID, cmd_bytes)

    def notification_handler(sender, data: bytearray):
        nonlocal file_size
        reassembler.feed(bytes(data))

        while reassembler.packets:
            cmd, payload = reassembler.packets.pop(0)

            if cmd == 0x30:  # GET_BATTERY
                battery_info["raw"] = payload.hex()
                if len(payload) >= 4:
                    voltage = struct.unpack_from("<H", payload, 2)[0]
                    pct = max(0, min(100, (voltage - 3000) * 100 // 1200)) if 2500 <= voltage <= 4300 else 0
                    battery_info["voltage_mv"] = voltage
                    battery_info["percent"] = pct
                battery_received.set()

            elif cmd == 0xEC:  # SYNC_TIME ACK
                pass

            elif cmd == 0xF2:  # FILE_START response
                if len(payload) >= 4:
                    file_size = struct.unpack_from("<I", payload, 0)[0]
                    file_started.set()
                    if file_size > 0:
                        file_data.clear()
                        asyncio.get_event_loop().call_soon_threadsafe(
                            asyncio.ensure_future,
                            write_cmd(build_packet(0xF3, struct.pack("<I", 0)))
                        )
                    else:
                        file_done.set()

            elif cmd == 0xF3:  # FILE_DATA response
                file_data.extend(payload)
                if len(file_data) < file_size:
                    asyncio.get_event_loop().call_soon_threadsafe(
                        asyncio.ensure_future,
                        write_cmd(build_packet(0xF3, struct.pack("<I", len(file_data))))
                    )
                else:
                    asyncio.get_event_loop().call_soon_threadsafe(
                        asyncio.ensure_future,
                        write_cmd(build_packet(0xF4))
                    )

            elif cmd == 0xF4:  # FILE_END
                file_done.set()

    # --- Connect ---
    # NOTE: Do NOT pass timeout= to BleakClient constructor on Windows —
    # it can interfere with WinRT connection handling.
    client = BleakClient(target)
    client_ref[0] = client

    try:
        log(f"  Connecting to {target}...")
        await asyncio.wait_for(client.connect(), timeout=15.0)
    except asyncio.TimeoutError:
        log(f"  Connect timed out (device off or out of range)")
        try:
            await client.disconnect()
        except Exception:
            pass
        return False, [], {}
    except Exception as e:
        err_str = str(e).strip()
        if err_str:
            log(f"  Connect failed: {err_str}")
        else:
            log(f"  Connect failed (device not reachable)")
        try:
            await client.disconnect()
        except Exception:
            pass
        return False, [], {}

    log(f"  Connected")

    try:
        # Give the BLE connection time to fully stabilize.
        # On Windows/WinRT, the GATT services need time to be discovered
        # after the low-level connection is established. Too short = drops.
        await asyncio.sleep(2)

        # Subscribe to notifications (with retry — don't check is_connected,
        # just try and handle the exception if it fails)
        subscribed = False
        for attempt in range(3):
            try:
                await client.start_notify(NOTIFY_UUID, notification_handler)
                subscribed = True
                break
            except Exception as e:
                if attempt < 2:
                    log(f"  Subscribe attempt {attempt+1} failed: {e}, retrying...")
                    await asyncio.sleep(1)
                else:
                    log(f"  Subscribe failed after 3 attempts: {e}")

        if not subscribed:
            return False, [], {}

        await asyncio.sleep(0.3)

        # --- GET_BATTERY (SAFE) ---
        await write_cmd(build_packet(0x30))
        try:
            await asyncio.wait_for(battery_received.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            pass

        if battery_info:
            log(f"  Battery: {battery_info.get('percent', '?')}% ({battery_info.get('voltage_mv', '?')} mV) raw={battery_info.get('raw', '?')}")

        # --- SYNC_TIME (SAFE) ---
        now = time.localtime()
        time_payload = struct.pack("<HBBBBB",
            now.tm_year, now.tm_mon, now.tm_mday,
            now.tm_hour, now.tm_min, now.tm_sec)
        await write_cmd(build_packet(0xEC, time_payload))
        await asyncio.sleep(0.3)

        # --- Download BP file (VISUAL — transfer icon) ---
        log(f"  Requesting bp2nibp.list...")
        fn = b"bp2nibp.list"
        fn_padded = fn + b"\x00" * (20 - len(fn))
        await write_cmd(build_packet(0xF2, fn_padded))

        # Wait for FILE_START response
        try:
            await asyncio.wait_for(file_started.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            log(f"  No response to file request (device may be measuring)")
            return False, [], battery_info

        if file_size == 0:
            log(f"  File is empty")
            return True, [], battery_info

        log(f"  Downloading {file_size} bytes...")

        try:
            await asyncio.wait_for(file_done.wait(), timeout=30)
        except asyncio.TimeoutError:
            log(f"  Download timed out ({len(file_data)}/{file_size} bytes)")
            return False, [], battery_info

        log(f"  Download complete ({len(file_data)} bytes)")

    finally:
        try:
            if client.is_connected:
                await client.disconnect()
        except Exception:
            pass
        log(f"  Disconnected")

    # --- Parse records and find new ones ---
    new_records = []
    if file_data:
        records = parse_bp_records(bytes(file_data))
        records.sort(key=lambda r: r["timestamp"])

        for r in records:
            key = (r["timestamp"], r["systolic"], r["diastolic"], r["pulse"])
            if key not in known_records:
                known_records.add(key)
                new_records.append(r)

        log(f"  Records: {len(records)} total, {len(new_records)} new")

    return True, new_records, battery_info


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
async def main_loop(target: str, interval: int, run_once: bool):
    known_records = set()
    cycle = 0
    consecutive_failures = 0
    running = True

    def signal_handler(sig, frame):
        nonlocal running
        running = False
        print()
        log("Stopping (Ctrl+C)...")

    signal.signal(signal.SIGINT, signal_handler)

    log(f"=== BP2 Cycling Fetch v3 ===")
    log(f"Target: {target}")
    log(f"Poll interval: {interval}s")
    log(f"Press Ctrl+C to stop")
    log(f"")

    while running:
        cycle += 1
        log(f"--- Cycle {cycle} ---")

        # Try to connect and fetch directly (no pre-scan — it breaks on
        # Windows after a failed connection attempt)
        success, new_records, battery = await fetch_cycle(target, known_records)

        if not success:
            consecutive_failures += 1
            # Exponential-ish backoff: 10s, 15s, 20s, 25s, 30s max
            retry_delay = min(5 + 5 * consecutive_failures, 30)
            log(f"  Will retry in {retry_delay}s (failure #{consecutive_failures})...")
            if run_once:
                break
            for i in range(retry_delay):
                if not running:
                    break
                await asyncio.sleep(1)
            continue

        consecutive_failures = 0

        # Display new records
        if new_records:
            # Show unique user IDs
            user_ids = sorted(set(r["user_id"] for r in new_records))
            print()
            log(f"  NEW MEASUREMENTS ({len(new_records)}) — user(s): {user_ids}")
            print(f"  {'#':>3}  {'Date/Time':<20} {'User':>6} {'SYS':>4} {'DIA':>4} {'PUL':>4} {'HR':>4}")
            print(f"  {'-'*3}  {'-'*20} {'-'*6} {'-'*4} {'-'*4} {'-'*4} {'-'*4}")
            for i, r in enumerate(new_records):
                print(f"  {i+1:3d}  {r['time_str']:<20} {r['user_id']:6d} {r['systolic']:4d} {r['diastolic']:4d} {r['pulse']:4d} {r['hr']:4d}")
            newest = new_records[-1]
            log(f"  LATEST: {newest['systolic']}/{newest['diastolic']} mmHg, "
                f"pulse {newest['pulse']}, HR {newest['hr']} bpm "
                f"(user {newest['user_id']}) @ {newest['time_str']}")
            print()
        else:
            log(f"  No new records since last fetch")

        if battery:
            log(f"  Battery: {battery.get('percent', '?')}% ({battery.get('voltage_mv', '?')} mV) raw={battery.get('raw', '?')}")

        if run_once:
            break

        # Wait for next cycle
        log(f"  Next poll in {interval}s...")
        for i in range(interval):
            if not running:
                break
            await asyncio.sleep(1)

    log(f"Total unique records seen: {len(known_records)}")
    log(f"Done.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BP2 Cycling Fetch v3 — emulates HA coordinator")
    parser.add_argument("address", nargs="?", default=DEFAULT_ADDRESS,
                        help=f"Device BLE address (default: {DEFAULT_ADDRESS})")
    parser.add_argument("--interval", type=int, default=30,
                        help="Seconds between poll cycles (default: 30)")
    parser.add_argument("--once", action="store_true",
                        help="Run one cycle and exit")
    args = parser.parse_args()

    asyncio.run(main_loop(args.address, args.interval, args.once))
