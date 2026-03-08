"""BP2 New Record Detection — find SAFE commands that change after a measurement.

Strategy: capture all SAFE command responses, then wait for user to take a
measurement, capture again, and diff. Any bytes that changed are candidates
for "new record available" detection — avoiding the transfer icon entirely.

SAFE commands to probe (no screen change):
  0x00  GET_INFO (40 bytes) — device state, may contain counters
  0x06  GET_CONFIG (9 bytes)
  0x08  RT_DATA (32 bytes) — status + battery, might have record count
  0x0D  unknown (2 bytes)
  0x26  GET_BLE_MAC (7 bytes) — probably static
  0x28  unknown (1 byte)
  0x30  GET_BATTERY (4 bytes) — voltage changes, but maybe status does too
  0x32  RT_PRESSURE (4 bytes)
  0x33  GET_LP_CONFIG (4 bytes)
  0xE1  GET_DEVICE_INFO (60 bytes)
  0xF1  READ_FILE_LIST (33 bytes) — might include file sizes!

Usage:
  python bp2_newrecord_detect.py

  1. Script connects and captures all SAFE responses -> "snapshot A"
  2. Disconnects and waits for you to take a BP measurement
  3. Press Enter after measurement is done
  4. Reconnects and captures again -> "snapshot B"
  5. Diffs A vs B and shows exactly which bytes changed
"""

import asyncio
import struct
import time
import sys

from bleak import BleakClient

WRITE_UUID = "8b00ace7-eb0b-49b0-bbe9-9aee0a26e1a3"
NOTIFY_UUID = "0734594a-a8e7-4b1a-a6b1-cd5243059a57"
DEFAULT_ADDRESS = "46:22:4E:7C:B4:D8"

# CRC-8/CCITT table
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


# SAFE commands to probe — these never cause screen changes
PROBE_CMDS = {
    0x00: "GET_INFO",
    0x06: "GET_CONFIG",
    0x08: "RT_DATA",
    0x0D: "unknown_0D",
    0x26: "GET_BLE_MAC",
    0x28: "unknown_28",
    0x30: "GET_BATTERY",
    0x32: "RT_PRESSURE",
    0x33: "GET_LP_CONFIG",
    0xE1: "GET_DEVICE_INFO",
    0xF1: "READ_FILE_LIST",
}


async def send_and_wait(client, reassembler, cmd, payload=b"", wait=0.8):
    """Send a command and collect responses."""
    reassembler.packets.clear()
    await client.write_gatt_char(WRITE_UUID, build_packet(cmd, payload))
    await asyncio.sleep(wait)
    results = []
    while reassembler.packets:
        rc, rd = reassembler.packets.pop(0)
        if rc == cmd:
            results.append(rd)
    return results


async def capture_snapshot(target: str, label: str) -> dict[int, bytes]:
    """Connect, send all SAFE probes, return {cmd: payload_bytes}."""
    reassembler = Reassembler()

    def on_notify(sender, data):
        reassembler.feed(bytes(data))

    print(f"\n{'='*60}")
    print(f"  SNAPSHOT {label}: Connecting to {target}...")
    print(f"{'='*60}")

    client = BleakClient(target)
    try:
        await asyncio.wait_for(client.connect(), timeout=15.0)
    except Exception as e:
        print(f"  Connect failed: {e}")
        return {}

    print(f"  Connected. Stabilizing...")
    await asyncio.sleep(2)

    # Subscribe with retry
    for attempt in range(3):
        try:
            await client.start_notify(NOTIFY_UUID, on_notify)
            break
        except Exception as e:
            if attempt < 2:
                print(f"  Subscribe attempt {attempt+1} failed, retrying...")
                await asyncio.sleep(1)
            else:
                print(f"  Subscribe failed: {e}")
                await client.disconnect()
                return {}

    await asyncio.sleep(0.3)

    snapshot = {}

    for cmd, name in sorted(PROBE_CMDS.items()):
        responses = await send_and_wait(client, reassembler, cmd)
        if responses:
            payload = responses[0]
            snapshot[cmd] = payload
            # Show hex dump with annotations
            hex_str = payload.hex()
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in payload)
            print(f"  0x{cmd:02X} {name:20s} ({len(payload):3d}B): {hex_str}")
            if any(32 <= b < 127 for b in payload):
                print(f"       {'':20s}        ASCII: {ascii_str}")
        else:
            print(f"  0x{cmd:02X} {name:20s}        : (no response)")

    # Also try CMD 0xF1 with empty payload AND with a filename to see difference
    # Some devices return file sizes in the file list

    await client.disconnect()
    print(f"  Disconnected.")
    return snapshot


def diff_snapshots(a: dict[int, bytes], b: dict[int, bytes], log_file):
    """Compare two snapshots byte-by-byte and show differences."""
    print(f"\n{'='*60}")
    print(f"  DIFF: Snapshot A vs Snapshot B")
    print(f"{'='*60}")
    log_file.write(f"\n{'='*60}\n")
    log_file.write(f"  DIFF: Snapshot A vs Snapshot B\n")
    log_file.write(f"{'='*60}\n")

    all_cmds = sorted(set(list(a.keys()) + list(b.keys())))
    changes_found = False

    for cmd in all_cmds:
        name = PROBE_CMDS.get(cmd, f"unknown_{cmd:02X}")
        pa = a.get(cmd, b"")
        pb = b.get(cmd, b"")

        if pa == pb:
            print(f"  0x{cmd:02X} {name:20s} : IDENTICAL ({len(pa)} bytes)")
            log_file.write(f"  0x{cmd:02X} {name:20s} : IDENTICAL ({len(pa)} bytes)\n")
            continue

        changes_found = True
        print(f"\n  0x{cmd:02X} {name:20s} : *** CHANGED ***")
        log_file.write(f"\n  0x{cmd:02X} {name:20s} : *** CHANGED ***\n")

        if len(pa) != len(pb):
            msg = f"       Size changed: {len(pa)} -> {len(pb)} bytes"
            print(msg)
            log_file.write(msg + "\n")

        # Show byte-by-byte diff
        max_len = max(len(pa), len(pb))
        for i in range(max_len):
            ba = pa[i] if i < len(pa) else None
            bb = pb[i] if i < len(pb) else None

            if ba != bb:
                ba_str = f"0x{ba:02X}" if ba is not None else "---"
                bb_str = f"0x{bb:02X}" if bb is not None else "---"

                # Try to interpret as useful values
                extra = ""
                if ba is not None and bb is not None:
                    diff = bb - ba
                    extra = f"  (diff: {diff:+d})"

                msg = f"       byte[{i:2d}]: {ba_str} -> {bb_str}{extra}"
                print(msg)
                log_file.write(msg + "\n")

        # Show full hex for both
        print(f"       A: {pa.hex()}")
        print(f"       B: {pb.hex()}")
        log_file.write(f"       A: {pa.hex()}\n")
        log_file.write(f"       B: {pb.hex()}\n")

        # Check if there's a uint32 LE at any offset that looks like a record count
        # Record count would increase by 1
        if len(pa) >= 4 and len(pb) >= 4:
            for off in range(len(pa) - 3):
                if off < len(pb) - 3:
                    va = struct.unpack_from("<I", pa, off)[0]
                    vb = struct.unpack_from("<I", pb, off)[0]
                    if vb == va + 1 and va > 0:
                        msg = f"       *** uint32 LE at offset {off}: {va} -> {vb} (incremented by 1!) ***"
                        print(msg)
                        log_file.write(msg + "\n")

            # Also check uint16 LE
            for off in range(len(pa) - 1):
                if off < len(pb) - 1:
                    va = struct.unpack_from("<H", pa, off)[0]
                    vb = struct.unpack_from("<H", pb, off)[0]
                    if vb == va + 1 and va > 0 and va < 10000:
                        msg = f"       *** uint16 LE at offset {off}: {va} -> {vb} (incremented by 1!) ***"
                        print(msg)
                        log_file.write(msg + "\n")

        # Check for file size changes (multiples of 37 = record size)
        if len(pa) >= 4 and len(pb) >= 4:
            for off in range(len(pa) - 3):
                if off < len(pb) - 3:
                    va = struct.unpack_from("<I", pa, off)[0]
                    vb = struct.unpack_from("<I", pb, off)[0]
                    if vb - va == 37 and va > 10:
                        msg = f"       *** uint32 LE at offset {off}: {va} -> {vb} (diff=37 = 1 BP record!) ***"
                        print(msg)
                        log_file.write(msg + "\n")

    if not changes_found:
        msg = "\n  NO CHANGES DETECTED between snapshots!"
        print(msg)
        log_file.write(msg + "\n")

    return changes_found


async def main():
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ADDRESS
    log_path = "newrecord_detect.log"

    print(f"BP2 New Record Detection Tool")
    print(f"Target: {target}")
    print(f"Log: {log_path}")
    print()
    print("This tool captures SAFE command responses before and after")
    print("a measurement to find which bytes indicate new records.")
    print()

    with open(log_path, "w", encoding="utf-8") as log_file:
        log_file.write(f"BP2 New Record Detection\n")
        log_file.write(f"Target: {target}\n")
        log_file.write(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        # Snapshot A — before measurement
        print("Step 1: Taking BEFORE snapshot...")
        snap_a = await capture_snapshot(target, "A (BEFORE)")

        if not snap_a:
            print("Failed to get snapshot A. Exiting.")
            return

        # Log snapshot A
        log_file.write("=== SNAPSHOT A (BEFORE) ===\n")
        for cmd in sorted(snap_a.keys()):
            name = PROBE_CMDS.get(cmd, f"unknown_{cmd:02X}")
            log_file.write(f"  0x{cmd:02X} {name}: {snap_a[cmd].hex()}\n")

        print(f"\nSnapshot A captured ({len(snap_a)} commands responded).")
        print()
        print("="*60)
        print("  NOW: Take a BP measurement on the device.")
        print("  Wait for the measurement to complete.")
        print("  Then press Enter here.")
        print("="*60)
        input("  Press Enter when measurement is done... ")

        # Snapshot B — after measurement
        print("\nStep 2: Taking AFTER snapshot...")
        snap_b = await capture_snapshot(target, "B (AFTER)")

        if not snap_b:
            print("Failed to get snapshot B. Exiting.")
            return

        # Log snapshot B
        log_file.write("\n=== SNAPSHOT B (AFTER) ===\n")
        for cmd in sorted(snap_b.keys()):
            name = PROBE_CMDS.get(cmd, f"unknown_{cmd:02X}")
            log_file.write(f"  0x{cmd:02X} {name}: {snap_b[cmd].hex()}\n")

        # Diff
        diff_snapshots(snap_a, snap_b, log_file)

        print(f"\nFull results saved to {log_path}")
        print()
        print("What we're looking for:")
        print("  - A byte that increments by 1 (record count)")
        print("  - A uint32 that increases by 37 (file size, 1 record = 37 bytes)")
        print("  - Any consistent change in a SAFE command response")


if __name__ == "__main__":
    asyncio.run(main())
