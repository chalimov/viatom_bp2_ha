"""
BP2 Silent Info Test — Uses only SAFE commands to gather device state.

Tests CMD_GET_INFO (0x00) which returns 40 bytes of device registers.
If this contains a measurement counter or timestamp, we can silently
detect new data without triggering BLE mode.

Run this TWICE:
  1. Before taking a measurement
  2. After taking a measurement
Compare the output to see what changed.

Usage:
    python bp2_silent_info_test.py [DEVICE_ADDRESS]
"""

import asyncio
import sys
import struct
import time
import os

from bleak import BleakClient

WRITE_UUID = "8b00ace7-eb0b-49b0-bbe9-9aee0a26e1a3"
NOTIFY_UUID = "0734594a-a8e7-4b1a-a6b1-cd5243059a57"
DEFAULT_ADDRESS = "46:22:4E:7C:B4:D8"
LOG_FILE = "bp2_silent_info_log.txt"

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


responses = {}

def notification_handler(sender, data: bytearray):
    if len(data) < 7:
        return
    cmd = data[1]
    length = data[5] | (data[6] << 8)
    payload = data[7:7+length] if len(data) >= 7+length else data[7:]
    responses[cmd] = payload
    print(f"  RX cmd=0x{cmd:02X}: {data.hex()}")


async def send_cmd(client, name, cmd, payload=b""):
    pkt = build_packet(cmd, payload)
    print(f"  TX {name} (0x{cmd:02X}): {pkt.hex()}")
    await client.write_gatt_char(WRITE_UUID, pkt)
    await asyncio.sleep(1.5)


def analyze_payload(name, cmd, payload):
    """Print detailed byte-by-byte analysis."""
    lines = []
    lines.append(f"\n  {name} (0x{cmd:02X}) — {len(payload)} bytes:")
    lines.append(f"  Raw hex: {payload.hex()}")
    lines.append(f"  Byte-by-byte:")
    for i, b in enumerate(payload):
        # Try various interpretations
        parts = f"    [{i:2d}] 0x{b:02X} ({b:3d})"
        # uint16 LE at this position
        if i + 1 < len(payload):
            u16 = payload[i] | (payload[i+1] << 8)
            parts += f"  | u16={u16}"
        # uint32 LE at this position
        if i + 3 < len(payload):
            u32 = struct.unpack_from("<I", payload, i)[0]
            parts += f"  | u32={u32}"
            # Try as unix timestamp
            if 1700000000 < u32 < 1900000000:
                ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(u32))
                parts += f"  | ts={ts_str}"
        lines.append(parts)
    return lines


async def main():
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ADDRESS
    log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), LOG_FILE)

    print(f"=== BP2 Silent Info Test ===")
    print(f"Target: {target}")
    print(f"Using ONLY safe commands (no BLE mode trigger)")
    print()

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
                return

    print(f"Connected!")
    all_lines = []
    all_lines.append(f"=== BP2 Silent Info Snapshot ===")
    all_lines.append(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    all_lines.append(f"Target: {target}")

    try:
        await asyncio.sleep(2)

        for attempt in range(3):
            try:
                await client.start_notify(NOTIFY_UUID, notification_handler)
                break
            except Exception as e:
                if attempt < 2:
                    await asyncio.sleep(2)
                else:
                    return

        await asyncio.sleep(0.5)

        # Send all safe commands
        print(f"\n--- Sending safe commands only ---")

        await send_cmd(client, "GET_INFO (LP-BP2W)", 0x00)
        await send_cmd(client, "GET_BATTERY", 0x30)
        await send_cmd(client, "GET_DEVICE_INFO", 0xE1)
        await send_cmd(client, "READ_FILE_LIST", 0xF1)

        # Also try GET_CONFIG (0x06) and RT_STATE (0x31) — untested but likely safe
        await send_cmd(client, "GET_CONFIG", 0x06)
        await send_cmd(client, "RT_STATE", 0x31)

        print(f"\n--- Analysis ---")

        # Analyze each response
        for cmd, payload in sorted(responses.items()):
            names = {
                0x00: "GET_INFO (LP-BP2W)",
                0x06: "GET_CONFIG",
                0x30: "GET_BATTERY",
                0x31: "RT_STATE",
                0xE1: "GET_DEVICE_INFO",
                0xF1: "READ_FILE_LIST",
            }
            name = names.get(cmd, f"CMD_0x{cmd:02X}")
            lines = analyze_payload(name, cmd, payload)
            for line in lines:
                print(line)
            all_lines.extend(lines)

    finally:
        try:
            await client.disconnect()
        except Exception:
            pass

    # Save to log file (append mode so we can compare runs)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write("\n" + "="*60 + "\n")
        for line in all_lines:
            f.write(line + "\n")

    print(f"\nDisconnected. Results appended to {LOG_FILE}")
    print(f"\nIMPORTANT: Run this AGAIN after taking a measurement!")
    print(f"Then compare the two snapshots in {LOG_FILE}")
    print(f"Look for values that changed — those indicate new data.")


if __name__ == "__main__":
    asyncio.run(main())
