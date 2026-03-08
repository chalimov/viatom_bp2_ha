"""
BP2 Quick Disconnect Test — Tests whether the device auto-exits BLE mode
after a clean BLE disconnection (no commands, or minimal commands).

Test 1 (default): Connect, wait 2s, disconnect immediately. No commands sent.
  → Does the device exit BLE mode on its own after disconnect?
  → If so, how long does it take?

Test 2 (--echo): Connect, send ECHO only, disconnect.
  → Same question.

Test 3 (--fetch): Connect, download BP file, disconnect.
  → Full data fetch. Does device exit BLE mode after?

After disconnect, watch the device screen and time how long
it takes to exit BLE mode (if it does at all).

Usage:
    python bp2_quick_disconnect_test.py                # Test 1: bare connect/disconnect
    python bp2_quick_disconnect_test.py --echo          # Test 2: echo then disconnect
    python bp2_quick_disconnect_test.py --fetch         # Test 3: full fetch then disconnect
    python bp2_quick_disconnect_test.py --address XX:XX:XX:XX:XX:XX  # custom address
"""

import asyncio
import sys
import struct
import time
import argparse

from bleak import BleakClient

# BLE UUIDs
SERVICE_UUID = "14839ac4-7d7e-415c-9a42-167340cf2339"
WRITE_UUID = "8b00ace7-eb0b-49b0-bbe9-9aee0a26e1a3"
NOTIFY_UUID = "0734594a-a8e7-4b1a-a6b1-cd5243059a57"

DEFAULT_ADDRESS = "46:22:4E:7C:B4:D8"

# CRC table
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


# File download state
file_data = bytearray()
file_size = 0
file_offset = 0
file_done = asyncio.Event()
responses = []


def make_notification_handler(client_ref):
    async def write_cmd(cmd_bytes):
        await client_ref[0].write_gatt_char(WRITE_UUID, cmd_bytes)

    def handler(sender, data: bytearray):
        global file_size, file_offset, file_data
        if len(data) < 2:
            return
        cmd = data[1]
        responses.append((cmd, bytes(data)))

        # Handle file read responses for --fetch mode
        if cmd == 0xF2:  # FILE_START response
            if len(data) >= 12:
                file_size = struct.unpack_from("<I", data, 7)[0]
                print(f"  File size: {file_size} bytes")
                # Request first chunk
                asyncio.get_event_loop().call_soon_threadsafe(
                    asyncio.ensure_future,
                    write_cmd(build_packet(0xF3, struct.pack("<I", 0)))
                )
        elif cmd == 0xF3:  # FILE_DATA response
            if len(data) > 9:
                chunk = data[7:-1]  # strip header and CRC
                # First 4 bytes of payload are the offset echo
                actual_data = chunk[4:]
                file_data.extend(actual_data)
                file_offset += len(actual_data)
                if file_offset < file_size:
                    asyncio.get_event_loop().call_soon_threadsafe(
                        asyncio.ensure_future,
                        write_cmd(build_packet(0xF3, struct.pack("<I", file_offset)))
                    )
                else:
                    # Done, send FILE_END
                    asyncio.get_event_loop().call_soon_threadsafe(
                        asyncio.ensure_future,
                        write_cmd(build_packet(0xF4))
                    )
        elif cmd == 0xF4:  # FILE_END response
            file_done.set()

    return handler


async def main():
    parser = argparse.ArgumentParser(description="BP2 Quick Disconnect Test")
    parser.add_argument("--address", default=DEFAULT_ADDRESS, help="Device BLE address")
    parser.add_argument("--echo", action="store_true", help="Send ECHO before disconnect")
    parser.add_argument("--fetch", action="store_true", help="Full file fetch before disconnect")
    args = parser.parse_args()

    target = args.address
    mode = "fetch" if args.fetch else ("echo" if args.echo else "bare")

    print(f"=== BP2 Quick Disconnect Test ===")
    print(f"Target: {target}")
    print(f"Mode: {mode}")
    print()

    client = BleakClient(target)
    client_ref = [client]

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

    connect_time = time.time()
    print(f"Connected at {time.strftime('%H:%M:%S')}")

    try:
        await asyncio.sleep(2)

        # Subscribe to notifications
        handler = make_notification_handler(client_ref)
        for attempt in range(3):
            try:
                await client.start_notify(NOTIFY_UUID, handler)
                break
            except Exception as e:
                if attempt < 2:
                    await asyncio.sleep(2)
                else:
                    print(f"Could not subscribe to notifications: {e}")
                    return

        await asyncio.sleep(0.5)

        if mode == "echo":
            print(f"\nSending ECHO...")
            await client.write_gatt_char(WRITE_UUID, build_packet(0x0A))
            await asyncio.sleep(1)
            print(f"ECHO response: {'yes' if responses else 'no'}")

        elif mode == "fetch":
            print(f"\nStarting file download (bp2nibp.list)...")
            filename = "bp2nibp.list"
            name_bytes = filename.encode("ascii")[:20]
            payload = name_bytes + b"\x00" * (20 - len(name_bytes))
            await client.write_gatt_char(WRITE_UUID, build_packet(0xF2, payload))

            try:
                await asyncio.wait_for(file_done.wait(), timeout=30)
                print(f"File downloaded: {len(file_data)} bytes in {time.time() - connect_time:.1f}s")
            except asyncio.TimeoutError:
                print(f"File download timed out (got {len(file_data)} of {file_size} bytes)")

        # Disconnect
        disconnect_time = time.time()
        session_duration = disconnect_time - connect_time

    finally:
        try:
            await client.disconnect()
        except Exception:
            pass

    print(f"\nDisconnected at {time.strftime('%H:%M:%S')} (session: {session_duration:.1f}s)")
    print()
    print(f"╔══════════════════════════════════════════════╗")
    print(f"║  NOW WATCH THE DEVICE SCREEN                ║")
    print(f"║                                             ║")
    print(f"║  Does it exit BLE mode on its own?          ║")
    print(f"║  If so, how many seconds after disconnect?  ║")
    print(f"║                                             ║")
    print(f"║  DO NOT press any button — just watch!      ║")
    print(f"╚══════════════════════════════════════════════╝")


if __name__ == "__main__":
    asyncio.run(main())
