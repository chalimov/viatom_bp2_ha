"""
BP2 Switch State Test — Tests whether CMD_SWITCH_STATE (0x09) can
return the device to idle mode after BLE connection, avoiding the
need to press a button to exit "BLE communication mode".

Theory: In the Lepu SDK (Bp2BleInterface.kt), CMD_SWITCH_STATE sends
a single byte payload indicating the desired device state:
  0x00 = idle/ready
  0x01 = BP measuring
  0x02 = ECG measuring

If we send CMD_SWITCH_STATE(0x00) before disconnecting, the device
should return to its normal idle display instead of staying in BLE mode.

This script:
  1. Connects to the BP2
  2. Sends ECHO to verify connection
  3. Waits 3 seconds (to let BLE mode fully activate)
  4. Sends CMD_SWITCH_STATE with payload 0x00 (idle)
  5. Waits 2 seconds
  6. Disconnects

Watch the device screen:
  - If the device exits BLE mode on its own → SUCCESS
  - If it stays in BLE mode until you press the button → FAILED (try other payloads)

Usage:
    python bp2_switch_state_test.py [DEVICE_ADDRESS]
"""

import asyncio
import sys
import struct

from bleak import BleakClient, BleakScanner

# BLE UUIDs for LP-BP2W
SERVICE_UUID = "14839ac4-7d7e-415c-9a42-167340cf2339"
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


def build_packet(cmd: int, payload: bytes = b"", seq: int = 0) -> bytes:
    cmd_inv = (~cmd) & 0xFF
    length = len(payload)
    pkt = bytearray()
    pkt.append(0xA5)
    pkt.append(cmd & 0xFF)
    pkt.append(cmd_inv)
    pkt.append(0x00)
    pkt.append(seq & 0xFF)
    pkt.append(length & 0xFF)
    pkt.append((length >> 8) & 0xFF)
    pkt.extend(payload)
    pkt.append(crc8(bytes(pkt)))
    return bytes(pkt)


seq = 0

def next_seq():
    global seq
    seq += 1
    return seq % 255


responses = []

def notification_handler(sender, data: bytearray):
    """Handle BLE notifications."""
    cmd = data[1] if len(data) >= 2 else 0
    print(f"  RX: cmd=0x{cmd:02X} len={len(data)} hex={data.hex()}")
    responses.append(bytes(data))


async def main():
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ADDRESS

    # Parse optional state argument
    state_byte = 0x00  # default: idle
    if len(sys.argv) > 2:
        state_byte = int(sys.argv[2], 0)  # supports 0x00, 0, etc.

    print(f"=== BP2 Switch State Test ===")
    print(f"Target: {target}")
    print(f"State to send: 0x{state_byte:02X}")
    print()
    print(f"Watch the device screen carefully!")
    print()

    client = BleakClient(target)

    # Connect with retry
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
                print("Could not connect. Exiting.")
                return

    try:
        print(f"Connected! MTU={client.mtu_size}")
        await asyncio.sleep(2)

        # Subscribe to notifications with retry
        for attempt in range(3):
            try:
                await client.start_notify(NOTIFY_UUID, notification_handler)
                print(f"Notifications subscribed.")
                break
            except Exception as e:
                print(f"  Notify subscribe failed: {e}")
                if attempt < 2:
                    await asyncio.sleep(2)
                else:
                    print("Could not subscribe. Exiting.")
                    return

        await asyncio.sleep(1)

        # Step 1: Send ECHO to verify communication
        print(f"\n--- Step 1: ECHO (verify link) ---")
        echo_pkt = build_packet(0x0A, seq=next_seq())
        await client.write_gatt_char(WRITE_UUID, echo_pkt)
        await asyncio.sleep(1)

        if responses:
            print(f"  ECHO OK — communication verified")
        else:
            print(f"  No ECHO response — communication may not work")

        # Step 2: Wait for BLE mode to fully activate
        print(f"\n--- Step 2: Waiting 3s for BLE mode to settle ---")
        print(f"  (Device should show BLE mode now)")
        await asyncio.sleep(3)

        # Step 3: Send CMD_SWITCH_STATE with desired state
        print(f"\n--- Step 3: Sending CMD_SWITCH_STATE(0x{state_byte:02X}) ---")
        responses.clear()
        switch_pkt = build_packet(0x09, bytes([state_byte]), seq=next_seq())
        print(f"  TX: {switch_pkt.hex()}")
        await client.write_gatt_char(WRITE_UUID, switch_pkt)
        await asyncio.sleep(2)

        if responses:
            print(f"  Got response — device acknowledged the command")
        else:
            print(f"  No response to SWITCH_STATE")

        # Step 4: Wait and observe
        print(f"\n--- Step 4: Waiting 5s — watch the device screen ---")
        print(f"  Did it exit BLE mode?")
        await asyncio.sleep(5)

        # Step 5: Disconnect
        print(f"\n--- Step 5: Disconnecting ---")

    finally:
        try:
            await client.disconnect()
        except Exception:
            pass

    print(f"\nDisconnected.")
    print()
    print(f"=== RESULTS ===")
    print(f"If the device exited BLE mode WITHOUT pressing a button → SUCCESS!")
    print(f"If it stayed in BLE mode → try different state values:")
    print(f"  python bp2_switch_state_test.py {target} 0x00  (idle)")
    print(f"  python bp2_switch_state_test.py {target} 0x01  (BP mode)")
    print(f"  python bp2_switch_state_test.py {target} 0x02  (ECG mode)")
    print(f"  python bp2_switch_state_test.py {target} 0x03")
    print(f"  python bp2_switch_state_test.py {target} 0x04")
    print(f"  python bp2_switch_state_test.py {target} 0xFF")


if __name__ == "__main__":
    asyncio.run(main())
