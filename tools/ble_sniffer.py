#!/usr/bin/env python3
"""Standalone BLE sniffer for Viatom BP2 protocol debugging.

Run this on any machine with BLE (Linux, Mac, or Termux on Android)
to observe the raw protocol before deploying the HA integration.

Usage:
    pip install bleak
    python ble_sniffer.py

    # Or with a known MAC address:
    python ble_sniffer.py AA:BB:CC:DD:EE:FF
"""

import asyncio
import sys
import struct
import time
from bleak import BleakClient, BleakScanner
from bleak.backends.characteristic import BleakGATTCharacteristic

SERVICE_UUID = "14839ac4-7d7e-415c-9a42-167340cf2339"
WRITE_UUID = "8b00ace7-eb0b-49b0-bbe9-9aee0a26e1a3"
NOTIFY_UUID = "0734594a-a8e7-4b1a-a6b1-cd5243059a57"

BP2_NAMES = {"BP2", "BP2A", "BP2W", "Checkme"}


def notification_handler(sender: BleakGATTCharacteristic, data: bytearray) -> None:
    """Print raw notifications for analysis."""
    hex_str = data.hex()
    ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    ts = time.strftime("%H:%M:%S")

    print(f"[{ts}] NOTIFY ({len(data):3d} bytes): {hex_str}")
    print(f"         ASCII: {ascii_str}")

    # Try to decode as Lepu packet
    if len(data) >= 8 and data[0] == 0xA5:
        cmd = data[1]
        cmd_inv = data[2]
        seq = struct.unpack_from("<H", data, 3)[0]
        length = struct.unpack_from("<H", data, 5)[0]
        payload = data[7 : 7 + length] if 7 + length <= len(data) else b""
        print(
            f"         LEPU: cmd=0x{cmd:02X} ~cmd=0x{cmd_inv:02X} "
            f"seq={seq} len={length} payload={payload.hex()}"
        )
        # If this looks like RT data with a BP result (status=5)
        if cmd in (0x16, 0x17) and len(payload) >= 1:
            status = payload[0]
            status_names = {
                0: "SLEEP", 1: "MEMORY", 2: "CHARGE", 3: "READY",
                4: "BP_MEASURING", 5: "BP_MEASURE_END",
                6: "ECG_MEASURING", 7: "ECG_MEASURE_END", 20: "VEN",
            }
            print(f"         STATUS: {status} ({status_names.get(status, 'UNKNOWN')})")
            if status == 5 and len(payload) >= 13:
                print(f"         *** BP RESULT detected — analyze payload bytes 5+ ***")
    print()


async def scan_for_bp2() -> str | None:
    """Scan for BP2 devices."""
    print("Scanning for Viatom BP2 devices (10 seconds)...")
    devices = await BleakScanner.discover(timeout=10)
    for d in devices:
        name = d.name or ""
        uuids = [str(u).lower() for u in (d.metadata.get("uuids", []))]
        if SERVICE_UUID in uuids or any(name.upper().startswith(n) for n in BP2_NAMES):
            print(f"  Found: {name} ({d.address}) RSSI={d.rssi}")
            return d.address
    print("  No BP2 devices found. Make sure the device is powered on.")
    return None


async def main(address: str | None = None) -> None:
    """Connect to BP2 and dump all notifications."""
    if not address:
        address = await scan_for_bp2()
        if not address:
            return

    print(f"\nConnecting to {address} ...")
    async with BleakClient(address, timeout=15) as client:
        print(f"Connected! MTU={client.mtu_size}")
        print("Subscribing to notifications...")
        await client.start_notify(NOTIFY_UUID, notification_handler)

        # Sync time
        ts = int(time.time())
        time_cmd = bytes([0xA5, 0x0C, 0xF3, 0x01, 0x00, 0x04, 0x00]) + struct.pack("<I", ts)
        # Add CRC
        from protocol import crc8
        time_cmd += bytes([crc8(struct.pack("<I", ts))])
        print(f"Sending SYNC_TIME: {time_cmd.hex()}")
        await client.write_gatt_char(WRITE_UUID, time_cmd, response=False)
        await asyncio.sleep(0.5)

        # Get info
        info_cmd = bytes([0xA5, 0x14, 0xEB, 0x02, 0x00, 0x00, 0x00, 0x00])
        print(f"Sending GET_INFO: {info_cmd.hex()}")
        await client.write_gatt_char(WRITE_UUID, info_cmd, response=False)
        await asyncio.sleep(0.5)

        # Get file list
        flist_cmd = bytes([0xA5, 0x18, 0xE7, 0x03, 0x00, 0x00, 0x00, 0x00])
        print(f"Sending GET_FILE_LIST: {flist_cmd.hex()}")
        await client.write_gatt_char(WRITE_UUID, flist_cmd, response=False)

        print("\n--- Listening for notifications (Ctrl+C to stop) ---\n")
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping...")

        await client.stop_notify(NOTIFY_UUID)
    print("Disconnected.")


if __name__ == "__main__":
    addr = sys.argv[1] if len(sys.argv) > 1 else None
    asyncio.run(main(addr))
