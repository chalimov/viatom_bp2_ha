"""
BP2 Direct BLE Probe — run on Windows/Mac/Linux with Bluetooth.

Connects directly to the LP-BP2W (no ESPHome proxy), subscribes to
ALL notify characteristics, tries writing to each writable char,
and logs everything that comes back.

Usage:
    pip install bleak
    python bp2_probe.py

If your device has a different address, pass it as an argument:
    python bp2_probe.py AA:BB:CC:DD:EE:FF
"""

import asyncio
import sys
import time
from datetime import datetime

from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError

# Your device address — change if needed, or pass as CLI arg
DEFAULT_ADDRESS = "46:22:4E:7C:B4:D8"

# Known UUIDs
LEPU_WRITE  = "8b00ace7-eb0b-49b0-bbe9-9aee0a26e1a3"
LEPU_NOTIFY = "0734594a-a8e7-4b1a-a6b1-cd5243059a57"
ALT_0001    = "8ec90001-f315-4f60-9fb8-838830daea50"
ALT_0002    = "8ec90002-f315-4f60-9fb8-838830daea50"

# CRC-8/MAXIM table
_CRC_TABLE = []
for _i in range(256):
    _crc = _i
    for _ in range(8):
        _crc = (_crc >> 1) ^ 0x8C if _crc & 1 else _crc >> 1
    _CRC_TABLE.append(_crc & 0xFF)

def crc8_maxim(data: bytes) -> int:
    crc = 0
    for b in data:
        crc = _CRC_TABLE[crc ^ b]
    return crc

def build_sync_time() -> bytes:
    """Build a Lepu Protocol V2 sync_time command."""
    now = datetime.now()
    payload = bytearray([
        now.year & 0xFF, (now.year >> 8) & 0xFF,
        now.month, now.day, now.hour, now.minute, now.second, 0x14,
    ])
    return _build_packet(0xC0, 0xFE00, payload)

def build_get_info() -> bytes:
    """Build CMD 0x00 get_info."""
    return _build_packet(0x00, 0x0000, b"")

def build_get_battery() -> bytes:
    """Build CMD 0x30 get_battery."""
    return _build_packet(0x30, 0x0003, b"")

def _build_packet(cmd: int, seq: int, payload: bytes) -> bytes:
    pkt = bytearray()
    pkt.append(0xA5)           # header
    pkt.append(cmd)            # command
    pkt.append(~cmd & 0xFF)   # ~command
    pkt.append(seq & 0xFF)    # seq low
    pkt.append((seq >> 8) & 0xFF)  # seq high
    length = len(payload)
    pkt.append(length & 0xFF)
    pkt.append((length >> 8) & 0xFF)
    pkt.extend(payload)
    pkt.append(crc8_maxim(bytes(pkt)))
    return bytes(pkt)


def ts():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


async def main():
    address = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ADDRESS
    print(f"[{ts()}] Scanning for {address}...")

    device = await BleakScanner.find_device_by_address(address, timeout=15.0)
    if not device:
        print(f"[{ts()}] Device not found! Make sure BP2 is awake.")
        return

    print(f"[{ts()}] Found: {device.name} ({device.address})")

    notifications = []

    def make_handler(char_label):
        def handler(_sender, data):
            raw = bytes(data)
            notifications.append((ts(), char_label, raw))
            print(f"  [{ts()}] NOTIFY on {char_label}: ({len(raw)}b) {raw.hex()}")
        return handler

    async with BleakClient(device, timeout=20.0) as client:
        print(f"[{ts()}] Connected! MTU={client.mtu_size}")

        # --- Try pairing/bonding ---
        print(f"\n[{ts()}] === Attempting to pair/bond ===")
        try:
            paired = await client.pair()
            print(f"[{ts()}] Pair result: {paired}")
        except Exception as e:
            print(f"[{ts()}] Pair failed (may already be paired): {e}")

        await asyncio.sleep(1.0)

        # --- Dump all services ---
        print(f"\n[{ts()}] === GATT Services ===")
        notify_chars = []
        writable_chars = []
        for service in client.services:
            print(f"  Service: {service.uuid}")
            for char in service.characteristics:
                props = ",".join(char.properties)
                descs = len(char.descriptors)
                print(f"    {char.uuid} [handle={char.handle}] props={props} desc={descs}")
                if "notify" in char.properties or "indicate" in char.properties:
                    notify_chars.append(char)
                if "write" in char.properties or "write-without-response" in char.properties:
                    writable_chars.append(char)

        # --- Subscribe to ALL notify/indicate chars ---
        print(f"\n[{ts()}] === Subscribing to {len(notify_chars)} notify chars ===")
        for char in notify_chars:
            label = f"{char.uuid[:12]}(h{char.handle})"
            try:
                await client.start_notify(char.uuid, make_handler(label))
                print(f"  Subscribed: {label}")
            except BleakError as e:
                print(f"  FAILED {label}: {e}")
            await asyncio.sleep(0.3)

        await asyncio.sleep(1.0)

        # --- Test each writable char with sync_time ---
        cmd_sync = build_sync_time()
        cmd_info = build_get_info()
        cmd_batt = build_get_battery()

        print(f"\n[{ts()}] === Testing writes ===")
        for char in writable_chars:
            label = f"{char.uuid[:12]}(h{char.handle})"
            props = char.properties

            # Determine write mode
            for mode_name, use_resp in [("write-with-response", True), ("write-without-response", False)]:
                if mode_name == "write-with-response" and "write" not in props:
                    continue
                if mode_name == "write-without-response" and "write-without-response" not in props:
                    continue

                notifications.clear()
                print(f"\n  [{ts()}] --- Write to {label} ({mode_name}) ---")
                try:
                    await client.write_gatt_char(char.uuid, cmd_sync, response=use_resp)
                    print(f"  [{ts()}] Wrote sync_time: {cmd_sync.hex()}")
                except BleakError as e:
                    print(f"  [{ts()}] Write FAILED: {e}")
                    continue

                # Wait for responses
                await asyncio.sleep(3.0)
                if not notifications:
                    print(f"  [{ts()}] No notifications received")
                else:
                    print(f"  [{ts()}] Got {len(notifications)} notification(s)")

                # If we got something, also try get_info and get_battery
                if notifications:
                    print(f"\n  [{ts()}] Sending get_info on same char...")
                    notifications.clear()
                    try:
                        await client.write_gatt_char(char.uuid, cmd_info, response=use_resp)
                        print(f"  [{ts()}] Wrote get_info: {cmd_info.hex()}")
                    except BleakError as e:
                        print(f"  [{ts()}] Write FAILED: {e}")
                    await asyncio.sleep(3.0)
                    if notifications:
                        print(f"  [{ts()}] Got {len(notifications)} notification(s)")

                    print(f"\n  [{ts()}] Sending get_battery on same char...")
                    notifications.clear()
                    try:
                        await client.write_gatt_char(char.uuid, cmd_batt, response=use_resp)
                        print(f"  [{ts()}] Wrote get_battery: {cmd_batt.hex()}")
                    except BleakError as e:
                        print(f"  [{ts()}] Write FAILED: {e}")
                    await asyncio.sleep(3.0)
                    if notifications:
                        print(f"  [{ts()}] Got {len(notifications)} notification(s)")

        # --- Post-pair retest: write to 8b00ace7 again ---
        print(f"\n[{ts()}] === Post-pair retest: 8b00ace7 write-without-response ===")
        notifications.clear()
        try:
            await client.write_gatt_char(LEPU_WRITE, cmd_sync, response=False)
            print(f"[{ts()}] Wrote sync_time to 8b00ace7 (w-o-r): {cmd_sync.hex()}")
        except BleakError as e:
            print(f"[{ts()}] Write failed: {e}")
        await asyncio.sleep(3.0)
        if notifications:
            print(f"[{ts()}] Post-pair: got {len(notifications)} notification(s)!")
            for t, label, raw in notifications:
                print(f"  [{t}] {label}: {raw.hex()}")
        else:
            print(f"[{ts()}] Post-pair: still no notifications")

        # --- CCCD manual write test ---
        print(f"\n[{ts()}] === Manual CCCD write for 0734594a ===")
        lepu_notify_char = None
        for service in client.services:
            for char in service.characteristics:
                if char.uuid == LEPU_NOTIFY:
                    lepu_notify_char = char
                    break
        if lepu_notify_char and lepu_notify_char.descriptors:
            for desc in lepu_notify_char.descriptors:
                print(f"  Descriptor: {desc.uuid} handle={desc.handle}")
                if "2902" in desc.uuid:
                    # CCCD - try writing 0x0001 (enable notifications)
                    try:
                        await client.write_gatt_descriptor(desc.handle, b"\x01\x00")
                        print(f"  [{ts()}] Wrote CCCD 0x0001 to enable notifications")
                    except BleakError as e:
                        print(f"  [{ts()}] CCCD write failed: {e}")
                    # Also try 0x0002 (enable indications)
                    try:
                        await client.write_gatt_descriptor(desc.handle, b"\x02\x00")
                        print(f"  [{ts()}] Wrote CCCD 0x0002 to enable indications")
                    except BleakError as e:
                        print(f"  [{ts()}] CCCD indication write failed: {e}")

            # Re-test write after manual CCCD
            await asyncio.sleep(1.0)
            notifications.clear()
            try:
                await client.write_gatt_char(LEPU_WRITE, cmd_sync, response=False)
                print(f"  [{ts()}] Re-wrote sync_time to 8b00ace7")
            except BleakError as e:
                print(f"  [{ts()}] Write failed: {e}")
            await asyncio.sleep(3.0)
            if notifications:
                print(f"  [{ts()}] After CCCD: got {len(notifications)} notification(s)!")
            else:
                print(f"  [{ts()}] After CCCD: still no notifications")

        # --- Final: just wait 10s and see if device sends anything spontaneously ---
        print(f"\n[{ts()}] === Waiting 10s for spontaneous data ===")
        notifications.clear()
        await asyncio.sleep(10.0)
        if notifications:
            print(f"[{ts()}] Got {len(notifications)} spontaneous notification(s)")
        else:
            print(f"[{ts()}] No spontaneous data")

        # --- Try reading all readable chars ---
        print(f"\n[{ts()}] === Reading all readable chars ===")
        for service in client.services:
            for char in service.characteristics:
                if "read" in char.properties:
                    try:
                        data = await client.read_gatt_char(char.uuid)
                        if len(data) > 0:
                            # Try to decode as string
                            try:
                                text = data.decode("utf-8", errors="replace")
                                print(f"  {char.uuid[:12]}: ({len(data)}b) hex={data.hex()} str=\"{text}\"")
                            except Exception:
                                print(f"  {char.uuid[:12]}: ({len(data)}b) {data.hex()}")
                        else:
                            print(f"  {char.uuid[:12]}: (empty)")
                    except BleakError as e:
                        print(f"  {char.uuid[:12]}: READ ERROR: {e}")

        print(f"\n[{ts()}] === DONE ===")


if __name__ == "__main__":
    asyncio.run(main())
