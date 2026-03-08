"""
BP2 Advertisement Monitor v2 — Watches BLE advertisements to understand
what data changes between device states (idle, measuring, post-measurement).

All data is written to a log file (bp2_advert_log.txt).
Console shows minimal status + alerts on REAL data changes.

IMPORTANT: platform_data and RSSI are excluded from change detection
because they change every single advertisement (noise).

Usage:
    python bp2_advert_monitor.py [DEVICE_ADDRESS]

Steps:
    1. Run this script
    2. Turn on BP2 device — wait for "Device found" message
    3. Take a BP measurement (single or 3x sequential)
    4. Wait for measurement to complete and results to show on device
    5. Wait another 10-15 seconds
    6. Press Ctrl+C to stop
    7. Share the bp2_advert_log.txt file
"""

import asyncio
import sys
import os
from datetime import datetime

from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

DEFAULT_ADDRESS = "46:22:4E:7C:B4:D8"
LOG_FILE = "bp2_advert_log.txt"

# Only track fields that could carry meaningful state
TRACKED_FIELDS = ("name", "service_uuids", "service_data", "manufacturer_data", "tx_power")

last_advert = {}
advert_count = 0
change_count = 0
log_fh = None
device_found = False


def log(msg: str) -> None:
    """Write to log file."""
    global log_fh
    if log_fh:
        log_fh.write(msg + "\n")
        log_fh.flush()


def detection_callback(device: BLEDevice, advertisement_data: AdvertisementData):
    """Called for every BLE advertisement from any device."""
    target = sys.argv[1].upper() if len(sys.argv) > 1 else DEFAULT_ADDRESS.upper()

    if device.address.upper() != target:
        return

    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    global last_advert, advert_count, change_count, device_found

    advert_count += 1

    # Collect meaningful advertisement fields only
    current = {
        "name": device.name,
        "service_uuids": sorted(str(u) for u in (advertisement_data.service_uuids or [])),
        "service_data": {
            str(k): v.hex() for k, v in (advertisement_data.service_data or {}).items()
        },
        "manufacturer_data": {
            str(k): v.hex() for k, v in (advertisement_data.manufacturer_data or {}).items()
        },
        "tx_power": advertisement_data.tx_power,
    }
    rssi = advertisement_data.rssi

    # Check what changed since last advertisement
    changes = []
    for key in TRACKED_FIELDS:
        old = last_advert.get(key)
        new = current.get(key)
        if old is not None and old != new:
            changes.append((key, old, new))

    if not device_found:
        # First advertisement — log everything
        device_found = True
        log(f"[{ts}] === FIRST ADVERTISEMENT from {device.address} ===")
        log(f"  Name:              {current['name']}")
        log(f"  RSSI:              {rssi}")
        log(f"  Service UUIDs:     {current['service_uuids']}")
        log(f"  Service Data:      {current['service_data']}")
        log(f"  Manufacturer Data: {current['manufacturer_data']}")
        log(f"  TX Power:          {current['tx_power']}")
        log("")
        # Console feedback
        print(f"\n  [{ts}] Device found! Logging to {LOG_FILE}")
        print(f"  Advertisement data: name={current['name']}, mfr={current['manufacturer_data']}")
        print(f"  Now take a measurement on the device...\n")
    elif changes:
        # Something meaningful changed!
        change_count += 1
        log(f"[{ts}] *** REAL CHANGE #{change_count} (advert #{advert_count}) ***")
        for key, old, new in changes:
            log(f"  {key}: {old} -> {new}")
        log(f"  (RSSI: {rssi})")
        log("")
        # Console alert
        change_desc = ", ".join(f"{k}" for k, _, _ in changes)
        print(f"\n  [{ts}] *** REAL CHANGE #{change_count}: {change_desc} ***")
        for key, old, new in changes:
            print(f"    {key}: {old} -> {new}")
        print()

    # Log heartbeat every 30 adverts for timeline reference
    if advert_count % 30 == 0:
        log(f"[{ts}] ... heartbeat (advert #{advert_count}, RSSI={rssi}, mfr={current['manufacturer_data']})")

    last_advert = current

    # Update console status line
    elapsed = ""
    print(f"  Adverts: {advert_count} | Real changes: {change_count} | RSSI: {rssi} | mfr: {current['manufacturer_data']}    ", end="\r")


async def main():
    global log_fh

    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ADDRESS
    log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), LOG_FILE)

    # Open log file
    log_fh = open(log_path, "w", encoding="utf-8")

    print(f"=== BP2 Advertisement Monitor v2 ===")
    print(f"Target: {target}")
    print(f"Log file: {log_path}")
    print(f"Tracking: {', '.join(TRACKED_FIELDS)}")
    print(f"Ignoring: rssi, platform_data (noise)")
    print()
    print(f"Instructions:")
    print(f"  1. Turn on the BP2 device")
    print(f"  2. Wait for 'Device found' message below")
    print(f"  3. Take a BP measurement on the device (wait for it to finish!)")
    print(f"  4. After results show on device, wait 10-15 more seconds")
    print(f"  5. Press Ctrl+C to stop")
    print(f"  6. Share {LOG_FILE}")
    print()
    print(f"  Scanning...")

    log(f"=== BP2 Advertisement Monitor v2 ===")
    log(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log(f"Target: {target}")
    log(f"Tracking fields: {', '.join(TRACKED_FIELDS)}")
    log(f"Excluded (noise): rssi, platform_data")
    log("")

    scanner = BleakScanner(detection_callback=detection_callback)
    await scanner.start()

    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\n\nStopping...")
    finally:
        await scanner.stop()

    log("")
    log(f"=== Monitor stopped ===")
    log(f"Ended: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log(f"Total advertisements: {advert_count}")
    log(f"Real changes (meaningful fields only): {change_count}")

    log_fh.close()
    print(f"\nDone. {advert_count} advertisements captured, {change_count} REAL changes.")
    print(f"Log saved to: {log_path}")


if __name__ == "__main__":
    asyncio.run(main())
