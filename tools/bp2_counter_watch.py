"""BP2 Counter Watch — monitors device state and fetches BP results.

Uses a PERSISTENT BLE connection (connect once, subscribe once, poll many).
When a new result is detected (state 5 or 17), downloads bp2nibp.list and
parses + displays the most recent BP record(s).

Device states (byte[39] of CMD 0x00 response):
  Single measurement:
    3  = idle (home screen)
    4  = measuring (cuff inflated, taking reading)
    5  = result ready (stays until user presses button)
  Triple measurement (3x sequential with average):
    15 = inflating (same role as 4 in single)
    16 = pause (between sequential measurements)
    17 = result ready (same role as 5 in single)

Usage:
    python bp2_counter_watch.py              # poll every 10s
    python bp2_counter_watch.py --interval 5 # poll every 5s
"""

import asyncio
import struct
import time
import argparse

from bleak import BleakClient

WRITE_UUID = "8b00ace7-eb0b-49b0-bbe9-9aee0a26e1a3"
NOTIFY_UUID = "0734594a-a8e7-4b1a-a6b1-cd5243059a57"
DEFAULT_ADDRESS = "46:22:4E:7C:B4:D8"

# File transfer commands
CMD_READ_FILE_START = 0xF2
CMD_READ_FILE_DATA  = 0xF3
CMD_READ_FILE_END   = 0xF4
BP_FILENAME = "bp2nibp.list"

# BP record constants
BP_HEADER_SIZE = 10
BP_RECORD_SIZE = 37

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


# --- Device state map ---
# Single measurement: 3 -> 4 -> 5 -> 3
# Triple measurement: 3 -> 15 -> 16 -> 15 -> 16 -> 15 -> 17 -> 3

STATE_NAMES = {
    3:  "IDLE",
    4:  "MEASURING",       # single: cuff inflated
    5:  "RESULT",          # single: result on screen
    15: "TRIPLE-MEAS",     # triple: cuff inflated
    16: "TRIPLE-PAUSE",    # triple: pause between measurements
    17: "TRIPLE-RESULT",   # triple: final result on screen
}

# States that mean "a new result is ready, fetch the file"
RESULT_STATES = {5, 17}
# States that mean "measurement in progress, don't disturb"
BUSY_STATES = {4, 15, 16}


# ---------------------------------------------------------------------------
# BP record parsing (from bp2nibp.list file)
# ---------------------------------------------------------------------------
def parse_bp_records(file_data: bytes) -> list[dict]:
    """Parse BP measurement records from bp2nibp.list file data.

    File format:
      Header: 10 bytes
      Records: 37 bytes each

    Record layout (37 bytes):
      [0-3]   timestamp (uint32 LE, unix seconds)
      [4-7]   user_id (uint32 LE)
      [8]     status_flag (0x00=normal, 0x01=irregular heartbeat)
      [9-12]  reserved (zeros)
      [13-14] systolic (uint16 LE, mmHg)
      [15-16] diastolic (uint16 LE, mmHg)
      [17-18] MAP (uint16 LE, mmHg) — mean arterial pressure (SDK misleadingly labels "pulse")
      [19-20] HR  (uint16 LE, bpm) — heart rate (shown on device screen)
      [21-36] padding (zeros)

    Note: Pulse Pressure (PP = systolic - diastolic) is NOT stored; it is calculated.
    """
    records = []
    if len(file_data) < BP_HEADER_SIZE + BP_RECORD_SIZE:
        return records

    record_data = file_data[BP_HEADER_SIZE:]
    num_records = len(record_data) // BP_RECORD_SIZE

    for i in range(num_records):
        rec = record_data[i * BP_RECORD_SIZE : (i + 1) * BP_RECORD_SIZE]
        if len(rec) < 21:
            break

        timestamp  = struct.unpack_from("<I", rec, 0)[0]
        user_id    = struct.unpack_from("<I", rec, 4)[0]
        status     = rec[8]
        systolic   = struct.unpack_from("<H", rec, 13)[0]
        diastolic  = struct.unpack_from("<H", rec, 15)[0]
        map_val    = struct.unpack_from("<H", rec, 17)[0]  # MAP (mmHg)
        hr         = struct.unpack_from("<H", rec, 19)[0]  # heart rate (bpm)

        # Skip empty slots
        if systolic == 0 or diastolic == 0:
            continue

        ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp)) if timestamp > 0 else "?"

        # Pulse pressure is calculated (confirmed: equals sys - dia exactly)
        pp = systolic - diastolic

        records.append({
            "timestamp": timestamp,
            "time_str": ts_str,
            "user_id": user_id,
            "systolic": systolic,
            "diastolic": diastolic,
            "map": map_val,   # [17-18] mean arterial pressure (mmHg)
            "hr": hr,         # [19-20] heart rate (bpm)
            "pp": pp,         # calculated pulse pressure (mmHg)
            "irregular": status == 1,
        })

    # Sort by timestamp descending (newest first)
    records.sort(key=lambda r: r["timestamp"], reverse=True)
    return records


# ---------------------------------------------------------------------------
# File download over existing BLE connection
# ---------------------------------------------------------------------------
async def download_bp_file(client, reassembler: Reassembler) -> bytes | None:
    """Download bp2nibp.list from the device. Returns raw file bytes or None."""

    # Step 1: FILE_START with 20-byte null-padded filename
    name_bytes = BP_FILENAME.encode("ascii")
    payload = name_bytes + b"\x00" * (20 - len(name_bytes))
    reassembler.packets.clear()
    await client.write_gatt_char(WRITE_UUID, build_packet(CMD_READ_FILE_START, payload))

    # Wait for file size response
    await asyncio.sleep(1.0)

    file_size = None
    for rc, rd in reassembler.packets:
        if rc == CMD_READ_FILE_START and len(rd) >= 4:
            file_size = struct.unpack_from("<I", rd, 0)[0]

    if file_size is None:
        print("       [fetch] no FILE_START response (device busy?)")
        return None

    if file_size == 0:
        print("       [fetch] file is empty (0 bytes)")
        # Still send FILE_END to clean up
        reassembler.packets.clear()
        await client.write_gatt_char(WRITE_UUID, build_packet(CMD_READ_FILE_END))
        await asyncio.sleep(0.5)
        return None

    print(f"       [fetch] file size: {file_size} bytes, downloading...")

    # Step 2: Read chunks
    file_buf = bytearray()
    offset = 0
    while offset < file_size:
        reassembler.packets.clear()
        chunk_payload = struct.pack("<I", offset)
        await client.write_gatt_char(WRITE_UUID, build_packet(CMD_READ_FILE_DATA, chunk_payload))
        await asyncio.sleep(0.5)

        got_data = False
        for rc, rd in reassembler.packets:
            if rc == CMD_READ_FILE_DATA:
                file_buf.extend(rd)
                offset += len(rd)
                got_data = True

        if not got_data:
            # Retry once with longer wait
            await asyncio.sleep(1.0)
            for rc, rd in reassembler.packets:
                if rc == CMD_READ_FILE_DATA:
                    file_buf.extend(rd)
                    offset += len(rd)
                    got_data = True
            if not got_data:
                print(f"       [fetch] stalled at offset {offset}/{file_size}, aborting")
                break

    # Step 3: FILE_END
    reassembler.packets.clear()
    await client.write_gatt_char(WRITE_UUID, build_packet(CMD_READ_FILE_END))
    await asyncio.sleep(0.5)

    print(f"       [fetch] downloaded {len(file_buf)} bytes")
    return bytes(file_buf)


def print_records(records: list[dict], known_keys: set, max_new: int = 5):
    """Print newly discovered BP records."""
    new_records = []
    for r in records:
        key = (r["timestamp"], r["systolic"], r["diastolic"], r["map"])
        if key not in known_keys:
            known_keys.add(key)
            new_records.append(r)

    if not new_records:
        newest = records[0] if records else None
        if newest:
            print(f"       [records] {len(records)} total on device, no NEW records")
            print(f"       [latest]  {newest['systolic']}/{newest['diastolic']} mmHg  "
                  f"MAP={newest['map']}  HR={newest['hr']}  PP={newest['pp']}  "
                  f"user {newest['user_id']}  @ {newest['time_str']}"
                  f"{'  !! IRREGULAR' if newest['irregular'] else ''}")
        return

    # Show newest first (they're already sorted newest-first)
    shown = new_records[:max_new]
    print(f"       [records] {len(new_records)} NEW record(s) ({len(records)} total on device):")
    print(f"       {'':4}  {'Time':<20}  {'BP':>7}  {'MAP':>5}  {'HR':>4}  {'PP':>4}  {'User':>6}  {'Flag'}")
    print(f"       {'':4}  {'----':<20}  {'--':>7}  {'---':>5}  {'--':>4}  {'--':>4}  {'----':>6}  {'----'}")
    for r in shown:
        flag = "IRR!" if r["irregular"] else ""
        print(f"       {'NEW':>4}  {r['time_str']:<20}  "
              f"{r['systolic']:>3}/{r['diastolic']:<3}  "
              f"{r['map']:>5}  {r['hr']:>4}  {r['pp']:>4}  "
              f"{r['user_id']:>6}  {flag}")
    if len(new_records) > max_new:
        print(f"       ... and {len(new_records) - max_new} more")


# ---------------------------------------------------------------------------
# Connection management
# ---------------------------------------------------------------------------
async def connect_and_subscribe(target: str, reassembler: Reassembler):
    """Connect to device and subscribe to notifications.

    Returns (client, None) on success or (None, error_string) on failure.
    Uses 2s post-connect stabilization (validated minimum for WinRT).
    """
    def on_notify(sender, data):
        reassembler.feed(bytes(data))

    client = BleakClient(target)
    try:
        await asyncio.wait_for(client.connect(), timeout=10.0)
    except asyncio.TimeoutError:
        return None, "connect timeout"
    except Exception as e:
        err = str(e).strip()
        return None, err if err else "connect failed"

    # Post-connect stabilization -- DO NOT reduce below 2s.
    await asyncio.sleep(2)

    # Subscribe with retry (up to 3 attempts)
    for attempt in range(3):
        try:
            await client.start_notify(NOTIFY_UUID, on_notify)
            return client, None
        except Exception as e:
            if attempt < 2:
                await asyncio.sleep(0.5)

    # All attempts failed -- disconnect cleanly
    try:
        await client.disconnect()
    except Exception:
        pass
    return None, "subscribe failed after 3 attempts"


async def send_cmd_and_read(client, reassembler: Reassembler,
                            cmd: int, wait: float = 0.8) -> list:
    """Send a command and collect response packets."""
    reassembler.packets.clear()
    await client.write_gatt_char(WRITE_UUID, build_packet(cmd))
    await asyncio.sleep(wait)
    return list(reassembler.packets)


async def poll_state(client, reassembler: Reassembler) -> dict:
    """Send CMD 0x00 on an existing connection, return parsed state."""
    try:
        packets = await send_cmd_and_read(client, reassembler, 0x00, wait=0.8)
    except Exception as e:
        return {"error": f"write failed: {str(e).strip()}"}

    result = {}
    for rc, rd in packets:
        if rc == 0x00 and len(rd) >= 40:
            result["state"] = rd[39]

    if "state" not in result:
        return {"error": "no CMD 0x00 response"}

    return result


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
async def main():
    parser = argparse.ArgumentParser(description="BP2 State Watch + Record Fetch")
    parser.add_argument("address", nargs="?", default=DEFAULT_ADDRESS)
    parser.add_argument("--interval", type=int, default=10,
                        help="Seconds between polls (default: 10)")
    parser.add_argument("--count", type=int, default=60,
                        help="Number of polls (default: 60)")
    parser.add_argument("--fetch-on-start", action="store_true",
                        help="Fetch records immediately on first connection")
    args = parser.parse_args()

    target = args.address
    print(f"BP2 State Watch + Record Fetch (persistent connection)")
    print(f"Target: {target}")
    print(f"Polling every {args.interval}s, up to {args.count} times")
    print(f"")
    print(f"Device states (CMD 0x00 byte[39]):")
    print(f"  Single:  3=IDLE  4=MEASURING  5=RESULT")
    print(f"  Triple: 15=INFLATING  16=PAUSE  17=RESULT")
    print(f"")
    print(f"Fetch triggers: state 5/17 (result), or state 3 after seeing activity")
    print(f"Press Ctrl+C to stop.\n")

    header = f"{'#':>3}  {'Time':<10}  {'State':>5}  {'Name':<14}  {'Action'}"
    print(header)
    print("-" * 70)

    reassembler = Reassembler()
    client = None
    prev_state = None
    fetched_this_cycle = False
    saw_activity = False  # True if we saw any non-idle state since last fetch
    reconnect_count = 0
    known_keys: set[tuple[int, int, int, int]] = set()  # dedup across fetches
    first_connect = True

    for i in range(args.count):
        ts = time.strftime("%H:%M:%S")

        # Ensure we have a live connection
        if client is None or not client.is_connected:
            if client is not None:
                reconnect_count += 1
                await asyncio.sleep(1)
            client, err = await connect_and_subscribe(target, reassembler)
            if err:
                tag = f"reconn#{reconnect_count}" if reconnect_count > 0 else "initial"
                print(f"{i+1:3d}  {ts:<10}  {'ERR':>5}  {'':14}  {err} ({tag})")
                client = None
                if i < args.count - 1:
                    await asyncio.sleep(3)
                continue
            conn_note = f" (reconnected #{reconnect_count})" if reconnect_count > 0 else " (connected)"
            print(f"     {ts:<10}                          {conn_note}")

            # Optionally fetch on first connect to seed known_keys
            if first_connect and args.fetch_on_start:
                first_connect = False
                print(f"       [initial fetch to seed known records]")
                file_data = await download_bp_file(client, reassembler)
                if file_data:
                    records = parse_bp_records(file_data)
                    for r in records:
                        known_keys.add((r["timestamp"], r["systolic"], r["diastolic"], r["map"]))
                    newest = records[0] if records else None
                    print(f"       [seeded] {len(records)} existing records")
                    if newest:
                        print(f"       [latest] {newest['systolic']}/{newest['diastolic']} mmHg  "
                              f"MAP={newest['map']}  HR={newest['hr']}  PP={newest['pp']}  "
                              f"user {newest['user_id']}  @ {newest['time_str']}")
            first_connect = False

        # Poll state on existing connection
        result = await poll_state(client, reassembler)

        if "error" in result:
            err_msg = result["error"]
            print(f"{i+1:3d}  {ts:<10}  {'ERR':>5}  {'':14}  {err_msg}")
            try:
                await client.disconnect()
            except Exception:
                pass
            client = None
        else:
            state = result.get("state", "?")
            state_name = STATE_NAMES.get(state, f"?({state})")

            # Track if we've seen any non-idle state (measurement activity)
            if state != 3 and state != "?":
                saw_activity = True

            # Determine action
            #
            # Fetch logic:
            #   1. State 5 or 17 (result on screen) -> fetch immediately
            #   2. State 3 (idle) BUT saw_activity is True -> user dismissed
            #      result quickly, we missed the 5/17 window -> fetch now
            #   3. State 3 with no prior activity -> skip (nothing new)
            #   4. State 4/15/16 (busy) -> wait
            action = ""
            should_fetch = False

            if state in RESULT_STATES and not fetched_this_cycle:
                # Case 1: result on screen, ideal time to fetch
                action = "<< RESULT -> FETCHING..."
                should_fetch = True
            elif state in RESULT_STATES and fetched_this_cycle:
                action = "(already fetched)"
            elif state == 3 and saw_activity and not fetched_this_cycle:
                # Case 2: back to idle after activity, user dismissed fast
                action = "<< IDLE after activity -> FETCHING (missed result screen)"
                should_fetch = True
            elif state in BUSY_STATES:
                # Case 4: measurement in progress
                if prev_state == 3 or prev_state is None:
                    action = "<< measuring started -> WAIT"
                elif prev_state in RESULT_STATES:
                    action = "<< new measurement started -> WAIT"
                else:
                    action = f"<< busy ({state_name})"
            elif state == 3:
                action = "(idle, skip)"

            if should_fetch:
                fetched_this_cycle = True
                saw_activity = False

            # Detect cycle reset: user dismissed result -> back to idle
            if state == 3 and prev_state in RESULT_STATES:
                fetched_this_cycle = False
                saw_activity = False

            print(f"{i+1:3d}  {ts:<10}  {state:>5}  {state_name:<14}  {action}")

            # Actually fetch the file if triggered
            if should_fetch and client is not None and client.is_connected:
                file_data = await download_bp_file(client, reassembler)
                if file_data:
                    records = parse_bp_records(file_data)
                    print_records(records, known_keys)

            if state != "?":
                prev_state = state

        # Wait for next poll
        if i < args.count - 1:
            try:
                for _ in range(args.interval):
                    await asyncio.sleep(1)
            except asyncio.CancelledError:
                break

    # Clean disconnect
    if client is not None and client.is_connected:
        try:
            await client.disconnect()
        except Exception:
            pass

    print(f"\nDone. Reconnections: {reconnect_count}, known records: {len(known_keys)}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopped.")
