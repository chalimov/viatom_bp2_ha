"""
BP2 Full Probe — Retrieves stored BP measurements from LP-BP2W via BLE.

This script performs the complete production flow:
  1. Connect & subscribe to notifications
  2. Echo/ping to verify communication
  3. GET_DEVICE_INFO (CMD 0xE1) — parse model, serial, firmware
  4. GET_INFO (CMD 0x00) — raw device registers
  5. SYNC_TIME (CMD 0xEC)
  6. GET_BATTERY (CMD 0x30)
  7. READ_FILE_START (CMD 0xF2) for "bp2nibp.list"
  8. READ_FILE_DATA (CMD 0xF3) — loop until complete
  9. READ_FILE_END (CMD 0xF4)
  10. Parse BP records from downloaded file

Uses the proven CRC-8/CCITT and writes to WRITE_UUID with response.

Usage:
    pip install bleak
    python bp2_full_probe.py [DEVICE_ADDRESS]
"""

import asyncio
import struct
import sys
import time
from datetime import datetime

from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError

# Device address
DEFAULT_ADDRESS = "46:22:4E:7C:B4:D8"

# BLE UUIDs
SERVICE_UUID = "14839ac4-7d7e-415c-9a42-167340cf2339"
WRITE_UUID   = "8b00ace7-eb0b-49b0-bbe9-9aee0a26e1a3"
NOTIFY_UUID  = "0734594a-a8e7-4b1a-a6b1-cd5243059a57"

# ---- CRC-8/CCITT (Lepu BLE CRC) ----
CRC8_TABLE = [
    0x00, 0x07, 0x0E, 0x09, 0x1C, 0x1B, 0x12, 0x15, 0x38, 0x3F, 0x36, 0x31, 0x24, 0x23, 0x2A, 0x2D,
    0x70, 0x77, 0x7E, 0x79, 0x6C, 0x6B, 0x62, 0x65, 0x48, 0x4F, 0x46, 0x41, 0x54, 0x53, 0x5A, 0x5D,
    0xE0, 0xE7, 0xEE, 0xE9, 0xFC, 0xFB, 0xF2, 0xF5, 0xD8, 0xDF, 0xD6, 0xD1, 0xC4, 0xC3, 0xCA, 0xCD,
    0x90, 0x97, 0x9E, 0x99, 0x8C, 0x8B, 0x82, 0x85, 0xA8, 0xAF, 0xA6, 0xA1, 0xB4, 0xB3, 0xBA, 0xBD,
    0xC7, 0xC0, 0xC9, 0xCE, 0xDB, 0xDC, 0xD5, 0xD2, 0xFF, 0xF8, 0xF1, 0xF6, 0xE3, 0xE4, 0xED, 0xEA,
    0xB7, 0xB0, 0xB9, 0xBE, 0xAB, 0xAC, 0xA5, 0xA2, 0x8F, 0x88, 0x81, 0x86, 0x93, 0x94, 0x9D, 0x9A,
    0x27, 0x20, 0x29, 0x2E, 0x3B, 0x3C, 0x35, 0x32, 0x1F, 0x18, 0x11, 0x16, 0x03, 0x04, 0x0D, 0x0A,
    0x57, 0x50, 0x59, 0x5E, 0x4B, 0x4C, 0x45, 0x42, 0x6F, 0x68, 0x61, 0x66, 0x73, 0x74, 0x7D, 0x7A,
    0x89, 0x8E, 0x87, 0x80, 0x95, 0x92, 0x9B, 0x9C, 0xB1, 0xB6, 0xBF, 0xB8, 0xAD, 0xAA, 0xA3, 0xA4,
    0xF9, 0xFE, 0xF7, 0xF0, 0xE5, 0xE2, 0xEB, 0xEC, 0xC1, 0xC6, 0xCF, 0xC8, 0xDD, 0xDA, 0xD3, 0xD4,
    0x69, 0x6E, 0x67, 0x60, 0x75, 0x72, 0x7B, 0x7C, 0x51, 0x56, 0x5F, 0x58, 0x4D, 0x4A, 0x43, 0x44,
    0x19, 0x1E, 0x17, 0x10, 0x05, 0x02, 0x0B, 0x0C, 0x21, 0x26, 0x2F, 0x28, 0x3D, 0x3A, 0x33, 0x34,
    0x4E, 0x49, 0x40, 0x47, 0x52, 0x55, 0x5C, 0x5B, 0x76, 0x71, 0x78, 0x7F, 0x6A, 0x6D, 0x64, 0x63,
    0x3E, 0x39, 0x30, 0x37, 0x22, 0x25, 0x2C, 0x2B, 0x06, 0x01, 0x08, 0x0F, 0x1A, 0x1D, 0x14, 0x13,
    0xAE, 0xA9, 0xA0, 0xA7, 0xB2, 0xB5, 0xBC, 0xBB, 0x96, 0x91, 0x98, 0x9F, 0x8A, 0x8D, 0x84, 0x83,
    0xDE, 0xD9, 0xD0, 0xD7, 0xC2, 0xC5, 0xCC, 0xCB, 0xE6, 0xE1, 0xE8, 0xEF, 0xFA, 0xFD, 0xF4, 0xF3,
]


def crc8_ccitt(data: bytes) -> int:
    crc = 0
    for b in data:
        crc = CRC8_TABLE[0xFF & (crc ^ b)]
    return crc


# ---- Command bytes ----
CMD_GET_INFO        = 0x00   # LP-BP2W GET_INFO (40-byte raw registers)
CMD_ECHO            = 0x0A   # Echo/ping (empty ACK)
CMD_GET_DEVICE_INFO = 0xE1   # Standard GET_INFO (60-byte structured)
CMD_SYNC_TIME       = 0xEC   # Sync time
CMD_GET_BATTERY     = 0x30   # Battery level
CMD_READ_FILE_LIST  = 0xF1   # File list
CMD_READ_FILE_START = 0xF2   # File read start (filename -> file size)
CMD_READ_FILE_DATA  = 0xF3   # File read data chunk
CMD_READ_FILE_END   = 0xF4   # File read end


seq_counter = 0


def build_packet(cmd: int, payload: bytes = b"") -> bytes:
    """Build Lepu V2 packet: A5 CMD ~CMD 0x00 SEQ LEN_LO LEN_HI [PAYLOAD] CRC8"""
    global seq_counter
    seq_counter = (seq_counter + 1) % 255

    pkt = bytearray()
    pkt.append(0xA5)
    pkt.append(cmd & 0xFF)
    pkt.append(~cmd & 0xFF)
    pkt.append(0x00)                    # TX flag
    pkt.append(seq_counter & 0xFF)      # seq
    length = len(payload)
    pkt.append(length & 0xFF)           # len lo
    pkt.append((length >> 8) & 0xFF)    # len hi
    pkt.extend(payload)
    pkt.append(crc8_ccitt(bytes(pkt)))  # CRC over everything before
    return bytes(pkt)


def ts():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def parse_lepu_packet(raw: bytes):
    """Parse a raw notification as a Lepu V2 packet. Returns (cmd, payload) or None."""
    if len(raw) < 8 or raw[0] != 0xA5:
        return None
    cmd = raw[1]
    cmd_inv = raw[2]
    if (cmd ^ cmd_inv) & 0xFF != 0xFF:
        return None
    seq = raw[4]
    length = raw[5] | (raw[6] << 8)
    total = 7 + length + 1
    if len(raw) < total:
        return None
    payload = raw[7:7+length]
    expected_crc = crc8_ccitt(raw[:total-1])
    actual_crc = raw[total-1]
    if expected_crc != actual_crc:
        print(f"  [{ts()}] CRC MISMATCH: expected=0x{expected_crc:02X} actual=0x{actual_crc:02X}")
        return None
    return (cmd, seq, payload)


def parse_device_info_e1(payload: bytes) -> dict:
    """Parse CMD 0xE1 response (60 bytes)."""
    info = {}
    if len(payload) < 17:
        return info
    info["hw_version"] = payload[0]
    info["sw_major"] = payload[3]
    info["sw_minor"] = payload[4]
    info["model"] = payload[9:17].decode("ascii", errors="replace").strip("\x00")

    if len(payload) >= 31:
        fw_year = struct.unpack_from("<H", payload, 24)[0]
        fw_month = payload[26]
        fw_day = payload[27]
        fw_hour = payload[28]
        fw_min = payload[29]
        fw_sec = payload[30]
        if 2020 <= fw_year <= 2040:
            info["fw_date"] = f"{fw_year}-{fw_month:02d}-{fw_day:02d} {fw_hour:02d}:{fw_min:02d}:{fw_sec:02d}"

    if len(payload) >= 38:
        sn_len = payload[37]
        if 0 < sn_len <= 20 and 38 + sn_len <= len(payload):
            info["serial"] = payload[38:38+sn_len].decode("ascii", errors="replace").strip("\x00")

    return info


def parse_device_info_00(payload: bytes) -> dict:
    """Parse CMD 0x00 response (40 bytes). Raw registers — dump hex for analysis."""
    info = {"raw_hex": payload.hex(), "length": len(payload)}
    # Try extracting some known fields
    if len(payload) >= 8:
        info["reg_0_3"] = struct.unpack_from("<I", payload, 0)[0]
        info["reg_4_7"] = struct.unpack_from("<I", payload, 4)[0]
    return info


def parse_bp_records(data: bytes) -> list:
    """Parse BP measurement records from bp2nibp.list file data.

    File format (verified from device dump):
      - Header: 10 bytes (byte 0: version?, byte 1: user count?, rest zeros)
      - Records: 37 bytes each, starting at offset 10

    Record format (37 bytes):
      [0-3]   timestamp (uint32 LE, unix seconds)
      [4-7]   user_id (uint32 LE)
      [8]     status_flag (0x00 or 0x01)
      [9-12]  reserved (zeros)
      [13-14] systolic (uint16 LE, mmHg)
      [15-16] diastolic (uint16 LE, mmHg)
      [17-18] pulse (uint16 LE, bpm)
      [19-20] MAP (uint16 LE, mmHg)
      [21-36] padding (zeros)
    """
    HEADER_SIZE = 10
    RECORD_SIZE = 37
    records = []

    if len(data) < HEADER_SIZE + RECORD_SIZE:
        return records

    record_data = data[HEADER_SIZE:]
    num_records = len(record_data) // RECORD_SIZE

    for i in range(num_records):
        rec = record_data[i * RECORD_SIZE : (i + 1) * RECORD_SIZE]
        if len(rec) < 21:
            break

        timestamp = struct.unpack_from("<I", rec, 0)[0]
        # user_id = struct.unpack_from("<I", rec, 4)[0]
        status_flag = rec[8]
        systolic = struct.unpack_from("<H", rec, 13)[0]
        diastolic = struct.unpack_from("<H", rec, 15)[0]
        pulse = struct.unpack_from("<H", rec, 17)[0]
        map_val = struct.unpack_from("<H", rec, 19)[0]

        # Sanity check — skip obviously invalid records
        if systolic == 0 or diastolic == 0 or pulse == 0:
            continue

        ts_str = ""
        if timestamp > 1000000000:
            ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))

        records.append({
            "systolic": systolic,
            "diastolic": diastolic,
            "pulse": pulse,
            "map": map_val,
            "timestamp": timestamp,
            "time_str": ts_str,
            "status_flag": status_flag,
            "offset": HEADER_SIZE + i * RECORD_SIZE,
        })

    return records


async def main():
    address = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ADDRESS
    print(f"[{ts()}] === BP2 Full Probe — Measurement Retrieval ===")
    print(f"[{ts()}] Target: {address}")
    print(f"[{ts()}] Scanning...")

    device = await BleakScanner.find_device_by_address(address, timeout=15.0)
    if not device:
        print(f"[{ts()}] Device not found! Make sure BP2 is awake.")
        return

    print(f"[{ts()}] Found: {device.name} ({device.address})")

    # State for packet reassembly and file download
    rx_buffer = bytearray()
    pending_packets = asyncio.Queue()
    file_data = bytearray()
    file_size = 0
    file_done = asyncio.Event()

    def notification_handler(_sender, data):
        """Reassemble and parse incoming notifications."""
        nonlocal file_data, file_size
        raw = bytes(data)

        # Try to parse complete Lepu packet(s) from this notification
        # For simplicity, handle single-packet notifications (most common)
        # and also accumulate into rx_buffer for fragmented ones
        rx_buffer.extend(raw)

        while len(rx_buffer) >= 8:
            # Find 0xA5 header
            idx = rx_buffer.find(b'\xA5')
            if idx < 0:
                rx_buffer.clear()
                return
            if idx > 0:
                del rx_buffer[:idx]

            if len(rx_buffer) < 7:
                return

            cmd = rx_buffer[1]
            cmd_inv = rx_buffer[2]
            if (cmd ^ cmd_inv) & 0xFF != 0xFF:
                del rx_buffer[:1]
                continue

            length = rx_buffer[5] | (rx_buffer[6] << 8)
            total = 7 + length + 1

            if length > 4096:
                del rx_buffer[:1]
                continue

            if len(rx_buffer) < total:
                return  # wait for more data

            pkt_bytes = bytes(rx_buffer[:total])
            del rx_buffer[:total]

            result = parse_lepu_packet(pkt_bytes)
            if result:
                cmd, seq, payload = result
                # Put on queue for main loop
                try:
                    pending_packets.put_nowait((cmd, seq, payload, pkt_bytes))
                except asyncio.QueueFull:
                    pass

    async def send_cmd(client, cmd, payload=b"", label=""):
        """Send a command and return the response packet, or None on timeout."""
        pkt = build_packet(cmd, payload)
        print(f"  [{ts()}] >>> {label} CMD=0x{cmd:02X}: {pkt.hex()}")

        # Drain any pending packets
        while not pending_packets.empty():
            try:
                pending_packets.get_nowait()
            except asyncio.QueueEmpty:
                break

        await client.write_gatt_char(WRITE_UUID, pkt, response=True)

        # Wait for response
        try:
            result = await asyncio.wait_for(pending_packets.get(), timeout=5.0)
            resp_cmd, resp_seq, resp_payload, resp_raw = result
            print(f"  [{ts()}] <<< Response CMD=0x{resp_cmd:02X} seq={resp_seq} payload={len(resp_payload)}b")
            return (resp_cmd, resp_seq, resp_payload, resp_raw)
        except TimeoutError:
            print(f"  [{ts()}] <<< No response (timeout)")
            return None

    async def send_cmd_raw(client, cmd, payload=b"", label=""):
        """Send command, don't wait for specific response — just fire and collect."""
        pkt = build_packet(cmd, payload)
        print(f"  [{ts()}] >>> {label} CMD=0x{cmd:02X}: {pkt.hex()}")
        await client.write_gatt_char(WRITE_UUID, pkt, response=True)

    # Retry logic for connection — Windows BLE can be flaky
    MAX_CONNECT_RETRIES = 3
    for attempt in range(1, MAX_CONNECT_RETRIES + 1):
        try:
            client = BleakClient(device, timeout=20.0)
            await client.connect()
            print(f"[{ts()}] Connected (attempt {attempt})! MTU={client.mtu_size}")
            break
        except Exception as e:
            print(f"[{ts()}] Connection attempt {attempt} failed: {e}")
            if attempt == MAX_CONNECT_RETRIES:
                print(f"[{ts()}] Giving up after {MAX_CONNECT_RETRIES} attempts.")
                return
            print(f"[{ts()}] Retrying in 3s...")
            await asyncio.sleep(3.0)

    try:
        # Let the connection settle before subscribing
        # On Windows, GATT services need time to be discovered
        await asyncio.sleep(2.0)

        # Force service discovery (helps on Windows)
        services = client.services
        svc_list = list(services)
        print(f"[{ts()}] Services discovered: {len(svc_list)} services")
        for svc in services:
            if SERVICE_UUID.lower() in str(svc.uuid).lower():
                print(f"[{ts()}]   Target service found: {svc.uuid}")
                for char in svc.characteristics:
                    props = ", ".join(char.properties)
                    print(f"[{ts()}]     Char {char.uuid}: [{props}]")

        # Subscribe to notifications — retry on failure
        for notify_attempt in range(1, 4):
            try:
                await client.start_notify(NOTIFY_UUID, notification_handler)
                print(f"[{ts()}] Subscribed to notifications")
                break
            except Exception as e:
                print(f"[{ts()}] Notify subscribe attempt {notify_attempt} failed: {e}")
                if notify_attempt == 3:
                    print(f"[{ts()}] Could not subscribe to notifications, aborting.")
                    return
                await asyncio.sleep(2.0)

        await asyncio.sleep(0.5)

        # ===== Step 1: Echo =====
        print(f"\n{'='*60}")
        print(f"  Step 1: Echo/Ping")
        print(f"{'='*60}")
        resp = await send_cmd(client, CMD_ECHO, label="ECHO")
        if resp:
            print(f"  Communication verified!")
        else:
            print(f"  WARNING: No echo response, continuing anyway...")

        # ===== Step 2: GET_DEVICE_INFO (0xE1) =====
        print(f"\n{'='*60}")
        print(f"  Step 2: GET_DEVICE_INFO (CMD 0xE1)")
        print(f"{'='*60}")
        resp = await send_cmd(client, CMD_GET_DEVICE_INFO, label="GET_DEVICE_INFO")
        if resp:
            cmd, seq, payload, raw = resp
            info = parse_device_info_e1(payload)
            print(f"  Model:    {info.get('model', '?')}")
            print(f"  Serial:   {info.get('serial', '?')}")
            print(f"  HW ver:   {info.get('hw_version', '?')}")
            print(f"  SW ver:   {info.get('sw_major', '?')}.{info.get('sw_minor', '?')}")
            print(f"  FW date:  {info.get('fw_date', '?')}")
            print(f"  Raw payload: {payload.hex()}")

        # ===== Step 3: GET_INFO (0x00) =====
        print(f"\n{'='*60}")
        print(f"  Step 3: GET_INFO (CMD 0x00)")
        print(f"{'='*60}")
        resp = await send_cmd(client, CMD_GET_INFO, label="GET_INFO")
        if resp:
            cmd, seq, payload, raw = resp
            info00 = parse_device_info_00(payload)
            print(f"  Raw ({info00['length']}b): {info00['raw_hex']}")

        # ===== Step 4: SYNC_TIME =====
        print(f"\n{'='*60}")
        print(f"  Step 4: SYNC_TIME (CMD 0xEC)")
        print(f"{'='*60}")
        now = time.localtime()
        time_payload = struct.pack("<HBBBBB",
            now.tm_year, now.tm_mon, now.tm_mday,
            now.tm_hour, now.tm_min, now.tm_sec)
        resp = await send_cmd(client, CMD_SYNC_TIME, time_payload, label="SYNC_TIME")
        if resp:
            print(f"  Time synced to {time.strftime('%Y-%m-%d %H:%M:%S')}")

        # ===== Step 5: GET_BATTERY =====
        print(f"\n{'='*60}")
        print(f"  Step 5: GET_BATTERY (CMD 0x30)")
        print(f"{'='*60}")
        resp = await send_cmd(client, CMD_GET_BATTERY, label="GET_BATTERY")
        if resp:
            cmd, seq, payload, raw = resp
            if len(payload) >= 2:
                print(f"  Battery status: {payload[0]}")
                print(f"  Battery level:  {payload[1]}%")
            print(f"  Raw: {payload.hex()}")

        # ===== Step 6: Read BP file =====
        print(f"\n{'='*60}")
        print(f"  Step 6: READ FILE — bp2nibp.list")
        print(f"{'='*60}")

        # 6a: FILE_START — get file size
        filename = "bp2nibp.list"
        name_bytes = filename.encode("ascii")
        name_padded = name_bytes + b"\x00" * (20 - len(name_bytes))
        resp = await send_cmd(client, CMD_READ_FILE_START, name_padded, label="FILE_START")

        if resp:
            cmd, seq, payload, raw = resp
            print(f"  Response payload ({len(payload)}b): {payload.hex()}")

            if len(payload) >= 4:
                file_size = struct.unpack_from("<I", payload, 0)[0]
                print(f"  File size: {file_size} bytes")
            else:
                print(f"  ERROR: unexpected file start response")
                file_size = 0

            if file_size > 0:
                # 6b: FILE_DATA — read chunks
                file_data.clear()
                offset = 0
                chunk_num = 0

                while offset < file_size:
                    chunk_num += 1
                    offset_payload = struct.pack("<I", offset)
                    print(f"\n  --- Chunk {chunk_num}: offset={offset}/{file_size} ---")
                    resp = await send_cmd(client, CMD_READ_FILE_DATA, offset_payload,
                                         label=f"FILE_DATA[{offset}]")

                    if resp:
                        cmd, seq, payload, raw_pkt = resp
                        file_data.extend(payload)
                        offset += len(payload)
                        print(f"  Got {len(payload)} bytes (total: {len(file_data)}/{file_size})")
                    else:
                        print(f"  ERROR: no response for chunk at offset {offset}")
                        # Try once more
                        await asyncio.sleep(1.0)
                        resp = await send_cmd(client, CMD_READ_FILE_DATA, offset_payload,
                                             label=f"FILE_DATA[{offset}] (retry)")
                        if resp:
                            cmd, seq, payload, raw_pkt = resp
                            file_data.extend(payload)
                            offset += len(payload)
                            print(f"  Retry got {len(payload)} bytes")
                        else:
                            print(f"  GIVING UP on chunk at offset {offset}")
                            break

                # 6c: FILE_END
                print(f"\n  --- FILE_END ---")
                resp = await send_cmd(client, CMD_READ_FILE_END, label="FILE_END")
                if resp:
                    print(f"  File read complete ACK")

                # 6d: Parse the file data
                print(f"\n  Downloaded {len(file_data)} bytes total")
                print(f"  Raw hex (first 200): {file_data[:200].hex()}")
                if len(file_data) > 200:
                    print(f"  ... ({len(file_data) - 200} more bytes)")

                # Hex dump for analysis
                print(f"\n  Full hex dump:")
                for i in range(0, len(file_data), 16):
                    hex_part = " ".join(f"{b:02X}" for b in file_data[i:i+16])
                    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in file_data[i:i+16])
                    print(f"    {i:04X}: {hex_part:<48s} {ascii_part}")

            elif file_size == 0:
                print(f"  File is empty — no stored measurements")
        else:
            print(f"  ERROR: no response for FILE_START")

        # ===== Step 7: Also try reading user.list =====
        print(f"\n{'='*60}")
        print(f"  Step 7: READ FILE — user.list")
        print(f"{'='*60}")
        filename2 = "user.list"
        name2_bytes = filename2.encode("ascii")
        name2_padded = name2_bytes + b"\x00" * (20 - len(name2_bytes))
        resp = await send_cmd(client, CMD_READ_FILE_START, name2_padded, label="FILE_START(user)")

        if resp:
            cmd, seq, payload, raw = resp
            print(f"  Response payload ({len(payload)}b): {payload.hex()}")
            if len(payload) >= 4:
                user_file_size = struct.unpack_from("<I", payload, 0)[0]
                print(f"  user.list size: {user_file_size} bytes")

                if user_file_size > 0:
                    user_data = bytearray()
                    uoffset = 0
                    while uoffset < user_file_size:
                        offset_payload = struct.pack("<I", uoffset)
                        resp = await send_cmd(client, CMD_READ_FILE_DATA, offset_payload,
                                             label=f"USER_DATA[{uoffset}]")
                        if resp:
                            cmd, seq, payload, raw_pkt = resp
                            user_data.extend(payload)
                            uoffset += len(payload)
                        else:
                            break

                    resp = await send_cmd(client, CMD_READ_FILE_END, label="FILE_END(user)")

                    print(f"  user.list ({len(user_data)} bytes):")
                    for i in range(0, len(user_data), 16):
                        hex_part = " ".join(f"{b:02X}" for b in user_data[i:i+16])
                        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in user_data[i:i+16])
                        print(f"    {i:04X}: {hex_part:<48s} {ascii_part}")

        # ===== Step 8: Try FILE_LIST command (0xF1) =====
        print(f"\n{'='*60}")
        print(f"  Step 8: FILE_LIST (CMD 0xF1) — discover available files")
        print(f"{'='*60}")
        resp = await send_cmd(client, CMD_READ_FILE_LIST, label="FILE_LIST")
        if resp:
            cmd, seq, payload, raw = resp
            print(f"  File list response ({len(payload)}b): {payload.hex()}")
            # Try to decode as ASCII strings
            try:
                text = payload.decode("ascii", errors="replace")
                if any(c.isalpha() for c in text):
                    print(f"  ASCII: {text}")
            except:
                pass
            # Hex dump
            for i in range(0, len(payload), 16):
                hex_part = " ".join(f"{b:02X}" for b in payload[i:i+16])
                ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in payload[i:i+16])
                print(f"    {i:04X}: {hex_part:<48s} {ascii_part}")

        # ===== Parse BP records =====
        print(f"\n{'='*60}")
        print(f"  RESULTS: Parsing BP measurements")
        print(f"{'='*60}")

        if file_data:
            records = parse_bp_records(bytes(file_data))
            if records:
                print(f"\n  Found {len(records)} BP measurement(s):\n")
                print(f"  {'#':>3}  {'Systolic':>8}  {'Diastolic':>9}  {'Pulse':>5}  {'MAP':>5}  {'Flag':>4}  {'Time':<20}")
                print(f"  {'---':>3}  {'--------':>8}  {'---------':>9}  {'-----':>5}  {'---':>5}  {'----':>4}  {'----':<20}")
                for i, r in enumerate(records, 1):
                    print(f"  {i:3d}  {r['systolic']:8d}  {r['diastolic']:9d}  {r['pulse']:5d}  {r['map']:5d}  {r['status_flag']:4d}  {r['time_str']:<20s}")
                print()
                # Summary
                sys_vals = [r['systolic'] for r in records]
                dia_vals = [r['diastolic'] for r in records]
                pls_vals = [r['pulse'] for r in records]
                print(f"  Summary ({len(records)} records):")
                print(f"    Systolic:  min={min(sys_vals)} max={max(sys_vals)} avg={sum(sys_vals)//len(sys_vals)}")
                print(f"    Diastolic: min={min(dia_vals)} max={max(dia_vals)} avg={sum(dia_vals)//len(dia_vals)}")
                print(f"    Pulse:     min={min(pls_vals)} max={max(pls_vals)} avg={sum(pls_vals)//len(pls_vals)}")
                # Date range: use min/max timestamps (records are in circular buffer order)
                valid_ts = [r for r in records if r['timestamp'] > 1000000000]
                if valid_ts:
                    earliest = min(valid_ts, key=lambda r: r['timestamp'])
                    latest = max(valid_ts, key=lambda r: r['timestamp'])
                    print(f"    Date range: {earliest['time_str'][:10]} to {latest['time_str'][:10]}")
            else:
                print(f"  No BP records found in file data")
                print(f"  File data may use a different record format")
                print(f"  Check the hex dump above for patterns")
        else:
            print(f"  No file data downloaded")

        print(f"\n[{ts()}] === DONE ===")

    finally:
        if client.is_connected:
            try:
                await client.disconnect()
                print(f"[{ts()}] Disconnected cleanly")
            except Exception as e:
                print(f"[{ts()}] Disconnect error (non-fatal): {e}")


if __name__ == "__main__":
    asyncio.run(main())
