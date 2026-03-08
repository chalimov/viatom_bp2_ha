"""
BP2 Command Scanner Part 2 — Continue from 0x26 onwards.

Part 1 found:
  0x13 = WiFi credentials (SSID, password, cloud server)
  0x24 or 0x25 = DANGER (turned off device + started inflation!)

This scan covers 0x26-0xFF, skipping all known dangerous commands.
Also tries commands with user-index payloads (0x00, 0x01, 0x02, 0x03).

All raw data is logged to tools/cmd_scan2.log — terminal shows status only.
"""

import asyncio
import sys
import struct
import time
import os
from datetime import datetime

from bleak import BleakClient

WRITE_UUID = "8b00ace7-eb0b-49b0-bbe9-9aee0a26e1a3"
NOTIFY_UUID = "0734594a-a8e7-4b1a-a6b1-cd5243059a57"
DEFAULT_ADDRESS = "46:22:4E:7C:B4:D8"

# ALL known dangerous commands — NEVER send
DANGER_CMDS = {
    0x04,  # FACTORY_RESET
    0x09,  # START_MEASUREMENT (cuff inflate)
    0x0A,  # START_MEASUREMENT (cuff inflate)
    0x24,  # DANGER — device off + inflation (scan1)
    0x25,  # DANGER — possibly this one instead of 0x24
    0x39,  # DANGER — inflation + disconnect (scan2)
    0xE2,  # DEVICE_RESET
    0xE3,  # FACTORY_RESET
}

# Skip file transfer (need special payloads)
SKIP_CMDS = {0xF2, 0xF3, 0xF4}

# Already scanned — skip these
ALREADY_SCANNED = set(range(0x00, 0x3A))  # 0x00-0x39 all done

LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cmd_scan2.log")

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


def has_ascii_text(data: bytes, min_run: int = 2) -> list:
    runs = []
    current = []
    for b in data:
        if 32 <= b < 127:
            current.append(chr(b))
        else:
            if len(current) >= min_run:
                runs.append("".join(current))
            current = []
    if len(current) >= min_run:
        runs.append("".join(current))
    return runs


def hex_dump(payload: bytes) -> str:
    """Full hex dump with ASCII for log file."""
    lines = []
    for offset in range(0, len(payload), 16):
        chunk = payload[offset:offset+16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"    {offset:04x}: {hex_str:<48s} {ascii_str}")
    return "\n".join(lines)


async def main():
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ADDRESS

    logf = open(LOG_PATH, "w", encoding="utf-8")
    def log(msg: str):
        logf.write(msg + "\n")
        logf.flush()

    log(f"=== BP2 Command Scan Part 2 ===")
    log(f"Date: {datetime.now().isoformat()}")
    log(f"Target: {target}")
    log(f"Skipping DANGER: {[f'0x{c:02X}' for c in sorted(DANGER_CMDS)]}")
    log(f"Skipping file transfer: {[f'0x{c:02X}' for c in sorted(SKIP_CMDS)]}")
    log("")

    print(f"BP2 Command Scan Part 2 — log: {LOG_PATH}")
    print(f"Target: {target}")
    print()

    reassembler = Reassembler()

    def notification_handler(sender, data: bytearray):
        reassembler.feed(bytes(data))

    client = BleakClient(target)

    for attempt in range(3):
        try:
            print(f"Connecting (attempt {attempt + 1}/3)...", end=" ", flush=True)
            await client.connect()
            print("OK")
            break
        except Exception as e:
            print(f"FAIL ({e})")
            log(f"Connection attempt {attempt+1} failed: {e}")
            if attempt < 2:
                await asyncio.sleep(3)
            else:
                print("Could not connect. Exiting.")
                logf.close()
                return

    try:
        await asyncio.sleep(2)

        for sub_attempt in range(3):
            try:
                await client.start_notify(NOTIFY_UUID, notification_handler)
                break
            except Exception as e:
                if sub_attempt < 2:
                    print(f"  Subscribe retry {sub_attempt+1}...")
                    log(f"Subscribe attempt {sub_attempt+1} failed: {e}")
                    try:
                        await client.disconnect()
                    except Exception:
                        pass
                    await asyncio.sleep(2)
                    await client.connect()
                    await asyncio.sleep(2)
                else:
                    print(f"  Subscribe failed. Exiting.")
                    log(f"Subscribe failed: {e}")
                    logf.close()
                    return

        await asyncio.sleep(0.5)

        responded_count = 0
        silent_count = 0
        interesting = []
        names_found = []
        last_cmd = None

        # PART A: Scan remaining commands 0x3A-0xFF
        START_FROM = 0x3A
        total_to_scan = sum(1 for c in range(START_FROM, 0x100) if c not in DANGER_CMDS and c not in SKIP_CMDS)
        scanned = 0

        print(f"Scanning 0x{START_FROM:02X}-0xFF ({total_to_scan} commands)...")
        log(f"--- PART A: Scanning 0x{START_FROM:02X}-0xFF ---\n")

        for cmd_code in range(START_FROM, 0x100):
            if cmd_code in DANGER_CMDS or cmd_code in SKIP_CMDS:
                continue

            reassembler.packets.clear()

            try:
                await client.write_gatt_char(WRITE_UUID, build_packet(cmd_code))
            except Exception as e:
                msg = f"WRITE FAILED at 0x{cmd_code:02X}: {e} — device likely disconnected"
                print(f"\n  !!! {msg}")
                print(f"  !!! Last OK: 0x{last_cmd:02X}" if last_cmd else "")
                print(f"  !!! Add 0x{cmd_code:02X} to danger list!")
                log(f"\n!!! {msg}")
                log(f"!!! Add 0x{cmd_code:02X} to DANGER_CMDS")
                break

            await asyncio.sleep(0.5)
            scanned += 1
            last_cmd = cmd_code

            if reassembler.packets:
                for resp_cmd, payload in reassembler.packets:
                    responded_count += 1
                    ascii_runs = has_ascii_text(payload)
                    has_name = any("VS" in r or "AS" in r for r in ascii_runs)

                    # Log full details
                    log(f"CMD 0x{cmd_code:02X} → resp 0x{resp_cmd:02X}, {len(payload)} bytes")
                    if ascii_runs:
                        log(f"  ASCII: {ascii_runs}")
                    log(hex_dump(payload))
                    log("")

                    if has_name:
                        names_found.append((cmd_code, resp_cmd, payload))
                        print(f"\n  *** 0x{cmd_code:02X}: FOUND NAME! ascii={ascii_runs} ***")

                    if has_name or (len(payload) > 4 and ascii_runs):
                        interesting.append(("scan", cmd_code, resp_cmd, payload))
            else:
                silent_count += 1
                log(f"CMD 0x{cmd_code:02X} — no response\n")

            # Progress: one dot per 16 commands
            if scanned % 16 == 0:
                pct = scanned * 100 // total_to_scan
                print(f"  [{pct:3d}%] scanned through 0x{cmd_code:02X} — {responded_count} responded, {silent_count} silent", flush=True)

        print(f"  [100%] Part A done: {responded_count} responded, {silent_count} silent")

        # PART B: Try commands with user-index payloads
        print(f"\nTrying parameterized commands (user-index payloads)...")
        log(f"\n--- PART B: Commands with user-index payloads ---\n")

        param_cmds = [0x00, 0x06, 0x08, 0x0D, 0x13]
        for cmd_code in param_cmds:
            for idx in range(4):
                idx_payload = bytes([idx])
                reassembler.packets.clear()

                try:
                    await client.write_gatt_char(WRITE_UUID, build_packet(cmd_code, idx_payload))
                except Exception as e:
                    log(f"CMD 0x{cmd_code:02X}+0x{idx:02X}: write failed ({e})")
                    print(f"  0x{cmd_code:02X}+0x{idx:02X}: write failed — stopping")
                    break

                await asyncio.sleep(0.5)

                if reassembler.packets:
                    for resp_cmd, payload in reassembler.packets:
                        ascii_runs = has_ascii_text(payload)
                        has_name = any("VS" in r or "AS" in r for r in ascii_runs)

                        log(f"CMD 0x{cmd_code:02X}+0x{idx:02X} → resp 0x{resp_cmd:02X}, {len(payload)} bytes")
                        if ascii_runs:
                            log(f"  ASCII: {ascii_runs}")
                        log(hex_dump(payload))
                        log("")

                        if has_name:
                            names_found.append((cmd_code, resp_cmd, payload))
                            print(f"  *** 0x{cmd_code:02X}+0x{idx:02X}: FOUND NAME! ascii={ascii_runs} ***")

                        if has_name or (len(payload) > 4 and ascii_runs):
                            interesting.append(("param", cmd_code, resp_cmd, payload, idx))
                else:
                    log(f"CMD 0x{cmd_code:02X}+0x{idx:02X} — no response\n")

            print(f"  0x{cmd_code:02X} with payloads 0x00-0x03: done")

        # SUMMARY
        print(f"\n{'='*50}")
        if names_found:
            print(f"  FOUND {len(names_found)} RESPONSE(S) WITH USER NAMES!")
            for cmd_code, resp_cmd, payload in names_found:
                ascii_runs = has_ascii_text(payload)
                print(f"    CMD 0x{cmd_code:02X} → {ascii_runs}")
        else:
            print(f"  User names NOT found in scanned range")

        print(f"  Responded: {responded_count} | Interesting: {len(interesting)}")
        print(f"  Full details in: {LOG_PATH}")
        print(f"{'='*50}")

        # Log summary too
        log(f"\n{'='*60}")
        log(f"SUMMARY")
        log(f"{'='*60}")
        log(f"Responded: {responded_count}")
        log(f"Silent: {silent_count}")
        log(f"Names found: {len(names_found)}")
        log(f"Interesting (has ASCII text): {len(interesting)}")
        if interesting:
            log(f"\nINTERESTING RESPONSES:")
            for item in interesting:
                if item[0] == "scan":
                    _, cmd_code, resp_cmd, payload = item
                    label = f"CMD 0x{cmd_code:02X}"
                elif item[0] == "param":
                    _, cmd_code, resp_cmd, payload, idx = item
                    label = f"CMD 0x{cmd_code:02X}+0x{idx:02X}"
                log(f"\n  {label} → 0x{resp_cmd:02X}, {len(payload)} bytes:")
                log(f"  ASCII: {has_ascii_text(payload)}")
                log(hex_dump(payload))

    finally:
        try:
            await client.disconnect()
        except Exception:
            pass

    logf.close()
    print(f"\nDone.")


if __name__ == "__main__":
    asyncio.run(main())
