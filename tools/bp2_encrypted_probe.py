"""
BP2 Encrypted BLE Probe — Tests AES-encrypted Lepu Protocol V2 for LP-BP2W.

KEY DISCOVERIES from reverse-engineering lepu-blepro-1.3.0.aar:
1. LP-BP2W uses AES/ECB/PKCS5Padding encryption on payloads
2. AES key = MD5("lepucloud") = c2a7cf50dafed885a8f8f7eac44335f3
3. CRC is CRC-8/CCITT (poly 0x07), NOT CRC-8/MAXIM!
4. LP-BP2W has DIFFERENT command bytes from standard BP2:
   - LP-BP2W: GET_INFO=0x00, GET_CONFIG=0x06, RT_DATA=0x30, etc.
   - Std BP2:  GET_INFO=0xE1, SYNC_TIME=0xEC, FILE_LIST=0xF1, etc.
5. Server: 203.195.204.99:7200 (WiFi cloud endpoint)

Usage:
    pip install bleak pycryptodome
    python bp2_encrypted_probe.py [DEVICE_ADDRESS]
"""

import asyncio
import hashlib
import sys
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError

# Device address
DEFAULT_ADDRESS = "46:22:4E:7C:B4:D8"

# BLE UUIDs
SERVICE_UUID = "14839ac4-7d7e-415c-9a42-167340cf2339"
WRITE_UUID   = "8b00ace7-eb0b-49b0-bbe9-9aee0a26e1a3"
NOTIFY_UUID  = "0734594a-a8e7-4b1a-a6b1-cd5243059a57"

# AES encryption key: MD5("lepucloud")
AES_KEY = hashlib.md5(b"lepucloud").digest()  # 16 bytes

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
    """CRC-8/CCITT as used by Lepu BLE protocol.
    Calculated over all bytes EXCEPT the last (CRC) byte.
    """
    crc = 0
    for b in data:
        crc = CRC8_TABLE[0xFF & (crc ^ b)]
    return crc


# ---- LP-BP2W Command bytes (from iffb.class) ----
CMD_GET_INFO        = 0x00
CMD_FACTORY_RESET   = 0x04
CMD_GET_CONFIG      = 0x06
CMD_RT_DATA         = 0x08  # or 0x30 in newer firmware
CMD_SWITCH_STATE    = 0x09
CMD_ECHO            = 0x0B
CMD_GET_FILE_LIST   = 0x11
CMD_READ_FILE_START = 0x12
CMD_READ_FILE_DATA  = 0x13
CMD_RT_DATA_V2      = 0x30
CMD_RT_STATE        = 0x31
CMD_RT_PRESSURE     = 0x32
CMD_CALIBRATION     = 0x33

# Standard BP2 commands (might also work)
CMD_STD_GET_INFO      = 0xE1
CMD_STD_SYNC_TIME     = 0xEC
CMD_STD_FILE_LIST     = 0xF1


def aes_encrypt(plaintext: bytes) -> bytes:
    """AES/ECB/PKCS5Padding encrypt."""
    if len(plaintext) == 0:
        return b""
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, AES.block_size))


def aes_decrypt(ciphertext: bytes) -> bytes:
    """AES/ECB/PKCS5Padding decrypt."""
    if len(ciphertext) == 0:
        return b""
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    try:
        return unpad(cipher.decrypt(ciphertext), AES.block_size)
    except ValueError:
        return cipher.decrypt(ciphertext)


def build_packet(cmd: int, payload: bytes = b"", encrypt: bool = False, seq: int = 0) -> bytes:
    """Build a Lepu Protocol V2 packet.

    Format: A5 CMD ~CMD SEQ_LO SEQ_HI LEN_LO LEN_HI [PAYLOAD] CRC8

    Note: SeqNo byte order from Bp2BleCmd.java: [3]=0x00, [4]=seqNo
    CRC is calculated over bytes [0..N-2] (everything except the CRC byte itself).
    """
    if encrypt and len(payload) > 0:
        payload = aes_encrypt(payload)

    pkt = bytearray()
    pkt.append(0xA5)                    # [0] header
    pkt.append(cmd & 0xFF)              # [1] command
    pkt.append(~cmd & 0xFF)             # [2] ~command
    pkt.append(0x00)                    # [3] seq high (always 0x00 in Bp2BleCmd.java)
    pkt.append(seq & 0xFF)              # [4] seq low
    length = len(payload)
    pkt.append(length & 0xFF)           # [5] length low
    pkt.append((length >> 8) & 0xFF)    # [6] length high
    pkt.extend(payload)                 # [7..7+len-1] payload

    # CRC-8/CCITT over bytes [0..N-2]
    crc = crc8_ccitt(bytes(pkt))
    pkt.append(crc)                     # [N-1] CRC
    return bytes(pkt)


def ts():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


async def main():
    address = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ADDRESS
    print(f"[{ts()}] === BP2 Encrypted BLE Probe ===")
    print(f"[{ts()}] AES Key: {AES_KEY.hex()}")
    print(f"[{ts()}] CRC: CRC-8/CCITT (poly 0x07)")
    print(f"[{ts()}] Scanning for {address}...")

    device = await BleakScanner.find_device_by_address(address, timeout=15.0)
    if not device:
        print(f"[{ts()}] Device not found! Make sure BP2 is awake.")
        return

    print(f"[{ts()}] Found: {device.name} ({device.address})")

    notifications = []
    seq_counter = [0]

    def notify_handler(_sender, data):
        raw = bytes(data)
        notifications.append(raw)
        print(f"\n  [{ts()}] *** NOTIFICATION ({len(raw)}b): {raw.hex()}")

        # Try to parse as Lepu V2
        if len(raw) >= 8 and raw[0] == 0xA5:
            cmd = raw[1]
            cmd_inv = raw[2]
            seq = raw[3] | (raw[4] << 8)
            length = raw[5] | (raw[6] << 8)
            content = raw[7:7+length] if 7+length <= len(raw) else raw[7:-1]
            print(f"  [{ts()}]   Lepu V2: CMD=0x{cmd:02X} ~CMD_OK={((cmd ^ cmd_inv) & 0xFF) == 0xFF} seq={seq} len={length}")
            print(f"  [{ts()}]   Content ({len(content)}b): {content.hex()}")

            # Verify CRC
            expected_crc = crc8_ccitt(raw[:-1])
            actual_crc = raw[-1]
            print(f"  [{ts()}]   CRC: actual=0x{actual_crc:02X} expected=0x{expected_crc:02X} {'OK' if actual_crc == expected_crc else 'MISMATCH'}")

            # Try AES decrypt on content
            if len(content) > 0 and len(content) % 16 == 0:
                try:
                    decrypted = aes_decrypt(content)
                    print(f"  [{ts()}]   AES Decrypted ({len(decrypted)}b): {decrypted.hex()}")
                    # Try as ASCII too
                    try:
                        ascii_text = decrypted.decode('ascii', errors='replace')
                        if any(c.isalpha() for c in ascii_text):
                            print(f"  [{ts()}]   ASCII: {ascii_text}")
                    except:
                        pass
                except Exception as e:
                    print(f"  [{ts()}]   Decrypt failed: {e}")
        else:
            print(f"  [{ts()}]   (Not Lepu V2 format, or too short)")

    async def send_cmd(client, cmd, payload=b"", encrypt=False, label="", write_mode="both"):
        seq_counter[0] = (seq_counter[0] + 1) % 255
        pkt = build_packet(cmd, payload, encrypt=encrypt, seq=seq_counter[0])
        mode = "ENC" if encrypt else "PLAIN"
        print(f"\n  [{ts()}] >>> {label} CMD=0x{cmd:02X} ({mode}): {pkt.hex()}")
        notifications.clear()

        success = False
        if write_mode in ("response", "both"):
            try:
                await client.write_gatt_char(WRITE_UUID, pkt, response=True)
                print(f"  [{ts()}] Write OK (with-response)")
                success = True
            except BleakError as e:
                if write_mode == "response":
                    print(f"  [{ts()}] Write failed: {e}")
                    return False

        if not success and write_mode in ("no-response", "both"):
            try:
                await client.write_gatt_char(WRITE_UUID, pkt, response=False)
                print(f"  [{ts()}] Write OK (without-response)")
            except BleakError as e:
                print(f"  [{ts()}] Write failed: {e}")
                return False

        await asyncio.sleep(3.0)
        if notifications:
            print(f"  [{ts()}] <<< Got {len(notifications)} notification(s)!")
            return True
        else:
            print(f"  [{ts()}] <<< No notifications")
            return False

    async with BleakClient(device, timeout=20.0) as client:
        print(f"[{ts()}] Connected! MTU={client.mtu_size}")

        # List all services and characteristics
        print(f"\n[{ts()}] === GATT Services ===")
        for service in client.services:
            print(f"  Service: {service.uuid}")
            for char in service.characteristics:
                props = ", ".join(char.properties)
                print(f"    Char: {char.uuid} [{props}] handle={char.handle}")
                for desc in char.descriptors:
                    print(f"      Desc: {desc.uuid} handle={desc.handle}")

        # Try subscribing to notifications — multiple strategies
        notify_subscribed = False

        # Strategy A: Normal start_notify on NOTIFY_UUID
        print(f"\n[{ts()}] Strategy A: start_notify({NOTIFY_UUID})")
        try:
            await client.start_notify(NOTIFY_UUID, notify_handler)
            notify_subscribed = True
            print(f"[{ts()}] Strategy A: SUCCESS")
        except Exception as e:
            print(f"[{ts()}] Strategy A failed: {e}")

        # Strategy B: Try WRITE_UUID for notifications (it might support notify too)
        if not notify_subscribed:
            print(f"\n[{ts()}] Strategy B: start_notify({WRITE_UUID})")
            try:
                await client.start_notify(WRITE_UUID, notify_handler)
                notify_subscribed = True
                print(f"[{ts()}] Strategy B: SUCCESS")
            except Exception as e:
                print(f"[{ts()}] Strategy B failed: {e}")

        # Strategy C: Manual CCCD write for notifications (0x0100)
        if not notify_subscribed:
            print(f"\n[{ts()}] Strategy C: Manual CCCD write (notifications)")
            for char in client.services.characteristics.values() if hasattr(client.services, 'characteristics') else []:
                pass
            # Find CCCD descriptor for NOTIFY_UUID
            notify_char = None
            for service in client.services:
                for char in service.characteristics:
                    if char.uuid == NOTIFY_UUID:
                        notify_char = char
                        break
            if notify_char:
                for desc in notify_char.descriptors:
                    if "2902" in desc.uuid:
                        print(f"  [{ts()}] Found CCCD at handle {desc.handle}")
                        try:
                            await client.write_gatt_descriptor(desc.handle, b"\x01\x00")
                            print(f"  [{ts()}] CCCD notification write OK")
                            notify_subscribed = True
                        except Exception as e:
                            print(f"  [{ts()}] CCCD notification failed: {e}")
                        if not notify_subscribed:
                            try:
                                await client.write_gatt_descriptor(desc.handle, b"\x02\x00")
                                print(f"  [{ts()}] CCCD indication write OK")
                                notify_subscribed = True
                            except Exception as e:
                                print(f"  [{ts()}] CCCD indication failed: {e}")

        # Strategy D: Try Nordic DFU char (8ec90001) for notifications
        NORDIC_NOTIFY = "8ec90001-f315-4f60-9fb8-838830daea50"
        print(f"\n[{ts()}] Strategy D: start_notify on Nordic DFU ({NORDIC_NOTIFY})")
        try:
            await client.start_notify(NORDIC_NOTIFY, notify_handler)
            print(f"[{ts()}] Strategy D: SUCCESS (Nordic DFU notifications)")
        except Exception as e:
            print(f"[{ts()}] Strategy D failed: {e}")

        if not notify_subscribed:
            print(f"\n[{ts()}] WARNING: Could not subscribe to Lepu notifications!")
            print(f"[{ts()}] Will still try sending commands (Nordic DFU may catch responses)")

        await asyncio.sleep(1.5)

        # ===== PHASE 1: Unencrypted with CORRECT CRC =====
        print(f"\n{'='*70}")
        print(f"  PHASE 1: Unencrypted LP-BP2W commands with CRC-8/CCITT")
        print(f"{'='*70}")

        for cmd_val, cmd_name in [
            (CMD_GET_INFO, "LP_GET_INFO"),
            (CMD_ECHO, "LP_ECHO"),
            (CMD_GET_CONFIG, "LP_GET_CONFIG"),
            (CMD_RT_DATA, "LP_RT_DATA"),
        ]:
            got = await send_cmd(client, cmd_val, b"", encrypt=False, label=cmd_name)
            if got:
                print(f"\n  *** {cmd_name} WORKS unencrypted! ***")
                break

        # ===== PHASE 2: Standard BP2 commands =====
        print(f"\n{'='*70}")
        print(f"  PHASE 2: Standard BP2 commands (0xE1, 0xEC)")
        print(f"{'='*70}")

        for cmd_val, cmd_name in [
            (CMD_STD_GET_INFO, "STD_GET_INFO"),
            (CMD_STD_SYNC_TIME, "STD_SYNC_TIME"),
        ]:
            got = await send_cmd(client, cmd_val, b"", encrypt=False, label=cmd_name)
            if got:
                print(f"\n  *** {cmd_name} WORKS! ***")
                break

        # ===== PHASE 3: Encrypted LP-BP2W commands =====
        print(f"\n{'='*70}")
        print(f"  PHASE 3: AES-encrypted LP-BP2W commands")
        print(f"{'='*70}")

        for cmd_val, cmd_name in [
            (CMD_GET_INFO, "LP_GET_INFO(enc)"),
            (CMD_ECHO, "LP_ECHO(enc)"),
            (CMD_GET_CONFIG, "LP_GET_CONFIG(enc)"),
            (CMD_RT_DATA, "LP_RT_DATA(enc)"),
            (CMD_RT_DATA_V2, "LP_RT_DATA_V2(enc)"),
        ]:
            # For ECHO, send some data
            payload = bytes([0x01, 0x02, 0x03, 0x04]) if "ECHO" in cmd_name else b""
            got = await send_cmd(client, cmd_val, payload, encrypt=True, label=cmd_name)
            if got:
                print(f"\n  *** {cmd_name} WORKS! ***")
                break

        # ===== PHASE 4: Encrypted standard BP2 commands =====
        print(f"\n{'='*70}")
        print(f"  PHASE 4: AES-encrypted standard BP2 commands")
        print(f"{'='*70}")

        for cmd_val, cmd_name in [
            (CMD_STD_GET_INFO, "STD_GET_INFO(enc)"),
            (CMD_STD_SYNC_TIME, "STD_SYNC_TIME(enc)"),
        ]:
            time_payload = bytes([
                datetime.now().year & 0xFF, (datetime.now().year >> 8) & 0xFF,
                datetime.now().month, datetime.now().day,
                datetime.now().hour, datetime.now().minute, datetime.now().second,
            ]) if "SYNC" in cmd_name else b""
            got = await send_cmd(client, cmd_val, time_payload, encrypt=True, label=cmd_name)
            if got:
                print(f"\n  *** {cmd_name} WORKS! ***")
                break

        # ===== PHASE 5: Brute-force common command bytes =====
        print(f"\n{'='*70}")
        print(f"  PHASE 5: Quick scan of possible command bytes (both encrypted and plain)")
        print(f"{'='*70}")

        # Try a broader set of commands that might be the ENCRYPT handshake
        for cmd_val in [0x0A, 0x14, 0x55, 0x6A, 0x7A, 0xA0, 0xC0, 0xFE]:
            got = await send_cmd(client, cmd_val, b"", encrypt=False,
                                label=f"CMD_0x{cmd_val:02X}")
            if got:
                print(f"\n  *** CMD 0x{cmd_val:02X} RESPONDED (plain)! ***")
                # Try getting more info
                await send_cmd(client, CMD_GET_INFO, b"", encrypt=False, label="follow-up GET_INFO")
                break

            got = await send_cmd(client, cmd_val, b"", encrypt=True,
                                label=f"CMD_0x{cmd_val:02X}(enc)")
            if got:
                print(f"\n  *** CMD 0x{cmd_val:02X} RESPONDED (enc)! ***")
                break

        # ===== PHASE 6: Write then READ approach =====
        print(f"\n{'='*70}")
        print(f"  PHASE 6: Write command then READ response from char")
        print(f"{'='*70}")

        for cmd_val, cmd_name, enc in [
            (CMD_GET_INFO, "LP_GET_INFO", False),
            (CMD_GET_INFO, "LP_GET_INFO(enc)", True),
            (CMD_STD_GET_INFO, "STD_GET_INFO", False),
            (CMD_STD_GET_INFO, "STD_GET_INFO(enc)", True),
        ]:
            seq_counter[0] = (seq_counter[0] + 1) % 255
            pkt = build_packet(cmd_val, b"", encrypt=enc, seq=seq_counter[0])
            mode = "ENC" if enc else "PLAIN"
            print(f"\n  [{ts()}] Write {cmd_name} ({mode}): {pkt.hex()}")
            try:
                await client.write_gatt_char(WRITE_UUID, pkt, response=True)
                print(f"  [{ts()}] Write OK")
            except BleakError:
                try:
                    await client.write_gatt_char(WRITE_UUID, pkt, response=False)
                    print(f"  [{ts()}] Write OK (no-resp)")
                except BleakError as e:
                    print(f"  [{ts()}] Write failed: {e}")
                    continue

            await asyncio.sleep(1.0)

            # Read from NOTIFY_UUID
            try:
                data = await client.read_gatt_char(NOTIFY_UUID)
                print(f"  [{ts()}] READ {NOTIFY_UUID}: ({len(data)}b) {data.hex()}")
                if len(data) >= 8 and data[0] == 0xA5:
                    cmd = data[1]
                    length = data[5] | (data[6] << 8)
                    content = data[7:7+length]
                    print(f"  [{ts()}]   CMD=0x{cmd:02X} len={length} content={content.hex()}")
                    if len(content) > 0 and len(content) % 16 == 0:
                        try:
                            dec = aes_decrypt(content)
                            print(f"  [{ts()}]   Decrypted: {dec.hex()}")
                        except:
                            pass
            except Exception as e:
                print(f"  [{ts()}] READ NOTIFY failed: {e}")

            # Read from WRITE_UUID
            try:
                data = await client.read_gatt_char(WRITE_UUID)
                print(f"  [{ts()}] READ {WRITE_UUID}: ({len(data)}b) {data.hex()}")
            except Exception as e:
                print(f"  [{ts()}] READ WRITE failed: {e}")

        # ===== PHASE 7: Try pairing first, then retry subscription =====
        print(f"\n{'='*70}")
        print(f"  PHASE 7: Attempt pairing then resubscribe")
        print(f"{'='*70}")
        try:
            paired = await client.pair()
            print(f"  [{ts()}] Pair result: {paired}")
            await asyncio.sleep(1.0)

            # Retry notification subscription after pairing
            print(f"  [{ts()}] Retrying start_notify after pairing...")
            try:
                await client.start_notify(NOTIFY_UUID, notify_handler)
                print(f"  [{ts()}] start_notify SUCCESS after pairing!")

                # Now try commands again
                for cmd_val, cmd_name, enc in [
                    (CMD_GET_INFO, "LP_GET_INFO", False),
                    (CMD_GET_INFO, "LP_GET_INFO(enc)", True),
                ]:
                    await send_cmd(client, cmd_val, b"", encrypt=enc, label=cmd_name)
            except Exception as e:
                print(f"  [{ts()}] start_notify still failed: {e}")
        except Exception as e:
            print(f"  [{ts()}] Pairing failed: {e}")

        # ===== Final: Wait for spontaneous data =====
        print(f"\n{'='*70}")
        print(f"  Waiting 5s for spontaneous notifications...")
        print(f"{'='*70}")
        notifications.clear()
        await asyncio.sleep(5.0)
        if notifications:
            print(f"[{ts()}] Got {len(notifications)} spontaneous notification(s)")

        print(f"\n[{ts()}] === DONE ===")
        print(f"\nSummary:")
        print(f"  AES Key: {AES_KEY.hex()}")
        print(f"  CRC: CRC-8/CCITT (poly 0x07)")
        print(f"  Write UUID: {WRITE_UUID}")
        print(f"  Notify UUID: {NOTIFY_UUID}")


if __name__ == "__main__":
    asyncio.run(main())
