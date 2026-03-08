# Viatom LP-BP2W BLE Protocol — Complete Reference

Reverse-engineered from the Lepu BLE SDK (blepro AAR decompilation) and validated
by exhaustive direct BLE testing on a physical LP-BP2W device, March 2026.

---

## 1. Device Overview

The Viatom LP-BP2W is a consumer blood pressure monitor with BLE connectivity.
It supports single and triple (3x averaged) BP measurements, multi-user profiles,
and on-device storage of measurement history. The device uses the Lepu Medical
BLE Protocol V2, shared across multiple Viatom / Checkme / Lepu branded devices.

Tested device:

- Model string: `32120011`
- Serial number: `2523C00812`
- Hardware version: `66` (0x42)
- Firmware version: `1.1`
- BLE address (test unit): `46:22:4E:7C:B4:D8`
- BLE local names: `BP2`, `BP2A`, `BP2W`, `Checkme BP2`, `LP-BP2`, `LP-BP2W`, `LP-BP2A`
- Manufacturer data in advertisements: `{62286: '00'}` (static, never changes)

---

## 2. BLE Service & Characteristics

| Role    | UUID                                     |
|---------|------------------------------------------|
| Service | `14839ac4-7d7e-415c-9a42-167340cf2339`   |
| Write   | `8b00ace7-eb0b-49b0-bbe9-9aee0a26e1a3`   |
| Notify  | `0734594a-a8e7-4b1a-a6b1-cd5243059a57`   |

Communication is request/response over a single GATT service. Commands are written
to the Write characteristic; responses arrive as notifications on the Notify
characteristic. BLE notifications may arrive fragmented across multiple MTU-sized
chunks and must be reassembled before parsing.

---

## 3. Packet Format (Lepu Protocol V2)

Every TX and RX message uses the same frame format:

```
Offset  Size  Field
------  ----  -----
  0       1   Header       — always 0xA5
  1       1   CMD          — command type byte
  2       1   ~CMD         — bitwise NOT of CMD (validation)
  3       1   Direction    — 0x00 for TX (host to device), 0x01 for RX (device to host)
  4       1   SEQ          — sequence counter (0-254, wraps)
  5       2   LENGTH       — payload length, uint16 little-endian
  7       N   PAYLOAD      — variable-length payload (N = LENGTH)
  7+N     1   CRC8         — CRC-8/CCITT over bytes [0 .. 6+N]
```

### 3.1 CRC Algorithm

**CRC-8/CCITT** with polynomial 0x07, initial value 0x00.

This is **NOT** CRC-8/MAXIM (which uses 0x31). Getting the polynomial wrong was the
root cause of all initial communication failures during reverse engineering. The CRC
is computed over the **entire packet** from byte 0 (header) through the last payload
byte — everything except the CRC byte itself.

The lookup table (from `BleCRC.java` in the Lepu SDK):

```
00 07 0E 09 1C 1B 12 15  38 3F 36 31 24 23 2A 2D
70 77 7E 79 6C 6B 62 65  48 4F 46 41 54 53 5A 5D
E0 E7 EE E9 FC FB F2 F5  D8 DF D6 D1 C4 C3 CA CD
90 97 9E 99 8C 8B 82 85  A8 AF A6 A1 B4 B3 BA BD
C7 C0 C9 CE DB DC D5 D2  FF F8 F1 F6 E3 E4 ED EA
B7 B0 B9 BE AB AC A5 A2  8F 88 81 86 93 94 9D 9A
27 20 29 2E 3B 3C 35 32  1F 18 11 16 03 04 0D 0A
57 50 59 5E 4B 4C 45 42  6F 68 61 66 73 74 7D 7A
89 8E 87 80 95 92 9B 9C  B1 B6 BF B8 AD AA A3 A4
F9 FE F7 F0 E5 E2 EB EC  C1 C6 CF C8 DD DA D3 D4
69 6E 67 60 75 72 7B 7C  51 56 5F 58 4D 4A 43 44
19 1E 17 10 05 02 0B 0C  21 26 2F 28 3D 3A 33 34
4E 49 40 47 52 55 5C 5B  76 71 78 7F 6A 6D 64 63
3E 39 30 37 22 25 2C 2B  06 01 08 0F 1A 1D 14 13
AE A9 A0 A7 B2 B5 BC BB  96 91 98 9F 8A 8D 84 83
DE D9 D0 D7 C2 C5 CC CB  E6 E1 E8 EF FA FD F4 F3
```

### 3.2 Sequence Counter

Starts at 1, increments per command sent, wraps at 254 back to 0. The device does
not validate the sequence number (any value is accepted), but matching sequences
between request and response helps correlate them.

---

## 4. Command Reference (Complete 0x00-0xFF Scan)

All 256 command codes were tested against a live LP-BP2W device. Each command is
classified by its observable side effects.

### 4.1 Safety Classifications

- **SAFE** — No visible side effect on the device. Screen does not change, no icons
  appear, user is not disturbed. Can be polled freely.
- **VISUAL** — Shows a transfer icon on the device screen. The icon auto-resolves
  when the BLE connection is closed (disconnect or FILE_END command).
- **DANGER** — Triggers cuff inflation (starts a BP measurement!), device reset,
  or factory reset. Must NEVER be sent in production code.
- **NO RESPONSE** — Command is silently ignored by the device.

### 4.2 SAFE Commands

| CMD    | Name             | Response Size | Description |
|--------|------------------|---------------|-------------|
| `0x00` | GET_INFO         | 40 bytes      | LP-BP2W device registers. Contains device state at byte[39], active user_id at ~byte[27]. The most important command for monitoring. |
| `0x06` | GET_CONFIG       | 9 bytes       | Device configuration. Byte[0] mirrors the device state from CMD 0x00 byte[39]. |
| `0x08` | RT_DATA          | 32 bytes      | Real-time data. Pushed by device during active measurement. Contains status, battery, cuff pressure, and final BP results. |
| `0x0B` | unknown          | 0 bytes       | Returns empty payload. Purpose unknown. |
| `0x0C` | unknown          | 0 bytes       | Returns empty payload. Purpose unknown. |
| `0x0D` | unknown          | 2 bytes       | Returns `00 00`. Purpose unknown. |
| `0x13` | WIFI_CREDENTIALS | 63 bytes      | Returns WiFi SSID, password, and cloud server URL in a TLV-like structure. |
| `0x21` | unknown          | varies        | Responded in initial scan. Purpose unknown. |
| `0x22` | unknown          | varies        | Responded in initial scan. Purpose unknown. |
| `0x23` | unknown          | varies        | Responded in initial scan. Purpose unknown. |
| `0x26` | GET_BLE_MAC      | 7 bytes       | BLE MAC address in reversed byte order. |
| `0x27` | unknown          | 0 bytes       | Returns empty payload. Purpose unknown. |
| `0x28` | unknown          | 1 byte        | Purpose unknown. |
| `0x29` | unknown          | 0 bytes       | Returns empty payload. Purpose unknown. |
| `0x30` | GET_BATTERY      | 4 bytes       | Battery status and voltage. See section 8. |
| `0x31` | RT_STATE         | 4 bytes       | **USELESS** — returns random garbage values each call. Not reliable. |
| `0x32` | RT_PRESSURE      | 4 bytes       | Real-time cuff pressure (only meaningful during measurement). |
| `0x33` | GET_LP_CONFIG    | 4 bytes       | LP-series-specific configuration. |
| `0xE1` | GET_DEVICE_INFO  | 60 bytes      | Structured device info with model, serial, firmware. The preferred info command. See section 7. |
| `0xEA` | unknown          | 0 bytes       | Returns empty payload. Purpose unknown. |
| `0xEC` | SYNC_TIME        | 0 bytes       | Sets the device clock. Accepts a 7-byte time payload. See section 9. |
| `0xF1` | READ_FILE_LIST   | 33 bytes      | Lists files on device. Returns filenames only — no sizes or record counts. Identical before and after measurement. Cannot be used for new-record detection. |
| `0xF5` | unknown          | 0 bytes       | Returns empty payload. Purpose unknown. |
| `0xF6` | unknown          | 0 bytes       | Returns empty payload. Purpose unknown. |
| `0xF7` | unknown          | 4 bytes       | Purpose unknown. |
| `0xF8` | unknown          | 0 bytes       | Returns empty payload. Purpose unknown. |

### 4.3 VISUAL Commands (File Transfer)

These commands show a transfer icon on the device screen. The icon disappears
automatically when the BLE connection closes or when READ_FILE_END is sent.

| CMD    | Name             | Payload        | Description |
|--------|------------------|----------------|-------------|
| `0xF2` | READ_FILE_START  | 20-byte null-padded filename | Begins file read. Response: 4-byte LE file size. |
| `0xF3` | READ_FILE_DATA   | 4-byte LE offset | Requests a data chunk at the given offset. Response: raw file data. |
| `0xF4` | READ_FILE_END    | none           | Ends file transfer. Clears transfer icon. |

File transfer protocol:
1. Send `0xF2` with filename -> receive file size (uint32 LE)
2. Send `0xF3` with offset 0 -> receive data chunk
3. Repeat `0xF3` with incrementing offset until all data received
4. Send `0xF4` to close -> receive ACK

If the device is actively measuring when `0xF2` is sent, the device silently
ignores the command (no response). This causes a timeout on the host side.
The measurement is NOT interrupted — this is safe.

### 4.4 DANGER Commands

**These must NEVER be sent in production code.**

| CMD    | Effect |
|--------|--------|
| `0x04` | Factory reset — erases all stored data and settings |
| `0x09` | Starts BP measurement — cuff inflates immediately |
| `0x0A` | Starts BP measurement — mislabeled "ECHO" in the SDK decompilation, but actually starts measurement on LP-BP2W |
| `0x24` | Device powers off + triggers cuff inflation |
| `0x25` | Device powers off + triggers cuff inflation (may be caused by 0x24 cascading) |
| `0x39` | Triggers cuff inflation + BLE disconnect |
| `0xE2` | Device reset (power cycle) |
| `0xE3` | Factory reset (standard command path) |

### 4.5 No Response Commands

The following ranges returned no response when tested:

`0x01-0x03`, `0x05`, `0x07`, `0x0E-0x10`, `0x14-0x20`, `0x2A-0x2F`,
`0x34-0x38`, `0x3A-0xE0`, `0xE4-0xE9`, `0xEB`, `0xED-0xF0`, `0xF9-0xFF`

### 4.6 LP-BP2W Specific vs Standard Commands

Two command sets work on LP-BP2W, both from the Lepu SDK:

1. **LP-BP2W specific** (from decompiled `iffb.class` in blepro AAR):
   `0x00`, `0x04`, `0x06`, `0x08`, `0x09`, `0x0A`, `0x11`, `0x12`, `0x13`
2. **Standard BP2** (from `UniversalBleCmd.java` in LepuBle):
   `0xE1`, `0xE2`, `0xE3`, `0xEC`, `0xF1`-`0xF8`

Both sets are fully functional on this device.

---

## 5. Device State Machine (CMD 0x00 byte[39])

The most important discovery for automation: byte 39 of the CMD 0x00 response
contains the current device state. This is identical to CMD 0x06 byte[0].

Polling CMD 0x00 is **completely invisible** to the user — no screen change, no
icons, no side effects of any kind.

### 5.1 Single Measurement Lifecycle

```
IDLE(3) -> MEASURING(4) -> RESULT(5) -> IDLE(3)
                                  ^
                                  |
                          user presses button
```

| State | Value | Description |
|-------|-------|-------------|
| IDLE  | 3     | Home screen. No measurement in progress. |
| MEASURING | 4 | Cuff is inflated, BP reading in progress. |
| RESULT | 5    | Result displayed on screen. Remains until user presses a button to dismiss. |

### 5.2 Triple Measurement Lifecycle

The device has a "triple measurement" mode that takes 3 sequential BP readings
with rest pauses between them, then displays the averaged result.

```
IDLE(3) -> INFLATING(15) -> PAUSE(16) -> INFLATING(15) -> PAUSE(16) -> INFLATING(15) -> RESULT(17) -> IDLE(3)
           1st reading       rest         2nd reading       rest         3rd reading       average       user dismisses
```

| State | Value | Description |
|-------|-------|-------------|
| TRIPLE-INFLATING | 15 | Cuff inflated for one of the 3 readings. Same role as state 4 in single mode. |
| TRIPLE-PAUSE | 16 | Rest period between sequential readings. |
| TRIPLE-RESULT | 17 | Averaged result displayed on screen. Same role as state 5 in single mode. |

### 5.3 State-Based Automation Strategy

For Home Assistant or any polling-based integration:

- Keep a persistent BLE connection (do not connect/disconnect per poll)
- Send CMD 0x00 every ~5 seconds
- Read byte[39] of the response
- Use the `saw_activity` / `fetched_this_cycle` flag pattern (see section 14.2)

State-based decisions:

- **State 4, 15, 16** (busy) → measurement in progress, set `saw_activity = True`, wait
- **State 5 or 17** (result) → result on screen, download `bp2nibp.list` if not `fetched_this_cycle`
- **State 3** (idle) after activity → user dismissed result quickly, download if `saw_activity` and not `fetched_this_cycle`
- **Transition 5/17 → 3** → reset both flags (ready for next measurement cycle)
- **State 3** for 120s with no activity → disconnect to free BLE proxy slot

This avoids showing the transfer icon unnecessarily, handles fast result dismissal,
multiple back-to-back measurements, and triple measurement mode correctly.

---

## 6. File System

### 6.1 Files on Device

Only two files exist on the LP-BP2W:

| Filename        | Content |
|-----------------|---------|
| `bp2nibp.list`  | Blood pressure measurement records |
| `bp2ecg.list`   | ECG measurement records |

`user.list` does **NOT** exist on this device model (tested explicitly).

### 6.2 BP Record File Format (bp2nibp.list)

The file has a fixed 10-byte header followed by 37-byte records:

```
File layout:
  [0-9]     Header (10 bytes)
            byte 0: version (?)
            byte 1: user count (?)
            bytes 2-9: zeros

  [10+]     Records (37 bytes each, circular buffer order)
```

#### Record Layout (37 bytes)

```
Offset  Size    Type       Field
------  ----    ----       -----
  0       4     uint32 LE  timestamp (Unix seconds)
  4       4     uint32 LE  user_id (Viatom cloud account ID)
  8       1     uint8      status_flag (0x00 = normal, 0x01 = irregular heartbeat)
  9       4     —          reserved (zeros)
  13      2     uint16 LE  systolic (mmHg)
  15      2     uint16 LE  diastolic (mmHg)
  17      2     uint16 LE  MAP — mean arterial pressure (mmHg)
                           SDK misleadingly labels this "pulse"
  19      2     uint16 LE  HR — heart rate (bpm), shown on device screen
  21      16    —          padding (zeros)
```

Notes:
- **MAP (offset [17-18])**: This is the measured mean arterial pressure in mmHg.
  The SDK source code misleadingly labels this field "pulse", but it is NOT a
  pulse rate (bpm). It is a pressure value (mmHg). Confirmed by comparing raw
  values against the device screen and known MAP ranges.
- **HR (offset [19-20])**: This is the heart rate in bpm, matching what the
  device displays on screen.
- **Pulse Pressure**: PP = systolic − diastolic. This is NOT stored in the
  record; it is a calculated value. Confirmed: PP matches exactly across all
  historical records.
- Records are stored in circular buffer order, not necessarily chronological.
  Sort by timestamp when processing.
- Empty record slots have systolic/diastolic all set to 0; skip these.
- The `status_flag` at byte[8] indicates irregular heartbeat when set to `1`.
  This was initially inverted in the SDK decompilation (checking `== 0` instead
  of `== 1`).

### 6.3 Record Deduplication

When re-downloading the file across multiple connections, use a composite key
of `(timestamp, systolic, diastolic, map)` to deduplicate records. The file
always returns ALL stored records, not just new ones.

---

## 7. CMD 0xE1 — GET_DEVICE_INFO (60 bytes)

This is the preferred command for obtaining structured device metadata.

### Response Layout

```
Offset  Size  Field
------  ----  -----
  0       1   hardware_version (e.g., 0x42 = 66)
  1       2   unknown / status
  3       1   software_version_major
  4       1   software_version_minor
  5       4   unknown
  9       8   model_string (ASCII, null-padded) — e.g., "32120011"
  17      1   sub-version / build number
  18      2   padding
  20      4   unknown (CRC or internal ID)
  24      2   device_clock_year (uint16 LE) — NOT firmware build date
  26      1   device_clock_month
  27      1   device_clock_day
  28      1   device_clock_hour
  29      1   device_clock_minute
  30      1   device_clock_second
  31      6   unknown / padding
  37      1   serial_number_length (e.g., 0x0A = 10)
  38      N   serial_number (ASCII) — e.g., "2523C00812"
  38+N    ..  padding (zeros to 60 bytes)
```

Important: bytes [24-30] contain the device's current clock (set by SYNC_TIME),
**NOT** the firmware build date. The clock resets if the device powers off.

### Example Raw Response

```hex
42 00 01 01 01 00 00 01 00 33 32 31 32 30 30 31 31
05 00 00 22 86 03 01 EA 07 03 07 17 06 37 02 01
00 00 00 00 0A 32 35 32 33 43 30 30 38 31 32 00...
```

---

## 8. CMD 0x30 — GET_BATTERY (4 bytes)

### Response Layout

```
Offset  Size  Field
------  ----  -----
  0       1   status_flags (e.g., 0xCE)
  1       1   unknown (e.g., 0x0A)
  2       2   voltage_mV (uint16 LE)
```

The voltage is in millivolts. Observed value: `0x0E83` = 3715 mV.

Battery percentage estimation (typical Li-ion curve):
- 3000 mV = 0%
- 3300 mV = 10%
- 3600 mV = 50%
- 3800 mV = 80%
- 4200 mV = 100%

Linear approximation: `percentage = clamp((voltage_mV - 3000) * 100 / 1200, 0, 100)`

---

## 9. CMD 0xEC — SYNC_TIME

Sets the device's internal clock. The device returns an empty ACK.

### Payload Format (7 bytes)

```
Offset  Size    Type       Field
------  ----    ----       -----
  0       2     uint16 LE  year
  2       1     uint8      month (1-12)
  3       1     uint8      day (1-31)
  4       1     uint8      hour (0-23)
  5       1     uint8      minute (0-59)
  6       1     uint8      second (0-59)
```

---

## 10. CMD 0x08 — RT_DATA (Real-Time Data)

Pushed by the device as notifications during active measurement. Not a
request/response command — the device sends these automatically.

### Payload Layout

```
Offset  Size    Field
------  ----    -----
  0       1     data_type
                  0 = BP measuring (cuff inflated, reading in progress)
                  1 = BP measurement end (result available)
                  2 = ECG measuring
                  3 = ECG end
  1       1     battery_status
  2       1     battery_level (percentage)
  3+      ..    type-specific data (see below)
```

#### Type 0: BP Measuring

```
  3       2     cuff_pressure (uint16 LE, mmHg)
```

#### Type 1: BP Measurement End

```
  3       2     systolic (uint16 LE, mmHg)
  5       2     diastolic (uint16 LE, mmHg)
  7       2     MAP — mean arterial pressure (uint16 LE, mmHg)
  9       2     HR — heart rate (uint16 LE, bpm) — SDK labels "pulse"
```

---

## 11. CMD 0x00 — GET_INFO (40 bytes)

The LP-BP2W specific info command. Returns raw device registers.

### Partially Decoded Layout

```
Offset  Size  Field
------  ----  -----
  0       8   unknown (timestamps / counters)
  8       4   unknown
  12      4   unknown
  16      4   unknown
  20      4   unknown
  24      1   battery_level (or charging status flag)
  25      1   battery_status
  26      1   unknown
  27      4   active_user_id (uint32 LE) — currently selected user's Viatom cloud ID
  31      8   unknown
  39      1   **device_state** — the key byte for automation (see section 5)
```

### Example Raw Response

```hex
10 DB 11 00 6A C2 11 00  D4 19 00 00 C8 00 40 05
3A 68 CD 03 6D 67 C8 00  01 01 00 D7 53 03 00 14
00 00 00 00 00 00 00 03
                     ^^
                     byte[39] = 0x03 = IDLE
```

---

## 12. CMD 0x13 — WIFI_CREDENTIALS (63 bytes)

Returns the device's stored WiFi configuration in a TLV-like structure:

- SSID (null-padded)
- Password (null-padded)
- Cloud server URL

This is used by the device for direct cloud sync (without a phone). Not needed
for Home Assistant integration.

---

## 13. User ID System

### 13.1 User IDs Are Opaque Cloud Integers

User IDs stored in BP records are **Viatom cloud account IDs** — sequential
integers assigned during account creation. They have absolutely NO encoding
relationship to user names. You cannot derive a name from an ID.

Known mappings from the test device:
- `218071` -> "AS"
- `278170` -> "VS"
- `278176` -> "Abcde Efg" (test user)

### 13.2 User Names Are NOT Accessible via BLE

User names are stored in the device's internal flash memory. They are written
by the Viatom mobile app during user setup and rendered by the device firmware
for screen display.

All 256 BLE commands were exhaustively tested with and without payloads.
**No command returns user names.** The only way to map user IDs to names is
manual configuration (e.g., an options flow in Home Assistant).

### 13.3 Active User ID

The currently selected user's ID can be read from CMD 0x00 response at
approximately offset 27 (4 bytes, uint32 LE).

---

## 14. BLE Connection Strategy

### 14.1 Windows / WinRT Quirks

The following issues were discovered and validated through extensive testing
on Windows with the Bleak BLE library (WinRT backend):

1. **Do NOT pass `timeout=` to the `BleakClient` constructor.** This breaks the
   WinRT backend. Use `asyncio.wait_for()` around `client.connect()` instead.

2. **2-second post-connect stabilization is required.** After `client.connect()`
   returns, GATT services need time to be discovered by WinRT. Without this
   delay, `start_notify()` fails because characteristic handles are not yet valid.
   2 seconds is the validated minimum; 1 second causes intermittent failures.

3. **BleakScanner gets permanently stuck after a failed connection.** Use direct
   `BleakClient(address).connect()` instead of scanning + connecting.

4. **Rapid connect/disconnect cycling causes ~25% subscribe failures.** The WinRT
   GATT client caches service handles. Connecting and disconnecting every 10
   seconds overwhelms the cache, causing stale handles and `start_notify()`
   failures. The fix is to use **persistent connections**: connect once, subscribe
   once, and keep the connection alive for the duration of monitoring.

### 14.2 Persistent Connection Pattern (Recommended)

Three-phase algorithm validated by direct BLE testing and implemented in
the Home Assistant coordinator:

```
PHASE 1 — CONNECTION
  Advertisement seen → connect → wait 2s (stabilization) → subscribe
  → housekeeping (battery, device info, time sync)
  → baseline file fetch (catches measurements taken while disconnected)

PHASE 2 — POLL LOOP (CMD 0x00 every ~5s)
  Track two flags: saw_activity, fetched_this_cycle

  State 4/15/16 (busy):   saw_activity = True, wait
  State 5/17 (result):    fetch file if not fetched_this_cycle, then set fetched_this_cycle
  State 3 (idle):         fetch file if saw_activity and not fetched_this_cycle
                          (handles fast result dismissal)
  Transition 5/17 → 3:   reset both flags (ready for next measurement cycle)

PHASE 3 — DISCONNECT
  Idle timeout (120s of continuous state 3 with no activity) → disconnect
  Connection lost → clean up, wait for next advertisement
```

Key behaviors:
- Baseline file fetch on every new connection catches offline measurements
- `saw_activity` flag detects when user dismisses result before we poll state 5/17
- Cycle reset on 5/17→3 transition handles multiple back-to-back measurements
- 120s idle timeout frees the BLE proxy slot for other devices

This eliminates subscribe failures entirely, handles all measurement modes
(single, triple, multiple back-to-back), and minimizes BLE overhead.

### 14.3 ESPHome BLE Proxy Compatibility

The connection pattern works through ESPHome BLE proxies. The 2-second
stabilization window also benefits proxy connections where there is additional
latency between the ESP32 and the HA host.

### 14.4 Measurement Safety

File download commands (`0xF2`/`0xF3`/`0xF4`) are **safe to send** while the
device is measuring. The device simply ignores `FILE_START` during an active
measurement (no response, causing a timeout). The measurement is NOT interrupted.
This was explicitly tested.

---

## 15. Measurement Detection Methods

### 15.1 Preferred: Device State Polling (CMD 0x00 byte[39])

Poll CMD 0x00 periodically. When byte[39] transitions to 5 (single result) or
17 (triple result), a new measurement is available. Download the file to retrieve
the record.

Advantages: invisible to user, no transfer icon, low BLE traffic.

### 15.2 Legacy: File Download Timeout

If using the old connect-per-cycle approach, attempt to download the file each
cycle. If the device is measuring, `FILE_START` will time out (device ignores it).
If not measuring, the file downloads normally.

Disadvantage: shows the transfer icon on every connection.

### 15.3 NOT Usable: RT_STATE (CMD 0x31)

Returns random garbage values on every call. Completely unreliable.

### 15.4 NOT Usable: Advertisement Data

The manufacturer data in BLE advertisements (`{62286: '00'}`) is completely
static. It never changes regardless of device state, measurements, or any
other condition.

### 15.5 NOT Usable: READ_FILE_LIST (CMD 0xF1)

Returns only 17 bytes per file containing the filename. Does NOT include file
sizes or record counts. The response is identical before and after a measurement.

---

## 16. CRC-8/CCITT Implementation

For reference, here is the complete CRC calculation in Python:

```python
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
```

---

## 17. Packet Reassembly

BLE notifications are limited by MTU (typically 20 bytes). A single Lepu packet
can span multiple notifications. The reassembler must:

1. Buffer incoming notification data
2. Scan for the 0xA5 header byte
3. Validate cmd/~cmd match at bytes [1] and [2]
4. Read the 2-byte length field at bytes [5-6]
5. Wait until `7 + length + 1` bytes are available
6. Verify CRC over bytes [0 .. 6+length]
7. Dispatch the complete packet and continue scanning the buffer

Reject packets with payload length > 2048 bytes as implausible (likely a
false header match).

---

## 18. SDK Source References

The protocol was decoded from the following sources in the Lepu BLE SDK:

| Source File | Contents |
|-------------|----------|
| `iffb.class` (blepro AAR) | LP-BP2W specific command codes and file handling |
| `UniversalBleCmd.java` (LepuBle) | Standard BP2 command codes |
| `Bp2BleInterface.kt` | RT_DATA parsing, device status codes |
| `Bp2BleCmd.java` | Command builders for standard BP2 commands |
| `BleCRC.java` | CRC-8/CCITT lookup table and algorithm |

---

## 19. Pitfalls and Lessons Learned

1. **CRC polynomial**: CRC-8/CCITT (0x07), NOT CRC-8/MAXIM (0x31). Getting this
   wrong produces valid-looking but rejected packets.

2. **CMD 0x0A is NOT echo**: The SDK decompilation labels this as "ECHO", but on
   LP-BP2W it starts a blood pressure measurement (cuff inflates immediately).

3. **SDK "pulse" is actually MAP**: The field at record offset [17-18] is labeled
   "pulse" in the SDK source code, but it is actually MAP (mean arterial pressure)
   in mmHg — NOT a pulse rate in bpm. The field at [19-20] is the actual heart
   rate (bpm) shown on the device screen. Pulse pressure (PP = sys − dia) is
   calculated, not stored.

4. **status_flag inversion**: The irregular heartbeat flag at record byte[8] was
   inverted in some SDK code (`== 0` for irregular). The correct check is `== 1`.

5. **user.list doesn't exist**: Some SDK paths reference a `user.list` file for
   multi-user management. This file does not exist on LP-BP2W.

6. **RT_STATE (0x31) is garbage**: Returns random values each call. Do not use.

7. **Advertisements are static**: manufacturer_data never changes. Cannot be used
   for state detection.

8. **READ_FILE_LIST has no sizes**: Only returns filenames. Cannot detect new records.

9. **Device clock bytes in CMD 0xE1 are NOT firmware date**: Bytes [24-30] in the
   GET_DEVICE_INFO response contain the device's current clock (set by SYNC_TIME),
   not the firmware build date.

10. **Windows BLE needs persistent connections**: Rapid connect/disconnect cycling
    causes ~25% subscribe failures due to stale GATT service cache in WinRT.
