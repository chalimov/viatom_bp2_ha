# 🩺 Viatom BP2 Blood Pressure Monitor — Home Assistant Integration

Custom integration for **Viatom / Checkme BP2, BP2A, BP2W** blood pressure monitors via BLE.

Works through **ESPHome Bluetooth Proxies** — no phone or ViHealth app needed.

## Features

- **Auto-discovery** via BLE service UUID when BP2 powers on
- **Local push** — no polling; reacts to BLE advertisements instantly
- **Real-time results** — captures systolic/diastolic/heart rate when measurement completes
- **Stored readings** — downloads BP history files from device memory (up to 50 readings)
- **Combined Blood Pressure sensor** — shows "125/82" format with measurement history attribute
- Exposes sensors: Blood Pressure (combined), Systolic, Diastolic, Heart Rate, MAP, Pulse Pressure, Battery, RSSI, Irregular Heartbeat flag
- **Persistent BLE connection** — stays connected with CMD 0x06 state polling to detect measurements without disturbing the user
- **ESPHome BLE Proxy compatible** — works through ESP32 proxies placed near the monitor

## Requirements

- Home Assistant 2025.1.0+
- ESPHome BLE proxy (ESP32) within range of the BP2 device
- Viatom BP2, BP2A, or BP2W blood pressure monitor

## Installation

### HACS (recommended)

1. Add this repository as a custom repository in HACS
2. Search for "Viatom BP2" and install
3. Restart Home Assistant

### Manual

1. Copy `custom_components/viatom_bp2/` to your HA `config/custom_components/` directory
2. Restart Home Assistant

## Setup

1. Power on your BP2 — it should be auto-discovered via your BLE proxies
2. If not auto-discovered, go to **Settings → Devices & Services → Add Integration → Viatom BP2**
3. Select your device and confirm

## How It Works

```
BP2 powers on → BLE advertisement → ESPHome proxy → HA Bluetooth stack

PHASE 1 — Connection:
    → Integration detects advertisement → connects via BLE
    → Subscribes to notifications
    → Housekeeping: battery, device info, time sync
    → Baseline fetch: downloads BP measurement file → parses → updates sensors

PHASE 2 — Monitoring (stays connected):
    → Polls device state every 5s (CMD 0x06, invisible to user)
    → Detects measurement activity (states 4/15/16 = busy, 5/17 = result)
    → Downloads new records when measurement completes
    → Handles single, triple, and back-to-back measurements

PHASE 3 — Disconnect:
    → After 120s idle with no measurement activity → disconnects
    → Frees BLE proxy slot for other devices
    → Reconnects automatically on next advertisement
```

The integration uses persistent BLE connections with state polling. This avoids the transfer
icon flashing on the device screen and handles all measurement scenarios reliably.

## Protocol Details

The BP2 uses Viatom's proprietary **Lepu BLE protocol** (not the standard Bluetooth SIG Blood
Pressure Profile). Key details from the [LepuDemo SDK](https://github.com/viatom-develop/LepuDemo):

| Parameter      | Value                                        |
|----------------|----------------------------------------------|
| Service UUID   | `14839AC4-7D7E-415C-9A42-167340CF2339`       |
| Write UUID     | `8B00ACE7-EB0B-49B0-BBE9-9AEE0A26E1A3`       |
| Notify UUID    | `0734594A-A8E7-4B1A-A6B1-CD5243059A57`       |
| Protocol       | Lepu framed packets (header + cmd + payload + CRC8) |

## ⚠️ Protocol Tuning

The byte-level protocol in `protocol.py` is based on reverse-engineering the LepuDemo SDK
documentation and common Lepu protocol patterns. **The exact payload formats may need adjustment
for your specific firmware version.**

### How to sniff the actual protocol

If the integration connects but doesn't parse data correctly:

1. **Enable debug logging** in HA:
   ```yaml
   logger:
     logs:
       custom_components.viatom_bp2: debug
   ```

2. **Take a measurement** with the BP2 — the debug log will show raw notification hex:
   ```
   BLE notification (20 bytes): a5170e00000d00...
   Packet: cmd=0x17 seq=0 payload_len=13
   ```

3. **Compare with ViHealth app** — install nRF Connect on Android, connect to BP2, and
   observe the GATT traffic while ViHealth reads data. This reveals the exact command/response
   byte sequences.

4. **Update `protocol.py`** — adjust `parse_rt_data()` and `parse_bp_file()` to match
   your device's actual payload layout.

### Alternative: Sniff ViHealth BLE traffic

Use Android's **BLE HCI snoop log** to capture all BLE traffic between ViHealth and the BP2:

1. Enable Developer Options on Android
2. Enable "Bluetooth HCI Snoop Log"
3. Open ViHealth, connect to BP2, sync data
4. Pull the log: `adb pull /sdcard/btsnoop_hci.log`
5. Open in Wireshark with the Bluetooth filter

## Example Automation

Push BP readings to a FHIR server or notification:

```yaml
automation:
  - alias: "Log Blood Pressure"
    trigger:
      - platform: state
        entity_id: sensor.viatom_bp2_blood_pressure
    condition:
      - condition: template
        value_template: "{{ states('sensor.viatom_bp2_systolic') | int > 0 }}"
    action:
      - service: notify.notify
        data:
          message: >
            BP: {{ states('sensor.viatom_bp2_blood_pressure') }} mmHg
            Heart Rate: {{ states('sensor.viatom_bp2_heart_rate') }} bpm
            Time: {{ states('sensor.viatom_bp2_last_measurement_time') }}
```

## Supported Devices

All devices are sold under the **Checkme** brand by Viatom.

| Device      | BLE Name     | Status   | Notes                            |
|-------------|--------------|----------|----------------------------------|
| BP2 Connect | LP-BP2W      | Tested   | 2-in-1 BP + EKG, development device |
| BP2         | BP2          | Untested | Upper arm BP monitor             |
| BP2A        | BP2A         | Untested | Compact/portable version         |

## Credits

- Protocol info from [viatom-develop/LepuDemo](https://github.com/viatom-develop/LepuDemo)
- Architecture inspired by [Rudertier/medisana_blood_pressure](https://github.com/Rudertier/medisana_blood_pressure)
- BLE patterns from [ecostech/viatom-ble](https://github.com/ecostech/viatom-ble)

## License

MIT
