# 🩺 Viatom BP2 Blood Pressure Monitor — Home Assistant Integration

Custom integration for **Viatom / Checkme BP2, BP2A, BP2W** blood pressure monitors via BLE.

Works through **ESPHome Bluetooth Proxies** — no phone or ViHealth app needed.

## Features

- **Auto-discovery** via BLE service UUID when BP2 powers on
- **Local push** — no polling; reacts to BLE advertisements instantly
- **Real-time results** — captures systolic/diastolic/pulse when measurement completes
- **Stored readings** — downloads BP history files from device memory (up to 50 readings)
- Exposes sensors: Systolic, Diastolic, Pulse, MAP, Battery, RSSI, Irregular Heartbeat flag
- **ESPHome BLE Proxy compatible** — works through ESP32 proxies placed near the monitor

## Requirements

- Home Assistant 2025.12.0+
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
    → Integration detects advertisement
    → Connects via BLE
    → Syncs time
    → Subscribes to notifications (real-time data)
    → Requests stored file list
    → Downloads BP measurement files
    → Parses results → Updates HA sensors
    → Disconnects
```

The BP2 is only BLE-active for a short window after powering on or completing a measurement.
The integration uses the `local_push` pattern — it reacts to BLE advertisements rather than
polling, which is both efficient and reliable with ESPHome proxies.

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
        entity_id: sensor.viatom_bp2_systolic
    condition:
      - condition: numeric_state
        entity_id: sensor.viatom_bp2_systolic
        above: 0
    action:
      - service: notify.notify
        data:
          message: >
            BP: {{ states('sensor.viatom_bp2_systolic') }}/{{ states('sensor.viatom_bp2_diastolic') }} mmHg
            Pulse: {{ states('sensor.viatom_bp2_pulse') }} bpm
            Time: {{ states('sensor.viatom_bp2_last_measurement_time') }}
```

## Supported Devices

| Device     | Status      | Notes                          |
|------------|-------------|--------------------------------|
| BP2        | 🔧 Expected | Same protocol as BP2A          |
| BP2A       | 🔧 Expected | Primary development target     |
| BP2W       | 🔧 Expected | WiFi variant, BLE still works  |
| BP2 Connect| ❓ Unknown  | May use different firmware      |

## Credits

- Protocol info from [viatom-develop/LepuDemo](https://github.com/viatom-develop/LepuDemo)
- Architecture inspired by [Rudertier/medisana_blood_pressure](https://github.com/Rudertier/medisana_blood_pressure)
- BLE patterns from [ecostech/viatom-ble](https://github.com/ecostech/viatom-ble)

## License

MIT
