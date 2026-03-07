"""Constants for the Viatom BP2 Blood Pressure Monitor integration."""

DOMAIN = "viatom_bp2"
MANUFACTURER = "Viatom / Checkme"

# BLE UUIDs (from Viatom LepuDemo SDK)
SERVICE_UUID = "14839ac4-7d7e-415c-9a42-167340cf2339"
WRITE_UUID = "8b00ace7-eb0b-49b0-bbe9-9aee0a26e1a3"
NOTIFY_UUID = "0734594a-a8e7-4b1a-a6b1-cd5243059a57"

# Device advertised names (add your device's name if different)
DEVICE_LOCAL_NAMES = {"BP2", "BP2A", "BP2W", "Checkme BP2", "BP2 ", "BP2A ", "LP-BP2", "LP-BP2W", "LP-BP2A"}
# Some devices prefix with a space or have trailing chars — we also match by service UUID

# BP2 device status codes (from LepuDemo SDK)
STATUS_SLEEP = 0
STATUS_MEMORY = 1
STATUS_CHARGE = 2
STATUS_READY = 3
STATUS_BP_MEASURING = 4
STATUS_BP_MEASURE_END = 5
STATUS_ECG_MEASURING = 6
STATUS_ECG_MEASURE_END = 7
STATUS_VEN = 20

# Battery status codes
BATTERY_NO_CHARGE = 0
BATTERY_CHARGING = 1
BATTERY_CHARGE_COMPLETE = 2
BATTERY_LOW = 3

# Timeouts
CONNECT_TIMEOUT = 15  # seconds
DATA_TIMEOUT = 10  # seconds
DISCONNECT_DELAY = 2  # seconds after last data received
