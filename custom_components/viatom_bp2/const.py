"""Constants for the Viatom BP2 Blood Pressure Monitor integration."""

DOMAIN = "viatom_bp2"
MANUFACTURER = "Viatom / Checkme"

# BLE UUIDs (from Viatom LepuDemo SDK)
SERVICE_UUID = "14839ac4-7d7e-415c-9a42-167340cf2339"
WRITE_UUID = "8b00ace7-eb0b-49b0-bbe9-9aee0a26e1a3"
NOTIFY_UUID = "0734594a-a8e7-4b1a-a6b1-cd5243059a57"

# Device advertised names (add your device's name if different)
DEVICE_LOCAL_NAMES = {
    "BP2", "BP2A", "BP2W", "Checkme BP2",
    "BP2 ", "BP2A ", "LP-BP2", "LP-BP2W", "LP-BP2A",
}
# Some devices prefix with a space or have trailing chars — we also match by service UUID

# Timeouts
CONNECT_TIMEOUT = 15  # seconds
DATA_TIMEOUT = 10  # seconds
DISCONNECT_DELAY = 2  # seconds after last data received

# User ID name mapping (options key, configured via UI options flow)
# User IDs are opaque Viatom cloud account IDs — sequential integers
# assigned during account creation. They have NO encoding relationship
# to user names. Names are stored in device internal flash (written by
# the Viatom app during user setup) and NOT accessible via BLE.
# The options flow shows discovered IDs and lets the user assign names.
CONF_USER_NAMES = "user_names"
