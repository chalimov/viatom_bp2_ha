"""Constants for the Viatom BP2 Blood Pressure Monitor integration."""

DOMAIN = "viatom_bp2"
MANUFACTURER = "Viatom / Checkme"

# BLE UUIDs (from Viatom LepuDemo SDK)
SERVICE_UUID = "14839ac4-7d7e-415c-9a42-167340cf2339"
WRITE_UUID = "8b00ace7-eb0b-49b0-bbe9-9aee0a26e1a3"
NOTIFY_UUID = "0734594a-a8e7-4b1a-a6b1-cd5243059a57"

# Device advertised names (add your device's name if different)
# Matching uses startswith() on stripped/uppercased name, so "BP2" covers "BP2A", "BP2W", etc.
DEVICE_LOCAL_NAMES = {"BP2", "LP-BP2", "Checkme BP2"}

# User ID name mapping (options key, configured via UI options flow)
# User IDs are opaque Viatom cloud account IDs — sequential integers
# assigned during account creation. They have NO encoding relationship
# to user names. Names are stored in device internal flash (written by
# the Viatom app during user setup) and NOT accessible via BLE.
# The options flow shows discovered IDs and lets the user assign names.
CONF_USER_NAMES = "user_names"
