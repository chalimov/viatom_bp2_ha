"""Viatom BP2 Blood Pressure Monitor integration for Home Assistant.

Connects to Viatom/Checkme BP2, BP2A, BP2W blood pressure monitors
via BLE (through ESPHome Bluetooth proxies or direct HA Bluetooth).

Automatically detects the device when it becomes active after a
measurement and retrieves BP readings.

Multi-user support: the device stores records with Viatom cloud
account IDs. Use the integration's Configure button to map discovered
user IDs to friendly names.
"""

from __future__ import annotations

import logging

from homeassistant.components import bluetooth
from homeassistant.components.bluetooth import (
    BluetoothCallbackMatcher,
    BluetoothScanningMode,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_ADDRESS, CONF_NAME, Platform
from homeassistant.core import HomeAssistant

from .const import DOMAIN, CONF_USER_NAMES
from .coordinator import ViatomBP2Coordinator

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.SENSOR]

# Typed ConfigEntry — runtime_data holds the coordinator
type ViatomBP2ConfigEntry = ConfigEntry[ViatomBP2Coordinator]


async def async_setup_entry(
    hass: HomeAssistant, entry: ViatomBP2ConfigEntry
) -> bool:
    """Set up Viatom BP2 from a config entry."""
    address: str = entry.data[CONF_ADDRESS]
    name: str = entry.data.get(CONF_NAME, "Viatom BP2")

    # Get user_names mapping from options (set via UI options flow)
    user_names: dict[int, str] = {}
    raw_names = entry.options.get(CONF_USER_NAMES, {})
    for uid, uname in raw_names.items():
        try:
            user_names[int(uid)] = str(uname)
        except (ValueError, TypeError):
            pass

    coordinator = ViatomBP2Coordinator(
        hass, entry, address, name, user_names=user_names
    )

    # Restore measurement history from persistent storage
    await coordinator.async_load_data()

    # Store coordinator in runtime_data (modern HA pattern, auto-cleaned on unload)
    entry.runtime_data = coordinator

    # Clean up background tasks and BLE connections on unload
    entry.async_on_unload(coordinator.async_shutdown)

    # Listen for options updates (user changes name mapping)
    entry.async_on_unload(entry.add_update_listener(_async_update_options))

    # Register for BLE advertisements matching the BP2
    entry.async_on_unload(
        bluetooth.async_register_callback(
            hass,
            coordinator.handle_bluetooth_event,
            BluetoothCallbackMatcher(address=address, connectable=True),
            BluetoothScanningMode.ACTIVE,
        )
    )

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    _LOGGER.info(
        "Viatom BP2 integration set up for %s (%s) — "
        "waiting for BLE advertisements via ESPHome proxies",
        name,
        address,
    )
    return True


async def _async_update_options(
    hass: HomeAssistant, entry: ViatomBP2ConfigEntry
) -> None:
    """Handle options update — reload the integration to pick up new names."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(
    hass: HomeAssistant, entry: ViatomBP2ConfigEntry
) -> bool:
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
