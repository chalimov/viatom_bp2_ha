"""Config flow for Viatom BP2 Blood Pressure Monitor."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components import bluetooth
from homeassistant.components.bluetooth import BluetoothServiceInfoBleak
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_ADDRESS, CONF_NAME

from .const import DOMAIN, SERVICE_UUID, DEVICE_LOCAL_NAMES

_LOGGER = logging.getLogger(__name__)


class ViatomBP2ConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Viatom BP2."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize."""
        self._discovery_info: BluetoothServiceInfoBleak | None = None

    async def async_step_bluetooth(
        self, discovery_info: BluetoothServiceInfoBleak
    ) -> ConfigFlowResult:
        """Handle bluetooth discovery."""
        _LOGGER.debug(
            "Bluetooth discovery: %s (%s) services=%s",
            discovery_info.name,
            discovery_info.address,
            discovery_info.service_uuids,
        )
        await self.async_set_unique_id(discovery_info.address)
        self._abort_if_unique_id_configured()
        self._discovery_info = discovery_info
        name = discovery_info.name or "Viatom BP2"
        self.context["title_placeholders"] = {"name": name}
        return await self.async_step_bluetooth_confirm()

    async def async_step_bluetooth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Confirm Bluetooth discovery."""
        assert self._discovery_info is not None
        if user_input is not None:
            return self.async_create_entry(
                title=self._discovery_info.name or "Viatom BP2",
                data={
                    CONF_ADDRESS: self._discovery_info.address,
                    CONF_NAME: self._discovery_info.name or "Viatom BP2",
                },
            )
        return self.async_show_form(
            step_id="bluetooth_confirm",
            description_placeholders={
                "name": self._discovery_info.name or "Viatom BP2",
            },
        )

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle user-initiated setup (show discovered devices)."""
        if user_input is not None:
            address = user_input[CONF_ADDRESS]
            await self.async_set_unique_id(address)
            self._abort_if_unique_id_configured()

            # Find the name from discovered devices
            name = "Viatom BP2"
            for info in bluetooth.async_discovered_service_info(self.hass, connectable=True):
                if info.address == address:
                    name = info.name or name
                    break

            return self.async_create_entry(
                title=name,
                data={
                    CONF_ADDRESS: address,
                    CONF_NAME: name,
                },
            )

        # Find BP2 devices in current bluetooth discoveries
        discovered: dict[str, str] = {}
        for info in bluetooth.async_discovered_service_info(self.hass, connectable=True):
            if self._is_bp2(info):
                discovered[info.address] = (
                    f"{info.name or 'Unknown'} ({info.address})"
                )

        if not discovered:
            return self.async_abort(reason="no_devices_found")

        import voluptuous as vol

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {vol.Required(CONF_ADDRESS): vol.In(discovered)}
            ),
        )

    @staticmethod
    def _is_bp2(info: BluetoothServiceInfoBleak) -> bool:
        """Check if a BLE device is a Viatom BP2."""
        # Match by service UUID
        if SERVICE_UUID in [u.lower() for u in info.service_uuids]:
            return True
        # Match by device name
        if info.name:
            name_upper = info.name.strip().upper()
            for known in DEVICE_LOCAL_NAMES:
                if name_upper.startswith(known.upper()):
                    return True
        return False
