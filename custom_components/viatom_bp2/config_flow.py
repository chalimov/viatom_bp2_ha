"""Config flow for Viatom BP2 Blood Pressure Monitor."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.components import bluetooth
from homeassistant.components.bluetooth import BluetoothServiceInfoBleak
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.const import CONF_ADDRESS, CONF_NAME
from homeassistant.core import callback

from .const import DOMAIN, SERVICE_UUID, DEVICE_LOCAL_NAMES, CONF_USER_NAMES

_LOGGER = logging.getLogger(__name__)


class ViatomBP2ConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Viatom BP2."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize."""
        self._discovery_info: BluetoothServiceInfoBleak | None = None

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: ConfigEntry,
    ) -> ViatomBP2OptionsFlow:
        """Get the options flow handler."""
        return ViatomBP2OptionsFlow(config_entry)

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
        if self._discovery_info is None:
            return self.async_abort(reason="no_devices_found")
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
            for info in bluetooth.async_discovered_service_info(
                self.hass, connectable=True
            ):
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
        current_ids = self._async_current_ids()
        discovered: dict[str, str] = {}
        for info in bluetooth.async_discovered_service_info(
            self.hass, connectable=True
        ):
            if info.address not in current_ids and self._is_bp2(info):
                discovered[info.address] = (
                    f"{info.name or 'Unknown'} ({info.address})"
                )

        if not discovered:
            return self.async_abort(reason="no_devices_found")

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
        if any(u.lower() == SERVICE_UUID for u in info.service_uuids):
            return True
        # Match by device name
        if info.name:
            name_upper = info.name.strip().upper()
            for known in DEVICE_LOCAL_NAMES:
                if name_upper.startswith(known.upper()):
                    return True
        return False


class ViatomBP2OptionsFlow(OptionsFlow):
    """Handle options for Viatom BP2 (user ID → name mapping).

    Shows a form with one text field per discovered user ID.
    The user can enter a friendly name for each ID. User IDs
    are Viatom cloud account IDs — they appear in BP records
    but are NOT decodable to names (opaque sequential integers).
    """

    def __init__(self, config_entry: ConfigEntry) -> None:
        """Initialize options flow."""
        self._config_entry = config_entry

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Manage user ID → name mapping."""
        if user_input is not None:
            # Save the mapping: keys are "user_NNNNNN", values are names
            user_names: dict[str, str] = {}
            for key, value in user_input.items():
                if key.startswith("user_") and value:
                    uid_str = key[5:]  # strip "user_" prefix
                    user_names[uid_str] = value.strip()

            return self.async_create_entry(
                title="",
                data={CONF_USER_NAMES: user_names},
            )

        # Collect all known user IDs from the coordinator's data
        discovered_ids: set[int] = set()
        try:
            coordinator = self._config_entry.runtime_data
            if coordinator and hasattr(coordinator, "bp_data"):
                for m in coordinator.bp_data.measurements:
                    if m.user_id:
                        discovered_ids.add(m.user_id)
        except AttributeError:
            pass  # Integration not loaded — no runtime_data available

        # Load existing names from options
        existing_names: dict[str, str] = self._config_entry.options.get(
            CONF_USER_NAMES, {}
        )

        # Also include IDs from existing config that might not be in
        # current measurements (device was restarted, etc.)
        for uid_str in existing_names:
            try:
                discovered_ids.add(int(uid_str))
            except (ValueError, TypeError):
                pass

        # Build the schema: one text field per discovered user ID
        schema_dict: dict[vol.Marker, Any] = {}

        if discovered_ids:
            for uid in sorted(discovered_ids):
                uid_str = str(uid)
                current_name = existing_names.get(uid_str, "")
                schema_dict[
                    vol.Optional(
                        f"user_{uid}",
                        default=current_name,
                        description={"suggested_value": current_name},
                    )
                ] = str
        else:
            return self.async_abort(reason="no_users_found")

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(schema_dict),
            description_placeholders={
                "info": (
                    "Enter friendly names for each discovered user ID. "
                    "These IDs are Viatom cloud account numbers shown "
                    "next to each BP measurement."
                )
            },
        )
