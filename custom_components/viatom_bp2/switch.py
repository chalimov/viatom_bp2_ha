"""Switch platform for Viatom BP2 Blood Pressure Monitor."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.switch import SwitchDeviceClass, SwitchEntity
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import ViatomBP2ConfigEntry
from .const import DOMAIN, MANUFACTURER
from .coordinator import ViatomBP2Coordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ViatomBP2ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up the BLE connection switch."""
    _LOGGER.warning("Switch async_setup_entry called for %s", entry.entry_id)
    coordinator = entry.runtime_data
    entity = ViatomBP2ConnectionSwitch(coordinator, entry)
    _LOGGER.warning("Switch entity created: unique_id=%s", entity.unique_id)
    async_add_entities([entity])
    _LOGGER.warning("Switch entity added")


class ViatomBP2ConnectionSwitch(
    CoordinatorEntity[ViatomBP2Coordinator], SwitchEntity
):
    """Switch to enable/disable BLE connection to the BP2 device."""

    _attr_has_entity_name = True
    _attr_translation_key = "ble_connection"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_device_class = SwitchDeviceClass.SWITCH

    def __init__(
        self,
        coordinator: ViatomBP2Coordinator,
        entry: ViatomBP2ConfigEntry,
    ) -> None:
        """Initialize the switch."""
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.address}_ble_connection"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, coordinator.address)},
            name=coordinator.device_name,
            manufacturer=MANUFACTURER,
            model="BP2",
        )

    @property
    def is_on(self) -> bool:
        """Return True if BLE connection is enabled."""
        return self.coordinator.connection_enabled

    @property
    def icon(self) -> str:
        """Return icon based on connection state."""
        return "mdi:bluetooth" if self.is_on else "mdi:bluetooth-off"

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Enable BLE connection."""
        await self.coordinator.async_enable_connection()

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Disable BLE connection."""
        await self.coordinator.async_disable_connection()
