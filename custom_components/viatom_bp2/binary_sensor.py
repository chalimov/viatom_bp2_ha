"""Viatom BP2 binary sensor platform."""

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import ViatomBP2ConfigEntry
from .const import DOMAIN, MANUFACTURER
from .coordinator import ViatomBP2Coordinator

_CONNECTION_STATUS = BinarySensorEntityDescription(
    key="connected",
    name="Connected",
    device_class=BinarySensorDeviceClass.CONNECTIVITY,
    entity_category=EntityCategory.DIAGNOSTIC,
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ViatomBP2ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Viatom BP2 binary sensors."""
    coordinator: ViatomBP2Coordinator = entry.runtime_data
    async_add_entities([ConnectionStatusSensor(coordinator)])


class ConnectionStatusSensor(
    CoordinatorEntity[ViatomBP2Coordinator], BinarySensorEntity
):
    """Binary sensor showing BLE connection status."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: ViatomBP2Coordinator) -> None:
        super().__init__(coordinator)
        self.entity_description = _CONNECTION_STATUS
        self._attr_unique_id = f"{coordinator.address}_connected"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, coordinator.address)},
            name=coordinator.device_name,
            manufacturer=MANUFACTURER,
            model="BP2",
        )
        self._attr_is_on = coordinator._connected

    @property
    def available(self) -> bool:
        """Always available — shows disconnected when device is off."""
        return True

    @callback
    def _handle_coordinator_update(self) -> None:
        is_on = self.coordinator._connected
        if self._attr_is_on != is_on:
            self._attr_is_on = is_on
            self.async_write_ha_state()
