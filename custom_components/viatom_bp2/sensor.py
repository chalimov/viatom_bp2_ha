"""Sensor platform for Viatom BP2 Blood Pressure Monitor."""

from __future__ import annotations

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import (
    EntityCategory,
    PERCENTAGE,
    SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import ViatomBP2ConfigEntry
from .const import DOMAIN, MANUFACTURER
from .coordinator import ViatomBP2Coordinator

SENSOR_DESCRIPTIONS: tuple[SensorEntityDescription, ...] = (
    SensorEntityDescription(
        key="systolic",
        translation_key="systolic",
        native_unit_of_measurement="mmHg",
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:heart-pulse",
    ),
    SensorEntityDescription(
        key="diastolic",
        translation_key="diastolic",
        native_unit_of_measurement="mmHg",
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:heart-pulse",
    ),
    SensorEntityDescription(
        key="pulse",
        translation_key="pulse",
        native_unit_of_measurement="bpm",
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:heart",
    ),
    SensorEntityDescription(
        key="mean_arterial_pressure",
        translation_key="mean_arterial_pressure",
        native_unit_of_measurement="mmHg",
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:heart-flash",
    ),
    SensorEntityDescription(
        key="measurement_time",
        translation_key="measurement_time",
        device_class=SensorDeviceClass.TIMESTAMP,
        icon="mdi:clock-outline",
    ),
    SensorEntityDescription(
        key="battery_level",
        translation_key="battery_level",
        native_unit_of_measurement=PERCENTAGE,
        device_class=SensorDeviceClass.BATTERY,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    SensorEntityDescription(
        key="rssi",
        translation_key="rssi",
        native_unit_of_measurement=SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
    ),
    SensorEntityDescription(
        key="irregular_heartbeat",
        translation_key="irregular_heartbeat",
        icon="mdi:heart-broken",
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ViatomBP2ConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up Viatom BP2 sensors."""
    coordinator = entry.runtime_data

    async_add_entities(
        ViatomBP2Sensor(coordinator, description, entry)
        for description in SENSOR_DESCRIPTIONS
    )


class ViatomBP2Sensor(CoordinatorEntity[ViatomBP2Coordinator], SensorEntity):
    """Representation of a Viatom BP2 sensor."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: ViatomBP2Coordinator,
        description: SensorEntityDescription,
        entry: ViatomBP2ConfigEntry,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{coordinator.address}_{description.key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, coordinator.address)},
            name=coordinator.device_name,
            manufacturer=MANUFACTURER,
            model="BP2",
        )

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle data update from coordinator."""
        data = self.coordinator.bp_data
        key = self.entity_description.key

        # Update device info with firmware/hardware versions once available
        if (
            data.device_info
            and data.device_info.fw_version
            and self._attr_device_info
            and not self._attr_device_info.get("sw_version")
        ):
            self._attr_device_info = DeviceInfo(
                identifiers={(DOMAIN, self.coordinator.address)},
                name=self.coordinator.device_name,
                manufacturer=MANUFACTURER,
                model="BP2",
                sw_version=data.device_info.fw_version,
                hw_version=data.device_info.hw_version or None,
            )

        if key == "irregular_heartbeat":
            # Only show after a measurement has been taken; display as
            # human-readable string since SensorEntity doesn't support bool
            if data.measurements:
                self._attr_native_value = (
                    "Detected" if data.irregular_heartbeat else "Normal"
                )
        else:
            value = getattr(data, key, None)
            if value is not None:
                self._attr_native_value = value

        # Add measurement history as extra state attributes for the systolic sensor
        if key == "systolic" and data.measurements:
            self._attr_extra_state_attributes = {
                "measurements": [
                    {
                        "systolic": m.systolic,
                        "diastolic": m.diastolic,
                        "pulse": m.pulse,
                        "map": m.mean_arterial_pressure,
                        "time": m.timestamp_str,
                        "irregular": m.irregular_heartbeat,
                    }
                    for m in data.measurements[-10:]  # last 10
                ]
            }

        self.async_write_ha_state()
