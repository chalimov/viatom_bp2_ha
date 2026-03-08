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

# Sensor order matters — HA shows entities in definition order.
# Group: primary BP → vitals → status → timing → diagnostics
SENSOR_DESCRIPTIONS: tuple[SensorEntityDescription, ...] = (
    # --- Combined blood pressure (primary display sensor) ---
    SensorEntityDescription(
        key="blood_pressure",
        translation_key="blood_pressure",
        icon="mdi:heart-pulse",
    ),
    # --- Individual BP readings (for automations, graphs, history) ---
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
    # --- Secondary vitals ---
    SensorEntityDescription(
        key="heart_rate",
        translation_key="heart_rate",
        native_unit_of_measurement="bpm",
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:heart-flash",
    ),
    SensorEntityDescription(
        key="mean_arterial_pressure",
        translation_key="mean_arterial_pressure",
        native_unit_of_measurement="mmHg",
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:heart",
        entity_registry_enabled_default=False,
    ),
    SensorEntityDescription(
        key="pulse_pressure",
        translation_key="pulse_pressure",
        native_unit_of_measurement="mmHg",
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:heart-outline",
        entity_registry_enabled_default=False,
    ),
    # --- Status ---
    SensorEntityDescription(
        key="irregular_heartbeat",
        translation_key="irregular_heartbeat",
        icon="mdi:heart-broken",
    ),
    # --- Timing ---
    SensorEntityDescription(
        key="measurement_time",
        translation_key="measurement_time",
        icon="mdi:clock-outline",
    ),
    # --- Diagnostics (hidden by default in HA UI) ---
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
        key="device_state_text",
        translation_key="device_state",
        icon="mdi:state-machine",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    SensorEntityDescription(
        key="user_id",
        translation_key="user_id",
        icon="mdi:account",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
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
            and not self._attr_device_info.get("sw_version")  # type: ignore[union-attr]
        ):
            self._attr_device_info = DeviceInfo(
                identifiers={(DOMAIN, self.coordinator.address)},
                name=self.coordinator.device_name,
                manufacturer=MANUFACTURER,
                model="BP2",
                sw_version=data.device_info.fw_version,
                hw_version=data.device_info.hw_version or None,
            )

        if key == "blood_pressure":
            # Combined sys/dia display: "125/82"
            if data.systolic is not None and data.diastolic is not None:
                self._attr_native_value = f"{data.systolic}/{data.diastolic}"
            # Attach measurement history as extra state attributes
            if data.measurements:
                self._attr_extra_state_attributes = {
                    "history": [
                        {
                            "bp": f"{m.systolic}/{m.diastolic}",
                            "hr": m.heart_rate,
                            "map": m.mean_arterial_pressure,
                            "pp": m.pulse_pressure,
                            "irregular": m.irregular_heartbeat,
                            "time": m.timestamp_str,
                        }
                        for m in data.measurements[-10:]  # last 10
                    ]
                }
        elif key == "irregular_heartbeat":
            # Only show after a measurement has been taken; display as
            # human-readable string since SensorEntity doesn't support bool
            if data.measurements:
                self._attr_native_value = (
                    "Detected" if data.irregular_heartbeat else "Normal"
                )
        elif key == "user_id":
            # Show the active user's name (from config) or raw cloud ID
            if data.user_id is not None:
                user_names = self.coordinator.user_names
                if data.user_id in user_names:
                    self._attr_native_value = user_names[data.user_id]
                else:
                    self._attr_native_value = str(data.user_id)
        elif key == "measurement_time":
            # measurement_time is already a string, not a datetime
            if data.measurement_time is not None:
                self._attr_native_value = data.measurement_time
        else:
            value = getattr(data, key, None)
            if value is not None:
                self._attr_native_value = value

        self.async_write_ha_state()
