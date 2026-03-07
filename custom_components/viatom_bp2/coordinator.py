"""Data coordinator for Viatom BP2 Blood Pressure Monitor.

Follows the HA local_push pattern: listens for BLE advertisements,
connects when the device is active, retrieves measurements, and
disconnects. Works through ESPHome BLE proxies.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
import logging
import time
from typing import Any

from bleak import BleakClient
from bleak.exc import BleakError
from bleak_retry_connector import establish_connection

from homeassistant.components import bluetooth
from homeassistant.components.bluetooth import BluetoothServiceInfoBleak
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import dt as dt_util

from .const import (
    DOMAIN,
    WRITE_UUID,
    NOTIFY_UUID,
)
from .protocol import (
    BpResult,
    DeviceInfo,
    RtData,
    PacketReassembler,
    LepuPacket,
    build_get_info,
    build_sync_time,
    build_get_file_list,
    build_read_file_start,
    parse_device_info,
    parse_rt_data,
    parse_bp_file,
    parse_file_list,
)

_LOGGER = logging.getLogger(__name__)

# Maximum number of stored measurements to keep in memory
MAX_STORED_MEASUREMENTS = 50

# Maximum BLE connection retries
MAX_CONNECT_RETRIES = 3


class ViatomBP2Data:
    """Container for the latest data from the BP2 device."""

    def __init__(self) -> None:
        self.systolic: int | None = None
        self.diastolic: int | None = None
        self.pulse: int | None = None
        self.mean_arterial_pressure: int | None = None
        self.irregular_heartbeat: bool = False
        self.measurement_time: datetime | None = None
        self.battery_level: int | None = None
        self.battery_status: int | None = None
        self.device_status: int | None = None
        self.device_info: DeviceInfo | None = None
        self.rssi: int | None = None
        self.last_update: float = 0
        self.measurements: list[BpResult] = []

    def update_from_rt(self, rt: RtData) -> bool:
        """Update from real-time data. Returns True if a new result is available."""
        self.device_status = rt.device_status
        self.battery_level = rt.battery_level
        self.battery_status = rt.battery_status
        if rt.result_ready and rt.systolic > 0:
            self.systolic = rt.systolic
            self.diastolic = rt.diastolic
            self.pulse = rt.pulse
            self.mean_arterial_pressure = rt.mean_arterial_pressure
            now = dt_util.now()
            self.measurement_time = now  # datetime with tzinfo for TIMESTAMP device class
            self.last_update = time.monotonic()
            result = BpResult(
                systolic=rt.systolic,
                diastolic=rt.diastolic,
                pulse=rt.pulse,
                mean_arterial_pressure=rt.mean_arterial_pressure,
                timestamp=int(now.timestamp()),
            )
            self.measurements.append(result)
            # Limit stored measurements to avoid unbounded memory growth
            if len(self.measurements) > MAX_STORED_MEASUREMENTS:
                self.measurements = self.measurements[-MAX_STORED_MEASUREMENTS:]
            return True
        return False

    def update_from_bp_result(self, result: BpResult) -> None:
        """Update from a stored BP file result."""
        self.systolic = result.systolic
        self.diastolic = result.diastolic
        self.pulse = result.pulse
        self.mean_arterial_pressure = result.mean_arterial_pressure
        self.irregular_heartbeat = result.irregular_heartbeat
        # Convert unix timestamp to timezone-aware datetime for TIMESTAMP sensor
        if result.timestamp > 0:
            self.measurement_time = dt_util.utc_from_timestamp(
                result.timestamp
            ).astimezone(dt_util.DEFAULT_TIME_ZONE)
        else:
            self.measurement_time = None
        self.last_update = time.monotonic()
        self.measurements.append(result)
        # Limit stored measurements
        if len(self.measurements) > MAX_STORED_MEASUREMENTS:
            self.measurements = self.measurements[-MAX_STORED_MEASUREMENTS:]


class ViatomBP2Coordinator(DataUpdateCoordinator[ViatomBP2Data]):
    """Coordinator for Viatom BP2 BLE data."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        address: str,
        name: str,
    ) -> None:
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_{address}",
        )
        self.address = address
        self.device_name = name
        self._entry = entry
        self._data = ViatomBP2Data()
        self._connected = False
        self._connecting = False
        self._reassembler = PacketReassembler()
        self._reassembler.on_packet = self._handle_packet
        self._file_data_buffer = bytearray()
        self._pending_files: list[str] = []
        self._got_result = asyncio.Event()
        self._all_files_done = asyncio.Event()
        self._all_files_done.set()  # No files pending initially
        self._current_client: BleakClient | None = None

    @property
    def bp_data(self) -> ViatomBP2Data:
        """Return current data."""
        return self._data

    @callback
    def handle_bluetooth_event(
        self,
        service_info: BluetoothServiceInfoBleak,
        change: bluetooth.BluetoothChange,
    ) -> None:
        """Handle a BLE advertisement from the BP2.

        Called by HA's bluetooth stack when the device is detected.
        We attempt to connect and retrieve data.
        """
        self._data.rssi = service_info.rssi
        _LOGGER.debug(
            "BLE advertisement from %s (RSSI: %s, change: %s)",
            self.address,
            service_info.rssi,
            change,
        )
        # Schedule connection attempt (avoid duplicate connections)
        if not self._connected and not self._connecting:
            # Set flag immediately in callback (synchronous) to prevent
            # duplicate scheduling from rapid BLE advertisements
            self._connecting = True
            self._entry.async_create_background_task(
                self.hass,
                self._connect_and_fetch(),
                name=f"viatom_bp2_connect_{self.address}",
            )

    async def _connect_and_fetch(self) -> None:
        """Connect to the BP2, subscribe to notifications, and fetch data."""
        self._got_result.clear()

        # Best practice: get a fresh BLEDevice each time (never reuse BleakClient)
        ble_device = bluetooth.async_ble_device_from_address(
            self.hass, self.address, connectable=True
        )
        if ble_device is None:
            _LOGGER.warning("No connectable device found for %s", self.address)
            self._connecting = False
            return

        client: BleakClient | None = None
        try:
            _LOGGER.info("Connecting to BP2 at %s ...", self.address)

            # Callback to get a fresh BLEDevice on retry — the device path may
            # change between attempts (especially with ESPHome BLE proxies)
            def _ble_device_callback():
                return bluetooth.async_ble_device_from_address(
                    self.hass, self.address, connectable=True
                ) or ble_device

            # Use bleak-retry-connector for reliable connections through proxies
            client = await establish_connection(
                client_class=BleakClient,
                device=ble_device,
                name=self.device_name,
                max_attempts=MAX_CONNECT_RETRIES,
                ble_device_callback=_ble_device_callback,
            )
            self._current_client = client
            self._connected = True
            _LOGGER.info("Connected to BP2 at %s", self.address)

            # --- DEBUG: dump all GATT services so we can verify UUIDs ---
            for service in client.services:
                _LOGGER.info(
                    "GATT Service: %s (handle %s)",
                    service.uuid, service.handle,
                )
                for char in service.characteristics:
                    props = ",".join(char.properties)
                    _LOGGER.info(
                        "  Characteristic: %s [%s] (handle %s)",
                        char.uuid, props, char.handle,
                    )
            # --- END DEBUG ---

            # Subscribe to notifications on BOTH the notify characteristic
            # and the write characteristic (some variants respond on either)
            self._reassembler.reset()
            _LOGGER.info("Subscribing to notifications on NOTIFY_UUID...")
            await client.start_notify(NOTIFY_UUID, self._notification_handler)
            _LOGGER.info("Notification subscription successful on NOTIFY_UUID")

            # Also try subscribing on WRITE_UUID in case device notifies there
            try:
                _LOGGER.info("Subscribing to notifications on WRITE_UUID...")
                await client.start_notify(WRITE_UUID, self._notification_handler)
                _LOGGER.info("Notification subscription successful on WRITE_UUID")
            except BleakError as e:
                _LOGGER.debug("WRITE_UUID doesn't support notify (expected): %s", e)

            # Try writing to NOTIFY characteristic (bidirectional pattern)
            # Some Lepu variants expect commands on the notify char
            _LOGGER.debug("Syncing time (via NOTIFY char)...")
            sync_cmd = build_sync_time()
            try:
                await client.write_gatt_char(NOTIFY_UUID, sync_cmd, response=True)
                _LOGGER.debug("Sent sync_time to NOTIFY_UUID: %s", sync_cmd.hex())
            except BleakError as e:
                _LOGGER.debug("Write to NOTIFY_UUID failed: %s", e)
            await asyncio.sleep(0.5)

            # Also try the original WRITE characteristic
            _LOGGER.debug("Syncing time (via WRITE char)...")
            await self._write_command(client, sync_cmd)
            await asyncio.sleep(0.5)

            # Request device info on both characteristics
            info_cmd = build_get_info()
            _LOGGER.debug("Requesting device info (via NOTIFY char)...")
            try:
                await client.write_gatt_char(NOTIFY_UUID, info_cmd, response=True)
                _LOGGER.debug("Sent get_info to NOTIFY_UUID: %s", info_cmd.hex())
            except BleakError as e:
                _LOGGER.debug("Write get_info to NOTIFY_UUID failed: %s", e)
            await asyncio.sleep(0.5)

            _LOGGER.debug("Requesting device info (via WRITE char)...")
            await self._write_command(client, info_cmd)
            await asyncio.sleep(0.5)

            # Request file list
            file_cmd = build_get_file_list()
            _LOGGER.debug("Requesting file list (via NOTIFY char)...")
            try:
                await client.write_gatt_char(NOTIFY_UUID, file_cmd, response=True)
            except BleakError as e:
                _LOGGER.debug("Write file_list to NOTIFY_UUID failed: %s", e)
            await asyncio.sleep(0.3)

            _LOGGER.debug("Requesting file list (via WRITE char)...")
            await self._write_command(client, file_cmd)

            # Wait for initial data (RT result or first file parse)
            try:
                await asyncio.wait_for(self._got_result.wait(), timeout=30)
                _LOGGER.info("Got measurement data from BP2")
            except TimeoutError:
                _LOGGER.debug(
                    "Timeout waiting for measurement result — "
                    "device may be idle or protocol needs tuning"
                )

            # Wait for any remaining file reads to complete before disconnecting
            try:
                await asyncio.wait_for(self._all_files_done.wait(), timeout=30)
            except TimeoutError:
                _LOGGER.warning("Timeout waiting for file reads to complete")

        except BleakError as e:
            _LOGGER.warning("BLE error with BP2 at %s: %s", self.address, e)
        except Exception:
            _LOGGER.exception("Unexpected error with BP2 at %s", self.address)
        finally:
            if client is not None:
                await self._disconnect(client)
            self._current_client = None
            self._connecting = False
            # Notify HA that data has been updated
            self.async_set_updated_data(self._data)

    async def _write_command(self, client: BleakClient, data: bytes) -> None:
        """Write a command to the BP2 write characteristic."""
        if client.is_connected:
            try:
                await client.write_gatt_char(WRITE_UUID, data, response=True)
                _LOGGER.debug("Sent command: %s", data.hex())
            except BleakError as e:
                _LOGGER.warning("Failed to write command: %s", e)

    def _notification_handler(
        self, _sender: Any, data: bytearray
    ) -> None:
        """Handle raw BLE notification data.

        Note: Bleak calls this from the event loop in modern versions,
        so it is safe to call _reassembler.feed() which triggers
        _handle_packet synchronously.
        """
        _LOGGER.debug("BLE notification (%d bytes): %s", len(data), data.hex())
        self._reassembler.feed(bytes(data))

    def _handle_packet(self, packet: LepuPacket) -> None:
        """Handle a decoded Lepu protocol packet.

        Called synchronously from notification_handler on the event loop.
        """
        _LOGGER.debug(
            "Packet: cmd=0x%02X seq=%d payload_len=%d",
            packet.cmd, packet.seq, len(packet.payload),
        )

        # Device info response
        if packet.cmd in (0x14, 0x15):
            info = parse_device_info(packet.payload)
            self._data.device_info = info
            self._data.battery_level = info.battery_level
            _LOGGER.info(
                "Device info: hw=%s fw=%s sn=%s battery=%d%%",
                info.hw_version, info.fw_version,
                info.serial_number, info.battery_level,
            )

        # Real-time data
        elif packet.cmd in (0x16, 0x17):
            rt = parse_rt_data(packet.payload)
            new_result = self._data.update_from_rt(rt)
            if new_result:
                _LOGGER.info(
                    "BP Result: %d/%d mmHg, pulse %d bpm",
                    self._data.systolic,
                    self._data.diastolic,
                    self._data.pulse,
                )
                self._got_result.set()

        # File list response
        elif packet.cmd in (0x18, 0x19):
            files = parse_file_list(packet.payload)
            _LOGGER.info("Device has %d stored files: %s", len(files), files)
            self._pending_files = files
            if files:
                self._all_files_done.clear()
                self._entry.async_create_background_task(
                    self.hass,
                    self._read_next_file(),
                    name=f"viatom_bp2_read_file_{self.address}",
                )
            else:
                self._all_files_done.set()

        # File data response
        elif packet.cmd in (0x1A, 0x1B, 0x1C, 0x1D):
            self._file_data_buffer.extend(packet.payload)

        # File read complete
        elif packet.cmd in (0x1E, 0x1F):
            if self._file_data_buffer:
                results = parse_bp_file(bytes(self._file_data_buffer))
                for r in results:
                    self._data.update_from_bp_result(r)
                    _LOGGER.info(
                        "Stored BP: %d/%d mmHg, pulse %d @ %s",
                        r.systolic, r.diastolic, r.pulse, r.timestamp_str,
                    )
                self._file_data_buffer.clear()
                if results:
                    self._got_result.set()
            if self._pending_files:
                self._entry.async_create_background_task(
                    self.hass,
                    self._read_next_file(),
                    name=f"viatom_bp2_read_file_{self.address}",
                )
            else:
                # All files processed
                self._all_files_done.set()

        else:
            _LOGGER.debug(
                "Unhandled packet cmd=0x%02X payload=%s",
                packet.cmd, packet.payload.hex(),
            )

    async def _read_next_file(self) -> None:
        """Read the next file from the pending list."""
        if not self._pending_files or self._current_client is None:
            return
        filename = self._pending_files.pop(0)
        _LOGGER.debug("Reading file: %s", filename)
        self._file_data_buffer.clear()
        await self._write_command(self._current_client, build_read_file_start(filename))

    async def _disconnect(self, client: BleakClient) -> None:
        """Disconnect from the BP2."""
        try:
            if client.is_connected:
                try:
                    await client.stop_notify(NOTIFY_UUID)
                except BleakError:
                    pass
                await client.disconnect()
        except BleakError:
            pass
        finally:
            self._connected = False
            _LOGGER.info("Disconnected from BP2 at %s", self.address)

    async def _async_update_data(self) -> ViatomBP2Data:
        """Return the latest data (called by HA coordinator)."""
        return self._data
