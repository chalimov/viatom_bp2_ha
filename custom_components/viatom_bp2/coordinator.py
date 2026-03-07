"""Data coordinator for Viatom BP2 Blood Pressure Monitor.

Follows the HA local_push pattern: listens for BLE advertisements,
connects when the device is active, retrieves measurements, and
disconnects. Works through ESPHome BLE proxies.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
import logging
import struct
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
    CMD_GET_INFO,
    CMD_GET_DEVICE_INFO,
    CMD_RT_DATA,
    CMD_GET_BATTERY,
    CMD_GET_CONFIG,
    CMD_SYNC_TIME,
    CMD_ECHO,
    CMD_READ_FILE_LIST,
    CMD_READ_FILE_START,
    CMD_READ_FILE_DATA,
    CMD_READ_FILE_END,
    CMD_GET_LP_CONFIG,
    FILE_BP_LIST,
    BpResult,
    DeviceInfo,
    RtData,
    PacketReassembler,
    LepuPacket,
    build_get_info,
    build_get_device_info,
    build_sync_time,
    build_get_config,
    build_get_battery,
    build_echo,
    build_read_file_start,
    build_read_file_data,
    build_read_file_end,
    parse_device_info,
    parse_device_info_v1,
    parse_rt_data,
    parse_bp_file,
    parse_battery,
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
            self.measurement_time = now
            self.last_update = time.monotonic()
            result = BpResult(
                systolic=rt.systolic,
                diastolic=rt.diastolic,
                pulse=rt.pulse,
                mean_arterial_pressure=rt.mean_arterial_pressure,
                timestamp=int(now.timestamp()),
            )
            self.measurements.append(result)
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
        if result.timestamp > 0:
            self.measurement_time = dt_util.as_local(
                dt_util.utc_from_timestamp(result.timestamp)
            )
        else:
            self.measurement_time = None
        self.last_update = time.monotonic()
        self.measurements.append(result)
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
        self._file_size: int = 0
        self._file_offset: int = 0
        self._got_result = asyncio.Event()
        self._all_files_done = asyncio.Event()
        self._all_files_done.set()
        self._current_client: BleakClient | None = None
        self._last_disconnect: float = 0  # monotonic timestamp
        self._cmd_response = asyncio.Event()
        self._measuring = False  # True if device is actively taking a measurement

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
        """Handle a BLE advertisement from the BP2."""
        self._data.rssi = service_info.rssi
        _LOGGER.debug(
            "BLE advertisement from %s (RSSI: %s, change: %s)",
            self.address,
            service_info.rssi,
            change,
        )
        # Cooldown: avoid reconnecting within 5 seconds of last disconnect
        if (
            not self._connected
            and not self._connecting
            and time.monotonic() - self._last_disconnect > 5
        ):
            self._connecting = True
            self._entry.async_create_background_task(
                self.hass,
                self._connect_and_fetch(),
                name=f"viatom_bp2_connect_{self.address}",
            )

    async def _connect_and_fetch(self) -> None:
        """Connect to the BP2, subscribe to notifications, and fetch data."""
        self._got_result.clear()

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

            def _ble_device_callback():
                return bluetooth.async_ble_device_from_address(
                    self.hass, self.address, connectable=True
                ) or ble_device

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

            # Log available services/characteristics for diagnostics
            for service in client.services:
                for char in service.characteristics:
                    props = ",".join(char.properties)
                    _LOGGER.debug(
                        "  Char %s [%s] props=%s",
                        char.uuid,
                        char.handle,
                        props,
                    )

            # Subscribe to Lepu notify characteristic (protocol responses)
            try:
                await client.start_notify(
                    NOTIFY_UUID, self._notification_handler
                )
                _LOGGER.info(
                    "Subscribed to Lepu notify char %s", NOTIFY_UUID[:12]
                )
            except BleakError as e:
                _LOGGER.warning(
                    "Failed to subscribe to Lepu notify %s: %s",
                    NOTIFY_UUID[:12],
                    e,
                )
                # If we can't subscribe to notifications, we can't communicate
                return

            # Give CCCD write time to propagate through ESPHome proxy
            await asyncio.sleep(0.5)

            # === Run production init sequence ===
            await self._run_init_sequence(client)

        except BleakError as e:
            _LOGGER.warning("BLE error with BP2 at %s: %s", self.address, e)
        except Exception:
            _LOGGER.exception("Unexpected error with BP2 at %s", self.address)
        finally:
            if client is not None:
                await self._disconnect(client)
            self._current_client = None
            self._connecting = False
            self.async_set_updated_data(self._data)

    async def _run_init_sequence(self, client: BleakClient) -> None:
        """Production init sequence: GET_INFO → SYNC_TIME → fetch stored BP data.

        Protocol verified working via direct BLE probe with CRC-8/CCITT.
        Commands are written to WRITE_UUID (8b00ace7) with write-with-response.
        Responses arrive on NOTIFY_UUID (0734594a).

        IMPORTANT: If the device is actively measuring BP, we do NOT send
        file download commands (which would kill the measurement). Instead
        we just wait for the real-time result to arrive.
        """
        _LOGGER.info("=== Starting BP2 init sequence ===")

        # Step 1: Echo/ping to verify communication
        _LOGGER.debug("Step 1: Echo/ping")
        await self._send_and_wait(client, build_echo(), timeout=3.0)

        # Step 2: Get device info (standard CMD 0xE1 — structured response)
        _LOGGER.debug("Step 2: GET_DEVICE_INFO (0xE1)")
        await self._send_and_wait(client, build_get_device_info(), timeout=3.0)

        # Step 3: Get LP-BP2W info (CMD 0x00 — raw registers)
        _LOGGER.debug("Step 3: GET_INFO (0x00)")
        await self._send_and_wait(client, build_get_info(), timeout=3.0)

        # Step 4: Sync time
        _LOGGER.debug("Step 4: SYNC_TIME")
        await self._send_and_wait(client, build_sync_time(), timeout=3.0)

        # Step 5: Get battery
        _LOGGER.debug("Step 5: GET_BATTERY")
        await self._send_and_wait(client, build_get_battery(), timeout=3.0)

        # Step 6: Check if the device is actively measuring.
        # After the info/battery commands, the device may have pushed
        # RT data (CMD 0x08) if a measurement is in progress. The
        # _notification_handler sets self._measuring when it sees
        # RT data with device_status == 0 (BP measuring).
        #
        # Also wait a moment for any queued RT notifications to arrive.
        await asyncio.sleep(0.5)

        if self._measuring:
            # Device is actively measuring — do NOT send file commands.
            # Wait for the measurement to complete (typically 30-60s).
            _LOGGER.info(
                "Device is measuring BP — waiting for result "
                "(not downloading files to avoid interruption)"
            )
            try:
                await asyncio.wait_for(
                    self._got_result.wait(), timeout=90.0
                )
                _LOGGER.info("Got measurement result while device was active")
            except TimeoutError:
                _LOGGER.warning(
                    "Measurement did not complete within 90s"
                )
        else:
            # Device is idle — safe to download stored measurements.
            _LOGGER.info("Step 6: Fetching stored BP measurements")
            self._all_files_done.clear()
            await self._write_command(
                client, build_read_file_start(FILE_BP_LIST)
            )

            # Wait for file download to complete (or timeout)
            try:
                await asyncio.wait_for(
                    self._all_files_done.wait(), timeout=30.0
                )
                _LOGGER.info(
                    "File download complete, %d measurements loaded",
                    len(self._data.measurements),
                )
            except TimeoutError:
                _LOGGER.warning("File download timed out after 30s")

        _LOGGER.info("=== BP2 init sequence complete ===")

    async def _send_and_wait(
        self, client: BleakClient, data: bytes, timeout: float = 3.0
    ) -> bool:
        """Send a command and wait for a response notification."""
        self._cmd_response.clear()
        await self._write_command(client, data)
        try:
            await asyncio.wait_for(
                self._cmd_response.wait(), timeout=timeout
            )
            return True
        except TimeoutError:
            _LOGGER.debug(
                "No response for command %s within %.1fs",
                data[:8].hex() if len(data) >= 8 else data.hex(),
                timeout,
            )
            return False

    async def _write_command(self, client: BleakClient, data: bytes) -> None:
        """Write a command to the Lepu write characteristic.

        Uses write-with-response (WRITE_REQ) — proven working in BLE probe.
        The LP-BP2W's 8b00ace7 char supports both write and write-without-response.
        """
        if client.is_connected:
            try:
                await client.write_gatt_char(WRITE_UUID, data, response=True)
                _LOGGER.debug(
                    "Sent command on %s: %s",
                    WRITE_UUID[:12],
                    data.hex(),
                )
            except BleakError:
                # Fall back to write-without-response
                try:
                    await client.write_gatt_char(
                        WRITE_UUID, data, response=False
                    )
                    _LOGGER.debug(
                        "Sent command (no-resp) on %s: %s",
                        WRITE_UUID[:12],
                        data.hex(),
                    )
                except BleakError as e:
                    _LOGGER.warning("Failed to write command: %s", e)

    def _notification_handler(
        self, _sender: Any, data: bytearray
    ) -> None:
        """Handle raw BLE notification data from the Lepu notify char.

        This callback may be invoked from a background thread (direct BT
        adapters) or from the event loop (ESPHome proxies). We schedule
        the actual processing on the event loop for thread safety.
        """
        raw = bytes(data)
        _LOGGER.debug(
            "BLE notification (%d bytes): %s", len(raw), raw.hex()
        )
        # Signal that we received a response
        self._cmd_response.set()
        self.hass.loop.call_soon_threadsafe(self._reassembler.feed, raw)

    def _handle_packet(self, packet: LepuPacket) -> None:
        """Handle a decoded Lepu protocol V2 packet."""
        _LOGGER.debug(
            "Packet: cmd=0x%02X seq=%d payload_len=%d",
            packet.cmd,
            packet.seq,
            len(packet.payload),
        )

        # Sync time ACK (CMD 0xEC)
        if packet.cmd == CMD_SYNC_TIME:
            _LOGGER.info("Time sync acknowledged")

        # LP-BP2W device info (CMD 0x00) — raw 40-byte response
        elif packet.cmd == CMD_GET_INFO:
            info = parse_device_info_v1(packet.payload)
            # Only update battery from this if we don't have it yet
            if info.battery_level > 0 and self._data.battery_level is None:
                self._data.battery_level = info.battery_level
            _LOGGER.info(
                "LP-BP2W info (CMD 0x00): %d bytes", len(packet.payload)
            )

        # Standard device info (CMD 0xE1) — structured 60-byte response
        elif packet.cmd == CMD_GET_DEVICE_INFO:
            info = parse_device_info(packet.payload)
            self._data.device_info = info
            _LOGGER.info(
                "Device info: hw=%s fw=%s model=%s sn=%s",
                info.hw_version,
                info.fw_version,
                info.model,
                info.serial_number,
            )

        # Echo ACK (CMD 0x0A) — empty response confirms communication
        elif packet.cmd == CMD_ECHO:
            _LOGGER.info("Echo/ping acknowledged — communication verified")

        # Config response (CMD 0x06 or CMD 0x33)
        elif packet.cmd in (CMD_GET_CONFIG, CMD_GET_LP_CONFIG):
            _LOGGER.debug("Config: %s", packet.payload.hex())

        # Battery response (CMD 0x30)
        elif packet.cmd == CMD_GET_BATTERY:
            level, status = parse_battery(packet.payload)
            if level > 0:
                self._data.battery_level = level
                self._data.battery_status = status
            _LOGGER.info("Battery: %d%% (status=%d)", level, status)

        # Real-time data (CMD 0x08) — pushed by device during measurement
        elif packet.cmd == CMD_RT_DATA:
            rt = parse_rt_data(packet.payload)
            self._data.battery_level = rt.battery_level
            self._data.device_status = rt.device_status

            if rt.measuring:
                self._measuring = True
                _LOGGER.debug(
                    "Measuring... cuff pressure: %d", rt.cuff_pressure
                )

            new_result = self._data.update_from_rt(rt)
            if new_result:
                self._measuring = False  # measurement done
                _LOGGER.info(
                    "BP Result: %d/%d mmHg, pulse %d bpm",
                    self._data.systolic,
                    self._data.diastolic,
                    self._data.pulse,
                )
                self._got_result.set()

        # File start response (CMD 0xF2) — returns file size
        elif packet.cmd == CMD_READ_FILE_START:
            if len(packet.payload) >= 4:
                self._file_size = struct.unpack_from(
                    "<I", packet.payload, 0
                )[0]
                _LOGGER.info("File size: %d bytes", self._file_size)
                if self._file_size > 0:
                    self._file_data_buffer.clear()
                    self._file_offset = 0
                    # Request first chunk
                    self._entry.async_create_background_task(
                        self.hass,
                        self._request_file_chunk(0),
                        name=f"viatom_bp2_file_{self.address}",
                    )
                else:
                    _LOGGER.info("File is empty (0 bytes)")
                    self._all_files_done.set()
            else:
                _LOGGER.warning(
                    "Unexpected file start response: %s",
                    packet.payload.hex(),
                )
                self._all_files_done.set()

        # File data response (CMD 0xF3) — contains chunked file data
        elif packet.cmd == CMD_READ_FILE_DATA:
            self._file_data_buffer.extend(packet.payload)
            self._file_offset += len(packet.payload)
            _LOGGER.debug(
                "File data chunk: %d bytes (total %d/%d)",
                len(packet.payload),
                len(self._file_data_buffer),
                self._file_size,
            )
            # Request next chunk if more data remains
            if self._file_offset < self._file_size:
                self._entry.async_create_background_task(
                    self.hass,
                    self._request_file_chunk(self._file_offset),
                    name=f"viatom_bp2_file_{self.address}",
                )
            else:
                # File complete — request file end
                self._entry.async_create_background_task(
                    self.hass,
                    self._finish_file_read(),
                    name=f"viatom_bp2_file_end_{self.address}",
                )

        # File end ACK (CMD 0xF4)
        elif packet.cmd == CMD_READ_FILE_END:
            _LOGGER.debug("File read complete ACK")
            # Parse the accumulated file data
            if self._file_data_buffer:
                results = parse_bp_file(bytes(self._file_data_buffer))
                _LOGGER.info("Parsed %d BP records from file", len(results))
                if results:
                    # Store all measurements
                    self._data.measurements = results[
                        -MAX_STORED_MEASUREMENTS:
                    ]
                    # Set "current" to the most recent by timestamp
                    newest = max(results, key=lambda r: r.timestamp)
                    self._data.update_from_bp_result(newest)
                    _LOGGER.info(
                        "Latest BP: %d/%d mmHg, pulse %d @ %s",
                        newest.systolic,
                        newest.diastolic,
                        newest.pulse,
                        newest.timestamp_str,
                    )
                    self._got_result.set()
                self._file_data_buffer.clear()
            self._all_files_done.set()

        else:
            _LOGGER.debug(
                "Unhandled packet cmd=0x%02X payload=%s",
                packet.cmd,
                packet.payload.hex() if packet.payload else "(empty)",
            )

    async def _request_file_chunk(self, offset: int) -> None:
        """Request a file data chunk at the given offset."""
        if self._current_client is not None:
            await self._write_command(
                self._current_client, build_read_file_data(offset)
            )

    async def _finish_file_read(self) -> None:
        """Send file read end command."""
        if self._current_client is not None:
            await self._write_command(
                self._current_client, build_read_file_end()
            )

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
            self._last_disconnect = time.monotonic()
            _LOGGER.info("Disconnected from BP2 at %s", self.address)

    async def _async_update_data(self) -> ViatomBP2Data:
        """Return the latest data (called by HA coordinator)."""
        return self._data
