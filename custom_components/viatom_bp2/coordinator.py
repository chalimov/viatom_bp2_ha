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
    CMD_RT_DATA,
    CMD_GET_BATTERY,
    CMD_GET_CONFIG,
    CMD_SYNC_TIME,
    CMD_GET_DEVICE_INFO,
    CMD_READ_FILE_START,
    CMD_READ_FILE_DATA,
    CMD_READ_FILE_END,
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
    build_read_file_start,
    build_read_file_data,
    build_read_file_end,
    parse_device_info,
    parse_rt_data,
    parse_bp_file,
    parse_battery,
)

_LOGGER = logging.getLogger(__name__)

# Maximum number of stored measurements to keep in memory
MAX_STORED_MEASUREMENTS = 50

# Maximum BLE connection retries
MAX_CONNECT_RETRIES = 3

# Alternative BLE characteristic UUID (8ec9XXXX service)
# The LP-BP2W uses 8ec90001 as a transport layer: commands are written here
# and ACKs come back, while actual protocol responses arrive on NOTIFY_UUID.
ALT_NOTIFY_UUID = "8ec90001-f315-4f60-9fb8-838830daea50"


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
        self._notification_received = asyncio.Event()
        # Active write UUID — set during connect to transport layer char
        self._active_write_uuid: str = WRITE_UUID

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
                        "  Char %s [%s] props=%s descriptors=%d",
                        char.uuid,
                        char.handle,
                        props,
                        len(char.descriptors),
                    )

            # === Dual-subscribe approach ===
            # The LP-BP2W uses a two-layer architecture:
            #   - Transport layer on 8ec90001 (write commands here, get ACKs)
            #   - Application layer on 0734594a (protocol responses arrive here)
            # We subscribe to BOTH and write through 8ec90001.

            # Subscribe to Lepu application layer (actual protocol responses)
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

            # Subscribe to transport layer (ACKs, may also carry data)
            try:
                await client.start_notify(
                    ALT_NOTIFY_UUID, self._transport_handler
                )
                _LOGGER.info(
                    "Subscribed to transport char %s", ALT_NOTIFY_UUID[:12]
                )
            except BleakError as e:
                _LOGGER.warning(
                    "Failed to subscribe to transport %s: %s",
                    ALT_NOTIFY_UUID[:12],
                    e,
                )

            # Give CCCD writes time to propagate through ESPHome proxy
            await asyncio.sleep(1.5)

            # Use 8ec90001 as the write characteristic
            self._active_write_uuid = ALT_NOTIFY_UUID
            _LOGGER.info(
                "Using write char: %s (transport layer)", ALT_NOTIFY_UUID[:12]
            )

            # === Run Protocol V2 init sequence ===
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
        """Diagnostic init: try multiple write strategies to find one that
        produces actual protocol responses (not just transport ACKs)."""
        cmd = build_sync_time()
        _LOGGER.info("=== DIAGNOSTIC: testing write strategies with sync_time ===")

        # Readable characteristics we can poll after each write
        read_uuids = [
            ("0734594a-a8e7-4b1a-a6b1-cd5243059a57", "Lepu notify"),
            ("8ec90002-f315-4f60-9fb8-838830daea50", "Alt 8ec9-0002"),
            ("8b00ace7-eb0b-49b0-bbe9-9aee0a26e1a3", "Lepu write"),
        ]

        # --- Strategy A: write to 8ec90001 (transport), then READ responses ---
        _LOGGER.info("--- Strategy A: write 8ec90001, read back from chars ---")
        try:
            await client.write_gatt_char(ALT_NOTIFY_UUID, cmd, response=True)
            _LOGGER.info("Strategy A: wrote to 8ec90001: %s", cmd.hex())
        except BleakError as e:
            _LOGGER.warning("Strategy A: write failed: %s", e)
        await asyncio.sleep(1.0)

        for uuid, label in read_uuids:
            char = client.services.get_characteristic(uuid)
            if char and "read" in char.properties:
                try:
                    data = await client.read_gatt_char(uuid)
                    _LOGGER.info(
                        "Strategy A: READ %s (%s) → %d bytes: %s",
                        label, uuid[:12], len(data), data.hex(),
                    )
                except BleakError as e:
                    _LOGGER.info("Strategy A: READ %s failed: %s", label, e)

        await asyncio.sleep(0.5)

        # --- Strategy B: write directly to 0734594a (bidirectional char) ---
        _LOGGER.info("--- Strategy B: write directly to 0734594a ---")
        self._notification_received.clear()
        notify_char = client.services.get_characteristic(NOTIFY_UUID)
        if notify_char and "write" in notify_char.properties:
            use_resp = "write-without-response" not in notify_char.properties
            try:
                await client.write_gatt_char(
                    NOTIFY_UUID, cmd, response=use_resp
                )
                _LOGGER.info(
                    "Strategy B: wrote to 0734594a (response=%s): %s",
                    use_resp, cmd.hex(),
                )
            except BleakError as e:
                _LOGGER.warning("Strategy B: write failed: %s", e)

            # Wait for notification on 0734594a
            try:
                await asyncio.wait_for(
                    self._notification_received.wait(), timeout=3.0
                )
                _LOGGER.info("Strategy B: GOT notification on 0734594a!")
            except TimeoutError:
                _LOGGER.info("Strategy B: no notification after 3s")
        else:
            _LOGGER.info("Strategy B: 0734594a not writable, skipping")

        await asyncio.sleep(0.5)

        # --- Strategy C: write to 8b00ace7 with response=True ---
        _LOGGER.info("--- Strategy C: write to 8b00ace7 response=True ---")
        self._notification_received.clear()
        write_char = client.services.get_characteristic(WRITE_UUID)
        if write_char:
            try:
                await client.write_gatt_char(
                    WRITE_UUID, cmd, response=True
                )
                _LOGGER.info(
                    "Strategy C: wrote to 8b00ace7 (response=True): %s",
                    cmd.hex(),
                )
            except BleakError as e:
                _LOGGER.warning("Strategy C: write failed: %s", e)

            try:
                await asyncio.wait_for(
                    self._notification_received.wait(), timeout=3.0
                )
                _LOGGER.info("Strategy C: GOT notification!")
            except TimeoutError:
                _LOGGER.info("Strategy C: no notification after 3s")

        await asyncio.sleep(0.5)

        # --- Strategy D: write to 8b00ace7 with response=False (original) ---
        _LOGGER.info("--- Strategy D: write to 8b00ace7 response=False ---")
        self._notification_received.clear()
        if write_char:
            try:
                await client.write_gatt_char(
                    WRITE_UUID, cmd, response=False
                )
                _LOGGER.info(
                    "Strategy D: wrote to 8b00ace7 (response=False): %s",
                    cmd.hex(),
                )
            except BleakError as e:
                _LOGGER.warning("Strategy D: write failed: %s", e)

            try:
                await asyncio.wait_for(
                    self._notification_received.wait(), timeout=3.0
                )
                _LOGGER.info("Strategy D: GOT notification!")
            except TimeoutError:
                _LOGGER.info("Strategy D: no notification after 3s")

        _LOGGER.info("=== DIAGNOSTIC COMPLETE ===")

    async def _write_command(self, client: BleakClient, data: bytes) -> None:
        """Write a command to the active write characteristic.

        IMPORTANT: Protocol V2 requires write-without-response (WRITE_CMD).
        Using WRITE_REQ (response=True) causes the device to silently
        ignore all commands on the Lepu service. For other services,
        we auto-detect from characteristic properties.
        """
        if client.is_connected:
            try:
                write_char = client.services.get_characteristic(
                    self._active_write_uuid
                )
                use_response = (
                    write_char is not None
                    and "write-without-response" not in write_char.properties
                )
                await client.write_gatt_char(
                    self._active_write_uuid, data, response=use_response
                )
                _LOGGER.debug(
                    "Sent command on %s: %s",
                    self._active_write_uuid[:12],
                    data.hex(),
                )
            except BleakError as e:
                _LOGGER.warning("Failed to write command: %s", e)

    def _notification_handler(
        self, _sender: Any, data: bytearray
    ) -> None:
        """Handle raw BLE notification data.

        This callback may be invoked from a background thread (direct BT
        adapters) or from the event loop (ESPHome proxies). We schedule
        the actual processing on the event loop for thread safety.
        """
        raw = bytes(data)
        _LOGGER.debug(
            "BLE notification (%d bytes): %s", len(raw), raw.hex()
        )
        # Signal that we received at least one notification (for probing)
        self._notification_received.set()
        self.hass.loop.call_soon_threadsafe(self._reassembler.feed, raw)

    def _transport_handler(
        self, _sender: Any, data: bytearray
    ) -> None:
        """Handle notifications from the transport layer (8ec90001).

        The LP-BP2W sends short ACK frames (e.g. 60 a5 02) on this
        characteristic for every command written.  These are NOT Lepu
        protocol packets — just transport-level acknowledgements.  We
        log them for diagnostics and also forward the raw bytes to the
        reassembler in case the device ever sends full protocol frames
        on this channel.
        """
        raw = bytes(data)
        _LOGGER.debug(
            "Transport notification (%d bytes): %s", len(raw), raw.hex()
        )
        # Short frames (≤4 bytes) are ACKs — log and skip
        if len(raw) <= 4:
            _LOGGER.debug("Transport ACK: %s", raw.hex())
            return
        # Longer frames may carry protocol data — feed to reassembler
        _LOGGER.info(
            "Transport layer sent %d-byte frame, feeding to reassembler",
            len(raw),
        )
        self.hass.loop.call_soon_threadsafe(self._reassembler.feed, raw)

    def _handle_packet(self, packet: LepuPacket) -> None:
        """Handle a decoded Lepu protocol V2 packet."""
        _LOGGER.debug(
            "Packet: cmd=0x%02X seq=0x%04X payload_len=%d",
            packet.cmd,
            packet.seq,
            len(packet.payload),
        )

        # Sync time ACK (CMD 0xC0)
        if packet.cmd == CMD_SYNC_TIME:
            _LOGGER.info("Time sync acknowledged")

        # Device info response (CMD 0x00)
        elif packet.cmd == CMD_GET_INFO:
            info = parse_device_info(packet.payload)
            self._data.device_info = info
            if info.battery_level > 0:
                self._data.battery_level = info.battery_level
            _LOGGER.info(
                "Device info: hw=%s fw=%s sn=%s battery=%d%%",
                info.hw_version,
                info.fw_version,
                info.serial_number,
                info.battery_level,
            )

        # Extended device info (CMD 0xE1)
        elif packet.cmd == CMD_GET_DEVICE_INFO:
            _LOGGER.info(
                "Extended device info: %d bytes", len(packet.payload)
            )

        # Config response (CMD 0x33)
        elif packet.cmd == CMD_GET_CONFIG:
            _LOGGER.debug("Config: %s", packet.payload.hex())

        # Battery response (CMD 0x30)
        elif packet.cmd == CMD_GET_BATTERY:
            level, status = parse_battery(packet.payload)
            if level > 0:
                self._data.battery_level = level
                self._data.battery_status = status
            _LOGGER.info("Battery: %d%% (status=%d)", level, status)

        # Real-time data (CMD 0x08) — pushed by device
        elif packet.cmd == CMD_RT_DATA:
            rt = parse_rt_data(packet.payload)
            self._data.battery_level = rt.battery_level
            self._data.device_status = rt.device_status
            new_result = self._data.update_from_rt(rt)
            if new_result:
                _LOGGER.info(
                    "BP Result: %d/%d mmHg, pulse %d bpm",
                    self._data.systolic,
                    self._data.diastolic,
                    self._data.pulse,
                )
                self._got_result.set()
            elif rt.measuring:
                _LOGGER.debug(
                    "Measuring... cuff pressure: %d", rt.cuff_pressure
                )

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
                for r in results:
                    self._data.update_from_bp_result(r)
                    _LOGGER.info(
                        "Stored BP: %d/%d mmHg, pulse %d @ %s",
                        r.systolic,
                        r.diastolic,
                        r.pulse,
                        r.timestamp_str,
                    )
                self._file_data_buffer.clear()
                if results:
                    self._got_result.set()
            self._all_files_done.set()

        else:
            _LOGGER.debug(
                "Unhandled packet cmd=0x%02X payload=%s",
                packet.cmd,
                packet.payload.hex(),
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
                # Stop notifications on both subscribed characteristics
                for uuid in (NOTIFY_UUID, ALT_NOTIFY_UUID):
                    try:
                        await client.stop_notify(uuid)
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
