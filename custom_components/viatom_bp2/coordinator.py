"""Data coordinator for Viatom BP2 Blood Pressure Monitor.

Uses a persistent BLE connection with CMD 0x06 (GET_CONFIG) state polling
to detect measurement activity and fetch results via disconnect-reconnect.

FIRMWARE QUIRK — FILE_START REJECTION ON FIRST CONNECTION:
  The LP-BP2W often rejects FILE_START (CMD 0xF2) with byte[3]=0xE1 on
  the very first BLE connection after device boot.  The second connection
  (after a clean disconnect) always succeeds.  Root cause unknown — the
  device may need a BLE session cycle before file transfer is ready.

FIRMWARE LIMITATION — ONE TRANSFER PER CONNECTION:
  The LP-BP2W firmware allows only ONE FILE_START per BLE connection.
  A second FILE_START on the same connection returns byte[3]=0xe1.

ALGORITHM — RECONNECT-DURING-MEASUREMENT:
  Connect → housekeeping → poll loop.  One persistent flag controls
  whether to fetch or just monitor:

    _fetch_succeeded=False (need data):
      RESULT or IDLE → fetch
        success → _fetch_succeeded=True, stay connected, keep monitoring
        rejected → disconnect → fast reconnect → retry
      BUSY → just monitor (wait for result)

    _fetch_succeeded=True (have data, monitoring):
      BUSY detected → need fresh FILE_START slot for upcoming fetch:
        Single (MEASURING) → disconnect → reconnect immediately
        Triple (TRIPLE-MEAS) → count transitions, reconnect on 3rd
      RESULT/IDLE → do nothing, just poll
      IDLE 120s → disconnect (idle timeout)

  After reconnect during measurement, _fetch_succeeded is reset to False
  (non-fetch exit), so the poll loop will fetch when RESULT arrives.
  The reconnect happens close to the fetch, keeping the slot fresh.

SAFE commands (no screen change, invisible to user):
  CMD 0x00 (GET_INFO), 0x06 (GET_CONFIG), 0x30 (GET_BATTERY),
  0xE1 (GET_DEVICE_INFO), 0xEC (SYNC_TIME), 0xF1 (READ_FILE_LIST)

VISUAL commands (show brief transfer icon, auto-resolves on disconnect):
  0xF2 (READ_FILE_START), 0xF3 (READ_FILE_DATA), 0xF4 (READ_FILE_END)

DANGEROUS — NEVER send on LP-BP2W:
  0x04 (FACTORY_RESET), 0x09 (SWITCH_STATE / start measurement),
  0x0A ("ECHO" = START_MEASUREMENT), 0x24/0x25 (inflate),
  0x39 (inflate + disconnect), 0xE2 (DEVICE_RESET), 0xE3 (FACTORY_RESET_STD)
"""

from __future__ import annotations

import asyncio
import dataclasses
from datetime import datetime, timedelta, timezone
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
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import dt as dt_util

# How often the HA framework calls _async_update_data as a fallback.
# 30s is fast enough to catch a device that powered on but whose
# advertisements were missed by the bluetooth callback.
RECONNECT_INTERVAL = timedelta(seconds=30)

from .const import (
    DOMAIN,
    WRITE_UUID,
    NOTIFY_UUID,
)
from .protocol import (
    CMD_GET_INFO,
    CMD_GET_DEVICE_INFO,
    CMD_RT_DATA,
    CMD_GET_CONFIG,
    CMD_SYNC_TIME,
    CMD_READ_FILE_START,
    CMD_READ_FILE_DATA,
    CMD_READ_FILE_END,
    CMD_GET_LP_CONFIG,
    FILE_BP_LIST,
    DEVICE_STATE_IDLE,
    DEVICE_STATE_MEASURING,
    DEVICE_STATE_TRIPLE_MEAS,
    DEVICE_STATES_RESULT,
    DEVICE_STATES_BUSY,
    BpResult,
    DeviceInfo,
    RtData,
    PacketReassembler,
    LepuPacket,
    build_get_config,
    build_get_device_info,
    build_sync_time,
    build_read_file_start,
    build_read_file_data,
    build_read_file_end,
    parse_device_info,
    parse_device_info_v1,
    parse_rt_data,
    parse_bp_file,
)

_LOGGER = logging.getLogger(__name__)

# Maximum number of stored measurements to keep in memory
MAX_STORED_MEASUREMENTS = 50

# Maximum BLE connection retries (2 is enough — first attempt may fail
# while ESPHome proxy warms up after HA restart, second succeeds)
MAX_CONNECT_RETRIES = 2

# Post-connect stabilization delay (seconds).
# GATT services need time to be discovered after the low-level connection.
# ESPHome proxies also benefit from a brief stabilization window.
# Validated via direct BLE testing: 2s is reliable, 1s causes drops.
POST_CONNECT_DELAY = 2.0

# Max subscribe retry attempts
MAX_SUBSCRIBE_RETRIES = 3

# How often to poll CMD 0x06 for device state (seconds).
# 5s is fast enough to catch brief state-5/17 appearances,
# slow enough to not spam the BLE link.
STATE_POLL_INTERVAL = 5

# File download timeout (seconds) — generous for large files over BLE
FILE_DOWNLOAD_TIMEOUT = 30.0

# Disconnect after this many seconds of continuous idle (state 3).
# Frees the BLE proxy slot for other devices.
IDLE_DISCONNECT_TIMEOUT = 120

# Persistent storage for measurement history
STORAGE_VERSION = 1
STORAGE_KEY_PREFIX = "viatom_bp2"

# State name map for logging
_STATE_NAMES = {
    3: "IDLE",
    4: "MEASURING",
    5: "RESULT",
    15: "TRIPLE-MEAS",
    16: "TRIPLE-PAUSE",
    17: "TRIPLE-RESULT",
}


class ViatomBP2Data:
    """Container for the latest data from the BP2 device."""

    def __init__(self) -> None:
        self.systolic: int | None = None
        self.diastolic: int | None = None
        self.mean_arterial_pressure: int | None = None  # MAP (mmHg)
        self.heart_rate: int | None = None  # HR (bpm) — shown on device screen
        self.pulse_pressure: int | None = None  # PP = sys - dia (calculated)
        self.user_id: int | None = None  # active user's Viatom cloud account ID
        self.irregular_heartbeat: bool = False
        self.measurement_time: str | None = None  # ISO format string
        self.battery_level: int | None = None
        self.battery_status: int | None = None
        self.device_status: int | None = None
        self.device_info: DeviceInfo | None = None
        self.device_state_text: str = "Disconnected"  # human-readable device state
        self.rssi: int | None = None
        self.last_update: float = 0
        self.measurements: list[BpResult] = []
        # Set of (timestamp, systolic, diastolic, map) to track known records
        self._known_keys: set[tuple[int, int, int, int]] = set()

    def update_from_bp_result(self, result: BpResult) -> None:
        """Update from a stored BP file result (newest record)."""
        self.systolic = result.systolic
        self.diastolic = result.diastolic
        self.mean_arterial_pressure = result.mean_arterial_pressure
        self.heart_rate = result.heart_rate
        self.pulse_pressure = result.pulse_pressure
        self.user_id = result.user_id
        self.irregular_heartbeat = result.irregular_heartbeat
        if result.timestamp > 0:
            # Use HA timezone for consistent display
            utc_dt = datetime.fromtimestamp(result.timestamp, tz=timezone.utc)
            local_dt = dt_util.as_local(utc_dt)
            self.measurement_time = local_dt.strftime("%Y-%m-%d %H:%M:%S")
        else:
            self.measurement_time = None
        self.last_update = time.monotonic()

    def update_from_rt(self, rt: RtData) -> bool:
        """Update from real-time data. Returns True if a new result is available."""
        self.device_status = rt.device_status
        self.battery_level = rt.battery_level
        self.battery_status = rt.battery_status
        if rt.result_ready and rt.systolic > 0:
            self.systolic = rt.systolic
            self.diastolic = rt.diastolic
            self.mean_arterial_pressure = rt.mean_arterial_pressure
            self.heart_rate = rt.heart_rate
            self.pulse_pressure = rt.systolic - rt.diastolic
            now = dt_util.now()
            self.measurement_time = now.isoformat()
            self.last_update = time.monotonic()
            result = BpResult(
                systolic=rt.systolic,
                diastolic=rt.diastolic,
                mean_arterial_pressure=rt.mean_arterial_pressure,
                heart_rate=rt.heart_rate,
                pulse_pressure=rt.systolic - rt.diastolic,
                timestamp=int(now.timestamp()),
            )
            self.measurements.append(result)
            if len(self.measurements) > MAX_STORED_MEASUREMENTS:
                self.measurements = self.measurements[-MAX_STORED_MEASUREMENTS:]
            return True
        return False

    def ingest_file_records(self, records: list[BpResult]) -> int:
        """Ingest parsed BP records, deduplicating against known records.

        Returns the number of new records added.
        """
        new_count = 0
        for r in records:
            key = (r.timestamp, r.systolic, r.diastolic, r.mean_arterial_pressure)
            if key not in self._known_keys:
                self._known_keys.add(key)
                self.measurements.append(r)
                new_count += 1

        # Trim measurements and known_keys to prevent unbounded growth
        if len(self.measurements) > MAX_STORED_MEASUREMENTS:
            self.measurements = self.measurements[-MAX_STORED_MEASUREMENTS:]
        max_known = MAX_STORED_MEASUREMENTS * 4
        if len(self._known_keys) > max_known:
            # Keep only keys for measurements still in the list
            retained = {
                (m.timestamp, m.systolic, m.diastolic, m.mean_arterial_pressure)
                for m in self.measurements
            }
            self._known_keys = retained

        # Update "current" to newest record by timestamp
        if records:
            newest = max(records, key=lambda r: r.timestamp)
            self.update_from_bp_result(newest)

        return new_count


class ViatomBP2Coordinator(DataUpdateCoordinator[ViatomBP2Data]):
    """Coordinator for Viatom BP2 BLE data.

    Uses persistent BLE connection with CMD 0x06 state polling to detect
    measurements and fetch results. See module docstring for algorithm.
    """

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        address: str,
        name: str,
        user_names: dict[int, str] | None = None,
    ) -> None:
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_{address}",
            update_interval=RECONNECT_INTERVAL,
        )
        self.address = address
        self.device_name = name
        self.user_names = user_names or {}  # user_id → friendly name
        self._entry = entry
        self._data = ViatomBP2Data()
        self._connected = False
        self._connecting = False
        self._reassembler = PacketReassembler()
        self._reassembler.on_packet = self._handle_packet
        # File transfer state
        self._file_data_buffer = bytearray()
        self._file_size: int = 0
        self._file_offset: int = 0
        self._all_files_done = asyncio.Event()
        self._all_files_done.set()
        # BLE connection state
        self._current_client: BleakClient | None = None
        self._last_disconnect: float = 0  # monotonic timestamp
        # Task tracking — prevent concurrent connections
        self._monitor_task: asyncio.Task | None = None
        self._reconnect_task: asyncio.Task | None = None
        # Per-command response events: cmd_byte → asyncio.Event
        self._pending_responses: dict[int, asyncio.Event] = {}
        # Device state polling (CMD 0x06 byte[0])
        self._device_state: int | None = None  # last polled state
        # Poll loop state machine — single flag algorithm
        self._fetch_succeeded = False  # persists across connections
        self._last_fetch_new_count: int = 0  # result of last file download
        self._new_data_pending = False  # triggers fast 1s reconnect
        # Persistent storage for measurement history
        self._store = Store(
            hass, STORAGE_VERSION, f"{STORAGE_KEY_PREFIX}_{address}"
        )

    @property
    def bp_data(self) -> ViatomBP2Data:
        """Return current data."""
        return self._data

    # ------------------------------------------------------------------
    # BLE advertisement handler — triggers connection
    # ------------------------------------------------------------------
    @callback
    def handle_bluetooth_event(
        self,
        service_info: BluetoothServiceInfoBleak,
        change: bluetooth.BluetoothChange,
    ) -> None:
        """Handle a BLE advertisement from the BP2.

        Called by HA bluetooth when the device is seen advertising.
        This means the device is awake (screen on). We connect and
        stay connected, polling device state until idle timeout.
        """
        self._data.rssi = service_info.rssi
        now = time.monotonic()
        _LOGGER.debug(
            "BLE advertisement from %s (RSSI: %s, change: %s, "
            "connected=%s, connecting=%s, since_disconnect=%.0fs)",
            self.address,
            service_info.rssi,
            change,
            self._connected,
            self._connecting,
            now - self._last_disconnect if self._last_disconnect else 0,
        )
        # Connect if:
        # 1. Not currently connected or connecting
        # 2. No active monitor/reconnect task running
        # 3. At least 10 seconds since last disconnect (connection cooldown)
        if (
            not self._connected
            and not self._connecting
            and not self._has_active_task()
            and now - self._last_disconnect > 10
        ):
            _LOGGER.info(
                "Device %s is advertising — initiating connection",
                self.address,
            )
            self._start_monitor()

    # ------------------------------------------------------------------
    # Task management — prevent concurrent connections
    # ------------------------------------------------------------------
    def _has_active_task(self) -> bool:
        """Check if a monitor or reconnect task is still running."""
        if self._monitor_task and not self._monitor_task.done():
            return True
        if self._reconnect_task and not self._reconnect_task.done():
            return True
        return False

    def _cancel_reconnect(self) -> None:
        """Cancel any pending reconnect task."""
        if self._reconnect_task and not self._reconnect_task.done():
            self._reconnect_task.cancel()
            self._reconnect_task = None

    def _start_monitor(self) -> None:
        """Start a new _connect_and_monitor task, cancelling any existing."""
        self._cancel_reconnect()
        if self._monitor_task and not self._monitor_task.done():
            self._monitor_task.cancel()
        self._connecting = True
        self._monitor_task = self._entry.async_create_background_task(
            self.hass,
            self._connect_and_monitor(),
            name=f"viatom_bp2_connect_{self.address}",
        )

    def _start_reconnect(self) -> None:
        """Start a reconnect loop task (only if no active tasks)."""
        if self._has_active_task():
            _LOGGER.debug("Skipping reconnect — task already active")
            return
        self._reconnect_task = self._entry.async_create_background_task(
            self.hass,
            self._reconnect_loop(),
            name=f"viatom_bp2_reconnect_{self.address}",
        )

    # ------------------------------------------------------------------
    # Connect, housekeep, then enter poll loop
    # ------------------------------------------------------------------
    async def _connect_and_monitor(self) -> None:
        """Connect to BP2, run housekeeping, then poll loop."""
        # Reset per-connection state (but NOT _fetch_succeeded — it persists)
        self._new_data_pending = False
        self._reassembler.reset()
        self._file_data_buffer.clear()
        self._file_size = 0
        self._file_offset = 0
        self._device_state = None

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
            self._data.device_state_text = "Connecting"
            self.async_set_updated_data(self._data)

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
            self._connecting = False
            self.last_update_success = True
            _LOGGER.info("Connected to BP2 at %s", self.address)

            # --- Post-connect stabilization ---
            await asyncio.sleep(POST_CONNECT_DELAY)

            # --- Subscribe to notifications with retry ---
            subscribed = False
            for attempt in range(MAX_SUBSCRIBE_RETRIES):
                try:
                    await client.start_notify(
                        NOTIFY_UUID, self._notification_handler
                    )
                    subscribed = True
                    _LOGGER.info(
                        "Subscribed to Lepu notify char %s",
                        NOTIFY_UUID[:12],
                    )
                    break
                except BleakError as e:
                    if attempt < MAX_SUBSCRIBE_RETRIES - 1:
                        _LOGGER.warning(
                            "Subscribe attempt %d/%d failed: %s, retrying...",
                            attempt + 1,
                            MAX_SUBSCRIBE_RETRIES,
                            e,
                        )
                        await asyncio.sleep(1)
                    else:
                        _LOGGER.warning(
                            "Failed to subscribe after %d attempts: %s",
                            MAX_SUBSCRIBE_RETRIES,
                            e,
                        )

            if not subscribed:
                return

            # Give CCCD write time to propagate through ESPHome proxy
            await asyncio.sleep(0.3)

            # === Housekeeping ===
            # Skip device info on fast reconnects — we already have it
            if self._data.device_info is None:
                _LOGGER.info("=== Housekeeping ===")
                await self._send_and_wait(
                    client, build_get_device_info(), timeout=3.0
                )
            else:
                _LOGGER.info("=== Housekeeping (quick) ===")
            # Sync device clock using HA's configured timezone
            ha_now = dt_util.now().timetuple()
            await self._send_and_wait(client, build_sync_time(ha_now), timeout=3.0)

            # === State poll loop ===
            # No separate fetch phase — the poll loop handles everything
            # via the single _fetch_succeeded flag.
            _LOGGER.info("=== Entering state poll loop ===")
            await self._poll_loop(client)

        except BleakError as e:
            _LOGGER.warning("BLE error with BP2 at %s: %s", self.address, e)
            self.last_update_success = False
        except Exception:
            _LOGGER.exception("Unexpected error with BP2 at %s", self.address)
            self.last_update_success = False
        finally:
            if client is not None:
                await self._disconnect(client)
            self._current_client = None
            self._connecting = False
            self.async_set_updated_data(self._data)

            # Clear _monitor_task BEFORE starting reconnect, so
            # _has_active_task() doesn't see the current (finishing) task.
            self._monitor_task = None

            # Schedule reconnection attempts — the bluetooth callback may not
            # fire again if the ESPHome proxy cached the device address. We
            # actively retry for up to 60s after disconnect to catch a device
            # that is still on (or turned back on quickly).
            self._start_reconnect()

    # ------------------------------------------------------------------
    # Poll loop — CMD 0x06 every 5s, reconnect-during-measurement
    # ------------------------------------------------------------------
    async def _poll_loop(self, client: BleakClient) -> None:
        """Poll device state via CMD 0x06, handle measurement lifecycle.

        Single flag: _fetch_succeeded (persists across connections).

          BUSY when _fetch_succeeded=True → reconnect to refresh FILE_START slot
            - Single (MEASURING): reconnect immediately
            - Triple (TRIPLE-MEAS): reconnect on 3rd measurement start
          BUSY when _fetch_succeeded=False → just monitor
          RESULT/IDLE when _fetch_succeeded=False → fetch
            - Rejected → disconnect for immediate reconnect
            - Success → continue monitoring on same connection
          RESULT/IDLE when _fetch_succeeded=True → just monitor
          IDLE 120s → disconnect (idle timeout)
        """
        idle_since: float | None = None
        consecutive_errors = 0
        exited_after_fetch = False
        # Track whether this connection's FILE_START slot is stale (already
        # used) and we need to reconnect before the next fetch.
        needs_slot_refresh = False
        # Count transitions INTO TRIPLE-MEAS (not raw polls) to detect 3rd.
        triple_meas_count = 0
        prev_state: int | None = None

        while client.is_connected:
            state = await self._poll_device_state(client)

            if state is None:
                consecutive_errors += 1
                if consecutive_errors >= 3:
                    _LOGGER.warning(
                        "3 consecutive poll failures — connection may be lost"
                    )
                    break
                await asyncio.sleep(STATE_POLL_INTERVAL)
                continue

            consecutive_errors = 0
            state_name = _STATE_NAMES.get(state, f"?({state})")

            self._data.device_state_text = state_name
            self.async_set_updated_data(self._data)

            if state in DEVICE_STATES_BUSY:
                idle_since = None

                # First BUSY after a successful fetch — we need a fresh slot.
                if self._fetch_succeeded:
                    needs_slot_refresh = True
                    triple_meas_count = 0
                    self._fetch_succeeded = False

                if needs_slot_refresh:
                    if state == DEVICE_STATE_MEASURING:
                        # Single measurement — reconnect now for fresh slot.
                        _LOGGER.info(
                            "State %d (%s) — single measurement, "
                            "reconnecting for fresh FILE_START slot",
                            state,
                            state_name,
                        )
                        self._new_data_pending = True
                        break

                    if (
                        state == DEVICE_STATE_TRIPLE_MEAS
                        and prev_state != DEVICE_STATE_TRIPLE_MEAS
                    ):
                        # Transition INTO TRIPLE-MEAS (from PAUSE or start).
                        triple_meas_count += 1
                        if triple_meas_count >= 3:
                            _LOGGER.info(
                                "State %d (%s) — 3rd triple measurement, "
                                "reconnecting for fresh FILE_START slot",
                                state,
                                state_name,
                            )
                            self._new_data_pending = True
                            break
                        _LOGGER.debug(
                            "State %d (%s) — triple measurement %d/3, "
                            "waiting",
                            state,
                            state_name,
                            triple_meas_count,
                        )
                    else:
                        _LOGGER.debug(
                            "State %d (%s) — measurement in progress",
                            state,
                            state_name,
                        )
                else:
                    self._fetch_succeeded = False
                    _LOGGER.debug(
                        "State %d (%s) — measurement in progress",
                        state,
                        state_name,
                    )

            elif state in DEVICE_STATES_RESULT or state == DEVICE_STATE_IDLE:
                if not self._fetch_succeeded:
                    _LOGGER.info(
                        "State %d (%s) — fetching data",
                        state,
                        state_name,
                    )
                    new_count = await self._fetch_bp_data(client)
                    if new_count == -1:
                        _LOGGER.info(
                            "Fetch rejected — disconnecting for "
                            "immediate reconnect"
                        )
                        self._new_data_pending = True
                        self.async_set_updated_data(self._data)
                        exited_after_fetch = True
                        break

                    self._fetch_succeeded = True
                    needs_slot_refresh = False
                    triple_meas_count = 0
                    _LOGGER.info(
                        "Fetch complete: %d new records (%d total known)",
                        new_count,
                        len(self._data._known_keys),
                    )
                    self.async_set_updated_data(self._data)
                    self.hass.async_create_task(self.async_save_data())

                else:
                    # _fetch_succeeded=True — just monitor
                    _LOGGER.debug(
                        "State %d (%s) — already fetched, monitoring",
                        state,
                        state_name,
                    )

                if state == DEVICE_STATE_IDLE:
                    if idle_since is None:
                        idle_since = time.monotonic()
                else:
                    idle_since = None

            # --- Idle disconnect timeout ---
            if (
                idle_since is not None
                and time.monotonic() - idle_since > IDLE_DISCONNECT_TIMEOUT
            ):
                _LOGGER.info(
                    "Idle for %ds — disconnecting to free BLE proxy slot",
                    IDLE_DISCONNECT_TIMEOUT,
                )
                break

            prev_state = state
            await asyncio.sleep(STATE_POLL_INTERVAL)

        # Reset _fetch_succeeded if we exited due to idle timeout, connection
        # loss, or errors (NOT after a fetch).  This ensures the next connection
        # will fetch — the device may have new data we missed while disconnected.
        if not exited_after_fetch:
            self._fetch_succeeded = False

    async def _poll_device_state(self, client: BleakClient) -> int | None:
        """Send CMD 0x06 (GET_CONFIG) and extract device state from byte[0].

        CMD 0x00 (GET_INFO) does NOT get responses through ESPHome BLE proxies.
        CMD 0x06 (GET_CONFIG) returns 9 bytes with device state at byte[0],
        using the same state codes (3=IDLE, 4=MEASURING, 5=RESULT, etc.).

        Returns the state integer (3, 4, 5, 15, 16, 17) or None on failure.
        """
        self._device_state = None

        ok = await self._send_and_wait(
            client, build_get_config(), timeout=3.0
        )
        if not ok:
            return None

        return self._device_state

    # ------------------------------------------------------------------
    # File download helper — called by poll loop on RESULT/IDLE
    # ------------------------------------------------------------------
    async def _fetch_bp_data(self, client: BleakClient) -> int:
        """Download bp2nibp.list and ingest records.

        Called once per connection by the poll loop (on RESULT or IDLE
        when _fetch_succeeded is False).  The firmware rejects a second
        FILE_START on the same connection with byte[3]=0xe1.

        Returns:
          -1  if FILE_START was rejected (0xE1 error, empty payload)
           0  if file was empty or timed out
          >0  number of NEW records found (after deduplication)
        """
        self._file_data_buffer.clear()
        self._file_size = 0
        self._file_offset = 0
        self._all_files_done.clear()
        self._last_fetch_new_count = 0

        _LOGGER.debug("Sending FILE_START for %s", FILE_BP_LIST)
        await self._write_command(
            client, build_read_file_start(FILE_BP_LIST)
        )

        try:
            await asyncio.wait_for(
                self._all_files_done.wait(), timeout=FILE_DOWNLOAD_TIMEOUT
            )
        except TimeoutError:
            _LOGGER.warning(
                "File download timed out after %.0fs — sending FILE_END cleanup",
                FILE_DOWNLOAD_TIMEOUT,
            )
            try:
                await self._write_command(client, build_read_file_end())
            except BleakError:
                pass
            self._file_data_buffer.clear()
            return 0

        return self._last_fetch_new_count

    # ------------------------------------------------------------------
    # Low-level BLE helpers
    # ------------------------------------------------------------------
    async def _send_and_wait(
        self, client: BleakClient, data: bytes, timeout: float = 3.0
    ) -> bool:
        """Send a command and wait for the matching response by command byte."""
        # Extract the command byte from the Lepu packet (byte[1])
        cmd_byte = data[1] if len(data) >= 2 else 0
        event = asyncio.Event()
        self._pending_responses[cmd_byte] = event
        try:
            await self._write_command(client, data)
            await asyncio.wait_for(event.wait(), timeout=timeout)
            return True
        except TimeoutError:
            _LOGGER.debug(
                "No response for cmd 0x%02X within %.1fs", cmd_byte, timeout
            )
            return False
        finally:
            self._pending_responses.pop(cmd_byte, None)

    async def _write_command(self, client: BleakClient, data: bytes) -> None:
        """Write a command to the Lepu write characteristic."""
        if not client.is_connected:
            return
        try:
            await client.write_gatt_char(WRITE_UUID, data, response=True)
            _LOGGER.debug(
                "Sent command on %s: %s",
                WRITE_UUID[:12],
                data.hex(),
            )
        except BleakError as first_err:
            _LOGGER.debug(
                "Write-with-response failed (%s), trying without response",
                first_err,
            )
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

        Called from the Bleak BLE thread — must use call_soon_threadsafe
        for all event loop operations (asyncio.Event is not thread-safe).
        """
        raw = bytes(data)
        _LOGGER.debug(
            "BLE notification (%d bytes): %s", len(raw), raw.hex()
        )
        self.hass.loop.call_soon_threadsafe(self._reassembler.feed, raw)

    # ------------------------------------------------------------------
    # Packet handler — dispatches decoded Lepu protocol packets
    # ------------------------------------------------------------------
    def _handle_packet(self, packet: LepuPacket) -> None:
        """Handle a decoded Lepu protocol V2 packet.

        Runs on the event loop (scheduled via call_soon_threadsafe).
        """
        _LOGGER.debug(
            "Packet: cmd=0x%02X seq=%d payload_len=%d",
            packet.cmd,
            packet.seq,
            len(packet.payload),
        )

        # Signal per-command response event (if anyone is waiting)
        event = self._pending_responses.get(packet.cmd)
        if event is not None:
            event.set()

        # Sync time ACK (CMD 0xEC)
        if packet.cmd == CMD_SYNC_TIME:
            _LOGGER.info("Time sync acknowledged")

        # LP-BP2W device info (CMD 0x00) — raw 40-byte response
        # Also contains device state at byte[39]
        elif packet.cmd == CMD_GET_INFO:
            info = parse_device_info_v1(packet.payload)
            if info.battery_level > 0 and self._data.battery_level is None:
                self._data.battery_level = info.battery_level
            # Extract device state from byte[39]
            if len(packet.payload) >= 40:
                self._device_state = packet.payload[39]
                state_name = _STATE_NAMES.get(self._device_state, "?")
                _LOGGER.debug(
                    "CMD 0x00 state: %d (%s)", self._device_state, state_name
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

        # Config response (CMD 0x06) — byte[0] = device state
        # This is the primary state polling command (replaces CMD 0x00
        # which does not get responses through ESPHome BLE proxies).
        elif packet.cmd == CMD_GET_CONFIG:
            if len(packet.payload) >= 1:
                self._device_state = packet.payload[0]
                state_name = _STATE_NAMES.get(self._device_state, "?")
                _LOGGER.debug(
                    "CMD 0x06 state: %d (%s), payload: %s",
                    self._device_state,
                    state_name,
                    packet.payload.hex(),
                )
            # Battery from CMD 0x06: byte[1]=status, byte[2]=level (0-100%)
            if len(packet.payload) >= 3:
                bat_status = packet.payload[1]
                bat_level = packet.payload[2]
                if 0 <= bat_level <= 100:
                    self._data.battery_level = bat_level
                    self._data.battery_status = bat_status
            if len(packet.payload) < 1:
                _LOGGER.debug("CMD 0x06 empty payload: %s", packet.payload.hex())

        # LP config response (CMD 0x33)
        elif packet.cmd == CMD_GET_LP_CONFIG:
            _LOGGER.debug("LP Config: %s", packet.payload.hex())

        # Real-time data (CMD 0x08) — pushed by device during measurement
        elif packet.cmd == CMD_RT_DATA:
            rt = parse_rt_data(packet.payload)
            self._data.battery_level = rt.battery_level
            self._data.device_status = rt.device_status
            if rt.measuring:
                _LOGGER.debug(
                    "RT_DATA: measuring, cuff pressure: %d", rt.cuff_pressure
                )
            new_result = self._data.update_from_rt(rt)
            if new_result:
                _LOGGER.info(
                    "RT_DATA result: %d/%d mmHg, MAP %d, HR %d bpm",
                    self._data.systolic,
                    self._data.diastolic,
                    self._data.mean_arterial_pressure,
                    self._data.heart_rate,
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
                    _LOGGER.info("File is empty (0 bytes)")
                    self._last_fetch_new_count = 0
                    self._all_files_done.set()
            else:
                _LOGGER.warning(
                    "FILE_START rejected (0xE1 error, payload=%s) — "
                    "device may need a reconnect before file transfer works",
                    packet.payload.hex(),
                )
                self._last_fetch_new_count = -1
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
            if self._file_offset < self._file_size:
                self._entry.async_create_background_task(
                    self.hass,
                    self._request_file_chunk(self._file_offset),
                    name=f"viatom_bp2_file_{self.address}",
                )
            else:
                self._entry.async_create_background_task(
                    self.hass,
                    self._finish_file_read(),
                    name=f"viatom_bp2_file_end_{self.address}",
                )

        # File end ACK (CMD 0xF4)
        elif packet.cmd == CMD_READ_FILE_END:
            _LOGGER.debug("File read complete ACK")
            self._last_fetch_new_count = 0
            if self._file_data_buffer and self._file_size > 0:
                if len(self._file_data_buffer) != self._file_size:
                    _LOGGER.warning(
                        "File size mismatch: expected %d, got %d bytes",
                        self._file_size,
                        len(self._file_data_buffer),
                    )
            if self._file_data_buffer:
                results = parse_bp_file(bytes(self._file_data_buffer))
                _LOGGER.info("Parsed %d BP records from file", len(results))
                if results:
                    new_count = self._data.ingest_file_records(results)
                    self._last_fetch_new_count = new_count
                    _LOGGER.info(
                        "Ingested %d new records (%d total known)",
                        new_count,
                        len(self._data._known_keys),
                    )
                    user_ids = sorted(set(r.user_id for r in results if r.user_id))
                    if user_ids:
                        _LOGGER.info("User IDs in records: %s", user_ids)
                    newest = max(results, key=lambda r: r.timestamp)
                    _LOGGER.info(
                        "Latest BP: %d/%d mmHg, MAP %d, HR %d, "
                        "user %d @ %s",
                        newest.systolic,
                        newest.diastolic,
                        newest.mean_arterial_pressure,
                        newest.heart_rate,
                        newest.user_id,
                        newest.timestamp_str,
                    )
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
        try:
            if self._current_client is not None:
                await self._write_command(
                    self._current_client, build_read_file_data(offset)
                )
        except Exception:
            _LOGGER.warning("File chunk request failed at offset %d", offset)
            self._all_files_done.set()

    async def _finish_file_read(self) -> None:
        """Send file read end command."""
        try:
            if self._current_client is not None:
                await self._write_command(
                    self._current_client, build_read_file_end()
                )
        except Exception:
            _LOGGER.warning("File read end command failed")
            self._all_files_done.set()

    # ------------------------------------------------------------------
    # Post-disconnect reconnection loop
    # ------------------------------------------------------------------
    async def _reconnect_loop(self) -> None:
        """Actively try to reconnect after disconnect.

        The HA bluetooth callback (handle_bluetooth_event) may not fire again
        after disconnect — the ESPHome proxy can cache the device address and
        HA may not report repeated identical advertisements as "changes".

        When _new_data_pending is True (measurement detected in poll loop),
        uses a fast 1s interval to minimize the delay before fetching new
        data on the reconnected session.  Otherwise checks every 15s.
        """
        fast = self._new_data_pending
        interval = 1 if fast else 15
        max_attempts = 60 if fast else 8  # 60×1s=60s or 8×15s=120s

        _LOGGER.info(
            "Starting reconnect loop for %s (fast=%s, interval=%ds)",
            self.address,
            fast,
            interval,
        )

        for attempt in range(max_attempts):
            await asyncio.sleep(interval)

            # Bail if someone else already connected
            if self._connected or self._connecting:
                _LOGGER.debug(
                    "Reconnect loop: already %s, stopping",
                    "connected" if self._connected else "connecting",
                )
                return

            ble_device = bluetooth.async_ble_device_from_address(
                self.hass, self.address, connectable=True
            )
            if ble_device is not None:
                _LOGGER.info(
                    "Reconnect loop: device %s available (attempt %d/%d), connecting",
                    self.address,
                    attempt + 1,
                    max_attempts,
                )
                self._start_monitor()
                return
            else:
                _LOGGER.debug(
                    "Reconnect loop: device %s not available (attempt %d/%d)",
                    self.address,
                    attempt + 1,
                    max_attempts,
                )

        # Clear the pending flag so the next connection uses normal interval.
        self._new_data_pending = False

        _LOGGER.info(
            "Reconnect loop: device %s not found after %ds, "
            "relying on bluetooth callback and periodic check",
            self.address,
            max_attempts * interval,
        )

    # ------------------------------------------------------------------
    # Shutdown (integration unload)
    # ------------------------------------------------------------------
    async def async_shutdown(self) -> None:
        """Clean up on integration unload — cancel tasks, disconnect BLE."""
        await self.async_save_data()
        if self._monitor_task and not self._monitor_task.done():
            self._monitor_task.cancel()
        if self._reconnect_task and not self._reconnect_task.done():
            self._reconnect_task.cancel()
        if self._current_client:
            await self._disconnect(self._current_client)

    # ------------------------------------------------------------------
    # Persistent storage — measurement history
    # ------------------------------------------------------------------
    async def async_save_data(self) -> None:
        """Persist measurements and known_keys to disk."""
        data = {
            "measurements": [
                dataclasses.asdict(m) for m in self._data.measurements
            ],
            "known_keys": [list(k) for k in self._data._known_keys],
        }
        await self._store.async_save(data)
        _LOGGER.debug(
            "Saved %d measurements to storage", len(self._data.measurements)
        )

    async def async_load_data(self) -> None:
        """Restore measurements and known_keys from disk."""
        data = await self._store.async_load()
        if not data:
            return
        for item in data.get("measurements", []):
            self._data.measurements.append(BpResult(**item))
        for key in data.get("known_keys", []):
            self._data._known_keys.add(tuple(key))
        if self._data.measurements:
            newest = max(self._data.measurements, key=lambda r: r.timestamp)
            self._data.update_from_bp_result(newest)
            self._fetch_succeeded = True
        _LOGGER.info(
            "Restored %d measurements from storage",
            len(self._data.measurements),
        )
        self.async_set_updated_data(self._data)

    # ------------------------------------------------------------------
    # Disconnect
    # ------------------------------------------------------------------
    async def _disconnect(self, client: BleakClient) -> None:
        """Disconnect from the BP2.

        IMPORTANT: Always call client.disconnect() even if is_connected
        returns False. When the device powers off, is_connected goes False
        but the ESPHome BLE proxy may still hold the connection slot.
        Calling disconnect() explicitly releases it for future connections.
        """
        try:
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
            self._data.device_state_text = "Disconnected"
            _LOGGER.info("Disconnected from BP2 at %s", self.address)

    # ------------------------------------------------------------------
    # HA DataUpdateCoordinator fallback
    # ------------------------------------------------------------------
    async def _async_update_data(self) -> ViatomBP2Data:
        """Periodic update — try to connect if device is available.

        Called every RECONNECT_INTERVAL by the HA coordinator framework.
        This catches cases where the bluetooth advertisement callback
        wasn't triggered (e.g., stable advertisements that HA doesn't
        report as changes).
        """
        if not self._connected and not self._connecting and not self._has_active_task():
            ble_device = bluetooth.async_ble_device_from_address(
                self.hass, self.address, connectable=True
            )
            if ble_device is not None:
                _LOGGER.info(
                    "Periodic check: device %s is available, connecting",
                    self.address,
                )
                self._start_monitor()
            else:
                _LOGGER.debug(
                    "Periodic check: device %s not available", self.address
                )
        return self._data
