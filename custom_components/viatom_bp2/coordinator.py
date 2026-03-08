"""Data coordinator for Viatom BP2 Blood Pressure Monitor.

Uses a persistent BLE connection with CMD 0x06 (GET_CONFIG) state polling
to detect measurement activity and fetch results via disconnect-reconnect.

FIRMWARE QUIRK — FILE_START REJECTION ON FIRST CONNECTION:
  The LP-BP2W often rejects FILE_START (CMD 0xF2) with byte[3]=0xE1 on
  the very first BLE connection after device boot.  The second connection
  (after a clean disconnect) always succeeds.  Root cause unknown — the
  device may need a BLE session cycle before file transfer is ready.

  Workaround: when FILE_START returns -1 (rejected), immediately
  disconnect and fast-reconnect (3s).  The retry succeeds reliably.

FIRMWARE LIMITATION — ONE TRANSFER PER CONNECTION:
  The LP-BP2W firmware allows only ONE FILE_START per BLE connection.
  A second FILE_START on the same connection returns byte[3]=0xe1.
  The correct solution is disconnect-reconnect: the new connection's
  FILE_START picks up any new records.

Algorithm (validated by real-world ESPHome proxy testing):

  PHASE 1 — CONNECTION + BASELINE FETCH
    Advertisement seen → connect + subscribe → housekeeping (battery,
    device info, time sync) → file fetch → enter poll loop.
    If FILE_START is rejected (0xE1), immediately disconnect and
    fast-reconnect — the retry always succeeds.
    When reconnecting for new data (_new_data_pending), the baseline
    fetch is SKIPPED — the poll loop will fetch when RESULT appears.

  PHASE 2 — POLL LOOP (CMD 0x06 every ~5s)
    Uses _transfer_used to decide between in-connection fetch and
    disconnect-reconnect:

    State 4/15/16 (busy):
      _transfer_used=True  → disconnect now (free slot for reconnect)
      _transfer_used=False → stay connected, wait for RESULT

    State 5/17 (result):
      _transfer_used=True  → disconnect, fast-reconnect to fetch
      _transfer_used=False → fetch in-connection (first transfer!)

    State 3 (idle) after activity: same logic as RESULT

    Disconnecting on MEASURING (when transfer slot is used) lets the
    reconnect happen during the ~30s measurement.  The reconnected
    session skips baseline fetch and waits for RESULT, then fetches
    in-connection with zero delay.

    On disconnect, _reconnect_loop fires with a fast 3s interval
    (instead of the normal 15s) when _new_data_pending is True.

  PHASE 3 — DISCONNECT + RECONNECT
    Connection lost, idle timeout (120s), or new data pending →
    disconnect, then reconnect loop re-establishes connection.
    Fast reconnect (3s) when new data is pending.

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
    CMD_GET_BATTERY,
    CMD_GET_CONFIG,
    CMD_SYNC_TIME,
    CMD_READ_FILE_START,
    CMD_READ_FILE_DATA,
    CMD_READ_FILE_END,
    CMD_GET_LP_CONFIG,
    FILE_BP_LIST,
    DEVICE_STATE_IDLE,
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
    build_get_battery,
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

# Disconnect after this many seconds of continuous idle (state 3)
# with no measurement activity, after the baseline fetch is done.
# Frees the BLE proxy slot for other devices.
IDLE_DISCONNECT_TIMEOUT = 120

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
        # Per-command response events: cmd_byte → asyncio.Event
        self._pending_responses: dict[int, asyncio.Event] = {}
        # Device state polling (CMD 0x06 byte[0])
        self._device_state: int | None = None  # last polled state
        # Poll loop state machine
        self._saw_activity = False  # seen any non-idle state since last fetch?
        self._fetched_this_cycle = False  # already fetched for current activity?
        self._prev_state: int | None = None  # previous poll state (for transition detection)
        self._last_fetch_new_count: int = 0  # result of last file download
        self._new_data_pending = False  # new measurement detected, need reconnect to fetch
        self._transfer_used = False  # True after file transfer (only 1 allowed per connection)

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
        # 2. At least 10 seconds since last disconnect (connection cooldown)
        if (
            not self._connected
            and not self._connecting
            and now - self._last_disconnect > 10
        ):
            _LOGGER.info(
                "Device %s is advertising — initiating connection",
                self.address,
            )
            self._connecting = True
            self._entry.async_create_background_task(
                self.hass,
                self._connect_and_monitor(),
                name=f"viatom_bp2_connect_{self.address}",
            )

    # ------------------------------------------------------------------
    # PHASE 1: Connect, housekeep, baseline fetch, then enter poll loop
    # ------------------------------------------------------------------
    async def _connect_and_monitor(self) -> None:
        """Connect to BP2, run housekeeping, baseline fetch, then poll loop."""
        # Reset per-connection state
        fetching_new = self._new_data_pending
        self._new_data_pending = False
        self._reassembler.reset()
        self._file_data_buffer.clear()
        self._file_size = 0
        self._file_offset = 0
        self._device_state = None
        self._prev_state = None
        self._saw_activity = False
        self._fetched_this_cycle = False
        self._transfer_used = False

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

            # === PHASE 1: Housekeeping ===
            _LOGGER.info("=== Phase 1: Housekeeping ===")
            await self._send_and_wait(client, build_get_battery(), timeout=3.0)
            await self._send_and_wait(client, build_get_device_info(), timeout=3.0)
            # Sync device clock using HA's configured timezone
            ha_now = dt_util.now().timetuple()
            await self._send_and_wait(client, build_sync_time(ha_now), timeout=3.0)

            # === PHASE 1: File fetch ===
            # Device firmware allows only ONE file transfer per connection.
            # When reconnecting for new data (fetching_new), we SKIP the
            # baseline fetch — the measurement is still in progress and
            # the new record isn't on flash yet.  The poll loop will do
            # the fetch when RESULT appears (using this connection's one
            # transfer slot).
            if fetching_new:
                _LOGGER.info(
                    "=== Phase 1: Skipping fetch (measurement in progress) — "
                    "poll loop will fetch on RESULT ==="
                )
                self._saw_activity = True  # so poll loop knows we're mid-cycle
            else:
                _LOGGER.info("=== Phase 1: Baseline file fetch ===")
                new_count = await self._fetch_bp_data(client)
                if new_count == -1:
                    # FILE_START rejected (0xE1) — device needs a fresh
                    # BLE connection before file transfer works.
                    # Disconnect immediately and fast-reconnect.
                    _LOGGER.info(
                        "Baseline fetch rejected — disconnecting for "
                        "immediate reconnect"
                    )
                    self._new_data_pending = True
                    self.async_set_updated_data(self._data)
                    return
                self._transfer_used = True
                _LOGGER.info(
                    "Fetch complete: %d new records (%d total known)",
                    new_count,
                    len(self._data._known_keys),
                )
            self.async_set_updated_data(self._data)

            # === PHASE 2: State poll loop ===
            _LOGGER.info("=== Phase 2: Entering state poll loop ===")
            await self._poll_loop(client)

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

            # Schedule reconnection attempts — the bluetooth callback may not
            # fire again if the ESPHome proxy cached the device address. We
            # actively retry for up to 60s after disconnect to catch a device
            # that is still on (or turned back on quickly).
            self._entry.async_create_background_task(
                self.hass,
                self._reconnect_loop(),
                name=f"viatom_bp2_reconnect_{self.address}",
            )

    # ------------------------------------------------------------------
    # PHASE 2: Poll loop — CMD 0x06 every 5s, detect measurement activity
    # ------------------------------------------------------------------
    async def _poll_loop(self, client: BleakClient) -> None:
        """Poll device state via CMD 0x06, handle measurement lifecycle.

        The LP-BP2W firmware only allows ONE file transfer per BLE connection.
        Behaviour depends on _transfer_used (whether this connection already
        did a file transfer):

        _transfer_used=True (baseline fetch was done):
          BUSY    → disconnect now (free slot), reconnect will wait for RESULT
          RESULT  → disconnect, fast-reconnect to fetch
          IDLE after activity → same as RESULT

        _transfer_used=False (reconnected, slot available):
          BUSY    → stay connected, wait for RESULT
          RESULT  → fetch in-connection (first transfer!)
          IDLE after activity → fetch in-connection

        In both cases:
          IDLE no activity → track idle duration for disconnect timeout
        """
        idle_since: float | None = None  # monotonic time when idle streak started
        consecutive_errors = 0

        while client.is_connected:
            # Poll CMD 0x06 (GET_CONFIG) — byte[0] = device state
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

            # Update diagnostic sensor with current state
            self._data.device_state_text = state_name
            self.async_set_updated_data(self._data)

            # --- Track measurement activity ---
            #
            # Key rule: device allows only 1 file transfer per connection.
            #   _transfer_used=True  → must disconnect-reconnect to fetch
            #   _transfer_used=False → can fetch in-connection (first transfer)
            #
            if state in DEVICE_STATES_BUSY:
                idle_since = None
                self._saw_activity = True
                self._fetched_this_cycle = False

                if self._transfer_used:
                    # Already used our transfer slot (baseline fetch).
                    # Disconnect now — reconnect will skip fetch and wait
                    # for RESULT in poll loop, then fetch in-connection.
                    _LOGGER.info(
                        "State %d (%s) — measurement started, "
                        "disconnecting to free transfer slot for reconnect",
                        state,
                        state_name,
                    )
                    self._new_data_pending = True
                    break
                else:
                    # Fresh connection (reconnected for new data) — stay
                    # connected and wait for RESULT to fetch in-connection.
                    _LOGGER.debug(
                        "State %d (%s) — measurement in progress "
                        "(transfer slot available, waiting for result)",
                        state,
                        state_name,
                    )

            elif state in DEVICE_STATES_RESULT:
                idle_since = None
                if not self._fetched_this_cycle:
                    if self._transfer_used:
                        # Can't fetch — disconnect and reconnect
                        _LOGGER.info(
                            "State %d (%s) — result on screen, "
                            "disconnecting to fetch via reconnect",
                            state,
                            state_name,
                        )
                        self._new_data_pending = True
                        break
                    else:
                        # Transfer slot available — fetch in-connection!
                        _LOGGER.info(
                            "State %d (%s) — result on screen, "
                            "fetching new data in-connection",
                            state,
                            state_name,
                        )
                        new_count = await self._fetch_bp_data(client)
                        self._transfer_used = True
                        _LOGGER.info(
                            "Fetch complete: %d new records (%d total known)",
                            new_count,
                            len(self._data._known_keys),
                        )
                        self.async_set_updated_data(self._data)
                        self._fetched_this_cycle = True
                        self._saw_activity = False

            elif state == DEVICE_STATE_IDLE:
                if self._saw_activity and not self._fetched_this_cycle:
                    if self._transfer_used:
                        _LOGGER.info(
                            "State 3 (IDLE) — missed RESULT window, "
                            "disconnecting to fetch via reconnect"
                        )
                        self._new_data_pending = True
                        break
                    else:
                        _LOGGER.info(
                            "State 3 (IDLE) — missed RESULT window, "
                            "fetching new data in-connection"
                        )
                        new_count = await self._fetch_bp_data(client)
                        self._transfer_used = True
                        _LOGGER.info(
                            "Fetch complete: %d new records (%d total known)",
                            new_count,
                            len(self._data._known_keys),
                        )
                        self.async_set_updated_data(self._data)
                        self._fetched_this_cycle = True
                        self._saw_activity = False

                # Reset cycle when returning to idle after a fetched result
                if self._prev_state in DEVICE_STATES_RESULT and self._fetched_this_cycle:
                    self._fetched_this_cycle = False
                    self._saw_activity = False

                # Track idle duration for disconnect timeout
                if idle_since is None:
                    idle_since = time.monotonic()

            self._prev_state = state

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

            # Wait for next poll
            await asyncio.sleep(STATE_POLL_INTERVAL)

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
    # File download helper — reusable for baseline and poll-triggered fetches
    # ------------------------------------------------------------------
    async def _fetch_bp_data(self, client: BleakClient) -> int:
        """Download bp2nibp.list and ingest records.

        This must be called only ONCE per BLE connection — the firmware
        rejects a second FILE_START with byte[3]=0xe1 (error).
        Called by _connect_and_monitor (baseline) or _poll_loop (on RESULT).

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
            else:
                _LOGGER.debug("CMD 0x06 empty payload: %s", packet.payload.hex())

        # LP config response (CMD 0x33)
        elif packet.cmd == CMD_GET_LP_CONFIG:
            _LOGGER.debug("LP Config: %s", packet.payload.hex())

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

    # ------------------------------------------------------------------
    # Post-disconnect reconnection loop
    # ------------------------------------------------------------------
    async def _reconnect_loop(self) -> None:
        """Actively try to reconnect after disconnect.

        The HA bluetooth callback (handle_bluetooth_event) may not fire again
        after disconnect — the ESPHome proxy can cache the device address and
        HA may not report repeated identical advertisements as "changes".

        When _new_data_pending is True (measurement detected in poll loop),
        uses a fast 3s interval to minimize the delay before fetching new
        data on the reconnected session.  Otherwise checks every 15s.
        """
        fast = self._new_data_pending
        interval = 3 if fast else 15
        max_attempts = 20 if fast else 8  # 20×3s=60s or 8×15s=120s

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
                self._connecting = True
                self._entry.async_create_background_task(
                    self.hass,
                    self._connect_and_monitor(),
                    name=f"viatom_bp2_reconnect_connect_{self.address}",
                )
                return
            else:
                _LOGGER.debug(
                    "Reconnect loop: device %s not available (attempt %d/%d)",
                    self.address,
                    attempt + 1,
                    max_attempts,
                )

        # Clear the pending flag — if the device was off this whole time,
        # the next connection should do a normal baseline fetch, not skip it.
        self._new_data_pending = False

        _LOGGER.info(
            "Reconnect loop: device %s not found after %ds, "
            "relying on bluetooth callback and periodic check",
            self.address,
            max_attempts * interval,
        )

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
        if not self._connected and not self._connecting:
            ble_device = bluetooth.async_ble_device_from_address(
                self.hass, self.address, connectable=True
            )
            if ble_device is not None:
                _LOGGER.info(
                    "Periodic check: device %s is available, connecting",
                    self.address,
                )
                self._connecting = True
                self._entry.async_create_background_task(
                    self.hass,
                    self._connect_and_monitor(),
                    name=f"viatom_bp2_periodic_{self.address}",
                )
            else:
                _LOGGER.debug(
                    "Periodic check: device %s not available", self.address
                )
        return self._data
