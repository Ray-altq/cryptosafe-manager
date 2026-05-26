import os
import sys
import time
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.events import EventBus, EventType
from src.core.security import (
    ActivityMonitor,
    ActivityMonitorConfig,
    MemoryGuard,
    PanicMode,
    ProtectedKeyOperation,
    SecureBuffer,
    constant_time_compare,
    get_platform_security_report,
    secure_string_compare,
)


class TestSecurityHardeningCore(unittest.TestCase):
    def test_constant_time_compare_handles_equal_different_and_none_values(self):
        self.assertTrue(constant_time_compare("Secret!123", "Secret!123"))
        self.assertFalse(constant_time_compare("Secret!123", "Secret!124"))
        self.assertFalse(constant_time_compare("Secret!123", "Secret!1234"))
        self.assertTrue(secure_string_compare("", None))

    def test_memory_guard_allocates_locks_when_possible_and_securely_wipes_buffer(self):
        guard = MemoryGuard()
        buffer, status = guard.allocate(16)

        copied = guard.copy_into(buffer, b"Secret!123")
        guard.secure_zero(buffer, 16)
        raw = bytes(bytearray(buffer))
        guard.unlock(buffer, 16)

        self.assertEqual(copied, len(b"Secret!123"))
        self.assertEqual(raw, b"\0" * 16)
        self.assertIn(status.platform, {"Windows", "Linux", "Darwin", ""})

    def test_secure_buffer_wipes_source_bytearray_and_closes_cleanly(self):
        payload = bytearray(b"TopSecret!456")

        secure_buffer = SecureBuffer(payload)
        protected_copy = secure_buffer.read()
        secure_buffer.close()

        self.assertEqual(payload, bytearray(b"\0" * len(payload)))
        self.assertEqual(protected_copy, b"TopSecret!456")

    def test_protected_key_operation_wipes_temporary_key_copy(self):
        key = b"k" * 32

        with ProtectedKeyOperation(key) as protected:
            mutable_key = protected.mutable_key
            self.assertEqual(protected.key, key)

        self.assertEqual(mutable_key, bytearray(b"\0" * 32))

    def test_activity_monitor_locks_after_configured_timeout(self):
        calls = []
        monitor = ActivityMonitor(
            lambda: calls.append("locked"),
            ActivityMonitorConfig(timeout_seconds=60, check_interval_seconds=0.1, sensitivity="medium"),
        )

        monitor.simulate_elapsed(61)
        triggered = monitor.tick()

        self.assertTrue(triggered)
        self.assertEqual(calls, ["locked"])
        self.assertEqual(monitor.lock_count, 1)

    def test_activity_monitor_sensitivity_ignores_background_noise(self):
        monitor = ActivityMonitor(
            lambda: None,
            ActivityMonitorConfig(timeout_seconds=60, sensitivity="medium"),
        )
        monitor.simulate_elapsed(30)
        idle_before = monitor.get_idle_seconds()

        monitor.record_activity("background")
        idle_after = monitor.get_idle_seconds()

        self.assertGreaterEqual(idle_after, idle_before)

    def test_panic_mode_runs_handlers_and_publishes_sanitized_event(self):
        bus = EventBus()
        events = []
        bus.subscribe(EventType.PANIC_MODE_ACTIVATED, lambda event: events.append(event))
        calls = []
        panic = PanicMode(event_bus=bus)
        panic.register_handler("clear_clipboard", lambda: calls.append("clipboard"))
        panic.register_handler("lock_vault", lambda: calls.append("lock"))

        result = panic.activate(method="hotkey", details={"password": "Secret!123", "reason": "manual"})

        self.assertTrue(result.activated)
        self.assertEqual(calls, ["clipboard", "lock"])
        self.assertEqual(events[0].type, EventType.PANIC_MODE_ACTIVATED)
        self.assertEqual(events[0].data["details"]["password"], "[redacted]")
        self.assertNotIn("Secret!123", str(events[0].data))

    def test_timing_attack_measurement_keeps_compare_paths_close(self):
        rounds = 5000

        def measure(left, right):
            started = time.perf_counter()
            for _ in range(rounds):
                constant_time_compare(left, right)
            return time.perf_counter() - started

        equal_time = measure("A" * 64, "A" * 64)
        different_time = measure("A" * 64, "B" * 64)
        different_length_time = measure("A" * 64, "B" * 32)
        slowest = max(equal_time, different_time, different_length_time)
        fastest = max(min(equal_time, different_time, different_length_time), 0.000001)

        self.assertLess(slowest / fastest, 2.5)

    def test_memory_protection_snapshot_does_not_keep_plaintext_after_wipe(self):
        secret = bytearray(b"Sprint7MemorySecret!789")
        secure_buffer = SecureBuffer(secret)
        protected_snapshot = secure_buffer.read()

        secure_buffer.close()
        wiped_snapshot = bytes(bytearray(secure_buffer.buffer or [])) if getattr(secure_buffer, "buffer", None) else b""

        self.assertIn(b"Sprint7MemorySecret!789", protected_snapshot)
        self.assertNotIn(b"Sprint7MemorySecret!789", bytes(secret))
        self.assertNotIn(b"Sprint7MemorySecret!789", wiped_snapshot)

    def test_auto_lock_reliability_simulates_twenty_four_hours(self):
        current_time = datetime(2026, 5, 23, tzinfo=timezone.utc)

        def clock():
            return current_time

        lock_events = []
        monitor = ActivityMonitor(
            lambda: lock_events.append(clock()),
            ActivityMonitorConfig(timeout_seconds=5 * 60, sensitivity="medium"),
            clock=clock,
        )

        for hour in range(24):
            current_time += timedelta(hours=1)
            monitor.record_activity("keyboard")
            self.assertFalse(monitor.tick(), f"unexpected lock after activity at hour {hour}")
            current_time += timedelta(minutes=6)
            self.assertTrue(monitor.tick(), f"missing lock after inactivity at hour {hour}")

        self.assertEqual(len(lock_events), 24)
        self.assertEqual(monitor.lock_count, 24)

    def test_panic_mode_stress_continues_after_handler_failure_and_recovers(self):
        bus = EventBus()
        events = []
        bus.subscribe(EventType.PANIC_MODE_ACTIVATED, lambda event: events.append(event))
        bus.subscribe(EventType.PANIC_MODE_DEACTIVATED, lambda event: events.append(event))
        calls = []
        panic = PanicMode(event_bus=bus)
        panic.register_handler("lock_vault", lambda: calls.append("lock"))
        panic.register_handler("failing_handler", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
        panic.register_handler("wipe_memory", lambda: calls.append("wipe"))

        result = panic.activate(method="stress-test", details={"private_key": "SecretKey"})
        second_result = panic.activate(method="stress-test-repeat")
        panic.reset_for_recovery()

        self.assertTrue(result.activated)
        self.assertFalse(second_result.activated)
        self.assertEqual(calls, ["lock", "wipe"])
        self.assertIn("failing_handler", result.handler_errors)
        self.assertFalse(panic.activated)
        self.assertEqual(events[-1].type, EventType.PANIC_MODE_DEACTIVATED)
        self.assertNotIn("SecretKey", str(events[0].data))

    def test_idle_activity_monitor_tick_is_lightweight(self):
        monitor = ActivityMonitor(lambda: None, ActivityMonitorConfig(timeout_seconds=60))

        started = time.perf_counter()
        for _ in range(10000):
            self.assertFalse(monitor.tick())
        elapsed = time.perf_counter() - started

        self.assertLess(elapsed, 1.0)

    def test_security_module_startup_smoke_is_fast(self):
        started = time.perf_counter()
        for _ in range(1000):
            ActivityMonitorConfig(timeout_seconds=300)
            PanicMode()
            MemoryGuard()
        elapsed = time.perf_counter() - started

        self.assertLess(elapsed, 1.0)

    def test_platform_security_reports_required_os_features_and_degradation(self):
        windows_report = get_platform_security_report("Windows").as_dict()
        macos_report = get_platform_security_report("Darwin").as_dict()
        linux_report = get_platform_security_report("Linux").as_dict()

        self.assertEqual(windows_report["platform"], "Windows")
        self.assertIn("credential_guard_probe", {feature["name"] for feature in windows_report["features"]})
        self.assertIn("keychain_services", {feature["name"] for feature in macos_report["features"]})
        self.assertIn("kernel_keyring", {feature["name"] for feature in linux_report["features"]})
        self.assertIn("degraded", windows_report)

    def test_startup_with_security_features_completes_under_three_seconds(self):
        started = time.perf_counter()
        for system_name in ("Windows", "Darwin", "Linux"):
            get_platform_security_report(system_name)
        ActivityMonitorConfig(timeout_seconds=300)
        PanicMode()
        MemoryGuard()
        elapsed = time.perf_counter() - started

        self.assertLess(elapsed, 3.0)

    def test_memory_protection_managed_overhead_stays_under_five_percent(self):
        guard = MemoryGuard()

        overhead_ratio = guard.managed_overhead_ratio(4096)

        self.assertLessEqual(overhead_ratio, 0.05)


if __name__ == "__main__":
    unittest.main()
