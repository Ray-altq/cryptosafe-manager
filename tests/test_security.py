import os
import sys
import unittest

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


if __name__ == "__main__":
    unittest.main()
