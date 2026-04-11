import os
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.clipboard import ClipboardAccessError, ClipboardMonitor, ClipboardService
from src.core.config import Config
from src.core.events import EventBus, EventType
from src.core.state_manager import StateManager
from src.database.db import Database


class FakeClipboardAdapter:
    def __init__(self):
        self.value = None
        self.copy_calls = 0
        self.clear_calls = 0

    def copy_to_clipboard(self, data: str) -> bool:
        self.value = data
        self.copy_calls += 1
        return True

    def clear_clipboard(self) -> bool:
        self.value = ""
        self.clear_calls += 1
        return True

    def get_clipboard_content(self):
        return self.value


class FailingCopyClipboardAdapter(FakeClipboardAdapter):
    def copy_to_clipboard(self, data: str) -> bool:
        self.copy_calls += 1
        return False


class FailingClearClipboardAdapter(FakeClipboardAdapter):
    def clear_clipboard(self) -> bool:
        self.clear_calls += 1
        return False


class ClipboardServiceTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_home = tempfile.TemporaryDirectory()
        self.home_path = Path(self.temp_home.name)
        self.original_home = Path.home
        Path.home = lambda: self.home_path
        self.addCleanup(self.temp_home.cleanup)
        self.addCleanup(self._restore_home)
        self.config = Config()
        self.database = Database(str(self.home_path / "clipboard.db"))
        self.addCleanup(self.database.close)
        self.state = StateManager()
        self.state.unlock()
        self.adapter = FakeClipboardAdapter()
        self.bus = EventBus()
        self.service = ClipboardService(
            self.adapter,
            database=self.database,
            config=self.config,
            state_manager=self.state,
            bus=self.bus,
        )

    def _restore_home(self):
        Path.home = self.original_home

    def test_copy_text_updates_status_and_state(self):
        self.service.copy_text("Secret!123", data_type="password", source_entry_id=7, source_label="GitHub")

        status = self.service.get_status()
        self.assertTrue(status.active)
        self.assertEqual(status.data_type, "password")
        self.assertEqual(status.source_entry_id, 7)
        self.assertEqual(self.adapter.value, "Secret!123")
        self.assertEqual(self.state.get_clipboard(), "Secret!123")
        self.assertIn("Sec", status.preview)
        self.assertEqual(self.service.reveal_current_text(), "Secret!123")

    def test_timeout_warning_and_clear(self):
        self.service.configure(timeout_seconds=5)
        self.service.copy_text("Secret!123")
        self.service._current_item.expires_at = datetime.now() + timedelta(seconds=4)

        result = self.service.tick()
        self.assertEqual(result, "warning")
        self.assertTrue(self.service.get_status().warning_emitted)

        self.service._current_item.expires_at = datetime.now() - timedelta(seconds=1)
        result = self.service.tick()
        self.assertEqual(result, "timeout")
        self.assertFalse(self.service.get_status().active)
        self.assertEqual(self.adapter.clear_calls, 1)

    def test_copy_is_blocked_when_state_is_locked(self):
        self.state.lock()

        with self.assertRaises(ClipboardAccessError):
            self.service.copy_text("Secret!123")

    def test_monitor_flags_external_change(self):
        self.service.copy_text("Secret!123")
        monitor = ClipboardMonitor(self.adapter, self.service)
        self.adapter.value = "Changed by another app"

        monitor.poll()
        status = self.service.get_status()
        self.assertFalse(status.suspicious_activity)

        monitor.poll()

        status = self.service.get_status()
        self.assertTrue(status.suspicious_activity)
        self.assertLessEqual(status.remaining_seconds, 1)

    def test_monitor_reacts_immediately_in_paranoid_mode(self):
        self.service.configure(security_level="paranoid")
        self.service.copy_text("Secret!123")
        monitor = ClipboardMonitor(self.adapter, self.service)
        self.adapter.value = "Changed by another app"

        monitor.poll()

        status = self.service.get_status()
        self.assertTrue(status.suspicious_activity)
        self.assertLessEqual(status.remaining_seconds, 1)

    def test_monitor_marks_external_clear_with_separate_reason(self):
        received_events = []
        self.bus.subscribe(EventType.CLIPBOARD_CLEARED, received_events.append)
        self.service.configure(security_level="paranoid")
        self.service.copy_text("Secret!123")
        monitor = ClipboardMonitor(self.adapter, self.service)
        self.adapter.value = ""

        monitor.poll()

        self.assertEqual(received_events[-1].data["reason"], "monitor_warning")
        self.assertEqual(received_events[-1].data["monitor_reason"], "external_clear")
        self.assertEqual(received_events[-1].data["entry_id"], None)
        self.assertEqual(received_events[-1].data["data_type"], "password")
        self.assertEqual(received_events[-1].data["observed_length"], 0)

    def test_settings_are_persisted_in_database(self):
        self.service.configure(
            timeout_seconds=15,
            notifications_enabled=False,
            security_level="paranoid",
            blocked_on_suspicious=True,
            preset="public_computer",
        )

        stored = self.database.get_setting("security.clipboard", {})
        self.assertEqual(stored["timeout_seconds"], 15)
        self.assertEqual(stored["security_level"], "paranoid")
        self.assertTrue(stored["blocked_on_suspicious"])

    def test_custom_preset_name_is_persisted_for_manual_profile(self):
        self.service.configure(
            timeout_seconds=42,
            notifications_enabled=False,
            security_level="advanced",
            blocked_on_suspicious=True,
            preset="custom",
        )

        stored = self.database.get_setting("security.clipboard", {})
        self.assertEqual(stored["preset"], "custom")
        self.assertEqual(stored["timeout_seconds"], 42)

    def test_allowed_applications_are_normalized_and_persisted(self):
        self.service.configure(
            allowed_applications=[" Code.exe ", "explorer", "code", "KEEPASSXC.EXE"],
        )

        stored = self.database.get_setting("security.clipboard", {})
        self.assertEqual(stored["allowed_applications"], ["code", "explorer", "keepassxc"])
        self.assertTrue(self.service.is_application_allowed("code.exe"))
        self.assertTrue(self.service.is_application_allowed("Keepassxc"))
        self.assertFalse(self.service.is_application_allowed("telegram"))

    def test_copy_is_blocked_for_application_outside_whitelist(self):
        clipboard_errors = []
        self.bus.subscribe(EventType.CLIPBOARD_ERROR, clipboard_errors.append)
        self.service.configure(allowed_applications=["cryptosafe-manager"])

        with self.assertRaises(ClipboardAccessError):
            self.service.copy_text("Secret!123", application_name="telegram")

        self.assertFalse(self.service.get_status().active)
        self.assertEqual(clipboard_errors[-1].data["error_code"], "application_not_allowed")
        self.assertEqual(clipboard_errors[-1].data["application_name"], "telegram")

    def test_replacement_copy_clears_previous_clipboard_content(self):
        self.service.copy_text("first-secret", source_entry_id=1)
        self.service.copy_text("second-secret", source_entry_id=2)

        status = self.service.get_status()
        self.assertTrue(status.active)
        self.assertEqual(status.source_entry_id, 2)
        self.assertEqual(self.adapter.value, "second-secret")
        self.assertEqual(self.adapter.clear_calls, 1)

    def test_copy_text_raises_error_when_adapter_write_fails(self):
        self.service = ClipboardService(
            FailingCopyClipboardAdapter(),
            database=self.database,
            config=self.config,
            state_manager=self.state,
            bus=self.bus,
        )

        with self.assertRaises(ClipboardAccessError):
            self.service.copy_text("Secret!123")

        self.assertFalse(self.service.get_status().active)

    def test_suspicious_activity_can_block_future_copies(self):
        self.service.configure(blocked_on_suspicious=True)
        self.service.copy_text("Secret!123")
        self.service.register_suspicious_activity(reason="external_change", observed_value="changed")

        with self.assertRaises(ClipboardAccessError):
            self.service.copy_text("AnotherSecret!456")

    def test_clear_event_marks_failed_system_clear(self):
        received_events = []
        self.bus.subscribe(EventType.CLIPBOARD_CLEARED, received_events.append)
        clipboard_errors = []
        self.bus.subscribe(EventType.CLIPBOARD_ERROR, clipboard_errors.append)
        self.service = ClipboardService(
            FailingClearClipboardAdapter(),
            database=self.database,
            config=self.config,
            state_manager=self.state,
            bus=self.bus,
        )
        self.service.copy_text("Secret!123")

        result = self.service.clear(reason="manual")

        self.assertTrue(result)
        self.assertTrue(self.service.did_last_clear_fail())
        self.assertEqual(received_events[-1].data["reason"], "manual")
        self.assertTrue(received_events[-1].data["clear_failed"])
        self.assertEqual(clipboard_errors[-1].data["operation"], "clear")
        self.assertEqual(clipboard_errors[-1].data["error_code"], "adapter_clear_failed")
        self.assertEqual(clipboard_errors[-1].data["clear_reason"], "manual")

    def test_copy_failure_publishes_clipboard_error_without_secret_value(self):
        clipboard_errors = []
        self.bus.subscribe(EventType.CLIPBOARD_ERROR, clipboard_errors.append)
        self.service = ClipboardService(
            FailingCopyClipboardAdapter(),
            database=self.database,
            config=self.config,
            state_manager=self.state,
            bus=self.bus,
        )

        with self.assertRaises(ClipboardAccessError):
            self.service.copy_text("Secret!123", data_type="password", source_entry_id=5)

        self.assertEqual(clipboard_errors[-1].data["operation"], "copy")
        self.assertEqual(clipboard_errors[-1].data["error_code"], "adapter_write_failed")
        self.assertEqual(clipboard_errors[-1].data["entry_id"], 5)
        self.assertEqual(clipboard_errors[-1].data["data_type"], "password")
        self.assertNotIn("Secret!123", str(clipboard_errors[-1].data))

    def test_failed_replacement_does_not_leave_previous_secret_active(self):
        self.service.copy_text("first-secret", data_type="password", source_entry_id=1)
        self.service.adapter = FailingCopyClipboardAdapter()

        with self.assertRaises(ClipboardAccessError):
            self.service.copy_text("second-secret", data_type="password", source_entry_id=2)

        self.assertFalse(self.service.get_status().active)
        self.assertIsNone(self.state.get_clipboard())

    def test_rapid_concurrent_copy_operations_keep_consistent_final_state(self):
        start_event = threading.Event()
        errors = []
        values = [f"secret-{index}" for index in range(5)]
        threads = []

        def worker(value: str, entry_id: int):
            try:
                start_event.wait(timeout=5)
                self.service.copy_text(value, data_type="password", source_entry_id=entry_id)
            except Exception as error:
                errors.append(error)

        for index, value in enumerate(values, start=1):
            thread = threading.Thread(target=worker, args=(value, index))
            threads.append(thread)
            thread.start()

        start_event.set()
        for thread in threads:
            thread.join(timeout=5)

        self.assertEqual(errors, [])
        final_value = self.service.reveal_current_text()
        self.assertIn(final_value, values)
        self.assertEqual(self.state.get_clipboard(), final_value)

    def test_concurrent_copy_clear_and_tick_operations_keep_state_consistent(self):
        start_event = threading.Event()
        errors = []

        def copy_worker():
            try:
                start_event.wait(timeout=5)
                for index in range(10):
                    self.service.copy_text(f"secret-{index}", data_type="password", source_entry_id=index)
            except Exception as error:
                errors.append(error)

        def clear_worker():
            try:
                start_event.wait(timeout=5)
                for _index in range(10):
                    self.service.clear(reason="manual", publish_event=False)
            except Exception as error:
                errors.append(error)

        def tick_worker():
            try:
                start_event.wait(timeout=5)
                for _index in range(10):
                    self.service.tick()
            except Exception as error:
                errors.append(error)

        threads = [
            threading.Thread(target=copy_worker),
            threading.Thread(target=clear_worker),
            threading.Thread(target=tick_worker),
        ]
        for thread in threads:
            thread.start()

        start_event.set()
        for thread in threads:
            thread.join(timeout=5)

        self.assertEqual(errors, [])
        status = self.service.get_status()
        revealed = self.service.reveal_current_text()
        if status.active:
            self.assertEqual(self.state.get_clipboard(), revealed)
            self.assertEqual(self.adapter.value, revealed)
        else:
            self.assertIn(self.state.get_clipboard(), {None, ""})

    def test_successful_copy_resets_failed_clear_flag_after_previous_failure(self):
        self.service = ClipboardService(
            FailingClearClipboardAdapter(),
            database=self.database,
            config=self.config,
            state_manager=self.state,
            bus=self.bus,
        )
        self.service.copy_text("Secret!123")
        self.service.clear(reason="manual")
        self.assertTrue(self.service.did_last_clear_fail())

        self.service.adapter = FakeClipboardAdapter()
        self.service.copy_text("Recovered!456")

        self.assertFalse(self.service.did_last_clear_fail())
        self.assertIsNone(self.service.get_last_clear_reason())


if __name__ == "__main__":
    unittest.main()
