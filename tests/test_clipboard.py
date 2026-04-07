import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.clipboard import ClipboardAccessError, ClipboardMonitor, ClipboardService
from src.core.config import Config
from src.core.events import EventBus
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
        self.assertTrue(status.suspicious_activity)
        self.assertLessEqual(status.remaining_seconds, 1)

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


if __name__ == "__main__":
    unittest.main()
