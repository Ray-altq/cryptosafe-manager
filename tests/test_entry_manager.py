import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.events import EventType, event_bus
from src.core.key_manager import KeyManager
from src.core.vault import AESGCMEncryptionService, EntryManager, EntryNotFoundError
from src.database.db import Database


class TestEntryManager(unittest.TestCase):
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_file.close()
        self.database = Database(self.temp_file.name)
        self.key_manager = KeyManager()
        self.key_manager.store_key("active", os.urandom(32))
        self.manager = EntryManager(self.database, AESGCMEncryptionService(self.key_manager))

    def tearDown(self):
        self.key_manager.clear_key()
        try:
            os.unlink(self.temp_file.name)
        except OSError:
            pass

    def test_create_and_get_entry_roundtrip(self):
        created = self.manager.create_entry(
            {
                "title": "Example",
                "username": "user@example.com",
                "password": "Secret!123",
                "url": "https://example.com",
                "notes": "Important",
                "category": "Work",
                "tags": ["work", "mail"],
            }
        )

        loaded = self.manager.get_entry(created["id"])

        self.assertEqual(loaded["title"], "Example")
        self.assertEqual(loaded["username"], "user@example.com")
        self.assertEqual(loaded["password"], "Secret!123")
        self.assertEqual(loaded["category"], "Work")
        self.assertEqual(loaded["tags"], "work,mail")

        raw_entry = self.database.get_entry(created["id"])
        self.assertIsNotNone(raw_entry)
        self.assertNotIn(b"Secret!123", raw_entry.encrypted_password)

    def test_get_all_entries_returns_decrypted_entries(self):
        self.manager.create_entry({"title": "One", "password": "alpha"})
        self.manager.create_entry({"title": "Two", "password": "beta"})

        entries = self.manager.get_all_entries()

        self.assertEqual(len(entries), 2)
        self.assertEqual({entry["title"] for entry in entries}, {"One", "Two"})

    def test_update_entry_reencrypts_payload(self):
        created = self.manager.create_entry({"title": "Example", "password": "Secret!123"})

        updated = self.manager.update_entry(
            created["id"],
            {
                "username": "new-user",
                "password": "NewSecret!456",
                "category": "Updated",
            },
        )

        self.assertEqual(updated["username"], "new-user")
        self.assertEqual(updated["password"], "NewSecret!456")
        self.assertEqual(updated["category"], "Updated")

    def test_delete_entry_requires_explicit_hard_delete_until_soft_delete_exists(self):
        created = self.manager.create_entry({"title": "Example", "password": "Secret!123"})

        with self.assertRaises(NotImplementedError):
            self.manager.delete_entry(created["id"])

        self.manager.delete_entry(created["id"], soft_delete=False)

        with self.assertRaises(EntryNotFoundError):
            self.manager.get_entry(created["id"])

    def test_missing_entry_raises_safe_error(self):
        with self.assertRaises(EntryNotFoundError):
            self.manager.get_entry(999999)

    def test_create_entry_publishes_event(self):
        received_events = []

        def handler(event):
            received_events.append(event)

        event_bus.subscribe(EventType.ENTRY_ADDED, handler)
        try:
            created = self.manager.create_entry({"title": "Published", "password": "Secret!123"})
        finally:
            event_bus.unsubscribe(EventType.ENTRY_ADDED, handler)

        self.assertEqual(len(received_events), 1)
        self.assertEqual(received_events[0].data["id"], created["id"])


if __name__ == "__main__":
    unittest.main()
