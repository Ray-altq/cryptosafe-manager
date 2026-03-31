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
        self.assertEqual(raw_entry.encrypted_password, b"")
        self.assertNotIn(b"Secret!123", raw_entry.encrypted_data)

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

    def test_create_entry_persists_category(self):
        created = self.manager.create_entry(
            {
                "title": "Categorized",
                "password": "Secret!123",
                "category": "Work",
            }
        )

        loaded = self.manager.get_entry(created["id"])

        self.assertEqual(loaded["category"], "Work")

    def test_delete_entry_soft_deletes_by_default(self):
        created = self.manager.create_entry({"title": "Example", "password": "Secret!123"})

        self.manager.delete_entry(created["id"])

        with self.assertRaises(EntryNotFoundError):
            self.manager.get_entry(created["id"])

        with self.database._get_connection() as conn:
            deleted_row = conn.execute(
                "SELECT original_entry_id, encrypted_data, title FROM deleted_entries WHERE original_entry_id = ?",
                (created["id"],),
            ).fetchone()

        self.assertIsNotNone(deleted_row)
        self.assertEqual(deleted_row["original_entry_id"], created["id"])
        self.assertEqual(deleted_row["title"], "Example")
        self.assertNotIn(b"Secret!123", deleted_row["encrypted_data"])

    def test_delete_entry_can_hard_delete_without_recycle_bin(self):
        created = self.manager.create_entry({"title": "Example", "password": "Secret!123"})

        self.manager.delete_entry(created["id"], soft_delete=False)

        with self.assertRaises(EntryNotFoundError):
            self.manager.get_entry(created["id"])

        with self.database._get_connection() as conn:
            deleted_row = conn.execute(
                "SELECT original_entry_id FROM deleted_entries WHERE original_entry_id = ?",
                (created["id"],),
            ).fetchone()

        self.assertIsNone(deleted_row)

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

    def test_get_entry_prefers_encrypted_data_from_new_schema(self):
        created = self.manager.create_entry({"title": "Schema", "password": "Secret!123"})
        raw_entry = self.database.get_entry(created["id"])
        self.assertIsNotNone(raw_entry)

        self.assertEqual(raw_entry.encrypted_password, b"")
        self.assertTrue(raw_entry.encrypted_data)

        loaded = self.manager.get_entry(created["id"])
        self.assertEqual(loaded["password"], "Secret!123")

    def test_crud_integration_handles_bulk_entry_lifecycle(self):
        created_ids = []
        for index in range(100):
            created = self.manager.create_entry(
                {
                    "title": f"Entry {index}",
                    "username": f"user{index}@example.com",
                    "password": f"Secret!{index:03d}Aa",
                    "url": f"https://example{index}.com",
                    "notes": f"note-{index}",
                    "category": "Work" if index % 2 == 0 else "Personal",
                    "tags": [f"tag-{index}", "bulk"],
                }
            )
            created_ids.append(created["id"])

        all_entries = self.manager.get_all_entries()
        self.assertEqual(len(all_entries), 100)
        self.assertEqual({entry["id"] for entry in all_entries}, set(created_ids))

        for entry_id in created_ids[:20]:
            updated = self.manager.update_entry(
                entry_id,
                {
                    "title": f"Updated {entry_id}",
                    "password": f"Updated!{entry_id:03d}Bb",
                    "category": "Updated",
                    "notes": f"updated-note-{entry_id}",
                },
            )
            self.assertEqual(updated["category"], "Updated")
            self.assertTrue(updated["title"].startswith("Updated "))
            self.assertTrue(updated["password"].startswith("Updated!"))

        for entry_id in created_ids[:10]:
            self.manager.delete_entry(entry_id)

        remaining_entries = self.manager.get_all_entries()
        self.assertEqual(len(remaining_entries), 90)
        self.assertFalse(any(entry["id"] in set(created_ids[:10]) for entry in remaining_entries))

        with self.database._get_connection() as conn:
            deleted_count = conn.execute("SELECT COUNT(*) AS total FROM deleted_entries").fetchone()["total"]
        self.assertEqual(deleted_count, 10)

        sample_updated = self.manager.get_entry(created_ids[10])
        self.assertEqual(sample_updated["category"], "Updated")
        self.assertEqual(sample_updated["notes"], f"updated-note-{created_ids[10]}")

    def test_future_fields_roundtrip_and_update(self):
        created = self.manager.create_entry(
            {
                "title": "Future-ready",
                "password": "Secret!123",
                "totp_secret": "JBSWY3DPEHPK3PXP",
                "sharing_metadata": {"shared_with": ["alice"], "permission": "read"},
            }
        )

        loaded = self.manager.get_entry(created["id"])
        self.assertEqual(loaded["totp_secret"], "JBSWY3DPEHPK3PXP")
        self.assertEqual(loaded["sharing_metadata"], {"shared_with": ["alice"], "permission": "read"})

        updated = self.manager.update_entry(
            created["id"],
            {
                "sharing_metadata": {"shared_with": ["alice", "bob"], "permission": "write"},
                "totp_secret": "NB2W45DFOIZA====",
            },
        )

        self.assertEqual(updated["totp_secret"], "NB2W45DFOIZA====")
        self.assertEqual(updated["sharing_metadata"]["permission"], "write")
        self.assertEqual(updated["sharing_metadata"]["shared_with"], ["alice", "bob"])


if __name__ == "__main__":
    unittest.main()
