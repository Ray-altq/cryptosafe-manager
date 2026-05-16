import os
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.database.db import Database
from src.database.models import KeyStore, VaultEntry


class TestDatabase(unittest.TestCase):  #класс для тестирования функциональности базы данных
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_file.close()
        self.db_path = self.temp_file.name
        self.db = Database(self.db_path)
        self.test_entry = VaultEntry(
            title="Test Site",
            username="test_user",
            encrypted_password=b"encrypted_test",
            encrypted_data=b"encrypted_test",
            url="https://test.com",
            notes="test notes",
            category="General",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            tags="test",
        )

    def tearDown(self):  #метод для очистки тестовой среды после каждого теста, который удаляет временный файл базы данных
        self.db.close()
        try:
            os.unlink(self.db_path)
        except OSError:
            pass

    def test_add_entry(self):  #тест для проверки добавления записи в базу данных
        entry_id = self.db.add_entry(self.test_entry)
        self.assertIsNotNone(entry_id)
        self.assertGreater(entry_id, 0)

    def test_get_entry(self):  #тест для проверки получения записи из базы данных
        entry_id = self.db.add_entry(self.test_entry)
        loaded = self.db.get_entry(entry_id)

        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.title, self.test_entry.title)
        self.assertEqual(loaded.username, self.test_entry.username)

    def test_get_all_entries(self):  #тест для проверки получения всех записей из базы данных
        self.db.add_entry(self.test_entry)
        self.db.add_entry(self.test_entry)
        self.db.add_entry(self.test_entry)

        entries = self.db.get_all_entries()
        self.assertEqual(len(entries), 3)

    def test_update_entry(self):  #тест для проверки обновления записи
        entry_id = self.db.add_entry(self.test_entry)

        entry = self.db.get_entry(entry_id)
        entry.title = "Updated Title"
        self.db.update_entry(entry)

        updated = self.db.get_entry(entry_id)
        self.assertEqual(updated.title, "Updated Title")

    def test_delete_entry(self):  #тест для проверки удаления записи
        entry_id = self.db.add_entry(self.test_entry)
        self.db.delete_entry(entry_id)

        deleted = self.db.get_entry(entry_id)
        self.assertIsNone(deleted)

    def test_user_version(self):  #тест для проверки, что версия базы данных установлена правильно
        with self.db._get_connection() as conn:
            cursor = conn.execute("PRAGMA user_version")
            version = cursor.fetchone()[0]
            self.assertEqual(version, 5)

            archive_table = conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'audit_archives'"
            ).fetchone()
            self.assertIsNotNone(archive_table)
            security_table = conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'audit_security_log'"
            ).fetchone()
            self.assertIsNotNone(security_table)

            update_trigger = conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'trigger' AND name = 'trg_audit_log_no_update'"
            ).fetchone()
            delete_trigger = conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'trigger' AND name = 'trg_audit_log_no_delete'"
            ).fetchone()
            self.assertIsNotNone(update_trigger)
            self.assertIsNotNone(delete_trigger)

    def test_settings_roundtrip(self):  #тест для проверки сохранения и получения настроек из базы данных
        self.db.set_setting("security.password_policy", {"min_length": 12})
        policy = self.db.get_setting("security.password_policy")
        self.assertEqual(policy["min_length"], 12)

    def test_key_store_roundtrip(self):  #тест для проверки сохранения и получения записи из хранилища ключей
        record = KeyStore(
            key_type="auth_hash",
            key_data=b"$argon2id$example",
            version=19,
            hash="$argon2id$example",
            created_at=datetime.now(),
            last_rotated_at=datetime.now(),
        )
        self.db.save_key_store(record)

        loaded = self.db.get_key_store("auth_hash")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.key_type, "auth_hash")
        self.assertEqual(loaded.version, 19)
        self.assertEqual(loaded.key_data, b"$argon2id$example")

    def test_reencrypt_passwords_reports_progress_and_respects_pause(self):
        first_id = self.db.add_entry(
            VaultEntry(
                title="One",
                username="user1",
                encrypted_password=b"one",
                created_at=datetime.now(),
                updated_at=datetime.now(),
            )
        )
        second_id = self.db.add_entry(
            VaultEntry(
                title="Two",
                username="user2",
                encrypted_password=b"two",
                created_at=datetime.now(),
                updated_at=datetime.now(),
            )
        )

        progress_updates = []
        pause_event = threading.Event()
        pause_event.clear()

        def release_pause():
            time.sleep(0.05)
            pause_event.set()

        threading.Thread(target=release_pause, daemon=True).start()

        updated = self.db.reencrypt_passwords(
            lambda ciphertext: ciphertext + b"!",
            progress_callback=lambda processed, total: progress_updates.append((processed, total)),
            pause_event=pause_event,
        )

        self.assertEqual(updated, 2)
        self.assertEqual(progress_updates[0], (0, 2))
        self.assertEqual(progress_updates[-1], (2, 2))
        self.assertEqual(self.db.get_entry(first_id).encrypted_password, b"one!")
        self.assertEqual(self.db.get_entry(second_id).encrypted_password, b"two!")
        self.assertEqual(self.db.get_entry(first_id).encrypted_data, b"one!")
        self.assertEqual(self.db.get_entry(second_id).encrypted_data, b"two!")

    def test_new_schema_supports_encrypted_data_and_category(self):
        entry_id = self.db.add_entry(self.test_entry)
        loaded = self.db.get_entry(entry_id)

        self.assertEqual(loaded.encrypted_data, b"encrypted_test")
        self.assertEqual(loaded.category, "General")

    def test_migration_v3_to_v4_backfills_encrypted_data(self):
        with self.db._get_connection() as conn:
            conn.execute("PRAGMA user_version = 3")
            conn.execute("DROP TABLE vault_entries")
            conn.execute(
                """
                CREATE TABLE vault_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    username TEXT NOT NULL,
                    encrypted_password BLOB NOT NULL,
                    url TEXT,
                    notes TEXT,
                    created_at TIMESTAMP NOT NULL,
                    updated_at TIMESTAMP NOT NULL,
                    tags TEXT
                )
                """
            )
            conn.execute(
                """
                INSERT INTO vault_entries
                (title, username, encrypted_password, url, notes, created_at, updated_at, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "Legacy",
                    "user",
                    b"legacy-secret",
                    "",
                    "",
                    datetime.now().isoformat(),
                    datetime.now().isoformat(),
                    "",
                ),
            )

        migrated = Database(self.db_path)
        entry = migrated.get_entry(1)

        self.assertIsNotNone(entry)
        self.assertEqual(entry.encrypted_password, b"legacy-secret")
        self.assertEqual(entry.encrypted_data, b"legacy-secret")
        self.assertEqual(entry.category, "")

    def test_migration_v4_to_v5_backfills_legacy_audit_rows(self):
        legacy_temp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        legacy_temp.close()
        initial_db = Database(legacy_temp.name)
        initial_db.close()

        import sqlite3

        legacy_conn = sqlite3.connect(legacy_temp.name)
        try:
            conn = legacy_conn
            conn.execute("PRAGMA user_version = 4")
            conn.execute("DROP TABLE audit_log")
            conn.execute(
                """
                CREATE TABLE audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    entry_id INTEGER,
                    details TEXT
                )
                """
            )
            conn.execute(
                """
                INSERT INTO audit_log (action, timestamp, entry_id, details)
                VALUES (?, ?, ?, ?)
                """,
                ("entry_added", datetime.now().isoformat(), 7, "legacy details"),
            )
            conn.commit()
        finally:
            legacy_conn.close()

        migrated = Database(legacy_temp.name)
        try:
            with migrated._get_connection() as conn:
                version = conn.execute("PRAGMA user_version").fetchone()[0]
                row = conn.execute(
                    "SELECT sequence_number, event_type, source, entry_data FROM audit_log"
                ).fetchone()

            self.assertEqual(version, 5)
            self.assertEqual(row["sequence_number"], 1)
            self.assertEqual(row["event_type"], "entry_added")
            self.assertEqual(row["source"], "legacy_migration")
            self.assertIn("legacy details", row["entry_data"])
        finally:
            migrated.close()
            try:
                os.unlink(legacy_temp.name)
            except OSError:
                pass

    def test_connection_pool_reuses_connections_between_requests(self):
        with self.db._get_connection() as first_conn:
            first_id = id(first_conn)

        with self.db._get_connection() as second_conn:
            second_id = id(second_conn)

        self.assertEqual(first_id, second_id)

    def test_audit_verification_policy_roundtrip(self):
        self.db.set_audit_verification_policy(interval_seconds=7200, recent_entry_limit=250, lock_on_tampering=True)
        policy = self.db.get_audit_verification_policy()
        self.assertEqual(policy["interval_seconds"], 7200)
        self.assertEqual(policy["recent_entry_limit"], 250)
        self.assertTrue(policy["lock_on_tampering"])

    def test_audit_security_event_roundtrip(self):
        event_id = self.db.add_audit_security_event(
            "audit_verification_failed",
            details={"trigger": "startup", "invalid_entries": 2},
            related_sequence_number=7,
        )
        self.assertGreater(event_id, 0)
        events = self.db.get_audit_security_events(limit=5)
        self.assertEqual(events[0]["event_type"], "audit_verification_failed")
        self.assertEqual(events[0]["related_sequence_number"], 7)
        self.assertIn('"trigger": "startup"', events[0]["details"])


if __name__ == "__main__":
    unittest.main()
