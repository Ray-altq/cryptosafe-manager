import os
import sys
import tempfile
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
            url="https://test.com",
            notes="test notes",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            tags="test",
        )

    def tearDown(self):  #метод для очистки тестовой среды после каждого теста, который удаляет временный файл базы данных
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
            self.assertEqual(version, 3)

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


if __name__ == "__main__":
    unittest.main()
