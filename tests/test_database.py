import unittest
import sys
import os
import tempfile
from datetime import datetime
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.database.db import Database
from src.database.models import VaultEntry

class TestDatabase(unittest.TestCase):
    """Тесты для базы данных"""
    
    def setUp(self):
        """Создаем временную БД для каждого теста"""
        # создаем временный файл
        self.temp_file = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.temp_file.close()
        self.db_path = self.temp_file.name
        
        # создаем БД
        self.db = Database(self.db_path)
        
        # тестовая запись
        self.test_entry = VaultEntry(
            title="Test Site",
            username="test_user",
            encrypted_password=b"encrypted_test",
            url="https://test.com",
            notes="test notes",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            tags="test"
        )
    
    def tearDown(self):
        """Удаляем временную БД после теста"""
        # просто удаляем файл, не трогаем соединения
        try:
            os.unlink(self.db_path)
        except:
            pass
    
    def test_add_entry(self):
        """Тест: добавление записи"""
        entry_id = self.db.add_entry(self.test_entry)
        self.assertIsNotNone(entry_id)
        self.assertGreater(entry_id, 0)
    
    def test_get_entry(self):
        """Тест: чтение записи"""
        entry_id = self.db.add_entry(self.test_entry)
        loaded = self.db.get_entry(entry_id)
        
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.title, self.test_entry.title)
        self.assertEqual(loaded.username, self.test_entry.username)
    
    def test_get_all_entries(self):
        """Тест: получение всех записей"""
        self.db.add_entry(self.test_entry)
        self.db.add_entry(self.test_entry)
        self.db.add_entry(self.test_entry)
        
        entries = self.db.get_all_entries()
        self.assertEqual(len(entries), 3)
    
    def test_update_entry(self):
        """Тест: обновление записи"""
        entry_id = self.db.add_entry(self.test_entry)
        
        entry = self.db.get_entry(entry_id)
        entry.title = "Updated Title"
        self.db.update_entry(entry)
        
        updated = self.db.get_entry(entry_id)
        self.assertEqual(updated.title, "Updated Title")
    
    def test_delete_entry(self):
        """Тест: удаление записи"""
        entry_id = self.db.add_entry(self.test_entry)
        self.db.delete_entry(entry_id)
        
        deleted = self.db.get_entry(entry_id)
        self.assertIsNone(deleted)
    
    def test_user_version(self):
        """Тест: версия БД (DB-3)"""
        with self.db._get_connection() as conn:
            cursor = conn.execute("PRAGMA user_version")
            version = cursor.fetchone()[0]
            self.assertEqual(version, 1)

if __name__ == '__main__':
    unittest.main()