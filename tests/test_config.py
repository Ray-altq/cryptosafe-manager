import unittest
import sys
import os
import tempfile
import json
import shutil
from pathlib import Path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.config import Config

class TestConfig(unittest.TestCase):
    """Тесты для конфигурации (TEST-2)"""
    
    def setUp(self):
        # создаем временную папку для тестового конфига
        self.test_dir = tempfile.mkdtemp()
        self.original_home = Path.home
        
        # подменяем home на временную папку
        Path.home = lambda: Path(self.test_dir)
    
    def tearDown(self):
        # восстанавливаем оригинальный home
        Path.home = self.original_home
        # удаляем временную папку
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_default_config(self):
        """Тест: настройки по умолчанию"""
        config = Config()
        
        timeout = config.get('security.clipboard_timeout')
        self.assertEqual(timeout, 30)  # должно быть 30 по умолчанию
        
        auto_lock = config.get('security.auto_lock_minutes')
        self.assertEqual(auto_lock, 5)  # должно быть 5 по умолчанию
    
    def test_set_and_get(self):
        """Тест: установка и получение значений"""
        config = Config()
        
        config.set('appearance.theme', 'dark')
        theme = config.get('appearance.theme')
        self.assertEqual(theme, 'dark')
        
        config.set('security.clipboard_timeout', 45)
        timeout = config.get('security.clipboard_timeout')
        self.assertEqual(timeout, 45)
    
    def test_nested_keys(self):
        """Тест: вложенные ключи"""
        config = Config()
        
        # устанавливаем через точечную нотацию
        config.set('security.clipboard_timeout', 60)
        
        # проверяем что структура сохранилась
        self.assertEqual(config.get('security.clipboard_timeout'), 60)
        self.assertEqual(config.get('security.auto_lock_minutes'), 5)
    
    def test_default_value(self):
        """Тест: значение по умолчанию"""
        config = Config()
        
        # несуществующий ключ
        value = config.get('nonexistent.key', 'default')
        self.assertEqual(value, 'default')

if __name__ == '__main__':
    unittest.main()