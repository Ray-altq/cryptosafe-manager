import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.config import Config


class TestConfig(unittest.TestCase):
    def setUp(self):
        # Создаём временную домашнюю директорию для изоляции тестов конфига.
        self.test_dir = tempfile.mkdtemp()
        self.original_home = Path.home
        Path.home = lambda: Path(self.test_dir)

    def tearDown(self):
        Path.home = self.original_home
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_default_config(self):
        config = Config()

        self.assertEqual(config.get("security.clipboard_timeout"), 30)
        self.assertEqual(config.get("security.auto_lock_minutes"), 5)

    def test_set_and_get(self):
        config = Config()

        config.set("appearance.theme", "dark")
        config.set("security.clipboard_timeout", 45)

        self.assertEqual(config.get("appearance.theme"), "dark")
        self.assertEqual(config.get("security.clipboard_timeout"), 45)

    def test_nested_keys(self):
        config = Config()
        config.set("security.clipboard_timeout", 60)

        self.assertEqual(config.get("security.clipboard_timeout"), 60)
        self.assertEqual(config.get("security.auto_lock_minutes"), 5)

    def test_default_value(self):
        config = Config()
        self.assertEqual(config.get("nonexistent.key", "default"), "default")


if __name__ == "__main__":
    unittest.main()
