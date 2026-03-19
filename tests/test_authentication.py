import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))  

from src.core.crypto.authentication import AuthenticationError, AuthenticationService
from src.core.crypto.key_derivation import KeyDerivation
from src.core.crypto.key_storage import KeyStorage
from src.core.crypto.password_validator import PasswordValidator
from src.core.state_manager import StateManager
from src.database.db import Database


class TestAuthentication(unittest.TestCase):  #класс для тестирования функциональности аутентификации
    def setUp(self):  #метод для настройки тестовой среды
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_file.close()
        self.database = Database(self.temp_file.name)
        self.key_storage = KeyStorage(self.database)
        self.key_derivation = KeyDerivation({})
        self.password_validator = PasswordValidator()
        self.state_manager = StateManager()
        self.auth = AuthenticationService(
            self.key_storage,
            self.key_derivation,
            self.password_validator,
            self.state_manager,
        )
        self.password = "ValidMasterPass123!"

    def tearDown(self):  #метод для очистки тестовой среды после каждого теста, который очищает кеш ключа и удаляет временный файл базы данных
        self.key_storage.clear_cached_key()
        try:
            os.unlink(self.temp_file.name)
        except OSError:
            pass

    def test_register_and_authenticate(self):  #тест для проверки регистрации и аутентификации
        self.auth.register_master_password(self.password)
        self.auth.logout()

        self.assertTrue(self.auth.authenticate(self.password))
        self.assertTrue(self.auth.is_authenticated())
        self.assertIsNotNone(self.auth.get_active_key())

    def test_invalid_password_rejected_on_registration(self):  #тест для проверки, что при регистрации с недопустимым паролем возникает ошибка аутентификации
        with self.assertRaises(AuthenticationError):
            self.auth.register_master_password("short")

    def test_change_master_password(self):  #тест для проверки изменения мастер-пароля
        self.auth.register_master_password(self.password)
        self.auth.change_master_password(self.password, "NewValidMasterPass456!")
        self.auth.logout()

        self.assertFalse(self.auth.authenticate(self.password))
        self.assertGreater(self.auth.get_lockout_remaining_seconds(), 0)
        self.auth._locked_until = None
        self.assertTrue(self.auth.authenticate("NewValidMasterPass456!"))


if __name__ == "__main__":
    unittest.main()
