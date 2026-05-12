import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.crypto.authentication import AuthenticationError, AuthenticationService
from src.core.crypto.key_derivation import KeyDerivation
from src.core.crypto.key_storage import KeyStorage
from src.core.crypto.password_validator import PasswordValidator
from src.core.crypto.placeholder import AES256Placeholder
from src.core.events import EventType, event_bus
from src.core.state_manager import StateManager
from src.database.db import Database
from src.database.models import VaultEntry


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
        self.password = "ValidMasterPass!9X"

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
        self.assertIsNotNone(self.state_manager.login_timestamp)

    def test_invalid_password_rejected_on_registration(self):  #тест для проверки, что при регистрации с недопустимым паролем возникает ошибка аутентификации
        with self.assertRaises(AuthenticationError):
            self.auth.register_master_password("short")

    def test_backoff_schedule(self):
        self.auth.register_master_password(self.password)
        self.auth.logout()

        self.assertFalse(self.auth.authenticate("wrong-1"))
        self.assertLessEqual(self.auth.get_lockout_remaining_seconds(), 1)
        self.auth._locked_until = None

        self.assertFalse(self.auth.authenticate("wrong-2"))
        self.assertLessEqual(self.auth.get_lockout_remaining_seconds(), 1)
        self.auth._locked_until = None

        self.assertFalse(self.auth.authenticate("wrong-3"))
        self.assertLessEqual(self.auth.get_lockout_remaining_seconds(), 5)

    def test_invalid_authentication_publishes_login_failed_event(self):
        self.auth.register_master_password(self.password)
        self.auth.logout()
        received_events = []

        def handler(event):
            received_events.append(event)

        event_bus.subscribe(EventType.USER_LOGIN_FAILED, handler)
        try:
            self.assertFalse(self.auth.authenticate("wrong-password"))
        finally:
            event_bus.unsubscribe(EventType.USER_LOGIN_FAILED, handler)

        self.assertEqual(len(received_events), 1)
        self.assertEqual(received_events[0].data["reason"], "invalid_password")
        self.assertGreaterEqual(received_events[0].data["failed_attempts"], 1)

    def test_change_master_password_reencrypts_entries(self):
        self.auth.register_master_password(self.password)
        old_key = self.auth.get_active_key()
        crypto = AES256Placeholder()

        entry = VaultEntry(
            title="site",
            username="user",
            encrypted_password=crypto.encrypt(b"secret", old_key),
        )
        entry_id = self.database.add_entry(entry)

        def rotate_entries(old_encryption_key, new_encryption_key):
            def transform(ciphertext: bytes) -> bytes:
                plaintext = crypto.decrypt(ciphertext, old_encryption_key)
                return crypto.encrypt(plaintext, new_encryption_key)

            self.database.reencrypt_passwords(transform)

        self.auth.change_master_password(self.password, "NewValidMasterPass!7Q", rotate_entries)
        self.auth.logout()

        self.assertTrue(self.auth.authenticate("NewValidMasterPass!7Q"))
        updated_entry = self.database.get_entry(entry_id)
        decrypted = crypto.decrypt(updated_entry.encrypted_password, self.auth.get_active_key())
        self.assertEqual(decrypted, b"secret")

    def test_register_persists_full_derivation_params(self):
        self.auth.register_master_password(self.password)

        metadata = self.key_storage.load_metadata()

        self.assertIsNotNone(metadata)
        self.assertEqual(metadata.params["auth_algorithm"], "argon2id")
        self.assertEqual(metadata.params["encryption_kdf"], "pbkdf2-hmac-sha256")
        self.assertEqual(metadata.params["pbkdf2_iterations"], 100000)
        self.assertEqual(metadata.params["pbkdf2_salt_len"], 16)
        self.assertEqual(metadata.params["pbkdf2_key_len"], 32)

    def test_authenticate_uses_stored_derivation_params(self):
        initial_auth = AuthenticationService(
            self.key_storage,
            KeyDerivation({"pbkdf2_iterations": 150000}),
            self.password_validator,
            self.state_manager,
        )
        initial_auth.register_master_password(self.password)
        original_key = initial_auth.get_active_key()
        crypto = AES256Placeholder()

        entry = VaultEntry(
            title="site",
            username="user",
            encrypted_password=crypto.encrypt(b"secret", original_key),
        )
        entry_id = self.database.add_entry(entry)
        initial_auth.logout()

        runtime_auth = AuthenticationService(
            self.key_storage,
            KeyDerivation({"pbkdf2_iterations": 300000}),
            self.password_validator,
            StateManager(),
        )

        self.assertTrue(runtime_auth.authenticate(self.password))
        self.assertEqual(runtime_auth.get_active_key(), original_key)

        updated_entry = self.database.get_entry(entry_id)
        decrypted = crypto.decrypt(updated_entry.encrypted_password, runtime_auth.get_active_key())
        self.assertEqual(decrypted, b"secret")

    def test_change_master_password_updates_stored_params(self):
        initial_auth = AuthenticationService(
            self.key_storage,
            KeyDerivation({"pbkdf2_iterations": 120000}),
            self.password_validator,
            self.state_manager,
        )
        initial_auth.register_master_password(self.password)

        updated_auth = AuthenticationService(
            self.key_storage,
            KeyDerivation({"pbkdf2_iterations": 220000}),
            self.password_validator,
            self.state_manager,
        )
        updated_auth.change_master_password(self.password, "NewValidMasterPass!7Q")

        metadata = self.key_storage.load_metadata()
        self.assertIsNotNone(metadata)
        self.assertEqual(metadata.params["pbkdf2_iterations"], 220000)

    def test_change_master_password_publishes_password_changed_event(self):
        self.auth.register_master_password(self.password)
        received_events = []

        def handler(event):
            received_events.append(event)

        event_bus.subscribe(EventType.PASSWORD_CHANGED, handler)
        try:
            self.auth.change_master_password(self.password, "NewValidMasterPass!7Q")
        finally:
            event_bus.unsubscribe(EventType.PASSWORD_CHANGED, handler)

        self.assertEqual(len(received_events), 1)
        self.assertEqual(received_events[0].data["status"], "success")


if __name__ == "__main__":
    unittest.main()
