import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.config import Config
from src.core.crypto.authentication import AuthenticationService
from src.core.crypto.key_derivation import KeyDerivation
from src.core.crypto.key_storage import KeyStorage
from src.core.crypto.placeholder import AES256Placeholder
from src.core.crypto.password_validator import PasswordValidator
from src.database.db import Database
from src.database.models import VaultEntry
from src.gui.main_window import MainWindow
from src.gui.setup_wizard import SetupWizard


class FakeVar:
    def __init__(self, value=None):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class FakeDialog:
    def __init__(self):
        self.destroyed = False

    def destroy(self):
        self.destroyed = True


class FakeLabel:
    def __init__(self):
        self.text = ""

    def config(self, **kwargs):
        if "text" in kwargs:
            self.text = kwargs["text"]


class FakeTable:
    def __init__(self):
        self.rows = []

    def set_data(self, rows):
        self.rows = list(rows)

    def clear(self):
        self.rows = []

    def get_selected(self):
        return None


class FakeRoot:
    def __init__(self):
        self.protocols = {}
        self.destroyed = False
        self.clipboard = ""

    def title(self, _value):
        pass

    def geometry(self, _value):
        pass

    def protocol(self, name, callback):
        self.protocols[name] = callback

    def bind_all(self, *_args, **_kwargs):
        pass

    def bind(self, *_args, **_kwargs):
        pass

    def after(self, _delay, _callback):
        pass

    def state(self):
        return "normal"

    def focus_displayof(self):
        return object()

    def clipboard_clear(self):
        self.clipboard = ""

    def clipboard_append(self, value):
        self.clipboard = value

    def config(self, **_kwargs):
        pass

    def destroy(self):
        self.destroyed = True

    def mainloop(self):
        pass


class IntegrationTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_home = tempfile.TemporaryDirectory()
        self.home_path = Path(self.temp_home.name)
        self.addCleanup(self.temp_home.cleanup)

        self.config_home_patch = patch("src.core.config.Path.home", return_value=self.home_path)
        self.setup_home_patch = patch("src.gui.setup_wizard.Path.home", return_value=self.home_path)
        self.config_home_patch.start()
        self.setup_home_patch.start()
        self.addCleanup(self.config_home_patch.stop)
        self.addCleanup(self.setup_home_patch.stop)

    def make_db_path(self, filename="vault.db"):
        return str(self.home_path / ".cryptosafe" / filename)

    def make_auth_service(self, database_path):
        database = Database(database_path)
        key_storage = KeyStorage(database)
        return AuthenticationService(
            key_storage,
            KeyDerivation({}),
            PasswordValidator(),
        )


class TestSetupWizardIntegration(IntegrationTestCase):
    def test_finish_initial_setup_persists_configuration_and_initializes_auth(self):
        db_path = self.make_db_path()
        config = Config()
        auth_service = self.make_auth_service(db_path)

        wizard = SetupWizard.__new__(SetupWizard)
        wizard.config = config
        wizard.auth_service = auth_service
        wizard.master_password = FakeVar("ValidMasterPass!9X")
        wizard.confirm_password = FakeVar("ValidMasterPass!9X")
        wizard.db_path = FakeVar(db_path)
        wizard.algorithm = FakeVar("XOR")
        wizard.pbkdf2_iterations = FakeVar(150000)
        wizard.auto_lock_minutes = FakeVar(7)
        wizard.key_cache_timeout_minutes = FakeVar(17)
        wizard.wizard = FakeDialog()

        with patch("src.gui.setup_wizard.messagebox.showinfo"), patch("src.gui.setup_wizard.messagebox.showerror"):
            wizard._finish()

        self.assertTrue(auth_service.is_initialized())
        self.assertTrue(auth_service.is_authenticated())
        self.assertTrue(wizard.wizard.destroyed)
        self.assertEqual(config.get("database.path"), db_path)
        self.assertEqual(config.get("crypto.pbkdf2_iterations"), 150000)
        self.assertEqual(config.get("security.auto_lock_minutes"), 7)
        self.assertEqual(config.get("security.key_cache_timeout_minutes"), 17)

        database = Database(db_path)
        self.assertIsNotNone(database.get_key_store("auth_hash"))
        self.assertIsNotNone(database.get_key_store("enc_salt"))
        self.assertIsNotNone(database.get_key_store("params"))
        self.assertEqual(database.get_setting("security.auto_lock_timeout_minutes"), 7)
        self.assertEqual(database.get_setting("security.key_cache_timeout_minutes"), 17)
        self.assertEqual(database.get_setting("crypto.key_derivation")["pbkdf2_iterations"], 150000)
        self.assertEqual(database.get_setting("security.password_policy")["min_password_length"], 12)


class TestMainWindowIntegration(IntegrationTestCase):
    def _patch_window_chrome(self):
        return [
            patch("src.gui.main_window.tk.Tk", side_effect=FakeRoot),
            patch.object(MainWindow, "_create_menu", lambda self: None),
            patch.object(MainWindow, "_create_toolbar", lambda self: None),
            patch.object(MainWindow, "_create_main_area", lambda self: setattr(self, "table", FakeTable())),
            patch.object(
                MainWindow,
                "_create_statusbar",
                lambda self: (
                    setattr(self, "status_label", FakeLabel()),
                    setattr(self, "clipboard_label", FakeLabel()),
                ),
            ),
            patch.object(MainWindow, "_setup_events", lambda self: None),
            patch.object(MainWindow, "_setup_activity_tracking", lambda self: None),
            patch.object(MainWindow, "_schedule_security_tasks", lambda self: None),
        ]

    def test_main_window_starts_with_existing_vault_and_loads_entries(self):
        db_path = self.make_db_path("existing.db")
        config = Config()
        config.set("database.path", db_path)
        config.set("security.auto_lock_minutes", 9)
        config.set("security.key_cache_timeout_minutes", 13)
        config.set("crypto.pbkdf2_iterations", 180000)

        database = Database(db_path)
        auth_service = self.make_auth_service(db_path)
        password = "ValidMasterPass!9X"
        auth_service.register_master_password(password)
        crypto = AES256Placeholder()
        encrypted_password = crypto.encrypt(b"secret", auth_service.get_active_key())
        auth_service.logout()
        entry_id = database.add_entry(
            VaultEntry(
                title="Example",
                username="demo",
                encrypted_password=encrypted_password,
                encrypted_data=encrypted_password,
                url="https://example.com",
                notes="seed",
                tags="",
            )
        )

        patchers = self._patch_window_chrome()
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

        with patch("src.gui.main_window.simpledialog.askstring", return_value=password), patch(
            "src.gui.main_window.messagebox.showerror"
        ), patch("src.gui.main_window.messagebox.showwarning"):
            window = MainWindow()
            self.addCleanup(window._on_close)

        self.assertEqual(window.db.db_path, db_path)
        self.assertTrue(window.auth_service.is_authenticated())
        self.assertEqual(window.state.inactivity_timeout, 9 * 60)
        self.assertIn("WM_DELETE_WINDOW", window.root.protocols)
        self.assertEqual(len(window.table.rows), 1)
        self.assertEqual(window.table.rows[0]["id"], entry_id)
        self.assertEqual(window.table.rows[0]["title"], "Example")
        self.assertEqual(window.table.rows[0]["username"], "demo")
        self.assertEqual(window.table.rows[0]["url"], "example.com")
        self.assertEqual(window.db.get_setting("security.auto_lock_timeout_minutes"), 9)
        self.assertEqual(window.db.get_setting("security.key_cache_timeout_minutes"), 13)
        self.assertEqual(window.db.get_setting("crypto.key_derivation")["pbkdf2_iterations"], 180000)

    def test_main_window_triggers_setup_for_uninitialized_vault(self):
        db_path = self.make_db_path("fresh.db")
        config = Config()
        config.set("database.path", db_path)

        patchers = self._patch_window_chrome()
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

        setup_calls = []

        def fake_setup(_root, passed_config, auth_service):
            setup_calls.append(passed_config.get("database.path"))
            auth_service.register_master_password("ValidMasterPass!9X")

        with patch("src.gui.main_window.SetupWizard", side_effect=fake_setup), patch(
            "src.gui.main_window.simpledialog.askstring", return_value="ValidMasterPass!9X"
        ), patch("src.gui.main_window.messagebox.showerror"), patch("src.gui.main_window.messagebox.showwarning"):
            window = MainWindow()
            self.addCleanup(window._on_close)

        self.assertEqual(setup_calls, [db_path])
        self.assertTrue(window.auth_service.is_initialized())
        self.assertTrue(window.auth_service.is_authenticated())
        self.assertEqual(window.db.db_path, db_path)


if __name__ == "__main__":
    unittest.main()
