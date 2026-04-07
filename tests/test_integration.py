import os
import sys
import tempfile
import tkinter as tk
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.clipboard import ClipboardStatus
from src.core.config import Config
from src.core.crypto.authentication import AuthenticationService
from src.core.crypto.key_derivation import KeyDerivation
from src.core.crypto.key_storage import KeyStorage
from src.core.crypto.placeholder import AES256Placeholder
from src.core.crypto.password_validator import PasswordValidator
from src.core.key_manager import KeyManager
from src.core.vault import AESGCMEncryptionService, EntryManager
from src.database.db import Database
from src.database.models import VaultEntry
from src.gui.main_window import EntryView, MainWindow
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


class FakeButton:
    def __init__(self):
        self.disabled = False

    def state(self, states):
        if "disabled" in states:
            self.disabled = True
        if "!disabled" in states:
            self.disabled = False

    def winfo_rootx(self):
        return 100

    def winfo_rooty(self):
        return 100

    def winfo_height(self):
        return 24


class FakeEntryWidget:
    def __init__(self):
        self.focused = False
        self.selection = None

    def focus_set(self):
        self.focused = True

    def selection_range(self, start, end):
        self.selection = (start, end)


class FakeTable:
    def __init__(self):
        self.rows = []

    def set_data(self, rows):
        self.rows = list(rows)

    def clear(self):
        self.rows = []

    def get_selected(self):
        return None


class FakeClipboardService:
    def __init__(self):
        self.calls = []
        self.status = ClipboardStatus(active=False)
        self.last_clear_reason = None
        self.settings = {
            "timeout_seconds": 30,
            "notifications_enabled": True,
            "security_level": "basic",
            "blocked_on_suspicious": False,
            "preset": "standard",
        }
        self.configure_calls = []

    def copy_text(self, value, **kwargs):
        self.calls.append((value, kwargs))

    def get_status(self):
        return self.status

    def get_last_clear_reason(self):
        return self.last_clear_reason

    def get_settings(self):
        return dict(self.settings)

    def configure(self, **kwargs):
        self.configure_calls.append(kwargs)
        self.settings.update(kwargs)


class FakeAuthService:
    def __init__(self):
        self.logged_out = False
        self.authenticated = False
        self.initialized = True

    def logout(self):
        self.logged_out = True

    def is_authenticated(self):
        return self.authenticated

    def is_initialized(self):
        return self.initialized

    def get_active_key(self):
        return b"x" * 32


class FakeKeyManager:
    def __init__(self):
        self.cleared = False

    def clear_key(self):
        self.cleared = True

    def store_key(self, _key_type, _value):
        pass


class FakeKeyStorage:
    def is_cache_expired(self):
        return False

    def touch_cached_key(self, _timeout_seconds):
        pass


class FakeStateManager:
    def __init__(self):
        self.clipboard_cleared = False
        self.application_active = True
        self.clipboard_content = None
        self.clipboard_timer = None

    def clear_clipboard(self):
        self.clipboard_cleared = True
        self.clipboard_content = None
        self.clipboard_timer = None

    def set_application_active(self, is_active):
        self.application_active = is_active

    def get_clipboard(self):
        return self.clipboard_content

    def should_auto_lock(self):
        return False

    def should_expire_key_cache(self):
        return False


class FakeRoot:
    def __init__(self):
        self.protocols = {}
        self.destroyed = False
        self.clipboard = ""
        self.update_calls = 0
        self.after_calls = []
        self.window_state = "normal"

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
        self.after_calls.append((_delay, _callback))
        return len(self.after_calls)

    def state(self):
        return self.window_state

    def focus_displayof(self):
        return object()

    def clipboard_clear(self):
        self.clipboard = ""

    def clipboard_append(self, value):
        self.clipboard = value

    def update(self):
        self.update_calls += 1

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


class TestMainWindowSearchAndFilter(IntegrationTestCase):
    def _make_window(self):
        window = MainWindow.__new__(MainWindow)
        window.table = FakeTable()
        window.search_var = FakeVar("")
        window.category_filter_var = FakeVar("Все")
        window.tag_filter_var = FakeVar("")
        window.updated_from_var = FakeVar("")
        window.updated_to_var = FakeVar("")
        window.password_strength_filter_var = FakeVar("Все")
        window.search_status_var = FakeVar("")
        window.search_entry = FakeEntryWidget()
        window.search_history_button = FakeButton()
        window.password_toggle_text = FakeVar("Показать пароли")
        window.passwords_visible = False
        window.password_visibility_overrides = {}
        window.search_history = []
        window.db = Database(self.make_db_path("search.db"))
        self.addCleanup(window.db.close)
        key_manager = KeyManager()
        key_manager.store_key("active", b"x" * 32)
        window.entry_manager = EntryManager(window.db, AESGCMEncryptionService(key_manager))
        window.root = FakeRoot()
        window._all_entries = [
            {
                "id": 1,
                "title": "GitHub",
                "username": "octocat",
                "password": "Secret!123",
                "category": "Work",
                "tags": "dev,code",
                "url": "github.com",
                "notes": "code hosting",
                "updated_at": datetime(2026, 3, 31, 20, 0),
                "_password_plain": "Secret!123",
                "_search_username": "octocat",
                "_search_url": "https://github.com",
                "_search_notes": "code hosting",
            },
            {
                "id": 2,
                "title": "Local Admin",
                "username": "admin",
                "password": "Local!456",
                "category": "Home",
                "tags": "infra,local",
                "url": "localhost",
                "notes": "local server",
                "updated_at": datetime(2026, 3, 31, 20, 5),
                "_password_plain": "Local!456",
                "_search_username": "admin",
                "_search_url": "http://localhost",
                "_search_notes": "local server",
            },
        ]
        return window

    def test_apply_entry_filter_supports_general_field_and_category_filters(self):
        window = self._make_window()

        window.search_var.set("github")
        window._apply_entry_filter()
        self.assertEqual([row["id"] for row in window.table.rows], [1])

        window.search_var.set("title:local")
        window._apply_entry_filter()
        self.assertEqual([row["id"] for row in window.table.rows], [2])

        window.search_var.set("user:octo notes:hosting")
        window._apply_entry_filter()
        self.assertEqual([row["id"] for row in window.table.rows], [1])

        window.search_var.set("")
        window.category_filter_var.set("Home")
        window._apply_entry_filter()
        self.assertEqual([row["id"] for row in window.table.rows], [2])
        self.assertEqual(window.search_status_var.get(), "Найдено: 1 из 2")

        window.category_filter_var.set("Все")
        window.tag_filter_var.set("dev")
        window._apply_entry_filter()
        self.assertEqual([row["id"] for row in window.table.rows], [1])

    def test_apply_entry_filter_supports_date_range_and_password_strength_filters(self):
        window = self._make_window()

        window.updated_from_var.set("2026-03-31")
        window.updated_to_var.set("2026-03-31")
        window.password_strength_filter_var.set("Средний")
        window._apply_entry_filter()
        self.assertEqual([row["id"] for row in window.table.rows], [1, 2])

        window.updated_from_var.set("2026-04-01")
        window._apply_entry_filter()
        self.assertEqual(window.table.rows, [])

        window.updated_from_var.set("")
        window.updated_to_var.set("")
        window.password_strength_filter_var.set("Слабый")
        window._apply_entry_filter()
        self.assertEqual(window.table.rows, [])

    def test_toggle_password_visibility_updates_table_rows(self):
        window = self._make_window()

        window._apply_entry_filter()
        self.assertNotEqual(window.table.rows[0]["password"], "Secret!123")

        result = window._toggle_password_visibility()
        self.assertEqual(result, "break")
        self.assertEqual(window.table.rows[0]["password"], "Secret!123  🙈")
        self.assertEqual(window.password_toggle_text.get(), "Скрыть пароли")

    def test_search_history_persists_and_reapplies_queries(self):
        window = self._make_window()

        for query in [f"query-{index}" for index in range(12)]:
            window._remember_search_query(query)

        self.assertEqual(len(window.search_history), 10)
        self.assertEqual(window.search_history[0], "query-11")
        self.assertEqual(window.search_history[-1], "query-2")
        self.assertFalse(window.search_history_button.disabled)

        stored_history = window.db.get_setting("ui.search_history", [])
        self.assertEqual(stored_history, window.search_history)

        window._apply_search_history_item("query-5")
        self.assertEqual(window.search_var.get(), "query-5")
        self.assertTrue(window.search_entry.focused)
        self.assertEqual(window.search_entry.selection, (0, tk.END))


class TestMainWindowDialogHelpers(IntegrationTestCase):
    def test_build_favicon_request_normalizes_host_and_builds_service_url(self):
        window = MainWindow.__new__(MainWindow)

        request_data = window._build_favicon_request("github.com/login")
        self.assertEqual(request_data["host"], "github.com")
        self.assertIn("google.com/s2/favicons", request_data["service_url"])
        self.assertIn("github.com", request_data["service_url"])

        request_with_scheme = window._build_favicon_request("https://sub.example.com/path")
        self.assertEqual(request_with_scheme["host"], "sub.example.com")

        self.assertIsNone(window._build_favicon_request(""))

    def test_set_system_clipboard_flushes_event_loop(self):
        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()

        window._set_system_clipboard("Secret!123")

        self.assertEqual(window.root.clipboard, "Secret!123")
        self.assertEqual(window.root.update_calls, 1)

    def test_copy_selected_username_uses_clipboard_service(self):
        window = MainWindow.__new__(MainWindow)
        window.clipboard_service = FakeClipboardService()
        window._on_activity = lambda: setattr(window, "_activity_called", True)
        entry = EntryView(
            {
                "id": 10,
                "title": "Example",
                "username": "demo-user",
                "encrypted_password": "Secret!123",
                "url": "",
                "notes": "",
            }
        )
        window._get_single_selected_entry = lambda _action: entry

        window.copy_selected_username()

        self.assertEqual(window.clipboard_service.calls[0][0], "demo-user")
        self.assertEqual(window.clipboard_service.calls[0][1]["data_type"], "username")
        self.assertTrue(window._activity_called)

    def test_copy_selected_all_uses_clipboard_service(self):
        window = MainWindow.__new__(MainWindow)
        window.clipboard_service = FakeClipboardService()
        window._on_activity = lambda: setattr(window, "_activity_called", True)
        window._decrypt_password = lambda _value: "Secret!123"
        entry = EntryView(
            {
                "id": 11,
                "title": "Example",
                "username": "demo-user",
                "encrypted_password": "encrypted",
                "url": "https://example.com",
                "notes": "note",
            }
        )
        window._get_single_selected_entry = lambda _action: entry

        window.copy_selected_all()

        copied_text = window.clipboard_service.calls[0][0]
        self.assertIn("Название: Example", copied_text)
        self.assertIn("Пароль: Secret!123", copied_text)
        self.assertEqual(window.clipboard_service.calls[0][1]["data_type"], "entry")
        self.assertTrue(window._activity_called)

    def test_refresh_clipboard_status_shows_preview_and_warning(self):
        window = MainWindow.__new__(MainWindow)
        window.clipboard_service = FakeClipboardService()
        window.clipboard_label = FakeLabel()
        window.clipboard_details_label = FakeLabel()
        window.clipboard_service.status = ClipboardStatus(
            active=True,
            data_type="password",
            source_entry_id=11,
            source_label="Example",
            preview="Sec*****",
            remaining_seconds=4,
            warning_emitted=True,
        )

        window._refresh_clipboard_status()

        self.assertEqual(window.clipboard_label.text, "Буфер обмена: пароль (4 сек)")
        self.assertIn("Источник: Example", window.clipboard_details_label.text)
        self.assertIn("Просмотр: Sec*****", window.clipboard_details_label.text)
        self.assertIn("Скоро очистка: 4 сек", window.clipboard_details_label.text)

    def test_on_clipboard_status_changed_updates_notice_and_table_marker(self):
        window = MainWindow.__new__(MainWindow)
        window.table = object()
        window.entry_manager = object()
        window.clipboard_service = FakeClipboardService()
        window.clipboard_notice_label = FakeLabel()
        window.clipboard_label = FakeLabel()
        window.clipboard_details_label = FakeLabel()
        window._clipboard_status_snapshot = ClipboardStatus(active=False)
        window._apply_entry_filter = lambda: setattr(window, "_filter_refreshed", True)

        status = ClipboardStatus(
            active=True,
            data_type="username",
            source_entry_id=12,
            source_label="GitHub",
            preview="d*****r",
            remaining_seconds=12,
        )

        window._on_clipboard_status_changed(status)

        self.assertEqual(window.clipboard_notice_label.text, "Скопировано: логин")
        self.assertEqual(window.clipboard_label.text, "Буфер обмена: логин (12 сек)")
        self.assertTrue(window._filter_refreshed)

    def test_format_entry_title_for_table_marks_active_clipboard_entry(self):
        window = MainWindow.__new__(MainWindow)
        window.clipboard_service = FakeClipboardService()
        window.clipboard_service.status = ClipboardStatus(active=True, source_entry_id=42, data_type="entry")

        marked_title = window._format_entry_title_for_table({"id": 42, "title": "Example"})
        plain_title = window._format_entry_title_for_table({"id": 41, "title": "Another"})

        self.assertEqual(marked_title, "Example [В буфере]")
        self.assertEqual(plain_title, "Another")

    def test_detect_clipboard_preset_returns_matching_profile_or_custom(self):
        window = MainWindow.__new__(MainWindow)

        secure_preset = window._detect_clipboard_preset(
            timeout_seconds=15,
            notifications_enabled=True,
            security_level="advanced",
            blocked_on_suspicious=False,
        )
        custom_preset = window._detect_clipboard_preset(
            timeout_seconds=42,
            notifications_enabled=False,
            security_level="advanced",
            blocked_on_suspicious=True,
        )

        self.assertEqual(secure_preset, "secure")
        self.assertEqual(custom_preset, "custom")

    def test_apply_clipboard_preset_to_vars_updates_all_fields(self):
        window = MainWindow.__new__(MainWindow)
        timeout_var = FakeVar(30)
        notifications_var = FakeVar(True)
        security_level_var = FakeVar("basic")
        blocked_var = FakeVar(False)

        applied = window._apply_clipboard_preset_to_vars(
            "public_computer",
            timeout_var=timeout_var,
            notifications_var=notifications_var,
            security_level_var=security_level_var,
            blocked_var=blocked_var,
        )

        self.assertTrue(applied)
        self.assertEqual(timeout_var.get(), 5)
        self.assertTrue(notifications_var.get())
        self.assertEqual(security_level_var.get(), "paranoid")
        self.assertTrue(blocked_var.get())

    def test_update_clipboard_notice_respects_notification_setting(self):
        window = MainWindow.__new__(MainWindow)
        window.clipboard_service = FakeClipboardService()
        window.clipboard_notice_label = FakeLabel()

        previous_status = ClipboardStatus(active=False)
        current_status = ClipboardStatus(active=True, data_type="password", remaining_seconds=30)

        window.clipboard_service.settings["notifications_enabled"] = False
        window._update_clipboard_notice(previous_status, current_status)
        self.assertEqual(window.clipboard_notice_label.text, "")

        window.clipboard_service.settings["notifications_enabled"] = True
        window._update_clipboard_notice(previous_status, current_status)
        self.assertEqual(window.clipboard_notice_label.text, "Скопировано: пароль")

    def test_update_clipboard_notice_shows_monitor_warning_reason(self):
        window = MainWindow.__new__(MainWindow)
        window.clipboard_service = FakeClipboardService()
        window.clipboard_notice_label = FakeLabel()
        window.clipboard_service.last_clear_reason = "monitor_warning"

        previous_status = ClipboardStatus(active=True, data_type="password")
        current_status = ClipboardStatus(active=False)

        window._update_clipboard_notice(previous_status, current_status)

        self.assertEqual(window.clipboard_notice_label.text, "Буфер обмена очищен из-за подозрительной активности")

    def test_handle_clipboard_security_alert_shows_warning_once_per_transition(self):
        window = MainWindow.__new__(MainWindow)
        window.root = FakeRoot()
        window.clipboard_service = FakeClipboardService()
        previous_status = ClipboardStatus(active=True, suspicious_activity=False)
        current_status = ClipboardStatus(
            active=True,
            data_type="password",
            source_label="GitHub",
            preview="Sec*****",
            suspicious_activity=True,
            blocked_future_copies=True,
        )

        with patch("src.gui.main_window.messagebox.showwarning") as showwarning:
            window._handle_clipboard_security_alert(previous_status, current_status)
            window._handle_clipboard_security_alert(current_status, current_status)

        self.assertEqual(showwarning.call_count, 1)
        warning_text = showwarning.call_args.args[1]
        self.assertIn("подозрительная активность", warning_text)
        self.assertIn("GitHub", warning_text)
        self.assertIn("временно заблокированы", warning_text)

    def test_refresh_clipboard_status_shows_copy_block_message(self):
        window = MainWindow.__new__(MainWindow)
        window.clipboard_service = FakeClipboardService()
        window.clipboard_label = FakeLabel()
        window.clipboard_details_label = FakeLabel()
        window.clipboard_service.status = ClipboardStatus(
            active=True,
            data_type="entry",
            source_label="Example",
            preview="E******e",
            suspicious_activity=True,
            blocked_future_copies=True,
        )

        window._refresh_clipboard_status()

        self.assertIn("Обнаружена подозрительная активность", window.clipboard_details_label.text)
        self.assertIn("Дальнейшее копирование временно заблокировано", window.clipboard_details_label.text)

    def test_suggest_usernames_prefers_existing_domain_matches_and_domain_patterns(self):
        window = MainWindow.__new__(MainWindow)
        window._all_entries = [
            {"username": "deploy@example.com", "url": "https://app.example.com"},
            {"username": "admin", "url": "http://localhost"},
        ]

        suggestions = window._suggest_usernames_for_url("https://mail.example.com/login")
        self.assertEqual(suggestions[0], "deploy@example.com")
        self.assertIn("admin@example.com", suggestions)

        localhost_suggestions = window._suggest_usernames_for_url("localhost")
        self.assertEqual(localhost_suggestions[0], "admin")
        self.assertIn("root", localhost_suggestions)


    def test_format_audit_log_line_for_clipboard_copy_is_human_readable(self):
        window = MainWindow.__new__(MainWindow)

        class AuditLogRecord:
            action = "clipboard_copied"
            timestamp = datetime(2026, 4, 7, 12, 30, 0)
            entry_id = 7
            details = "entry_id=7, data_type=password, timeout_seconds=30, source_label=GitHub"

        line = window._format_audit_log_line(AuditLogRecord())

        self.assertIn("Копирование в буфер обмена", line)
        self.assertIn("entry=7", line)
        self.assertIn("тип=пароль", line)
        self.assertIn("источник=GitHub", line)
        self.assertIn("таймаут=30 сек", line)

    def test_format_audit_log_line_for_clipboard_clear_expands_reason(self):
        window = MainWindow.__new__(MainWindow)

        class AuditLogRecord:
            action = "clipboard_cleared"
            timestamp = datetime(2026, 4, 7, 12, 30, 1)
            entry_id = 7
            details = "reason=monitor_warning, entry_id=7, data_type=password, observed_length=21"

        line = window._format_audit_log_line(AuditLogRecord())

        self.assertIn("Очистка буфера обмена", line)
        self.assertIn("Буфер обмена очищен из-за подозрительной активности", line)
        self.assertIn("тип=пароль", line)
        self.assertIn("наблюдаемая длина=21", line)

    def test_format_clipboard_clear_reason_handles_manual_and_replacement(self):
        window = MainWindow.__new__(MainWindow)

        self.assertEqual(window._format_clipboard_clear_reason("manual"), "Буфер обмена очищен вручную")
        self.assertEqual(
            window._format_clipboard_clear_reason("replacement"),
            "Буфер обмена заменён новым содержимым",
        )

class TestMainWindowSecurityState(IntegrationTestCase):
    def test_lock_vault_clears_decrypted_entries_and_password_visibility_state(self):
        window = MainWindow.__new__(MainWindow)
        window.auth_service = FakeAuthService()
        window.key_manager = FakeKeyManager()
        window.state = FakeStateManager()
        window.root = FakeRoot()
        window.table = FakeTable()
        window.table.set_data([{"id": 1, "title": "Visible"}])
        window.password_toggle_text = FakeVar("Скрыть пароли")
        window.search_status_var = FakeVar("Найдено: 1")
        window.passwords_visible = True
        window.password_visibility_overrides = {1: True}
        window._all_entries = [{"id": 1, "password": "Secret!123"}]
        window._set_status = lambda value: setattr(window, "_status_value", value)

        with patch("src.gui.main_window.event_bus.publish"), patch.object(MainWindow, "_require_login") as require_login:
            window._lock_vault(show_dialog=False)

        self.assertTrue(window.auth_service.logged_out)
        self.assertTrue(window.key_manager.cleared)
        self.assertTrue(window.state.clipboard_cleared)
        self.assertEqual(window._all_entries, [])
        self.assertFalse(window.passwords_visible)
        self.assertEqual(window.password_visibility_overrides, {})
        self.assertEqual(window.password_toggle_text.get(), "Показать пароли")
        self.assertEqual(window.search_status_var.get(), "Найдено: 0")
        self.assertEqual(window.table.rows, [])
        self.assertEqual(window._status_value, "Заблокировано")
        self.assertFalse(require_login.called)

    def test_lock_if_window_minimized_locks_authenticated_session(self):
        window = MainWindow.__new__(MainWindow)
        window.auth_service = FakeAuthService()
        window.auth_service.authenticated = True
        window.config = Config()
        window.state = FakeStateManager()
        window.root = FakeRoot()
        window.root.window_state = "iconic"
        window._lock_vault = lambda show_dialog=True: setattr(window, "_locked_with", show_dialog)

        window._lock_if_window_minimized()

        self.assertFalse(window.state.application_active)
        self.assertEqual(window._locked_with, False)

    def test_prompt_unlock_if_needed_reloads_entries_after_restore(self):
        window = MainWindow.__new__(MainWindow)
        window.auth_service = FakeAuthService()
        window.auth_service.authenticated = False
        window.key_manager = FakeKeyManager()
        window._initial_login_completed = True
        window._login_prompt_active = False
        window._require_login = lambda initial=False: setattr(window.auth_service, "authenticated", True)
        window._load_entries = lambda: setattr(window, "_entries_reloaded", True)

        window._prompt_unlock_if_needed()

        self.assertTrue(window.auth_service.authenticated)
        self.assertTrue(window._entries_reloaded)

    def test_focus_loss_lock_is_delayed_while_temporary_clipboard_is_active(self):
        window = MainWindow.__new__(MainWindow)
        window.auth_service = FakeAuthService()
        window.auth_service.authenticated = True
        window.config = Config()
        window.state = FakeStateManager()
        window.state.application_active = False
        window.state.clipboard_content = "Secret!123"
        window.root = FakeRoot()
        window.root.focus_displayof = lambda: None
        window._lock_vault = lambda show_dialog=True: setattr(window, "_locked_with", show_dialog)

        window._lock_if_application_inactive()

        self.assertFalse(hasattr(window, "_locked_with"))

    def test_clipboard_expiration_locks_unfocused_window_when_focus_lock_is_enabled(self):
        window = MainWindow.__new__(MainWindow)
        window.auth_service = FakeAuthService()
        window.auth_service.authenticated = True
        window.config = Config()
        window.key_storage = FakeKeyStorage()
        window.state = FakeStateManager()
        window.state.application_active = False
        window.state.clipboard_timer = object()
        window.state.clipboard_content = None
        window.root = FakeRoot()
        window.clipboard_label = FakeLabel()
        window._lock_vault = lambda show_dialog=True: setattr(window, "_locked_with", show_dialog)
        window._clear_system_clipboard = lambda: setattr(window, "_clipboard_cleared", True)

        with patch("src.gui.main_window.event_bus.publish"):
            window._check_security_timers()

        self.assertTrue(window._clipboard_cleared)
        self.assertEqual(window._locked_with, False)


if __name__ == "__main__":
    unittest.main()
