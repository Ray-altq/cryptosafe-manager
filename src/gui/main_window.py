import os
import queue
import threading
import tkinter as tk
import ctypes
from base64 import b64encode
from datetime import datetime
from typing import Optional
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from tkinter import filedialog, messagebox, simpledialog, ttk

from ..core.clipboard import ClipboardAccessError, ClipboardMonitor, ClipboardService, ClipboardStatus, create_platform_adapter
from ..core.config import Config
from ..core.crypto.authentication import AuthenticationError, AuthenticationService
from ..core.crypto.key_derivation import KeyDerivation
from ..core.crypto.key_storage import KeyStorage
from ..core.crypto.password_validator import PasswordValidator
from ..core.crypto.placeholder import AES256Placeholder
from ..core.events import AuditLogger, Event, EventType, event_bus
from ..core.key_manager import KeyManager
from ..core.state_manager import StateManager
from ..core.vault import (
    AESGCMEncryptionService,
    EntryManager,
    EntryNotFoundError,
    PasswordGenerator,
    PasswordGeneratorOptions,
)
from ..database.db import Database
from .setup_wizard import SetupWizard
from .widgets.password_entry import PasswordEntry
from .widgets.secure_table import SecureTable


class EntryView(dict):
    def __getattr__(self, item):
        try:
            return self[item]
        except KeyError as error:
            raise AttributeError(item) from error


class MainWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("CryptoSafe Manager")
        self.root.geometry("980x640")

        self.config = Config()
        self.state = StateManager()
        self.state.set_inactivity_timeout(self.config.get("security.auto_lock_minutes", 5) * 60)
        self.state.set_key_cache_timeout(self.config.get("security.key_cache_timeout_minutes", 60) * 60)

        self.db = Database(self.config.get("database.path", "cryptosafe.db"))
        self.key_manager = KeyManager()
        self.key_storage = KeyStorage(self.db)
        self.key_derivation = KeyDerivation(self.config.get("crypto", {}))
        self.password_validator = PasswordValidator(self.config.get("security", {}))
        self.auth_service = AuthenticationService(
            self.key_storage,
            self.key_derivation,
            self.password_validator,
            self.state,
        )
        self.crypto = AES256Placeholder(self.key_manager)
        self.vault_crypto = AESGCMEncryptionService(self.key_manager)
        self.entry_manager = EntryManager(self.db, self.vault_crypto, legacy_encryption_service=self.crypto)
        self.password_generator = PasswordGenerator()
        self.passwords_visible = False
        self.password_visibility_overrides = {}
        self.search_history = []
        self._favicon_cache = {}
        self._login_prompt_active = False
        self._initial_login_completed = False
        self.audit_logger = AuditLogger(self.db, event_bus)
        self.clipboard_service = ClipboardService(
            create_platform_adapter(self.root),
            database=self.db,
            config=self.config,
            state_manager=self.state,
        )
        self.clipboard_monitor = ClipboardMonitor(self.clipboard_service.adapter, self.clipboard_service)
        self._clipboard_status_snapshot = ClipboardStatus(active=False)
        self.clipboard_service.subscribe(self._on_clipboard_status_changed)
        self._persist_runtime_settings()
        self._load_password_policy()
        self._load_search_history()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        if not self.auth_service.is_initialized():
            SetupWizard(self.root, self.config, self.auth_service)
            if not self.auth_service.is_initialized():
                self._on_close()
                return
            self.db = self.auth_service.key_storage.database
            self.key_storage = self.auth_service.key_storage
            self.entry_manager = EntryManager(self.db, self.vault_crypto, legacy_encryption_service=self.crypto)
            self.audit_logger.close()
            self.audit_logger = AuditLogger(self.db, event_bus)
            self._persist_runtime_settings()
            self._load_password_policy()
            self.password_visibility_overrides = {}
            self._load_search_history()

        self._create_menu()
        self._create_toolbar()
        self._create_main_area()
        self._create_statusbar()
        self._setup_events()
        self._setup_activity_tracking()

        self._require_login(initial=True)
        self._initial_login_completed = True
        if not self.auth_service.is_authenticated():
            return
        self._load_entries()
        self._schedule_security_tasks()

    def _persist_runtime_settings(self):
        self.db.set_setting(
            "crypto.key_derivation",
            {
                "argon2_time": self.config.get("crypto.argon2_time", 3),
                "argon2_memory": self.config.get("crypto.argon2_memory", 65536),
                "argon2_parallelism": self.config.get("crypto.argon2_parallelism", 4),
                "argon2_hash_len": self.config.get("crypto.argon2_hash_len", 32),
                "pbkdf2_iterations": self.config.get("crypto.pbkdf2_iterations", 100000),
                "pbkdf2_salt_len": self.config.get("crypto.pbkdf2_salt_len", 16),
                "pbkdf2_key_len": self.config.get("crypto.pbkdf2_key_len", 32),
            },
        )
        self.db.set_setting("security.auto_lock_timeout_minutes", self.config.get("security.auto_lock_minutes", 5))
        self.db.set_setting("security.key_cache_timeout_minutes", self.config.get("security.key_cache_timeout_minutes", 60))
        self.db.set_setting("security.lock_on_focus_loss", self.config.get("security.lock_on_focus_loss", True))
        self.db.set_setting("security.lock_on_minimize", self.config.get("security.lock_on_minimize", True))
        self.db.set_setting("security.clipboard", self.clipboard_service.get_settings(), encrypted=True)

    def _load_password_policy(self):
        policy = self.db.get_setting("security.password_policy", {})
        if not isinstance(policy, dict):
            return
        self.password_validator.min_length = policy.get("min_password_length", self.password_validator.min_length)
        self.password_validator.require_uppercase = policy.get(
            "require_uppercase", self.password_validator.require_uppercase
        )
        self.password_validator.require_lowercase = policy.get(
            "require_lowercase", self.password_validator.require_lowercase
        )
        self.password_validator.require_digits = policy.get("require_digits", self.password_validator.require_digits)
        self.password_validator.require_special = policy.get(
            "require_special", self.password_validator.require_special
        )

    def _load_search_history(self):
        loaded_history = self.db.get_setting("ui.search_history", [])
        if not isinstance(loaded_history, list):
            self.search_history = []
            return
        self.search_history = [
            str(item).strip()
            for item in loaded_history
            if isinstance(item, str) and str(item).strip()
        ][:10]

    def _create_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Файл", menu=file_menu)
        file_menu.add_command(label="Новый vault", command=self.new_database)
        file_menu.add_command(label="Открыть vault", command=self.open_database)
        file_menu.add_command(label="Резервная копия", command=self.backup)
        file_menu.add_separator()
        file_menu.add_command(label="Заблокировать", command=self._lock_vault)
        file_menu.add_command(label="Выход", command=self._on_close)

        entry_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Записи", menu=entry_menu)
        entry_menu.add_command(label="Добавить", command=self.add_entry)
        entry_menu.add_command(label="Изменить", command=self.edit_entry)
        entry_menu.add_command(label="Удалить", command=self.delete_entry)
        entry_menu.add_command(label="Показать пароль", command=self.show_selected_password)
        entry_menu.add_command(label="Скопировать пароль", command=self.copy_selected_password)

        entry_menu.add_command(label="Скопировать логин", command=self.copy_selected_username)
        entry_menu.add_command(label="Скопировать запись", command=self.copy_selected_all)

        security_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Безопасность", menu=security_menu)
        security_menu.add_command(label="Сменить мастер-пароль", command=self.change_master_password)
        security_menu.add_command(label="Настройки", command=self.show_settings)
        security_menu.add_command(label="Журнал аудита", command=self.show_logs)

        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Справка", menu=help_menu)
        help_menu.add_command(label="О программе", command=self.show_about)

    def _create_toolbar(self):
        toolbar = ttk.Frame(self.root)
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=6, pady=6)

        actions_row = ttk.Frame(toolbar)
        actions_row.pack(fill=tk.X, pady=(0, 4))
        search_row = ttk.Frame(toolbar)
        search_row.pack(fill=tk.X, pady=(0, 4))
        filters_row = ttk.Frame(toolbar)
        filters_row.pack(fill=tk.X)

        ttk.Button(actions_row, text="Добавить", command=self.add_entry).pack(side=tk.LEFT, padx=2)
        ttk.Button(actions_row, text="Изменить", command=self.edit_entry).pack(side=tk.LEFT, padx=2)
        ttk.Button(actions_row, text="Удалить", command=self.delete_entry).pack(side=tk.LEFT, padx=2)
        ttk.Button(actions_row, text="Показать пароль", command=self.show_selected_password).pack(side=tk.LEFT, padx=(10, 2))
        ttk.Button(actions_row, text="Скопировать пароль", command=self.copy_selected_password).pack(side=tk.LEFT, padx=2)
        self.password_toggle_text = tk.StringVar(value="Показать пароли")
        ttk.Button(actions_row, text="Скопировать логин", command=self.copy_selected_username).pack(side=tk.LEFT, padx=2)
        ttk.Button(actions_row, text="Скопировать запись", command=self.copy_selected_all).pack(side=tk.LEFT, padx=2)
        ttk.Button(actions_row, textvariable=self.password_toggle_text, command=self._toggle_password_visibility).pack(
            side=tk.LEFT, padx=(8, 2)
        )
        ttk.Button(actions_row, text="Заблокировать", command=self._lock_vault).pack(side=tk.RIGHT, padx=2)

        ttk.Label(search_row, text="Поиск").pack(side=tk.LEFT, padx=(0, 4))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_args: self._apply_entry_filter())
        self.search_entry = ttk.Entry(search_row, textvariable=self.search_var, width=28)
        self.search_entry.pack(side=tk.LEFT, padx=2)
        self.search_entry.bind("<Escape>", lambda _event: self._clear_search())
        self.search_entry.bind("<Return>", self._commit_search_query)
        self.search_entry.bind("<FocusOut>", self._remember_current_search)
        self.search_history_button = ttk.Button(search_row, text="История", command=self._show_search_history_menu)
        self.search_history_button.pack(side=tk.LEFT, padx=(2, 4))
        ttk.Button(search_row, text="Сбросить", command=self._clear_search).pack(side=tk.LEFT, padx=(2, 8))
        self.search_status_var = tk.StringVar(value="Найдено: 0")
        ttk.Label(search_row, textvariable=self.search_status_var).pack(side=tk.LEFT, padx=(4, 0))
        ttk.Label(filters_row, text="Категория").pack(side=tk.LEFT, padx=(0, 4))
        self.category_filter_var = tk.StringVar(value="Все")
        self.category_filter = ttk.Combobox(
            filters_row,
            textvariable=self.category_filter_var,
            state="readonly",
            width=12,
            values=["Все"],
        )
        self.category_filter.pack(side=tk.LEFT, padx=2)
        self.category_filter.bind("<<ComboboxSelected>>", lambda _event: self._apply_entry_filter())
        ttk.Label(filters_row, text="Тег").pack(side=tk.LEFT, padx=(8, 4))
        self.tag_filter_var = tk.StringVar()
        self.tag_filter_var.trace_add("write", lambda *_args: self._apply_entry_filter())
        self.tag_filter_entry = ttk.Entry(filters_row, textvariable=self.tag_filter_var, width=12)
        self.tag_filter_entry.pack(side=tk.LEFT, padx=2)
        ttk.Label(filters_row, text="Дата с").pack(side=tk.LEFT, padx=(8, 4))
        self.updated_from_var = tk.StringVar()
        self.updated_from_var.trace_add("write", lambda *_args: self._apply_entry_filter())
        self.updated_from_entry = ttk.Entry(filters_row, textvariable=self.updated_from_var, width=10)
        self.updated_from_entry.pack(side=tk.LEFT, padx=2)
        ttk.Label(filters_row, text="по").pack(side=tk.LEFT, padx=(4, 4))
        self.updated_to_var = tk.StringVar()
        self.updated_to_var.trace_add("write", lambda *_args: self._apply_entry_filter())
        self.updated_to_entry = ttk.Entry(filters_row, textvariable=self.updated_to_var, width=10)
        self.updated_to_entry.pack(side=tk.LEFT, padx=2)
        ttk.Label(filters_row, text="Сила").pack(side=tk.LEFT, padx=(8, 4))
        self.password_strength_filter_var = tk.StringVar(value="Все")
        self.password_strength_filter = ttk.Combobox(
            filters_row,
            textvariable=self.password_strength_filter_var,
            state="readonly",
            width=10,
            values=["Все", "Слабый", "Средний", "Сильный"],
        )
        self.password_strength_filter.pack(side=tk.LEFT, padx=2)
        self.password_strength_filter.bind("<<ComboboxSelected>>", lambda _event: self._apply_entry_filter())
        self._update_search_history_button()

    def _create_main_area(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        columns = [
            {"id": "title", "label": "Название", "width": 180},
            {"id": "username", "label": "Имя пользователя", "width": 180},
            {"id": "password", "label": "Пароль", "width": 150},
            {"id": "category", "label": "Категория", "width": 140},
            {"id": "url", "label": "URL", "width": 260},
            {"id": "updated_at", "label": "Обновлено", "width": 160},
        ]
        self.table = SecureTable(main_frame, columns)
        self.table.pack(fill=tk.BOTH, expand=True)
        self.table.bind_primary_click(self._handle_table_click)
        self._create_table_context_menu()

    def _create_table_context_menu(self):
        self.table_menu = tk.Menu(self.root, tearoff=0)
        self.table_menu.add_command(label="Изменить", command=self.edit_entry)
        self.table_menu.add_command(label="Удалить", command=self.delete_entry)
        self.table_menu.add_separator()
        self.table_menu.add_command(label="Показать пароль", command=self.show_selected_password)
        self.table_menu.add_command(label="Скопировать пароль", command=self.copy_selected_password)
        self.table_menu.add_command(label="Скопировать логин", command=self.copy_selected_username)
        self.table_menu.add_command(label="Скопировать запись", command=self.copy_selected_all)
        self.table.bind_context_menu(self._show_table_context_menu)

    def _show_table_context_menu(self, event):
        selected = self.table.ensure_row_selected_at_y(event.y)
        if not selected:
            return
        try:
            self.table_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.table_menu.grab_release()

    def _create_statusbar(self):
        statusbar = ttk.Frame(self.root)
        statusbar.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_label = ttk.Label(statusbar, text="Заблокировано")
        self.status_label.pack(side=tk.LEFT, padx=5)

        self.clipboard_label = ttk.Label(statusbar, text="Буфер обмена: пуст")
        self.clipboard_label.pack(side=tk.LEFT, padx=20)
        self.clipboard_details_label = ttk.Label(statusbar, text="")
        self.clipboard_details_label.pack(side=tk.LEFT, padx=5)
        self.clipboard_notice_label = ttk.Label(statusbar, text="")
        self.clipboard_notice_label.pack(side=tk.LEFT, padx=10)

        ttk.Label(statusbar, text="v2.0").pack(side=tk.RIGHT, padx=5)

    def _setup_events(self):
        event_bus.subscribe(EventType.ENTRY_ADDED, self._on_entry_changed)
        event_bus.subscribe(EventType.ENTRY_UPDATED, self._on_entry_changed)
        event_bus.subscribe(EventType.ENTRY_DELETED, self._on_entry_changed)
        event_bus.subscribe(EventType.USER_LOGGED_IN, lambda _event: self._set_status("Разблокировано"))
        event_bus.subscribe(EventType.USER_LOGGED_OUT, lambda _event: self._set_status("Заблокировано"))
        event_bus.subscribe(EventType.CLIPBOARD_COPIED, lambda _event: self._refresh_clipboard_status())
        event_bus.subscribe(EventType.CLIPBOARD_CLEARED, lambda _event: self._refresh_clipboard_status())
        event_bus.subscribe(EventType.VAULT_LOCKED, lambda _event: self.clipboard_service.clear(reason="vault_locked"))

    def _setup_activity_tracking(self):
        for sequence in ("<Any-KeyPress>", "<Any-ButtonPress>", "<Motion>"):
            self.root.bind_all(sequence, self._on_activity, add="+")
        self.root.bind("<FocusIn>", self._on_focus_in, add="+")
        self.root.bind("<FocusOut>", self._on_focus_out, add="+")
        self.root.bind("<Unmap>", self._on_unmap, add="+")
        self.root.bind("<Map>", self._on_map, add="+")
        self.root.bind_all("<Control-f>", self._focus_search, add="+")
        self.root.bind_all("<Control-F>", self._focus_search, add="+")
        self.root.bind_all("<Control-Shift-P>", self._toggle_password_visibility, add="+")
        self.root.bind_all("<Control-Shift-p>", self._toggle_password_visibility, add="+")

    def _schedule_security_tasks(self):
        self._check_security_timers()
        self.root.after(1000, self._schedule_security_tasks)

    def _check_security_timers(self):
        if self.state.should_auto_lock() or self.state.should_expire_key_cache() or self.key_storage.is_cache_expired():
            self._lock_vault(show_dialog=False)
        clipboard_tick_result = None
        if hasattr(self, "clipboard_service") and hasattr(self, "clipboard_monitor"):
            clipboard_tick_result = self.clipboard_service.tick()
            self.clipboard_monitor.poll()
        elif self.state.clipboard_timer and self.state.get_clipboard() is None:
            self._clear_system_clipboard()
            event_bus.publish(Event(EventType.CLIPBOARD_CLEARED, {}))
            clipboard_tick_result = "timeout"
        if clipboard_tick_result == "timeout" and self._should_lock_after_clipboard_clear():
            self._lock_vault(show_dialog=False)
        self._refresh_clipboard_status()

    def _on_activity(self, _event=None):
        if self.state.is_unlocked():
            self.state.update_activity()
            self.key_storage.touch_cached_key(self.state.key_cache_timeout)

    def _on_focus_in(self, _event=None):
        self.state.set_application_active(True)

    def _on_focus_out(self, _event=None):
        self.state.set_application_active(False)
        self.root.after(150, self._lock_if_application_inactive)

    def _on_unmap(self, _event=None):
        self.state.set_application_active(False)
        self.root.after(100, self._lock_if_window_minimized)

    def _on_map(self, _event=None):
        self.state.set_application_active(True)
        if getattr(self, "_initial_login_completed", False):
            self.root.after(100, self._prompt_unlock_if_needed)

    def _lock_if_application_inactive(self):
        try:
            app_has_focus = self.root.focus_displayof() is not None
            is_iconic = self.root.state() == "iconic"
        except tk.TclError:
            return

        if app_has_focus or is_iconic:
            return

        self.state.set_application_active(False)
        if self.config.get("security.lock_on_focus_loss", True) and self.auth_service.is_authenticated():
            if self.state.get_clipboard() is not None:
                return
            self._lock_vault(show_dialog=False)

    def _lock_if_window_minimized(self):
        try:
            window_state = self.root.state()
        except tk.TclError:
            return

        if window_state not in {"iconic", "withdrawn"}:
            return

        self.state.set_application_active(False)
        if self.config.get("security.lock_on_minimize", True) and self.auth_service.is_authenticated():
            self._lock_vault(show_dialog=False)

    def _prompt_unlock_if_needed(self):
        if self._login_prompt_active:
            return
        if not getattr(self, "_initial_login_completed", False):
            return
        if not self.auth_service.is_initialized():
            return
        if self.auth_service.is_authenticated():
            return

        self._require_login()
        if self.auth_service.is_authenticated():
            self.key_manager.store_key("active", self.auth_service.get_active_key())
            self._load_entries()

    def _should_lock_after_clipboard_clear(self) -> bool:
        if self.state.application_active:
            return False
        if not self.config.get("security.lock_on_focus_loss", True):
            return False
        return self.auth_service.is_authenticated()

    def _set_status(self, text: str):
        self.status_label.config(text=text)

    def _on_clipboard_status_changed(self, status: ClipboardStatus):
        previous_status = getattr(self, "_clipboard_status_snapshot", ClipboardStatus(active=False))
        self._clipboard_status_snapshot = status
        self._sync_clipboard_row_marker(previous_status, status)
        self._update_clipboard_notice(previous_status, status)
        self._refresh_clipboard_status()

    def _refresh_clipboard_status(self):
        status = self._get_clipboard_status()
        if not status.active:
            self.clipboard_label.config(text="Буфер обмена: пуст")
            if hasattr(self, "clipboard_details_label"):
                self.clipboard_details_label.config(text="")
            return

        data_type_label = self._format_clipboard_data_type(status.data_type)
        if status.remaining_seconds > 0:
            status_text = f"Буфер обмена: {data_type_label} ({status.remaining_seconds} сек)"
        else:
            status_text = f"Буфер обмена: {data_type_label}"
        self.clipboard_label.config(text=status_text)

        details_parts = []
        if status.source_label:
            details_parts.append(f"Источник: {status.source_label}")
        if status.preview:
            details_parts.append(f"Просмотр: {status.preview}")
        if status.suspicious_activity:
            details_parts.append("Обнаружена подозрительная активность")
        elif status.warning_emitted and status.remaining_seconds > 0:
            details_parts.append(f"Скоро очистка: {status.remaining_seconds} сек")
        if hasattr(self, "clipboard_details_label"):
            self.clipboard_details_label.config(text=" | ".join(details_parts))

    def _get_clipboard_status(self) -> ClipboardStatus:
        if hasattr(self, "clipboard_service"):
            return self.clipboard_service.get_status()

        clipboard_value = self.state.get_clipboard()
        if not clipboard_value:
            return ClipboardStatus(active=False)

        remaining_seconds = 0
        if self.state.clipboard_timer is not None:
            remaining_seconds = max(0, int((self.state.clipboard_timer - datetime.now()).total_seconds()))
        return ClipboardStatus(
            active=True,
            data_type="password",
            preview="***",
            remaining_seconds=remaining_seconds,
        )

    def _format_clipboard_data_type(self, data_type: str) -> str:
        mapping = {
            "password": "пароль",
            "username": "логин",
            "entry": "запись",
            "text": "текст",
        }
        return mapping.get(str(data_type or "").strip().lower(), "данные")

    def _update_clipboard_notice(self, previous_status: ClipboardStatus, status: ClipboardStatus):
        if not hasattr(self, "clipboard_notice_label"):
            return

        notice_text = ""
        if status.active and not previous_status.active:
            notice_text = f"Скопировано: {self._format_clipboard_data_type(status.data_type)}"
        elif status.active and status.warning_emitted and not previous_status.warning_emitted:
            notice_text = f"Буфер обмена будет очищен через {status.remaining_seconds} сек"
        elif not status.active and previous_status.active:
            clear_reason = ""
            if hasattr(self, "clipboard_service"):
                clear_reason = self.clipboard_service.get_last_clear_reason() or ""
            if clear_reason == "monitor_warning":
                notice_text = "Буфер обмена очищен из-за подозрительной активности"
            elif clear_reason == "timeout":
                notice_text = "Буфер обмена очищен автоматически"
            elif clear_reason == "vault_locked":
                notice_text = "Буфер обмена очищен при блокировке vault"
            else:
                notice_text = "Буфер обмена очищен"
        elif status.blocked_future_copies and not previous_status.blocked_future_copies:
            notice_text = "Копирование временно заблокировано настройками безопасности"

        self.clipboard_notice_label.config(text=notice_text)

    def _sync_clipboard_row_marker(self, previous_status: ClipboardStatus, status: ClipboardStatus):
        previous_entry_id = previous_status.source_entry_id if previous_status.active else None
        current_entry_id = status.source_entry_id if status.active else None
        if previous_entry_id == current_entry_id and previous_status.active == status.active:
            return
        if hasattr(self, "table") and hasattr(self, "entry_manager"):
            self._apply_entry_filter()

    def _format_entry_title_for_table(self, entry) -> str:
        title = str(entry.get("title", ""))
        status = self._get_clipboard_status()
        if status.active and status.source_entry_id == entry.get("id"):
            return f"{title} [В буфере]"
        return title

    def _set_system_clipboard(self, value: str):
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(value)
            self.root.update()
        except tk.TclError:
            pass

    def _clear_system_clipboard(self):
        try:
            self.root.clipboard_clear()
            self.root.update()
        except tk.TclError:
            pass
        self._clear_windows_clipboard()
        if hasattr(self, "clipboard_service"):
            self.clipboard_service.clear(reason="manual", publish_event=False)

    def _clear_windows_clipboard(self):
        if os.name != "nt":
            return

        try:
            user32 = ctypes.windll.user32
        except AttributeError:
            return

        if not user32.OpenClipboard(None):
            return
        try:
            user32.EmptyClipboard()
        finally:
            user32.CloseClipboard()

    def _require_login(self, initial: bool = False):
        self._login_prompt_active = True
        while not self.auth_service.is_authenticated():
            password = simpledialog.askstring(
                "Мастер-пароль",
                "Введите мастер-пароль, чтобы разблокировать vault:",
                show="*",
                parent=self.root,
            )
            if password is None:
                if initial:
                    self._on_close()
                self._login_prompt_active = False
                return

            try:
                if self.auth_service.authenticate(password):
                    self.key_manager.store_key("active", self.auth_service.get_active_key())
                    event_bus.publish(Event(EventType.VAULT_UNLOCKED, {}))
                    break
            except AuthenticationError as error:
                messagebox.showerror("Ошибка аутентификации", str(error), parent=self.root)
                continue

            remaining = self.auth_service.get_lockout_remaining_seconds()
            messagebox.showwarning(
                "Доступ запрещён",
                f"Неверный мастер-пароль. Повторите попытку примерно через {remaining} сек."
                if remaining
                else "Неверный мастер-пароль.",
                parent=self.root,
            )

        self._set_status("Разблокировано")
        self.state.update_activity()
        self.key_storage.touch_cached_key(self.state.key_cache_timeout)
        self._login_prompt_active = False

    def _load_entries(self):
        if not self.auth_service.is_authenticated():
            self._all_entries = []
            self.table.clear()
            if hasattr(self, "search_status_var"):
                self.search_status_var.set("Найдено: 0")
            return

        entries = self.entry_manager.get_all_entries()
        self.password_visibility_overrides = {}
        self._all_entries = entries
        self._update_category_filter_options()
        self._apply_entry_filter()

    def _clear_sensitive_view_state(self):
        # Очищаем расшифрованные данные и состояние показа паролей при блокировке.
        self._all_entries = []
        self.passwords_visible = False
        self.password_visibility_overrides = {}
        if hasattr(self, "table"):
            self.table.clear()
        if hasattr(self, "password_toggle_text"):
            self.password_toggle_text.set("Показать пароли")
        if hasattr(self, "search_status_var"):
            self.search_status_var.set("Найдено: 0")

    def _apply_entry_filter(self):
        raw_entries = getattr(self, "_all_entries", [])
        query = getattr(self, "search_var", None)
        search_text = query.get().strip() if query is not None else ""
        category_filter = getattr(self, "category_filter_var", None)
        selected_category = category_filter.get().strip() if category_filter is not None else "Все"
        tag_filter_var = getattr(self, "tag_filter_var", None)
        updated_from_var = getattr(self, "updated_from_var", None)
        updated_to_var = getattr(self, "updated_to_var", None)
        password_strength_var = getattr(self, "password_strength_filter_var", None)
        filtered_entries = self.entry_manager.search_entries(
            search_text,
            selected_category,
            raw_entries,
            updated_from=updated_from_var.get().strip() if updated_from_var is not None else "",
            updated_to=updated_to_var.get().strip() if updated_to_var is not None else "",
            password_strength=password_strength_var.get().strip() if password_strength_var is not None else "",
            tag=tag_filter_var.get().strip() if tag_filter_var is not None else "",
        )

        data = []
        for entry in filtered_entries:
            data.append(
                {
                    "id": entry["id"],
                    "title": self._format_entry_title_for_table(entry),
                    "username": self._mask_username(entry["username"]),
                    "password": self._format_password_for_table(entry["password"], entry["id"]),
                    "category": entry["category"],
                    "url": self._format_url_for_table(entry["url"]),
                    "updated_at": entry["updated_at"].strftime("%Y-%m-%d %H:%M") if entry["updated_at"] else "",
                    "_password_plain": entry["password"],
                    "_search_username": entry["username"],
                    "_search_url": entry["url"],
                    "_search_notes": entry["notes"],
                }
            )

        self.table.set_data(data)
        if hasattr(self, "search_status_var"):
            self.search_status_var.set(f"Найдено: {len(filtered_entries)} из {len(raw_entries)}")

    def _update_category_filter_options(self):
        if not hasattr(self, "category_filter"):
            return

        categories = sorted(
            {
                str(entry.get("category", "")).strip()
                for entry in getattr(self, "_all_entries", [])
                if str(entry.get("category", "")).strip()
            }
        )
        values = ["Все", *categories]
        self.category_filter.configure(values=values)

        current_value = self.category_filter_var.get().strip()
        if current_value not in values:
            self.category_filter_var.set("Все")

    def _clear_search(self):
        if hasattr(self, "search_var"):
            self.search_var.set("")
        if hasattr(self, "category_filter_var"):
            self.category_filter_var.set("Все")
        if hasattr(self, "tag_filter_var"):
            self.tag_filter_var.set("")
        if hasattr(self, "updated_from_var"):
            self.updated_from_var.set("")
        if hasattr(self, "updated_to_var"):
            self.updated_to_var.set("")
        if hasattr(self, "password_strength_filter_var"):
            self.password_strength_filter_var.set("Все")
        if hasattr(self, "search_entry"):
            self.search_entry.focus_set()

    def _toggle_password_visibility(self, _event=None):
        self.passwords_visible = not self.passwords_visible
        self.password_visibility_overrides = {}
        if hasattr(self, "password_toggle_text"):
            self.password_toggle_text.set("Скрыть пароли" if self.passwords_visible else "Показать пароли")
        self._apply_entry_filter()
        return "break"

    def _handle_table_click(self, event):
        cell = self.table.get_cell_at(event.x, event.y)
        if not cell or cell["column_id"] != "password":
            return

        entry_id = cell["row"]["id"]
        current_visibility = self._is_password_visible(entry_id)
        self.password_visibility_overrides[entry_id] = not current_visibility
        self._apply_entry_filter()
        self.table.ensure_row_selected_at_y(event.y)
        return "break"

    def _focus_search(self, _event=None):
        if hasattr(self, "search_entry"):
            self.search_entry.focus_set()
            self.search_entry.selection_range(0, tk.END)
        return "break"

    def _commit_search_query(self, _event=None):
        self._remember_search_query(getattr(self, "search_var", tk.StringVar()).get())
        return "break"

    def _remember_current_search(self, _event=None):
        self._remember_search_query(getattr(self, "search_var", tk.StringVar()).get())

    def _remember_search_query(self, query: str):
        normalized_query = str(query or "").strip()
        if not normalized_query:
            return

        updated_history = [item for item in self.search_history if item != normalized_query]
        updated_history.insert(0, normalized_query)
        self.search_history = updated_history[:10]
        self.db.set_setting("ui.search_history", self.search_history)
        self._update_search_history_button()

    def _update_search_history_button(self):
        if not hasattr(self, "search_history_button"):
            return
        if self.search_history:
            self.search_history_button.state(["!disabled"])
        else:
            self.search_history_button.state(["disabled"])

    def _show_search_history_menu(self):
        if not self.search_history or not hasattr(self, "search_history_button"):
            return

        history_menu = tk.Menu(self.root, tearoff=0)
        for query in self.search_history:
            history_menu.add_command(
                label=query,
                command=lambda value=query: self._apply_search_history_item(value),
            )

        try:
            history_menu.tk_popup(
                self.search_history_button.winfo_rootx(),
                self.search_history_button.winfo_rooty() + self.search_history_button.winfo_height(),
            )
        finally:
            history_menu.grab_release()

    def _apply_search_history_item(self, query: str):
        if hasattr(self, "search_var"):
            self.search_var.set(query)
        if hasattr(self, "search_entry"):
            self.search_entry.focus_set()
            self.search_entry.selection_range(0, tk.END)

    def _mask_username(self, username: str) -> str:
        if not username:
            return ""
        if len(username) <= 4:
            return username
        return f"{username[:4]}{'*' * max(4, len(username) - 4)}"

    def _is_password_visible(self, entry_id: int) -> bool:
        return self.password_visibility_overrides.get(entry_id, self.passwords_visible)

    def _format_password_for_table(self, password: str, entry_id: Optional[int] = None) -> str:
        if not password:
            return ""
        is_visible = self.passwords_visible if entry_id is None else self._is_password_visible(entry_id)
        if is_visible:
            return f"{password}  🙈"
        return f"{'•' * max(8, min(len(password), 16))}  👁"

    def _format_url_for_table(self, url: str) -> str:
        if not url:
            return ""
        parsed = urlparse(url)
        if parsed.netloc:
            return parsed.netloc
        if "://" not in url:
            parsed = urlparse(f"https://{url}")
            if parsed.netloc:
                return parsed.netloc
        return url

    def _encrypt_password(self, password: str) -> bytes:
        return self.crypto.encrypt(password.encode("utf-8"))

    def _decrypt_password(self, encrypted_password: bytes) -> str:
        if isinstance(encrypted_password, str):
            return encrypted_password
        return self.crypto.decrypt(encrypted_password).decode("utf-8")

    def _build_entry_dialog(self, title: str, entry=None):
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("520x560")
        dialog.transient(self.root)
        dialog.grab_set()

        ttk.Label(dialog, text="Название").pack(anchor=tk.W, padx=8, pady=(8, 2))
        title_entry = ttk.Entry(dialog, width=60)
        title_entry.pack(fill=tk.X, padx=8, pady=2)

        ttk.Label(dialog, text="Имя пользователя").pack(anchor=tk.W, padx=8, pady=(8, 2))
        username_entry = ttk.Entry(dialog, width=60)
        username_entry.pack(fill=tk.X, padx=8, pady=2)
        ttk.Label(dialog, text="Подсказка логина").pack(anchor=tk.W, padx=8, pady=(4, 2))
        username_suggestion = ttk.Combobox(dialog, state="readonly", width=57, values=[])
        username_suggestion.pack(fill=tk.X, padx=8, pady=(0, 2))
        username_suggestion.bind(
            "<<ComboboxSelected>>",
            lambda _event: self._apply_username_suggestion(username_entry, username_suggestion.get()),
        )

        ttk.Label(dialog, text="Пароль").pack(anchor=tk.W, padx=8, pady=(8, 2))
        password_entry = PasswordEntry(dialog, width=50)
        password_entry.pack(fill=tk.X, padx=8, pady=2)
        ttk.Button(
            dialog,
            text="Сгенерировать пароль",
            command=lambda: self._open_password_generator_dialog(dialog, password_entry),
        ).pack(anchor=tk.E, padx=8, pady=(0, 4))
        strength_var = tk.StringVar(value="Сложность пароля: не задан")
        ttk.Label(dialog, textvariable=strength_var).pack(anchor=tk.W, padx=8, pady=(0, 4))

        ttk.Label(dialog, text="URL").pack(anchor=tk.W, padx=8, pady=(8, 2))
        url_entry = ttk.Entry(dialog, width=60)
        url_entry.pack(fill=tk.X, padx=8, pady=2)
        favicon_status = tk.StringVar(value="Иконка сайта: не выбрана")
        favicon_label = ttk.Label(dialog, textvariable=favicon_status, compound=tk.LEFT)
        favicon_label.pack(anchor=tk.W, padx=8, pady=(0, 4))

        ttk.Label(dialog, text="Категория").pack(anchor=tk.W, padx=8, pady=(8, 2))
        category_entry = ttk.Entry(dialog, width=60)
        category_entry.pack(fill=tk.X, padx=8, pady=2)
        ttk.Label(dialog, text="Теги").pack(anchor=tk.W, padx=8, pady=(8, 2))
        tags_entry = ttk.Entry(dialog, width=60)
        tags_entry.pack(fill=tk.X, padx=8, pady=2)

        ttk.Label(dialog, text="Заметки").pack(anchor=tk.W, padx=8, pady=(8, 2))
        notes_text = tk.Text(dialog, height=7, width=60)
        notes_text.pack(fill=tk.BOTH, expand=True, padx=8, pady=2)

        if entry:
            title_entry.insert(0, entry["title"])
            username_entry.insert(0, entry["username"])
            password_entry.set(entry["password"])
            url_entry.insert(0, entry["url"])
            category_entry.insert(0, entry["category"])
            tags_entry.insert(0, entry.get("tags", ""))
            notes_text.insert("1.0", entry["notes"])

        password_entry.entry.bind(
            "<KeyRelease>",
            lambda _event: self._on_password_entry_changed(dialog, password_entry, strength_var),
        )
        url_entry.bind("<KeyRelease>", lambda _event: self._schedule_favicon_preview(dialog, url_entry))
        url_entry.bind("<FocusOut>", lambda _event: self._schedule_favicon_preview(dialog, url_entry))
        url_entry.bind(
            "<KeyRelease>",
            lambda _event: self._schedule_username_suggestions(dialog, url_entry, username_entry),
            add="+",
        )
        url_entry.bind(
            "<FocusOut>",
            lambda _event: self._schedule_username_suggestions(dialog, url_entry, username_entry),
            add="+",
        )
        self._update_password_strength(password_entry, strength_var)
        dialog.category_entry = category_entry
        dialog.tags_entry = tags_entry
        dialog.strength_var = strength_var
        dialog.password_was_generated = False
        dialog.favicon_status = favicon_status
        dialog.favicon_label = favicon_label
        dialog.favicon_image = None
        dialog.favicon_after_id = None
        dialog.favicon_request_token = None
        dialog.username_suggestion = username_suggestion
        dialog.username_suggestion_after_id = None
        self._schedule_favicon_preview(dialog, url_entry, delay_ms=0)
        self._schedule_username_suggestions(dialog, url_entry, username_entry, delay_ms=0)
        return dialog, title_entry, username_entry, password_entry, url_entry, notes_text

    def _collect_entry_form(self, title_entry, username_entry, password_entry, url_entry, notes_text):
        dialog = title_entry.master
        title = title_entry.get().strip()
        username = username_entry.get().strip()
        password = password_entry.get().strip()
        url = url_entry.get().strip()
        category_entry = getattr(title_entry.master, "category_entry", None)
        category = category_entry.get().strip() if category_entry is not None else ""
        tags_entry = getattr(title_entry.master, "tags_entry", None)
        tags = tags_entry.get().strip() if tags_entry is not None else ""
        notes = notes_text.get("1.0", tk.END).strip()

        if not title or not password:
            raise ValueError("Поля «Название» и «Пароль» обязательны.")

        if url and not self._is_valid_url(url):
            raise ValueError("URL имеет некорректный формат.")

        if not getattr(dialog, "password_was_generated", False) and not self.password_generator.is_strong_enough(password):
            raise ValueError(
                "Слишком слабый пароль. Усильте его вручную или воспользуйтесь генератором паролей."
            )

        return title, username, password, url, notes, category, tags

    def _schedule_username_suggestions(self, dialog, url_entry, username_entry, delay_ms: int = 250):
        if not hasattr(dialog, "username_suggestion"):
            return
        after_id = getattr(dialog, "username_suggestion_after_id", None)
        if after_id:
            try:
                dialog.after_cancel(after_id)
            except tk.TclError:
                pass

        def run_suggestions():
            dialog.username_suggestion_after_id = None
            self._update_username_suggestions(dialog, url_entry.get().strip(), username_entry)

        dialog.username_suggestion_after_id = dialog.after(delay_ms, run_suggestions)

    def _update_username_suggestions(self, dialog, raw_url: str, username_entry):
        suggestion_widget = getattr(dialog, "username_suggestion", None)
        if suggestion_widget is None:
            return

        suggestions = self._suggest_usernames_for_url(raw_url)
        suggestion_widget.configure(values=suggestions)
        if suggestions:
            suggestion_widget.set(suggestions[0])
            if not username_entry.get().strip() and self._has_existing_domain_username(raw_url):
                self._apply_username_suggestion(username_entry, suggestions[0])
        else:
            suggestion_widget.set("")

    def _apply_username_suggestion(self, username_entry, suggestion: str):
        value = str(suggestion or "").strip()
        if not value:
            return
        username_entry.delete(0, tk.END)
        username_entry.insert(0, value)

    def _suggest_usernames_for_url(self, raw_url: str):
        host = self._extract_normalized_host(raw_url)
        if not host:
            return []

        base_domain = self._extract_base_domain(host)
        suggestions = []

        for entry in getattr(self, "_all_entries", []):
            entry_host = self._extract_normalized_host(entry.get("url", ""))
            if not entry_host:
                continue
            if entry_host == host or self._extract_base_domain(entry_host) == base_domain:
                username = str(entry.get("username", "")).strip()
                if username and username not in suggestions:
                    suggestions.append(username)

        if host == "localhost" or host.endswith(".local"):
            generated = ["admin", "root", "user"]
        else:
            generated = [
                f"admin@{base_domain}",
                f"support@{base_domain}",
                f"info@{base_domain}",
                base_domain.split(".", 1)[0],
                "admin",
            ]

        for item in generated:
            if item and item not in suggestions:
                suggestions.append(item)
        return suggestions[:5]

    def _has_existing_domain_username(self, raw_url: str) -> bool:
        host = self._extract_normalized_host(raw_url)
        if not host:
            return False
        base_domain = self._extract_base_domain(host)
        for entry in getattr(self, "_all_entries", []):
            entry_host = self._extract_normalized_host(entry.get("url", ""))
            if entry_host and (entry_host == host or self._extract_base_domain(entry_host) == base_domain):
                if str(entry.get("username", "")).strip():
                    return True
        return False

    def _extract_normalized_host(self, raw_url: str) -> str:
        value = str(raw_url or "").strip()
        if not value:
            return ""
        candidate = value if "://" in value else f"https://{value}"
        parsed = urlparse(candidate)
        host = (parsed.netloc or parsed.path).strip().lower()
        if ":" in host:
            host = host.split(":", 1)[0]
        return host

    def _extract_base_domain(self, host: str) -> str:
        parts = [part for part in str(host or "").split(".") if part]
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return str(host or "")

    def _schedule_favicon_preview(self, dialog, url_entry, delay_ms: int = 250):
        if not hasattr(dialog, "favicon_status"):
            return
        after_id = getattr(dialog, "favicon_after_id", None)
        if after_id:
            try:
                dialog.after_cancel(after_id)
            except tk.TclError:
                pass

        def run_preview():
            dialog.favicon_after_id = None
            self._update_favicon_preview(dialog, url_entry.get().strip())

        dialog.favicon_after_id = dialog.after(delay_ms, run_preview)

    def _update_favicon_preview(self, dialog, raw_url: str):
        favicon_request = self._build_favicon_request(raw_url)
        if favicon_request is None:
            self._set_dialog_favicon_placeholder(dialog, "Иконка сайта: не выбрана")
            return

        host = favicon_request["host"]
        cached_image = self._favicon_cache.get(host)
        if cached_image is not None:
            self._set_dialog_favicon_image(dialog, cached_image, host)
            return

        self._set_dialog_favicon_placeholder(dialog, f"Иконка сайта: {host}")
        request_token = f"{host}:{raw_url}"
        dialog.favicon_request_token = request_token

        def worker():
            image_data = self._download_favicon_image(favicon_request["service_url"])

            def apply_result():
                if getattr(dialog, "favicon_request_token", None) != request_token:
                    return
                if image_data is None:
                    self._set_dialog_favicon_placeholder(dialog, f"Иконка сайта: {host}")
                    return
                self._favicon_cache[host] = image_data
                self._set_dialog_favicon_image(dialog, image_data, host)

            try:
                dialog.after(0, apply_result)
            except tk.TclError:
                pass

        threading.Thread(target=worker, daemon=True).start()

    def _build_favicon_request(self, raw_url: str):
        value = str(raw_url or "").strip()
        if not value:
            return None

        candidate = value if "://" in value else f"https://{value}"
        parsed = urlparse(candidate)
        host = (parsed.netloc or parsed.path).strip().lower()
        if not host:
            return None

        if ":" in host:
            host = host.split(":", 1)[0]

        if not host:
            return None

        service_url = f"https://www.google.com/s2/favicons?sz=64&domain_url=https://{host}"
        return {"host": host, "service_url": service_url}

    def _download_favicon_image(self, service_url: str) -> Optional[str]:
        try:
            request = Request(service_url, headers={"User-Agent": "CryptoSafe-Manager/1.0"})
            with urlopen(request, timeout=3) as response:
                image_bytes = response.read()
        except (OSError, URLError, ValueError):
            return None

        if not image_bytes:
            return None
        return b64encode(image_bytes).decode("ascii")

    def _set_dialog_favicon_placeholder(self, dialog, text: str):
        status_var = getattr(dialog, "favicon_status", None)
        label = getattr(dialog, "favicon_label", None)
        if status_var is not None:
            status_var.set(text)
        if label is not None:
            label.configure(image="")
        dialog.favicon_image = None

    def _set_dialog_favicon_image(self, dialog, image_data: str, host: str):
        label = getattr(dialog, "favicon_label", None)
        status_var = getattr(dialog, "favicon_status", None)
        if label is None or status_var is None:
            return

        try:
            image = tk.PhotoImage(data=image_data)
        except tk.TclError:
            self._set_dialog_favicon_placeholder(dialog, f"Иконка сайта: {host}")
            return

        dialog.favicon_image = image
        label.configure(image=image)
        status_var.set(f"Иконка сайта: {host}")

    def _get_selected_entry(self):
        selected = self.table.get_selected()
        if not selected:
            return None
        try:
            entry = self.entry_manager.get_entry(selected["id"])
            entry["encrypted_password"] = entry["password"]
            return EntryView(entry)
        except EntryNotFoundError:
            return None

    def _get_selected_entries(self):
        entries = []
        for selected in self.table.get_selected_items():
            try:
                entry = self.entry_manager.get_entry(selected["id"])
                entry["encrypted_password"] = entry["password"]
                entries.append(EntryView(entry))
            except EntryNotFoundError:
                continue
        return entries

    def _get_single_selected_entry(self, action_name: str):
        selected_entries = self._get_selected_entries()
        if not selected_entries:
            messagebox.showwarning("Предупреждение", f"Выберите запись для действия «{action_name}».")
            return None
        if len(selected_entries) > 1:
            messagebox.showwarning("Предупреждение", f"Для действия «{action_name}» нужно выбрать только одну запись.")
            return None
        return selected_entries[0]

    def _on_entry_changed(self, _event):
        self._load_entries()

    def _generate_entry_password(
        self,
        dialog,
        password_entry: PasswordEntry,
        options: PasswordGeneratorOptions | None = None,
    ):
        password = self.password_generator.generate(options or PasswordGeneratorOptions())
        password_entry.set(password)
        password_entry.show_password.set(True)
        dialog.password_was_generated = True
        strength_var = getattr(password_entry.master, "strength_var", None)
        if strength_var is not None:
            self._update_password_strength(password_entry, strength_var)

    def _open_password_generator_dialog(self, parent_dialog, password_entry: PasswordEntry):
        dialog = tk.Toplevel(self.root)
        dialog.title("Параметры генерации пароля")
        dialog.geometry("360x320")
        dialog.transient(parent_dialog)
        dialog.grab_set()
        dialog.resizable(False, False)

        length_var = tk.IntVar(value=16)
        uppercase_var = tk.BooleanVar(value=True)
        lowercase_var = tk.BooleanVar(value=True)
        digits_var = tk.BooleanVar(value=True)
        symbols_var = tk.BooleanVar(value=True)
        ambiguous_var = tk.BooleanVar(value=False)

        ttk.Label(dialog, text="Длина пароля").pack(anchor=tk.W, padx=10, pady=(12, 2))
        ttk.Spinbox(dialog, from_=8, to=64, textvariable=length_var).pack(fill=tk.X, padx=10, pady=2)

        ttk.Checkbutton(dialog, text="Включать заглавные буквы", variable=uppercase_var).pack(
            anchor=tk.W, padx=10, pady=(12, 2)
        )
        ttk.Checkbutton(dialog, text="Включать строчные буквы", variable=lowercase_var).pack(
            anchor=tk.W, padx=10, pady=2
        )
        ttk.Checkbutton(dialog, text="Включать цифры", variable=digits_var).pack(anchor=tk.W, padx=10, pady=2)
        ttk.Checkbutton(dialog, text="Включать символы", variable=symbols_var).pack(anchor=tk.W, padx=10, pady=2)
        ttk.Checkbutton(dialog, text="Исключить неоднозначные символы", variable=ambiguous_var).pack(
            anchor=tk.W, padx=10, pady=(12, 2)
        )

        def generate():
            options = PasswordGeneratorOptions(
                length=length_var.get(),
                include_uppercase=uppercase_var.get(),
                include_lowercase=lowercase_var.get(),
                include_digits=digits_var.get(),
                include_symbols=symbols_var.get(),
                exclude_ambiguous=ambiguous_var.get(),
            )
            try:
                self._generate_entry_password(parent_dialog, password_entry, options)
            except (ValueError, RuntimeError) as error:
                messagebox.showerror("Ошибка", str(error), parent=dialog)
                return
            dialog.destroy()

        button_frame = ttk.Frame(dialog)
        button_frame.pack(fill=tk.X, padx=10, pady=(18, 10))
        ttk.Button(button_frame, text="Сгенерировать", command=generate).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="Отмена", command=dialog.destroy).pack(side=tk.RIGHT, padx=(0, 8))

    def _on_password_entry_changed(self, dialog, password_entry: PasswordEntry, strength_var: tk.StringVar):
        dialog.password_was_generated = False
        self._update_password_strength(password_entry, strength_var)

    def _update_password_strength(self, password_entry: PasswordEntry, strength_var: tk.StringVar):
        strength_var.set(f"Сложность пароля: {self._describe_password_strength(password_entry.get())}")

    def _describe_password_strength(self, password: str) -> str:
        if not password:
            return "не задан"
        if len(password) < 8:
            return "слабый"
        if self.password_generator.is_strong_enough(password):
            return "сильный"
        if len(password) >= 10:
            return "средний"
        return "слабый"

    def _is_valid_url(self, url: str) -> bool:
        candidate = url if "://" in url else f"https://{url}"
        parsed = urlparse(candidate)
        if parsed.scheme not in {"http", "https"}:
            return False
        hostname = parsed.netloc
        if not hostname:
            return False
        if hostname == "localhost":
            return True
        return "." in hostname

    def _rotate_vault_entries(self, old_key: bytes, new_key: bytes):
        old_crypto = AES256Placeholder()
        new_crypto = AES256Placeholder()
        old_vault_crypto = AESGCMEncryptionService()
        new_vault_crypto = AESGCMEncryptionService()
        progress_dialog = tk.Toplevel(self.root)
        progress_dialog.title("Смена мастер-пароля")
        progress_dialog.geometry("420x180")
        progress_dialog.transient(self.root)
        progress_dialog.grab_set()
        progress_dialog.resizable(False, False)

        status_var = tk.StringVar(value="Подготовка к пере-шифрованию записей...")
        progress_var = tk.DoubleVar(value=0)
        pause_button_text = tk.StringVar(value="Пауза")
        progress_queue: queue.Queue = queue.Queue()
        pause_event = threading.Event()
        pause_event.set()
        state = {"paused": False, "processed": 0, "total": 0, "error": None}

        ttk.Label(progress_dialog, text="Пере-шифрование vault", font=("Segoe UI", 10, "bold")).pack(
            anchor=tk.W, padx=12, pady=(12, 6)
        )
        ttk.Label(progress_dialog, textvariable=status_var, wraplength=380, justify=tk.LEFT).pack(
            anchor=tk.W, padx=12, pady=(0, 10)
        )
        progressbar = ttk.Progressbar(progress_dialog, variable=progress_var, maximum=1, mode="determinate")
        progressbar.pack(fill=tk.X, padx=12, pady=(0, 12))

        button_frame = ttk.Frame(progress_dialog)
        button_frame.pack(fill=tk.X, padx=12, pady=(0, 12))

        def update_status():
            suffix = " (пауза)" if state["paused"] else ""
            if state["total"] == 0:
                status_var.set(f"Пере-шифрование записей...{suffix}")
            else:
                status_var.set(f"Пере-шифровано записей: {state['processed']} из {state['total']}{suffix}")

        def toggle_pause():
            state["paused"] = not state["paused"]
            if state["paused"]:
                pause_event.clear()
                pause_button_text.set("Продолжить")
            else:
                pause_event.set()
                pause_button_text.set("Пауза")
            update_status()

        pause_button = ttk.Button(button_frame, textvariable=pause_button_text, command=toggle_pause)
        pause_button.pack(side=tk.RIGHT)
        progress_dialog.protocol("WM_DELETE_WINDOW", lambda: None)

        def transform(legacy_ciphertext: bytes, encrypted_payload: bytes) -> tuple[bytes, bytes]:
            updated_legacy = legacy_ciphertext
            if legacy_ciphertext:
                plaintext = old_crypto.decrypt(legacy_ciphertext, old_key)
                updated_legacy = new_crypto.encrypt(plaintext, new_key)

            updated_payload = encrypted_payload
            if encrypted_payload:
                try:
                    plaintext_payload = old_vault_crypto.decrypt(encrypted_payload, old_key)
                    updated_payload = new_vault_crypto.encrypt(plaintext_payload, new_key)
                except Exception:
                    updated_payload = encrypted_payload

            return updated_legacy, updated_payload

        def worker():
            try:
                self.db.reencrypt_entry_payloads(
                    transform,
                    progress_callback=lambda processed, total: progress_queue.put(("progress", processed, total)),
                    pause_event=pause_event,
                )
                progress_queue.put(("done",))
            except Exception as error:
                progress_queue.put(("error", str(error)))

        def poll_progress():
            try:
                while True:
                    message = progress_queue.get_nowait()
                    kind = message[0]
                    if kind == "progress":
                        _, processed, total = message
                        state["processed"] = processed
                        state["total"] = total
                        progressbar.configure(maximum=max(total, 1))
                        progress_var.set(processed if total else 0)
                        update_status()
                    elif kind == "done":
                        pause_button.state(["disabled"])
                        status_var.set(
                            "Пере-шифрование завершено."
                            if state["total"]
                            else "Записей для пере-шифрования не найдено."
                        )
                        progress_dialog.destroy()
                        return
                    elif kind == "error":
                        state["error"] = message[1]
                        progress_dialog.destroy()
                        return
            except queue.Empty:
                pass

            if progress_dialog.winfo_exists():
                progress_dialog.after(100, poll_progress)

        threading.Thread(target=worker, daemon=True).start()
        poll_progress()
        progress_dialog.wait_window()

        if state["error"] is not None:
            raise RuntimeError(state["error"])

    def new_database(self):
        if not messagebox.askyesno("Подтверждение", "Создать новую базу vault? Данные в выбранном файле будут потеряны."):
            return

        new_path = filedialog.asksaveasfilename(
            title="Создать новый vault",
            defaultextension=".db",
            filetypes=[("SQLite database", "*.db"), ("All files", "*.*")],
        )
        if not new_path:
            return

        if os.path.exists(new_path):
            os.remove(new_path)
        self.config.set("database.path", new_path)
        if self.audit_logger:
            self.audit_logger.close()
        self.db.close()
        self.db = Database(new_path)
        self.key_storage = KeyStorage(self.db)
        self.auth_service = AuthenticationService(
            self.key_storage,
            self.key_derivation,
            self.password_validator,
            self.state,
        )
        self.entry_manager = EntryManager(self.db, self.vault_crypto, legacy_encryption_service=self.crypto)
        self.audit_logger = AuditLogger(self.db, event_bus)
        self._persist_runtime_settings()
        self._load_password_policy()
        SetupWizard(self.root, self.config, self.auth_service)
        if not self.auth_service.is_initialized():
            return
        self.key_manager.store_key("active", self.auth_service.get_active_key())
        self._load_entries()

    def open_database(self):
        path = filedialog.askopenfilename(
            title="Открыть базу vault",
            filetypes=[("SQLite database", "*.db"), ("All files", "*.*")],
        )
        if not path:
            return

        self.config.set("database.path", path)
        if self.audit_logger:
            self.audit_logger.close()
        self.db.close()
        self.db = Database(path)
        self.key_storage = KeyStorage(self.db)
        self.auth_service = AuthenticationService(
            self.key_storage,
            self.key_derivation,
            self.password_validator,
            self.state,
        )
        self.entry_manager = EntryManager(self.db, self.vault_crypto, legacy_encryption_service=self.crypto)
        self.audit_logger = AuditLogger(self.db, event_bus)
        self._persist_runtime_settings()
        self._load_password_policy()
        if not self.auth_service.is_initialized():
            SetupWizard(self.root, self.config, self.auth_service)
            if not self.auth_service.is_initialized():
                return
        self._lock_vault(show_dialog=False)
        self._require_login()
        if self.auth_service.is_authenticated():
            self.key_manager.store_key("active", self.auth_service.get_active_key())
            self._load_entries()

    def backup(self):
        backup_path = filedialog.asksaveasfilename(
            title="Создать резервную копию vault",
            defaultextension=".db",
            filetypes=[("SQLite database", "*.db"), ("All files", "*.*")],
        )
        if not backup_path:
            return
        self.db.backup(backup_path)
        messagebox.showinfo("Резервная копия", "Резервная копия успешно создана.")

    def add_entry(self):
        if not self.auth_service.is_authenticated():
            self._require_login()
        dialog, title_entry, username_entry, password_entry, url_entry, notes_text = self._build_entry_dialog("Добавить запись")

        def save():
            try:
                title, username, password, url, notes, category, tags = self._collect_entry_form(
                    title_entry, username_entry, password_entry, url_entry, notes_text
                )
            except ValueError as error:
                messagebox.showerror("Ошибка", str(error), parent=dialog)
                return

            self.entry_manager.create_entry(
                {
                    "title": title,
                    "username": username,
                    "password": password,
                    "url": url,
                    "category": category,
                    "notes": notes,
                    "tags": tags,
                }
            )
            dialog.destroy()

        ttk.Button(dialog, text="Сохранить", command=save).pack(pady=10)

    def edit_entry(self):
        entry = self._get_single_selected_entry("Изменить")
        if not entry:
            messagebox.showwarning("Предупреждение", "Выберите запись для редактирования.")
            return

        dialog, title_entry, username_entry, password_entry, url_entry, notes_text = self._build_entry_dialog(
            "Редактировать запись",
            entry,
        )

        def save():
            try:
                title, username, password, url, notes, category, tags = self._collect_entry_form(
                    title_entry, username_entry, password_entry, url_entry, notes_text
                )
            except ValueError as error:
                messagebox.showerror("Ошибка", str(error), parent=dialog)
                return

            self.entry_manager.update_entry(
                entry["id"],
                {
                    "title": title,
                    "username": username,
                    "password": password,
                    "url": url,
                    "category": category,
                    "notes": notes,
                    "tags": tags,
                },
            )
            dialog.destroy()

        ttk.Button(dialog, text="Сохранить изменения", command=save).pack(pady=10)

    def delete_entry(self):
        selected_items = self.table.get_selected_items()
        if len(selected_items) > 1:
            if not messagebox.askyesno("Подтверждение", f"Удалить выбранные записи ({len(selected_items)})?"):
                return
            for selected in selected_items:
                self.entry_manager.delete_entry(selected["id"])
            return
        selected = self.table.get_selected()
        if not selected:
            messagebox.showwarning("Предупреждение", "Выберите запись для удаления.")
            return
        if messagebox.askyesno("Подтверждение", f"Удалить запись «{selected['title']}»?"):
            self.entry_manager.delete_entry(selected["id"])

    def show_selected_password(self):
        entry = self._get_single_selected_entry("Показать пароль")
        if not entry:
            messagebox.showwarning("Предупреждение", "Сначала выберите запись.")
            return
        messagebox.showinfo("Пароль", self._decrypt_password(entry.encrypted_password))
        self._on_activity()

    def copy_selected_password(self):
        entry = self._get_single_selected_entry("Скопировать пароль")
        if not entry:
            messagebox.showwarning("Предупреждение", "Сначала выберите запись.")
            return
        password = self._decrypt_password(entry.encrypted_password)
        try:
            self.clipboard_service.copy_text(
                password,
                data_type="password",
                source_entry_id=entry.id,
                source_label=entry.title,
            )
        except ClipboardAccessError as error:
            messagebox.showerror("Ошибка буфера обмена", str(error))
            return
        self._on_activity()

    def copy_selected_username(self):
        entry = self._get_single_selected_entry("Скопировать логин")
        if not entry:
            messagebox.showwarning("Предупреждение", "Сначала выберите запись.")
            return
        username = str(entry.get("username", "")).strip()
        if not self._copy_entry_to_clipboard(
            username,
            data_type="username",
            entry=entry,
            action_name="Скопировать логин",
        ):
            return
        self._on_activity()

    def copy_selected_all(self):
        entry = self._get_single_selected_entry("Скопировать запись")
        if not entry:
            messagebox.showwarning("Предупреждение", "Сначала выберите запись.")
            return

        payload_parts = [
            f"Название: {entry.title}",
            f"Логин: {entry.username}",
            f"Пароль: {self._decrypt_password(entry.encrypted_password)}",
        ]
        if entry.get("url"):
            payload_parts.append(f"URL: {entry.url}")
        if entry.get("notes"):
            payload_parts.append(f"Заметки: {entry.notes}")

        if not self._copy_entry_to_clipboard(
            "\n".join(payload_parts),
            data_type="entry",
            entry=entry,
            action_name="Скопировать запись",
        ):
            return
        self._on_activity()

    def _copy_entry_to_clipboard(self, value: str, *, data_type: str, entry, action_name: str) -> bool:
        normalized_value = str(value or "")
        if not normalized_value.strip():
            messagebox.showwarning("Предупреждение", f"Для действия «{action_name}» нет данных.")
            return False
        try:
            self.clipboard_service.copy_text(
                normalized_value,
                data_type=data_type,
                source_entry_id=entry.id,
                source_label=entry.title,
            )
        except ClipboardAccessError as error:
            messagebox.showerror("Ошибка буфера обмена", str(error))
            return False
        return True

    def show_logs(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Журнал аудита")
        dialog.geometry("760x420")
        text = tk.Text(dialog, wrap=tk.NONE)
        text.pack(fill=tk.BOTH, expand=True)
        for log in self.db.get_audit_logs():
            timestamp = log.timestamp.strftime("%Y-%m-%d %H:%M:%S") if log.timestamp else ""
            text.insert("end", f"{timestamp} | {log.action} | entry={log.entry_id} | {log.details}\n")
        text.config(state=tk.DISABLED)

    def show_settings(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Настройки")
        dialog.geometry("460x450")

        clipboard_timeout = tk.IntVar(value=self.config.get("security.clipboard_timeout", 30))
        auto_lock_minutes = tk.IntVar(value=self.config.get("security.auto_lock_minutes", 5))
        min_password_length = tk.IntVar(value=self.config.get("security.min_password_length", 12))
        key_cache_timeout_minutes = tk.IntVar(value=self.config.get("security.key_cache_timeout_minutes", 60))
        lock_on_focus_loss = tk.BooleanVar(value=self.config.get("security.lock_on_focus_loss", True))
        lock_on_minimize = tk.BooleanVar(value=self.config.get("security.lock_on_minimize", True))

        ttk.Label(dialog, text="Таймаут буфера обмена (сек)").pack(anchor=tk.W, padx=10, pady=(12, 2))
        ttk.Spinbox(dialog, from_=5, to=300, textvariable=clipboard_timeout).pack(fill=tk.X, padx=10, pady=2)

        ttk.Label(dialog, text="Таймаут авто-блокировки (мин)").pack(anchor=tk.W, padx=10, pady=(12, 2))
        ttk.Spinbox(dialog, from_=1, to=120, textvariable=auto_lock_minutes).pack(fill=tk.X, padx=10, pady=2)

        ttk.Label(dialog, text="Таймаут кэша ключа (мин)").pack(anchor=tk.W, padx=10, pady=(12, 2))
        ttk.Spinbox(dialog, from_=1, to=60, textvariable=key_cache_timeout_minutes).pack(fill=tk.X, padx=10, pady=2)

        ttk.Label(dialog, text="Минимальная длина мастер-пароля").pack(anchor=tk.W, padx=10, pady=(12, 2))
        ttk.Spinbox(dialog, from_=8, to=64, textvariable=min_password_length).pack(fill=tk.X, padx=10, pady=2)

        ttk.Checkbutton(
            dialog,
            text="Блокировать при потере фокуса",
            variable=lock_on_focus_loss,
        ).pack(
            anchor=tk.W, padx=10, pady=(12, 2)
        )
        ttk.Checkbutton(
            dialog,
            text="Блокировать при сворачивании",
            variable=lock_on_minimize,
        ).pack(
            anchor=tk.W, padx=10, pady=2
        )

        def save():
            self.config.set("security.clipboard_timeout", clipboard_timeout.get())
            self.config.set("security.auto_lock_minutes", auto_lock_minutes.get())
            self.config.set("security.min_password_length", min_password_length.get())
            self.config.set("security.key_cache_timeout_minutes", key_cache_timeout_minutes.get())
            self.config.set("security.lock_on_focus_loss", lock_on_focus_loss.get())
            self.config.set("security.lock_on_minimize", lock_on_minimize.get())
            self.password_validator.min_length = min_password_length.get()
            self.db.set_setting(
                "security.password_policy",
                {
                    "min_password_length": min_password_length.get(),
                    "require_uppercase": self.config.get("security.require_uppercase", True),
                    "require_lowercase": self.config.get("security.require_lowercase", True),
                    "require_digits": self.config.get("security.require_digits", True),
                    "require_special": self.config.get("security.require_special", True),
                },
            )
            self.state.set_inactivity_timeout(auto_lock_minutes.get() * 60)
            self.state.set_key_cache_timeout(key_cache_timeout_minutes.get() * 60)
            self._persist_runtime_settings()
            messagebox.showinfo("Настройки", "Настройки сохранены.", parent=dialog)
            dialog.destroy()

        ttk.Button(dialog, text="Сохранить", command=save).pack(pady=16)
        ttk.Button(dialog, text="Сменить мастер-пароль", command=self.change_master_password).pack(pady=2)

    def change_master_password(self):
        current_password = simpledialog.askstring("Смена пароля", "Текущий мастер-пароль:", show="*", parent=self.root)
        if current_password is None:
            return
        new_password = simpledialog.askstring("Смена пароля", "Новый мастер-пароль:", show="*", parent=self.root)
        if new_password is None:
            return
        confirm = simpledialog.askstring("Смена пароля", "Подтвердите новый мастер-пароль:", show="*", parent=self.root)
        if confirm != new_password:
            messagebox.showerror("Ошибка", "Пароли не совпадают.")
            return
        try:
            self.auth_service.change_master_password(
                current_password,
                new_password,
                rotate_entries_callback=self._rotate_vault_entries,
            )
            self.key_manager.store_key("active", self.auth_service.get_active_key())
            messagebox.showinfo("Успешно", "Мастер-пароль успешно изменён.")
        except AuthenticationError as error:
            messagebox.showerror("Ошибка", str(error))

    def _lock_vault(self, show_dialog: bool = True):
        self.auth_service.logout()
        self.key_manager.clear_key()
        self.state.clear_clipboard()
        self._clear_system_clipboard()
        event_bus.publish(Event(EventType.VAULT_LOCKED, {}))
        self._clear_sensitive_view_state()
        self._set_status("Заблокировано")
        if show_dialog:
            self._require_login()
            if self.auth_service.is_authenticated():
                self.key_manager.store_key("active", self.auth_service.get_active_key())
                self._load_entries()

    def _on_close(self):
        try:
            self.auth_service.logout()
        except Exception:
            pass
        self.key_manager.clear_key()
        self.state.clear_clipboard()
        self._clear_sensitive_view_state()
        self._clear_system_clipboard()
        try:
            self.audit_logger.close()
        except Exception:
            pass
        try:
            self.db.close()
        except Exception:
            pass
        self.root.destroy()

    def show_about(self):
        messagebox.showinfo(
            "О программе",
            "CryptoSafe Manager\nВерсия 2.0\n\n"
            "Менеджер паролей с локальным зашифрованным хранилищем, мастер-паролем и журналом аудита.",
        )

    def run(self):
        self.root.mainloop()
