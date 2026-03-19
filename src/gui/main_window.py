import os
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, simpledialog, ttk

from ..core.config import Config
from ..core.crypto.authentication import AuthenticationError, AuthenticationService
from ..core.crypto.key_derivation import KeyDerivation
from ..core.crypto.key_storage import KeyStorage
from ..core.crypto.password_validator import PasswordValidator
from ..core.crypto.placeholder import AES256Placeholder
from ..core.events import AuditLogger, Event, EventType, event_bus
from ..core.key_manager import KeyManager
from ..core.state_manager import StateManager
from ..database.db import Database
from ..database.models import VaultEntry
from .setup_wizard import SetupWizard
from .widgets.password_entry import PasswordEntry
from .widgets.secure_table import SecureTable


class MainWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("CryptoSafe Manager")
        self.root.geometry("980x640")

        self.config = Config()
        self.state = StateManager()
        self.state.set_inactivity_timeout(self.config.get("security.auto_lock_minutes", 5) * 60)

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
        self.audit_logger = AuditLogger(self.db, event_bus)
        self._load_password_policy()

        if not self.auth_service.is_initialized():
            SetupWizard(self.root, self.config, self.auth_service)
            if not self.auth_service.is_initialized():
                self.root.destroy()
                return
            self.db = self.auth_service.key_storage.database
            self.key_storage = self.auth_service.key_storage
            self.audit_logger.close()
            self.audit_logger = AuditLogger(self.db, event_bus)
            self._load_password_policy()

        self._create_menu()
        self._create_toolbar()
        self._create_main_area()
        self._create_statusbar()
        self._setup_events()
        self._setup_activity_tracking()

        self._require_login(initial=True)
        if not self.auth_service.is_authenticated():
            return
        self._load_entries()
        self._schedule_security_tasks()

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

    def _create_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New vault", command=self.new_database)
        file_menu.add_command(label="Open vault", command=self.open_database)
        file_menu.add_command(label="Backup", command=self.backup)
        file_menu.add_separator()
        file_menu.add_command(label="Lock", command=self._lock_vault)
        file_menu.add_command(label="Exit", command=self.root.quit)

        entry_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Entries", menu=entry_menu)
        entry_menu.add_command(label="Add", command=self.add_entry)
        entry_menu.add_command(label="Edit", command=self.edit_entry)
        entry_menu.add_command(label="Delete", command=self.delete_entry)
        entry_menu.add_command(label="Show password", command=self.show_selected_password)
        entry_menu.add_command(label="Copy password", command=self.copy_selected_password)

        security_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Security", menu=security_menu)
        security_menu.add_command(label="Change master password", command=self.change_master_password)
        security_menu.add_command(label="Settings", command=self.show_settings)
        security_menu.add_command(label="Audit log", command=self.show_logs)

        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)

    def _create_toolbar(self):
        toolbar = ttk.Frame(self.root)
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=6, pady=6)

        ttk.Button(toolbar, text="Add", command=self.add_entry).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Edit", command=self.edit_entry).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Delete", command=self.delete_entry).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Show Password", command=self.show_selected_password).pack(side=tk.LEFT, padx=10)
        ttk.Button(toolbar, text="Copy Password", command=self.copy_selected_password).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Lock", command=self._lock_vault).pack(side=tk.RIGHT, padx=2)

    def _create_main_area(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        columns = [
            {"id": "title", "label": "Title", "width": 180},
            {"id": "username", "label": "Username", "width": 180},
            {"id": "url", "label": "URL", "width": 260},
            {"id": "updated_at", "label": "Updated", "width": 160},
        ]
        self.table = SecureTable(main_frame, columns)
        self.table.pack(fill=tk.BOTH, expand=True)

    def _create_statusbar(self):
        statusbar = ttk.Frame(self.root)
        statusbar.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_label = ttk.Label(statusbar, text="Locked")
        self.status_label.pack(side=tk.LEFT, padx=5)

        self.clipboard_label = ttk.Label(statusbar, text="Clipboard: empty")
        self.clipboard_label.pack(side=tk.LEFT, padx=20)

        ttk.Label(statusbar, text="v2.0").pack(side=tk.RIGHT, padx=5)

    def _setup_events(self):
        event_bus.subscribe(EventType.ENTRY_ADDED, self._on_entry_changed)
        event_bus.subscribe(EventType.ENTRY_UPDATED, self._on_entry_changed)
        event_bus.subscribe(EventType.ENTRY_DELETED, self._on_entry_changed)
        event_bus.subscribe(EventType.USER_LOGGED_IN, lambda _event: self._set_status("Unlocked"))
        event_bus.subscribe(EventType.USER_LOGGED_OUT, lambda _event: self._set_status("Locked"))
        event_bus.subscribe(EventType.CLIPBOARD_COPIED, lambda _event: self._refresh_clipboard_status())
        event_bus.subscribe(EventType.CLIPBOARD_CLEARED, lambda _event: self._refresh_clipboard_status())

    def _setup_activity_tracking(self):
        for sequence in ("<Any-KeyPress>", "<Any-ButtonPress>", "<Motion>"):
            self.root.bind_all(sequence, self._on_activity, add="+")

    def _schedule_security_tasks(self):
        self._check_security_timers()
        self.root.after(1000, self._schedule_security_tasks)

    def _check_security_timers(self):
        if self.state.should_auto_lock():
            self._lock_vault()
        if self.state.clipboard_timer and self.state.get_clipboard() is None:
            try:
                self.root.clipboard_clear()
            except tk.TclError:
                pass
            event_bus.publish(Event(EventType.CLIPBOARD_CLEARED, {}))
        self._refresh_clipboard_status()

    def _on_activity(self, _event=None):
        if self.state.is_unlocked():
            self.state.update_activity()

    def _set_status(self, text: str):
        self.status_label.config(text=text)

    def _refresh_clipboard_status(self):
        self.clipboard_label.config(
            text="Clipboard: has password" if self.state.get_clipboard() else "Clipboard: empty"
        )

    def _require_login(self, initial: bool = False):
        while not self.auth_service.is_authenticated():
            password = simpledialog.askstring(
                "Master Password",
                "Enter the master password to unlock the vault:",
                show="*",
                parent=self.root,
            )
            if password is None:
                if initial:
                    self.root.destroy()
                return

            try:
                if self.auth_service.authenticate(password):
                    self.key_manager.store_key("active", self.auth_service.get_active_key())
                    event_bus.publish(Event(EventType.VAULT_UNLOCKED, {}))
                    break
            except AuthenticationError as error:
                messagebox.showerror("Authentication error", str(error), parent=self.root)
                continue

            remaining = self.auth_service.get_lockout_remaining_seconds()
            messagebox.showwarning(
                "Access denied",
                f"Wrong master password. Retry after about {remaining} sec." if remaining else "Wrong master password.",
                parent=self.root,
            )

        self._set_status("Unlocked")
        self.state.update_activity()

    def _load_entries(self):
        if not self.auth_service.is_authenticated():
            self.table.clear()
            return

        entries = self.db.get_all_entries()
        data = []
        for entry in entries:
            data.append(
                {
                    "id": entry.id,
                    "title": entry.title,
                    "username": entry.username,
                    "url": entry.url,
                    "updated_at": entry.updated_at.strftime("%Y-%m-%d %H:%M") if entry.updated_at else "",
                }
            )
        self.table.set_data(data)

    def _encrypt_password(self, password: str) -> bytes:
        return self.crypto.encrypt(password.encode("utf-8"))

    def _decrypt_password(self, encrypted_password: bytes) -> str:
        return self.crypto.decrypt(encrypted_password).decode("utf-8")

    def _build_entry_dialog(self, title: str, entry=None):
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("520x460")
        dialog.transient(self.root)
        dialog.grab_set()

        ttk.Label(dialog, text="Title").pack(anchor=tk.W, padx=8, pady=(8, 2))
        title_entry = ttk.Entry(dialog, width=60)
        title_entry.pack(fill=tk.X, padx=8, pady=2)

        ttk.Label(dialog, text="Username").pack(anchor=tk.W, padx=8, pady=(8, 2))
        username_entry = ttk.Entry(dialog, width=60)
        username_entry.pack(fill=tk.X, padx=8, pady=2)

        ttk.Label(dialog, text="Password").pack(anchor=tk.W, padx=8, pady=(8, 2))
        password_entry = PasswordEntry(dialog, width=50)
        password_entry.pack(fill=tk.X, padx=8, pady=2)

        ttk.Label(dialog, text="URL").pack(anchor=tk.W, padx=8, pady=(8, 2))
        url_entry = ttk.Entry(dialog, width=60)
        url_entry.pack(fill=tk.X, padx=8, pady=2)

        ttk.Label(dialog, text="Notes").pack(anchor=tk.W, padx=8, pady=(8, 2))
        notes_text = tk.Text(dialog, height=7, width=60)
        notes_text.pack(fill=tk.BOTH, expand=True, padx=8, pady=2)

        if entry:
            title_entry.insert(0, entry.title)
            username_entry.insert(0, entry.username)
            password_entry.set(self._decrypt_password(entry.encrypted_password))
            url_entry.insert(0, entry.url)
            notes_text.insert("1.0", entry.notes)

        return dialog, title_entry, username_entry, password_entry, url_entry, notes_text

    def _collect_entry_form(self, title_entry, username_entry, password_entry, url_entry, notes_text):
        title = title_entry.get().strip()
        username = username_entry.get().strip()
        password = password_entry.get().strip()
        url = url_entry.get().strip()
        notes = notes_text.get("1.0", tk.END).strip()

        if not title or not username or not password:
            raise ValueError("Title, username and password are required.")

        return title, username, password, url, notes

    def _get_selected_entry(self):
        selected = self.table.get_selected()
        if not selected:
            return None
        return self.db.get_entry(selected["id"])

    def _on_entry_changed(self, _event):
        self._load_entries()

    def new_database(self):
        if not messagebox.askyesno("Confirm", "Create a new vault database? Existing data in that file will be lost."):
            return

        new_path = filedialog.asksaveasfilename(
            title="Create new vault",
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
        self.db = Database(new_path)
        self.key_storage = KeyStorage(self.db)
        self.auth_service = AuthenticationService(
            self.key_storage,
            self.key_derivation,
            self.password_validator,
            self.state,
        )
        self.audit_logger = AuditLogger(self.db, event_bus)
        self._load_password_policy()
        SetupWizard(self.root, self.config, self.auth_service)
        if not self.auth_service.is_initialized():
            return
        self.key_manager.store_key("active", self.auth_service.get_active_key())
        self._load_entries()

    def open_database(self):
        path = filedialog.askopenfilename(
            title="Open vault database",
            filetypes=[("SQLite database", "*.db"), ("All files", "*.*")],
        )
        if not path:
            return

        self.config.set("database.path", path)
        if self.audit_logger:
            self.audit_logger.close()
        self.db = Database(path)
        self.key_storage = KeyStorage(self.db)
        self.auth_service = AuthenticationService(
            self.key_storage,
            self.key_derivation,
            self.password_validator,
            self.state,
        )
        self.audit_logger = AuditLogger(self.db, event_bus)
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
            title="Backup vault",
            defaultextension=".db",
            filetypes=[("SQLite database", "*.db"), ("All files", "*.*")],
        )
        if not backup_path:
            return
        self.db.backup(backup_path)
        messagebox.showinfo("Backup", "Backup created successfully.")

    def add_entry(self):
        if not self.auth_service.is_authenticated():
            self._require_login()
        dialog, title_entry, username_entry, password_entry, url_entry, notes_text = self._build_entry_dialog("Add Entry")

        def save():
            try:
                title, username, password, url, notes = self._collect_entry_form(
                    title_entry, username_entry, password_entry, url_entry, notes_text
                )
            except ValueError as error:
                messagebox.showerror("Error", str(error), parent=dialog)
                return

            entry = VaultEntry(
                title=title,
                username=username,
                encrypted_password=self._encrypt_password(password),
                url=url,
                notes=notes,
                created_at=datetime.now(),
                updated_at=datetime.now(),
                tags="",
            )
            entry_id = self.db.add_entry(entry)
            event_bus.publish(Event(EventType.ENTRY_ADDED, {"id": entry_id, "title": title}))
            dialog.destroy()

        ttk.Button(dialog, text="Save", command=save).pack(pady=10)

    def edit_entry(self):
        entry = self._get_selected_entry()
        if not entry:
            messagebox.showwarning("Warning", "Select an entry to edit.")
            return

        dialog, title_entry, username_entry, password_entry, url_entry, notes_text = self._build_entry_dialog(
            "Edit Entry",
            entry,
        )

        def save():
            try:
                title, username, password, url, notes = self._collect_entry_form(
                    title_entry, username_entry, password_entry, url_entry, notes_text
                )
            except ValueError as error:
                messagebox.showerror("Error", str(error), parent=dialog)
                return

            entry.title = title
            entry.username = username
            entry.encrypted_password = self._encrypt_password(password)
            entry.url = url
            entry.notes = notes
            self.db.update_entry(entry)
            event_bus.publish(Event(EventType.ENTRY_UPDATED, {"id": entry.id, "title": title}))
            dialog.destroy()

        ttk.Button(dialog, text="Save changes", command=save).pack(pady=10)

    def delete_entry(self):
        selected = self.table.get_selected()
        if not selected:
            messagebox.showwarning("Warning", "Select an entry to delete.")
            return
        if messagebox.askyesno("Confirm", f"Delete entry '{selected['title']}'?"):
            self.db.delete_entry(selected["id"])
            event_bus.publish(Event(EventType.ENTRY_DELETED, {"id": selected["id"], "title": selected["title"]}))

    def show_selected_password(self):
        entry = self._get_selected_entry()
        if not entry:
            messagebox.showwarning("Warning", "Select an entry first.")
            return
        messagebox.showinfo("Password", self._decrypt_password(entry.encrypted_password))
        self.state.update_activity()

    def copy_selected_password(self):
        entry = self._get_selected_entry()
        if not entry:
            messagebox.showwarning("Warning", "Select an entry first.")
            return
        password = self._decrypt_password(entry.encrypted_password)
        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        self.state.set_clipboard(password, self.config.get("security.clipboard_timeout", 30))
        event_bus.publish(Event(EventType.CLIPBOARD_COPIED, {"entry_id": entry.id}))

    def show_logs(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Audit Log")
        dialog.geometry("760x420")
        text = tk.Text(dialog, wrap=tk.NONE)
        text.pack(fill=tk.BOTH, expand=True)
        for log in self.db.get_audit_logs():
            timestamp = log.timestamp.strftime("%Y-%m-%d %H:%M:%S") if log.timestamp else ""
            text.insert("end", f"{timestamp} | {log.action} | entry={log.entry_id} | {log.details}\n")
        text.config(state=tk.DISABLED)

    def show_settings(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Settings")
        dialog.geometry("460x360")

        clipboard_timeout = tk.IntVar(value=self.config.get("security.clipboard_timeout", 30))
        auto_lock_minutes = tk.IntVar(value=self.config.get("security.auto_lock_minutes", 5))
        min_password_length = tk.IntVar(value=self.config.get("security.min_password_length", 12))

        ttk.Label(dialog, text="Clipboard timeout (sec)").pack(anchor=tk.W, padx=10, pady=(12, 2))
        ttk.Spinbox(dialog, from_=5, to=300, textvariable=clipboard_timeout).pack(fill=tk.X, padx=10, pady=2)

        ttk.Label(dialog, text="Auto-lock timeout (min)").pack(anchor=tk.W, padx=10, pady=(12, 2))
        ttk.Spinbox(dialog, from_=1, to=120, textvariable=auto_lock_minutes).pack(fill=tk.X, padx=10, pady=2)

        ttk.Label(dialog, text="Minimum master password length").pack(anchor=tk.W, padx=10, pady=(12, 2))
        ttk.Spinbox(dialog, from_=8, to=64, textvariable=min_password_length).pack(fill=tk.X, padx=10, pady=2)

        def save():
            self.config.set("security.clipboard_timeout", clipboard_timeout.get())
            self.config.set("security.auto_lock_minutes", auto_lock_minutes.get())
            self.config.set("security.min_password_length", min_password_length.get())
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
            messagebox.showinfo("Settings", "Settings saved.", parent=dialog)
            dialog.destroy()

        ttk.Button(dialog, text="Save", command=save).pack(pady=16)
        ttk.Button(dialog, text="Change master password", command=self.change_master_password).pack(pady=2)

    def change_master_password(self):
        current_password = simpledialog.askstring("Change Password", "Current master password:", show="*", parent=self.root)
        if current_password is None:
            return
        new_password = simpledialog.askstring("Change Password", "New master password:", show="*", parent=self.root)
        if new_password is None:
            return
        confirm = simpledialog.askstring("Change Password", "Confirm new master password:", show="*", parent=self.root)
        if confirm != new_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return
        try:
            self.auth_service.change_master_password(current_password, new_password)
            self.key_manager.store_key("active", self.auth_service.get_active_key())
            messagebox.showinfo("Success", "Master password changed.")
        except AuthenticationError as error:
            messagebox.showerror("Error", str(error))

    def _lock_vault(self, show_dialog: bool = True):
        self.auth_service.logout()
        self.key_manager.clear_key()
        self.state.clear_clipboard()
        try:
            self.root.clipboard_clear()
        except tk.TclError:
            pass
        event_bus.publish(Event(EventType.VAULT_LOCKED, {}))
        self.table.clear()
        self._set_status("Locked")
        if show_dialog:
            self._require_login()
            if self.auth_service.is_authenticated():
                self.key_manager.store_key("active", self.auth_service.get_active_key())
                self._load_entries()

    def show_about(self):
        messagebox.showinfo(
            "About",
            "CryptoSafe Manager\nVersion 2.0\n\n"
            "Password manager with encrypted local storage, master-password auth and audit logging.",
        )

    def run(self):
        self.root.mainloop()
