import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from ..core.crypto.authentication import AuthenticationError, AuthenticationService
from ..core.crypto.key_storage import KeyStorage
from ..database.db import Database


class SetupWizard:
    def __init__(self, parent, config, auth_service: AuthenticationService):
        self.parent = parent
        self.config = config
        self.auth_service = auth_service

        self.wizard = tk.Toplevel(parent)
        self.wizard.title("Первоначальная настройка")
        self.wizard.geometry("540x480")
        self.wizard.transient(parent)
        self.wizard.grab_set()
        self.wizard.resizable(False, False)

        self.master_password = tk.StringVar()
        self.confirm_password = tk.StringVar()
        self.db_path = tk.StringVar(value=str(Path.home() / ".cryptosafe" / "vault.db"))
        self.algorithm = tk.StringVar(value=self.config.get("crypto.algorithm", "XOR"))
        self.pbkdf2_iterations = tk.IntVar(value=self.config.get("crypto.pbkdf2_iterations", 100000))

        self.current_step = 0
        self.steps = [
            self._step_welcome,
            self._step_master_password,
            self._step_database_location,
            self._step_encryption_settings,
            self._step_finish,
        ]

        self._create_widgets()
        self._show_step(0)
        self.wizard.wait_window()

    def _create_widgets(self):
        self.title_label = ttk.Label(self.wizard, text="", font=("Segoe UI", 14, "bold"))
        self.title_label.pack(pady=10)

        self.content_frame = ttk.Frame(self.wizard, relief=tk.SUNKEN, padding=12)
        self.content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        button_frame = ttk.Frame(self.wizard)
        button_frame.pack(fill=tk.X, padx=20, pady=10)

        self.back_btn = ttk.Button(button_frame, text="< Назад", command=self._prev_step)
        self.back_btn.pack(side=tk.LEFT)

        self.next_btn = ttk.Button(button_frame, text="Далее >", command=self._next_step)
        self.next_btn.pack(side=tk.RIGHT)

        self.finish_btn = ttk.Button(button_frame, text="Готово", command=self._finish)

    def _show_step(self, step: int):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

        self.title_label.config(text=f"Шаг {step + 1} из {len(self.steps)}")
        self.steps[step]()
        self.back_btn.config(state=tk.NORMAL if step > 0 else tk.DISABLED)

        if step == len(self.steps) - 1:
            self.next_btn.pack_forget()
            self.finish_btn.pack(side=tk.RIGHT)
        else:
            self.finish_btn.pack_forget()
            self.next_btn.pack(side=tk.RIGHT)

    def _next_step(self):
        if self.current_step == 1 and not self._validate_password():
            return
        if self.current_step == 2 and not self._validate_db_path():
            return

        if self.current_step < len(self.steps) - 1:
            self.current_step += 1
            self._show_step(self.current_step)

    def _prev_step(self):
        if self.current_step > 0:
            self.current_step -= 1
            self._show_step(self.current_step)

    def _step_welcome(self):
        text = tk.Text(self.content_frame, wrap=tk.WORD, height=10, font=("Segoe UI", 10))
        text.insert(
            "1.0",
            "Добро пожаловать в CryptoSafe Manager.\n\n"
            "Этот мастер поможет:\n"
            "1. Создать мастер-пароль\n"
            "2. Выбрать расположение базы данных vault\n"
            "3. Сохранить криптографические параметры\n\n"
            "Нажмите «Далее», чтобы продолжить.",
        )
        text.config(state=tk.DISABLED)
        text.pack(fill=tk.BOTH, expand=True)

    def _step_master_password(self):
        ttk.Label(self.content_frame, text="Создание мастер-пароля", font=("Segoe UI", 10, "bold")).pack(
            anchor=tk.W, pady=(0, 8)
        )
        ttk.Label(self.content_frame, text="Мастер-пароль").pack(anchor=tk.W)
        ttk.Entry(self.content_frame, textvariable=self.master_password, show="*", width=42).pack(
            fill=tk.X, pady=(0, 10)
        )
        ttk.Label(self.content_frame, text="Подтверждение пароля").pack(anchor=tk.W)
        ttk.Entry(self.content_frame, textvariable=self.confirm_password, show="*", width=42).pack(
            fill=tk.X, pady=(0, 10)
        )
        ttk.Label(
            self.content_frame,
            text="Используйте длинный пароль с буквами разного регистра, цифрами и специальными символами.",
            foreground="gray",
            justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(8, 0))

    def _step_database_location(self):
        ttk.Label(self.content_frame, text="Расположение базы данных vault", font=("Segoe UI", 10, "bold")).pack(
            anchor=tk.W, pady=(0, 8)
        )
        ttk.Label(self.content_frame, text="Путь к файлу базы данных").pack(anchor=tk.W)
        path_frame = ttk.Frame(self.content_frame)
        path_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Entry(path_frame, textvariable=self.db_path).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(path_frame, text="Обзор...", command=self._browse_db).pack(side=tk.RIGHT, padx=(5, 0))

    def _step_encryption_settings(self):
        ttk.Label(self.content_frame, text="Настройки шифрования", font=("Segoe UI", 10, "bold")).pack(
            anchor=tk.W, pady=(0, 8)
        )
        ttk.Label(self.content_frame, text="Алгоритм").pack(anchor=tk.W)
        combo = ttk.Combobox(self.content_frame, textvariable=self.algorithm, values=["XOR"], state="readonly")
        combo.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(self.content_frame, text="Количество итераций PBKDF2").pack(anchor=tk.W)
        ttk.Spinbox(
            self.content_frame,
            from_=100000,
            to=1000000,
            increment=10000,
            textvariable=self.pbkdf2_iterations,
        ).pack(fill=tk.X, pady=(0, 10))

    def _step_finish(self):
        text = tk.Text(self.content_frame, wrap=tk.WORD, height=10, font=("Segoe UI", 10))
        text.insert(
            "1.0",
            f"Все готово к инициализации vault.\n\n"
            f"База данных: {self.db_path.get()}\n"
            f"Алгоритм: {self.algorithm.get()}\n"
            f"Итерации PBKDF2: {self.pbkdf2_iterations.get()}\n\n"
            "Нажмите «Готово», чтобы создать vault и сохранить мастер-пароль.",
        )
        text.config(state=tk.DISABLED)
        text.pack(fill=tk.BOTH, expand=True)

    def _browse_db(self):
        filename = filedialog.asksaveasfilename(
            title="Выберите файл базы данных vault",
            defaultextension=".db",
            filetypes=[("SQLite database", "*.db"), ("All files", "*.*")],
        )
        if filename:
            self.db_path.set(filename)

    def _validate_password(self) -> bool:
        if not self.master_password.get():
            messagebox.showerror("Ошибка", "Введите мастер-пароль")
            return False
        if self.master_password.get() != self.confirm_password.get():
            messagebox.showerror("Ошибка", "Пароли не совпадают")
            return False
        return True

    def _validate_db_path(self) -> bool:
        if not self.db_path.get():
            messagebox.showerror("Ошибка", "Укажите путь к файлу базы данных")
            return False
        return True

    def _finish(self):
        if not self._validate_password() or not self._validate_db_path():
            return

        self.config.set("database.path", self.db_path.get())
        self.config.set("crypto.algorithm", self.algorithm.get())
        self.config.set("crypto.pbkdf2_iterations", self.pbkdf2_iterations.get())

        database = Database(self.db_path.get())
        self.auth_service.key_storage = KeyStorage(database)

        try:
            self.auth_service.register_master_password(self.master_password.get())
        except AuthenticationError as error:
            messagebox.showerror("Ошибка", str(error))
            return

        database.set_setting(
            "security.password_policy",
            {
                "min_password_length": self.config.get("security.min_password_length", 12),
                "require_uppercase": self.config.get("security.require_uppercase", True),
                "require_lowercase": self.config.get("security.require_lowercase", True),
                "require_digits": self.config.get("security.require_digits", True),
                "require_special": self.config.get("security.require_special", True),
            },
        )

        messagebox.showinfo("Успешно", "Vault успешно инициализирован.")
        self.wizard.destroy()
