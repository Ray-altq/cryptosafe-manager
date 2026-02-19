import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path

class SetupWizard:
    """Мастер первоначальной настройки (GUI-3 MUST)"""
    
    def __init__(self, parent, config):
        self.parent = parent
        self.config = config
        
        # создаем окно мастера
        self.wizard = tk.Toplevel(parent)
        self.wizard.title("Первоначальная настройка")
        self.wizard.geometry("500x450")
        self.wizard.transient(parent)  # поверх главного
        self.wizard.grab_set()  # модальное окно
        self.wizard.resizable(False, False)
        
        # переменные для хранения введенных данных
        self.master_password = tk.StringVar()
        self.confirm_password = tk.StringVar()
        self.db_path = tk.StringVar(value=str(Path.home() / '.cryptosafe' / 'vault.db'))
        
        # текущий шаг
        self.current_step = 0
        self.steps = [
            self._step_welcome,
            self._step_master_password,
            self._step_database_location,
            self._step_encryption_settings,
            self._step_finish
        ]
        
        # создаем интерфейс
        self._create_widgets()
        self._show_step(0)
        
        # ждем закрытия
        self.wizard.wait_window()
    
    def _create_widgets(self):
        """Создание общего интерфейса мастера"""
        # заголовок шага
        self.title_label = ttk.Label(self.wizard, text="", font=('Arial', 14, 'bold'))
        self.title_label.pack(pady=10)
        
        # рамка для содержимого шага
        self.content_frame = ttk.Frame(self.wizard, relief=tk.SUNKEN, padding=10)
        self.content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # рамка для кнопок
        button_frame = ttk.Frame(self.wizard)
        button_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.back_btn = ttk.Button(button_frame, text="< Назад", command=self._prev_step)
        self.back_btn.pack(side=tk.LEFT)
        
        self.next_btn = ttk.Button(button_frame, text="Далее >", command=self._next_step)
        self.next_btn.pack(side=tk.RIGHT)
        
        self.finish_btn = ttk.Button(button_frame, text="Готово", command=self._finish)
        # finish_btn пока не показываем
    
    def _show_step(self, step: int):
        """Показать шаг с номером step"""
        # очищаем содержимое
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        # обновляем заголовок
        self.title_label.config(text=f"Шаг {step + 1} из {len(self.steps)}")
        
        # показываем нужный шаг
        self.steps[step]()
        
        # обновляем состояние кнопок
        self.back_btn.config(state=tk.NORMAL if step > 0 else tk.DISABLED)
        
        if step == len(self.steps) - 1:
            # последний шаг - показываем кнопку Готово
            self.next_btn.pack_forget()
            self.finish_btn.pack(side=tk.RIGHT)
        else:
            # не последний шаг - показываем Далее
            self.finish_btn.pack_forget()
            self.next_btn.pack(side=tk.RIGHT)
    
    def _next_step(self):
        """Перейти к следующему шагу"""
        if self.current_step < len(self.steps) - 1:
            # проверка текущего шага перед переходом
            if self.current_step == 1 and not self._validate_password():
                return
            if self.current_step == 2 and not self._validate_db_path():
                return
            
            self.current_step += 1
            self._show_step(self.current_step)
    
    def _prev_step(self):
        """Вернуться к предыдущему шагу"""
        if self.current_step > 0:
            self.current_step -= 1
            self._show_step(self.current_step)
    
    def _step_welcome(self):
        """Шаг 1: Приветствие"""
        text = tk.Text(self.content_frame, wrap=tk.WORD, height=8, font=('Arial', 10))
        text.insert('1.0', """Добро пожаловать в CryptoSafe Manager!

Этот мастер поможет настроить приложение для первого использования.

Что нужно сделать:
1. Создать мастер-пароль (главный пароль для доступа)
2. Выбрать место для хранения базы данных
3. Настроить параметры шифрования

Нажмите "Далее" для продолжения.""")
        text.config(state=tk.DISABLED)
        text.pack(fill=tk.BOTH, expand=True)
    
    def _step_master_password(self):
        """Шаг 2: Создание мастер-пароля"""
        ttk.Label(self.content_frame, text="Придумайте мастер-пароль:", 
                 font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(0,5))
        
        ttk.Label(self.content_frame, text="Мастер-пароль:").pack(anchor=tk.W)
        pw_entry = ttk.Entry(self.content_frame, textvariable=self.master_password, 
                            show="*", width=40)
        pw_entry.pack(fill=tk.X, pady=(0,10))
        pw_entry.focus()
        
        ttk.Label(self.content_frame, text="Подтверждение:").pack(anchor=tk.W)
        confirm_entry = ttk.Entry(self.content_frame, textvariable=self.confirm_password, 
                                 show="*", width=40)
        confirm_entry.pack(fill=tk.X, pady=(0,10))
        
        # подсказка
        ttk.Label(self.content_frame, 
                 text="Мастер-пароль должен содержать минимум 8 символов.\n"
                      "Запомните его! Без него вы не сможете получить доступ к данным.",
                 foreground="gray",
                 justify=tk.LEFT).pack(pady=10)
    
    def _step_database_location(self):
        """Шаг 3: Выбор расположения БД"""
        ttk.Label(self.content_frame, text="Выберите место для базы данных:",
                 font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(0,10))
        
        ttk.Label(self.content_frame, text="Путь к файлу:").pack(anchor=tk.W)
        
        # поле с путем и кнопкой обзора
        path_frame = ttk.Frame(self.content_frame)
        path_frame.pack(fill=tk.X, pady=(0,10))
        
        path_entry = ttk.Entry(path_frame, textvariable=self.db_path)
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        ttk.Button(path_frame, text="Обзор...", command=self._browse_db).pack(side=tk.RIGHT, padx=(5,0))
        
        # информация
        ttk.Label(self.content_frame, 
                 text="База данных будет храниться в указанном файле.\n"
                      "Рекомендуется выбрать защищенное место (например, Documents).",
                 foreground="gray",
                 justify=tk.LEFT).pack(pady=10)
    
    def _step_encryption_settings(self):
        """Шаг 4: Настройки шифрования (заглушка)"""
        ttk.Label(self.content_frame, text="Настройки шифрования:",
                 font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(0,10))
        
        ttk.Label(self.content_frame, text="Алгоритм:").pack(anchor=tk.W)
        algo_combo = ttk.Combobox(self.content_frame, 
                                  values=["AES-256 (рекомендуется)", "XOR (только для тестов)"],
                                  state="readonly")
        algo_combo.current(0)
        algo_combo.pack(fill=tk.X, pady=(0,10))
        
        ttk.Label(self.content_frame, text="Количество итераций:").pack(anchor=tk.W)
        ttk.Spinbox(self.content_frame, from_=1000, to=1000000, increment=1000).pack(fill=tk.X, pady=(0,10))
        
        ttk.Label(self.content_frame, 
                 text="Эти настройки будут использоваться для шифрования.\n"
                      "Оставьте значения по умолчанию, если не уверены.",
                 foreground="gray",
                 justify=tk.LEFT).pack(pady=10)
    
    def _step_finish(self):
        """Шаг 5: Завершение"""
        text = tk.Text(self.content_frame, wrap=tk.WORD, height=10, font=('Arial', 10))
        text.insert('1.0', f"""Настройка завершена!

Проверьте введенные данные:

✓ Мастер-пароль: установлен
✓ База данных: {self.db_path.get()}
✓ Шифрование: настроено

Нажмите "Готово" для запуска приложения.

Важно: запишите мастер-пароль в надежное место!""")
        text.config(state=tk.DISABLED)
        text.pack(fill=tk.BOTH, expand=True)
    
    def _browse_db(self):
        """Открыть диалог выбора файла для БД"""
        filename = filedialog.asksaveasfilename(
            title="Выберите файл базы данных",
            defaultextension=".db",
            filetypes=[("SQLite database", "*.db"), ("All files", "*.*")]
        )
        if filename:
            self.db_path.set(filename)
    
    def _validate_password(self) -> bool:
        """Проверка мастер-пароля"""
        password = self.master_password.get()
        confirm = self.confirm_password.get()
        
        if not password:
            messagebox.showerror("Ошибка", "Введите мастер-пароль")
            return False
        
        if len(password) < 8:
            messagebox.showerror("Ошибка", "Мастер-пароль должен быть не менее 8 символов")
            return False
        
        if password != confirm:
            messagebox.showerror("Ошибка", "Пароли не совпадают")
            return False
        
        return True
    
    def _validate_db_path(self) -> bool:
        """Проверка пути к БД"""
        if not self.db_path.get():
            messagebox.showerror("Ошибка", "Укажите путь к файлу базы данных")
            return False
        return True
    
    def _finish(self):
        """Завершение настройки и сохранение"""
        # финальная проверка
        if not self._validate_password():
            return
        if not self._validate_db_path():
            return
        
        # сохраняем настройки
        self.config.set('database.path', self.db_path.get())
        
        # TODO: здесь будет создание мастер-ключа 
        
        messagebox.showinfo("Успешно", "Настройка завершена! Приложение готово к работе.")
        self.wizard.destroy()