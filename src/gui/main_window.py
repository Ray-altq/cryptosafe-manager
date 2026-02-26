import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime

# импорты наших модулей
from ..core.config import Config
from ..core.state_manager import StateManager
from ..core.events import event_bus, Event, EventType
from ..database.db import Database
from ..database.models import VaultEntry
from .widgets.password_entry import PasswordEntry
from .widgets.secure_table import SecureTable
from .setup_wizard import SetupWizard

class MainWindow:
    """Главное окно приложения"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("CryptoSafe Manager")
        self.root.geometry("900x600")
        
        # инициализация компонентов
        self.config = Config()
        
        # проверяем, нужно ли показать мастер настройки
        if self._is_first_run():
            SetupWizard(self.root, self.config)
        
        self.state = StateManager()
        self.db = Database(self.config.get('database.path', 'cryptosafe.db'))
        
        # создаем интерфейс
        self._create_menu()      # панель меню
        self._create_toolbar()    # панель инструментов
        self._create_main_area()  # основная область с таблицей
        self._create_statusbar()  # строка состояния
        
        # загружаем данные
        self._load_entries()
        
        # подписываемся на события
        self._setup_events()
    
    def _is_first_run(self) -> bool:
        """Проверка, первый ли запуск (нужен ли мастер)"""
        import os
        db_path = self.config.get('database.path')
        return not os.path.exists(db_path)
    
    def _create_menu(self):
        """Создание меню"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # меню Файл
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Файл", menu=file_menu)
        file_menu.add_command(label="Создать", command=self.new_database)
        file_menu.add_command(label="Открыть", command=self.open_database)
        file_menu.add_separator()
        file_menu.add_command(label="Резервная копия", command=self.backup)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.root.quit)
        
        # меню Правка
        edit_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Правка", menu=edit_menu)
        edit_menu.add_command(label="Добавить", command=self.add_entry)
        edit_menu.add_command(label="Изменить", command=self.edit_entry)
        edit_menu.add_command(label="Удалить", command=self.delete_entry)
        
        # меню Вид
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Вид", menu=view_menu)
        view_menu.add_command(label="Логи", command=self.show_logs)
        view_menu.add_command(label="Настройки", command=self.show_settings)
        
        # меню Справка
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Справка", menu=help_menu)
        help_menu.add_command(label="О программе", command=self.show_about)
    
    def _create_toolbar(self):
        """Создание панели инструментов"""
        toolbar = ttk.Frame(self.root)
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        
        ttk.Button(toolbar, text="Добавить", command=self.add_entry).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Изменить", command=self.edit_entry).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Удалить", command=self.delete_entry).pack(side=tk.LEFT, padx=2)
    
    def _create_main_area(self):
        """Создание основной области с таблицей"""
        # рамка для таблицы
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # колонки таблицы
        columns = [
            {'id': 'title', 'label': 'Название', 'width': 150},
            {'id': 'username', 'label': 'Имя пользователя', 'width': 150},
            {'id': 'url', 'label': 'URL', 'width': 200},
            {'id': 'updated_at', 'label': 'Обновлено', 'width': 150}
        ]
        
        self.table = SecureTable(main_frame, columns)
        self.table.pack(fill=tk.BOTH, expand=True)
    
    def _create_statusbar(self):
        """Создание строки состояния"""
        statusbar = ttk.Frame(self.root)
        statusbar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # статус входа
        self.status_label = ttk.Label(statusbar, text="Заблокировано")
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        # таймер буфера (заглушка)
        ttk.Label(statusbar, text="Буфер: пуст").pack(side=tk.LEFT, padx=20)
        
        # версия
        ttk.Label(statusbar, text="v1.0").pack(side=tk.RIGHT, padx=5)
    
    def _setup_events(self):
        """Подписка на события"""
        event_bus.subscribe(EventType.ENTRY_ADDED, self._on_entry_added)
        event_bus.subscribe(EventType.ENTRY_UPDATED, self._on_entry_updated)
        event_bus.subscribe(EventType.ENTRY_DELETED, self._on_entry_deleted)
    
    def _on_entry_added(self, event):
        self._load_entries()
        self.status_label.config(text="Запись добавлена")
    
    def _on_entry_updated(self, event):
        self._load_entries()
        self.status_label.config(text="Запись обновлена")
    
    def _on_entry_deleted(self, event):
        self._load_entries()
        self.status_label.config(text="Запись удалена")
    
    def _load_entries(self):
        """Загрузка записей из БД в таблицу"""
        entries = self.db.get_all_entries()
        
        # преобразуем для таблицы
        data = []
        for entry in entries:
            data.append({
                'id': entry.id,
                'title': entry.title,
                'username': entry.username,
                'url': entry.url,
                'updated_at': entry.updated_at.strftime('%Y-%m-%d %H:%M') if entry.updated_at else ''
            })
        
        self.table.set_data(data)
    
    # ===== обработчики команд меню =====
    
    def new_database(self):
        """Создать новую БД"""
        if messagebox.askyesno("Подтверждение", "Создать новую базу данных? Все данные будут потеряны!"):
            import os
            if os.path.exists(self.db.db_path):
                os.remove(self.db.db_path)
            self.db = Database(self.db.db_path)
            self._load_entries()
            event_bus.publish(Event(EventType.ENTRY_DELETED, "all"))
    
    def open_database(self):
        """Открыть другую БД (заглушка)"""
        messagebox.showinfo("Инфо", "Открыть БД - будет позже")
    
    def backup(self):
        """Резервное копирование (заглушка)"""
        self.db.backup("backup.db")
        messagebox.showinfo("Инфо", "Резервная копия создана")
    
    def add_entry(self):
        """Диалог добавления записи"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Добавить запись")
        dialog.geometry("500x400")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # поля ввода
        ttk.Label(dialog, text="Название:").pack(anchor=tk.W, padx=5, pady=2)
        title_entry = ttk.Entry(dialog, width=50)
        title_entry.pack(padx=5, pady=2)
        
        ttk.Label(dialog, text="Имя пользователя:").pack(anchor=tk.W, padx=5, pady=2)
        username_entry = ttk.Entry(dialog, width=50)
        username_entry.pack(padx=5, pady=2)
        
        ttk.Label(dialog, text="Пароль:").pack(anchor=tk.W, padx=5, pady=2)
        password_entry = PasswordEntry(dialog, width=50)
        password_entry.pack(padx=5, pady=2)
        
        ttk.Label(dialog, text="URL:").pack(anchor=tk.W, padx=5, pady=2)
        url_entry = ttk.Entry(dialog, width=50)
        url_entry.pack(padx=5, pady=2)
        
        ttk.Label(dialog, text="Заметки:").pack(anchor=tk.W, padx=5, pady=2)
        notes_text = tk.Text(dialog, height=5, width=50)
        notes_text.pack(padx=5, pady=2)
        
        def save():
          #получаем данные из полей
          title = title_entry.get().strip()
          username = username_entry.get().strip()
          password = password_entry.get().strip()
          url = url_entry.get().strip()
          notes = notes_text.get("1.0", tk.END).strip()
        
          #проверка обязательных полей
          if not title:
            messagebox.showerror("Ошибка", "Введите название")
            return
          if not username:
            messagebox.showerror("Ошибка", "Введите имя пользователя")
            return
          if not password:
            messagebox.showerror("Ошибка", "Введите пароль")
            return
        
          #сохраняем пароль как байты (без шифрования) (потом изменю!!!)
          encrypted = password.encode('utf-8')
        
          entry = VaultEntry(
              title=title,
              username=username,
              encrypted_password=encrypted,
              url=url,
              notes=notes,
              created_at=datetime.now(),
              updated_at=datetime.now(),
              tags=""
          ) 
        
          entry_id = self.db.add_entry(entry)
          event_bus.publish(Event(EventType.ENTRY_ADDED, {"id": entry_id}))
        
          #обновляем таблицу
          self._load_entries()
        
          dialog.destroy()
          messagebox.showinfo("Успех", f"Запись '{title}' добавлена!")

        ttk.Button(dialog, text="Сохранить", command=save).pack(pady=10)  #кнопка сохранения
    
    def edit_entry(self):
        """Диалог изменения записи"""
        selected = self.table.get_selected()
        if not selected:
            messagebox.showwarning("Предупреждение", "Выберите запись для редактирования")
            return
        
        # TODO: загрузить полную запись из БД
        messagebox.showinfo("Инфо", f"Редактирование {selected['title']} - будет позже")
    
    def delete_entry(self):
        """Удаление записи"""
        selected = self.table.get_selected()
        if not selected:
            messagebox.showwarning("Предупреждение", "Выберите запись для удаления")
            return
        
        if messagebox.askyesno("Подтверждение", f"Удалить запись {selected['title']}?"):
            self.db.delete_entry(selected['id'])
            event_bus.publish(Event(EventType.ENTRY_DELETED, selected))
    
    def show_logs(self):
        """Показать логи (заглушка)"""
        messagebox.showinfo("Инфо", "Журнал аудита - будет позже")
    
    def show_settings(self):
        """Показать настройки (заглушка)"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Настройки")
        dialog.geometry("400x300")
        
        notebook = ttk.Notebook(dialog)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # вкладка безопасность
        security_frame = ttk.Frame(notebook)
        notebook.add(security_frame, text="Безопасность")
        ttk.Label(security_frame, text="Таймаут буфера: 30 сек").pack(pady=10)
        ttk.Label(security_frame, text="Автоблокировка: 5 мин").pack(pady=10)
        
        # вкладка внешний вид
        appearance_frame = ttk.Frame(notebook)
        notebook.add(appearance_frame, text="Внешний вид")
        ttk.Label(appearance_frame, text="Тема: светлая").pack(pady=10)
        ttk.Label(appearance_frame, text="Язык: русский").pack(pady=10)
    
    def show_about(self):
        """О программе"""
        messagebox.showinfo(
            "О программе",
            "CryptoSafe Manager\nВерсия 1.0\n\nМенеджер паролей с шифрованием"
        )
    
    def run(self):
        """Запуск приложения"""
        self.root.mainloop()