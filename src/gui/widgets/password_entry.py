import tkinter as tk
from tkinter import ttk

class PasswordEntry(ttk.Frame):
    """Поле ввода пароля с кнопкой показа/скрытия (GUI-2)"""
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent)
        
        # переменная для отслеживания состояния (показан/скрыт)
        self.show_password = tk.BooleanVar(value=False)
        
        # поле ввода (изначально скрыто)
        self.entry = ttk.Entry(self, show="*", **kwargs)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # кнопка показа/скрытия
        self.toggle_btn = ttk.Button(
            self,
            text="👁",
            width=3,
            command=self.toggle_show
        )
        self.toggle_btn.pack(side=tk.RIGHT, padx=(2, 0))
        
        # отслеживаем изменение переменной
        self.show_password.trace('w', self._update_visibility)
    
    def toggle_show(self):
        """Переключить видимость пароля"""
        self.show_password.set(not self.show_password.get())
    
    def _update_visibility(self, *args):
        """Обновить видимость в зависимости от show_password"""
        if self.show_password.get():
            self.entry.config(show="")
            self.toggle_btn.config(text="скрыть")
        else:
            self.entry.config(show="*")
            self.toggle_btn.config(text="👁")
    
    def get(self) -> str:
        """Получить текст пароля"""
        return self.entry.get()
    
    def set(self, value: str):
        """Установить текст пароля"""
        self.entry.delete(0, tk.END)
        self.entry.insert(0, value)
    
    def clear(self):
        """Очистить поле"""
        self.entry.delete(0, tk.END)