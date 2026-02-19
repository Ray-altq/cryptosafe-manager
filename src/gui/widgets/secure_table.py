import tkinter as tk
from tkinter import ttk
from typing import List, Dict, Any

class SecureTable(ttk.Frame):
    """Таблица для отображения записей хранилища (GUI-2)"""
    
    def __init__(self, parent, columns: List[Dict[str, Any]]):
        super().__init__(parent)
        
        self.columns = columns
        self.data = []
        
        # создаем таблицу
        self.tree = ttk.Treeview(
            self,
            columns=[col['id'] for col in columns],
            show='headings',
            selectmode='browse'
        )
        
        # настраиваем заголовки
        for col in columns:
            self.tree.heading(col['id'], text=col['label'])
            width = col.get('width', 100)
            self.tree.column(col['id'], width=width)
        
        # скроллбары
        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(self, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # размещаем
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        
        # настройка весов для ресайза
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
    
    def set_data(self, data: List[Dict[str, Any]]):
        """Заполнить таблицу данными"""
        # очищаем
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        self.data = data
        
        # добавляем новые строки
        for i, row in enumerate(data):
            values = [row.get(col['id'], '') for col in self.columns]
            self.tree.insert('', 'end', iid=str(i), values=values)
    
    def get_selected(self) -> Dict[str, Any]:
        """Получить выбранную запись"""
        selection = self.tree.selection()
        if selection:
            index = int(selection[0])
            return self.data[index]
        return None
    
    def clear(self):
        """Очистить таблицу"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.data = []