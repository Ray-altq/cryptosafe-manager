import tkinter as tk
from tkinter import ttk
from typing import Any, Callable, Dict, List, Optional


class SecureTable(ttk.Frame):
    """Таблица для отображения записей хранилища."""

    def __init__(self, parent, columns: List[Dict[str, Any]]):
        super().__init__(parent)

        self.columns = columns
        self.data: List[Dict[str, Any]] = []
        self._sort_state: Dict[str, bool] = {}

        self.tree = ttk.Treeview(
            self,
            columns=[col["id"] for col in columns],
            show="headings",
            selectmode="browse",
        )

        for col in columns:
            self.tree.heading(
                col["id"],
                text=col["label"],
                command=lambda column_id=col["id"]: self._sort_by(column_id),
            )
            self.tree.column(col["id"], width=col.get("width", 100))

        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(self, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

    def _sort_by(self, column_id: str):
        if not self.data:
            return

        reverse = not self._sort_state.get(column_id, False)
        self._sort_state = {column_id: reverse}
        self.data.sort(key=lambda row: self._sort_key(row.get(column_id)), reverse=reverse)
        self.set_data(self.data)

    def _sort_key(self, value: Any):
        if value is None:
            return ""
        return str(value).lower()

    def set_data(self, data: List[Dict[str, Any]]):
        """Заполнить таблицу данными."""
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.data = list(data)

        for i, row in enumerate(self.data):
            values = [row.get(col["id"], "") for col in self.columns]
            self.tree.insert("", "end", iid=str(i), values=values)

    def get_selected(self) -> Optional[Dict[str, Any]]:
        """Получить выбранную запись."""
        selection = self.tree.selection()
        if selection:
            index = int(selection[0])
            return self.data[index]
        return None

    def select_row_at_y(self, y: int) -> Optional[Dict[str, Any]]:
        """Выбрать строку по координате Y внутри таблицы."""
        item_id = self.tree.identify_row(y)
        if not item_id:
            return None
        self.tree.selection_set(item_id)
        self.tree.focus(item_id)
        return self.get_selected()

    def bind_context_menu(self, callback: Callable):
        """Привязать обработчик контекстного меню к строкам таблицы."""
        self.tree.bind("<Button-3>", callback, add="+")

    def clear(self):
        """Очистить таблицу."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.data = []
