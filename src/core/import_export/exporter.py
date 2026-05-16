from typing import Any, Dict, Iterable, Optional

from .models import ExportOptions


class VaultExporter:
    def __init__(self, entry_manager, database=None, event_bus=None):
        self.entry_manager = entry_manager
        self.database = database
        self.event_bus = event_bus

    def get_entries_for_export(self, options: Optional[ExportOptions] = None) -> list[Dict[str, Any]]:
        selected_options = options or ExportOptions()
        if selected_options.entry_ids:
            return [self.entry_manager.get_entry(int(entry_id)) for entry_id in selected_options.entry_ids]
        return list(self.entry_manager.get_all_entries())

    def filter_entry_fields(self, entries: Iterable[Dict[str, Any]], include_fields: Optional[list[str]]) -> list[Dict[str, Any]]:
        if not include_fields:
            return [dict(entry) for entry in entries]
        allowed = set(include_fields)
        return [
            {key: value for key, value in dict(entry).items() if key in allowed}
            for entry in entries
        ]
