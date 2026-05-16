import csv
import io
from typing import Dict, Iterable, List


class CSVVaultFormat:
    name = "csv"
    fieldnames = ["title", "username", "password", "url", "notes", "category", "tags"]
    aliases = {
        "name": "title",
        "title": "title",
        "username": "username",
        "login": "username",
        "password": "password",
        "url": "url",
        "website": "url",
        "extra": "notes",
        "notes": "notes",
        "grouping": "category",
        "folder": "category",
        "category": "category",
        "tags": "tags",
    }

    def serialize_rows(self, rows: Iterable[Dict[str, str]]) -> str:
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=self.fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: str(row.get(field, "") or "") for field in self.fieldnames})
        return output.getvalue()

    def parse_rows(self, payload: str) -> List[Dict[str, str]]:
        reader = csv.DictReader(io.StringIO(payload))
        if not reader.fieldnames:
            return []
        return [
            self._normalize_row(row)
            for row in reader
        ]

    def _normalize_row(self, row: Dict[str, str]) -> Dict[str, str]:
        normalized = {field: "" for field in self.fieldnames}
        for key, value in row.items():
            target = self.aliases.get(str(key or "").strip().lower())
            if target:
                normalized[target] = str(value or "")
        return normalized
