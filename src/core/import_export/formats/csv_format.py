import csv
import io
from typing import Dict, Iterable, List


class CSVVaultFormat:
    name = "csv"
    fieldnames = ["title", "username", "password", "url", "notes", "category", "tags"]

    def serialize_rows(self, rows: Iterable[Dict[str, str]]) -> str:
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=self.fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: str(row.get(field, "") or "") for field in self.fieldnames})
        return output.getvalue()

    def parse_rows(self, payload: str) -> List[Dict[str, str]]:
        reader = csv.DictReader(io.StringIO(payload))
        return [
            {field: str(row.get(field, "") or "") for field in self.fieldnames}
            for row in reader
        ]
