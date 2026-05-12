import csv
import io
import json
from datetime import datetime, timezone
from typing import Iterable


def export_logs_to_json(logs: Iterable, public_key: str = "", exporter: str = "CryptoSafe Manager") -> str:
    payload = {
        "metadata": {
            "exported_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "exporter": exporter,
            "public_key": public_key,
        },
        "entries": [serialize_log(log) for log in logs],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)


def export_logs_to_csv(logs: Iterable) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=[
            "sequence_number",
            "timestamp",
            "event_type",
            "severity",
            "user_id",
            "source",
            "entry_id",
            "details",
            "previous_hash",
            "entry_hash",
            "signature",
            "public_key",
        ],
    )
    writer.writeheader()
    for log in logs:
        writer.writerow(serialize_log(log))
    return buffer.getvalue()


def export_logs_to_pdf(logs: Iterable, title: str = "CryptoSafe Audit Report") -> bytes:
    lines = [title, ""]
    for log in logs:
        payload = serialize_log(log)
        lines.append(
            f"{payload['sequence_number']} | {payload['timestamp']} | {payload['event_type']} | {payload['severity']}"
        )
        lines.append(f"source={payload['source']} user={payload['user_id']} entry_id={payload['entry_id']}")
        lines.append(f"details={payload['details']}")
        lines.append("")
    content = "\n".join(lines).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    pdf = (
        "%PDF-1.4\n"
        "1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n"
        "2 0 obj<< /Type /Pages /Count 1 /Kids [3 0 R] >>endobj\n"
        "3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>endobj\n"
        f"4 0 obj<< /Length {len(content) + 20} >>stream\nBT /F1 10 Tf 40 760 Td ({content}) Tj ET\nendstream endobj\n"
        "xref\n0 5\n0000000000 65535 f \n"
        "trailer<< /Size 5 /Root 1 0 R >>\nstartxref\n0\n%%EOF"
    )
    return pdf.encode("utf-8")


def serialize_log(log) -> dict:
    return {
        "sequence_number": getattr(log, "sequence_number", getattr(log, "id", "")),
        "timestamp": getattr(log, "timestamp", ""),
        "event_type": getattr(log, "event_type", getattr(log, "action", "")),
        "severity": getattr(log, "severity", "INFO"),
        "user_id": getattr(log, "user_id", "local-user"),
        "source": getattr(log, "source", "unknown"),
        "entry_id": getattr(log, "entry_id", None),
        "details": getattr(log, "details", ""),
        "previous_hash": getattr(log, "previous_hash", ""),
        "entry_hash": getattr(log, "entry_hash", ""),
        "signature": getattr(log, "signature", ""),
        "public_key": getattr(log, "public_key", ""),
    }
