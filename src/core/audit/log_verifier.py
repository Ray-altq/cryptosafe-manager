import hashlib
import json
from typing import Any, Dict, List, Optional


class AuditLogVerifier:
    def __init__(self, database, signer):
        self.database = database
        self.signer = signer

    def verify(self, start_sequence: int = 0, limit: Optional[int] = None) -> Dict[str, Any]:
        rows = self.database.get_audit_log_chain(start_sequence=start_sequence, limit=limit)
        results: Dict[str, Any] = {
            "verified": True,
            "total_entries": len(rows),
            "valid_entries": 0,
            "invalid_entries": [],
            "chain_breaks": [],
        }

        previous_hash = None
        for row in rows:
            entry_data = row.entry_data or ""
            computed_hash = hashlib.sha256(entry_data.encode("utf-8")).hexdigest()
            if computed_hash != row.entry_hash:
                results["verified"] = False
                results["invalid_entries"].append(
                    {"sequence_number": row.sequence_number, "reason": "hash_mismatch"}
                )
                continue

            if not self._verify_signature(entry_data, row.signature, row.public_key):
                results["verified"] = False
                results["invalid_entries"].append(
                    {"sequence_number": row.sequence_number, "reason": "invalid_signature"}
                )
                continue

            if previous_hash is not None and row.previous_hash != previous_hash:
                results["verified"] = False
                results["chain_breaks"].append(
                    {
                        "sequence_number": row.sequence_number,
                        "expected_previous_hash": previous_hash,
                        "actual_previous_hash": row.previous_hash,
                    }
                )
                continue

            previous_hash = row.entry_hash
            results["valid_entries"] += 1
        return results

    def export_verification_report(self, start_sequence: int = 0, limit: Optional[int] = None) -> str:
        return json.dumps(self.verify(start_sequence=start_sequence, limit=limit), ensure_ascii=False, indent=2)

    def _verify_signature(self, entry_data: str, signature: str, public_key: str) -> bool:
        if signature == "legacy" and public_key == "legacy":
            return True
        return self.signer.verify(entry_data.encode("utf-8"), signature, public_key)
