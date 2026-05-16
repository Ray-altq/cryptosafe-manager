import json
from typing import Any, Dict


class NativeJSONFormat:
    name = "encrypted_json"
    version = "1.0"

    def serialize_header(self, package: Dict[str, Any]) -> str:
        return json.dumps(package, ensure_ascii=False, sort_keys=True)

    def deserialize_header(self, payload: str) -> Dict[str, Any]:
        parsed = json.loads(payload)
        if not isinstance(parsed, dict):
            raise ValueError("Native JSON export must be a JSON object")
        return parsed

    def is_native_export(self, payload: Dict[str, Any]) -> bool:
        return bool(payload.get("cryptosafe_export"))
