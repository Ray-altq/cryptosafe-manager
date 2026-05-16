import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from .exceptions import ImportValidationError


QR_PAYLOAD_VERSION = 1
QR_PAYLOAD_TTL_SECONDS = 5 * 60


@dataclass(frozen=True)
class KeyExchangePayload:
    identifier: str
    public_key: str
    fingerprint: str
    nonce: str
    created_at: str
    expires_at: str
    checksum: str


class KeyExchangeService:
    def __init__(self, database=None):
        self.database = database

    def fingerprint_public_key(self, public_key: str) -> str:
        digest = hashlib.sha256(str(public_key).encode("utf-8")).hexdigest().upper()
        return ":".join(digest[index:index + 2] for index in range(0, 32, 2))

    def build_qr_payload(self, *, identifier: str, public_key: str) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        payload = {
            "type": "cryptosafe_key_exchange",
            "version": QR_PAYLOAD_VERSION,
            "identifier": str(identifier),
            "public_key": str(public_key),
            "fingerprint": self.fingerprint_public_key(public_key),
            "nonce": base64.urlsafe_b64encode(os.urandom(16)).decode("ascii").rstrip("="),
            "created_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=QR_PAYLOAD_TTL_SECONDS)).isoformat(),
        }
        payload["checksum"] = self._checksum(payload)
        return payload

    def serialize_qr_payload(self, payload: Dict[str, Any]) -> str:
        self.validate_qr_payload(payload)
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    def parse_qr_payload(self, raw_payload: str) -> KeyExchangePayload:
        try:
            payload = json.loads(raw_payload)
        except json.JSONDecodeError as exc:
            raise ImportValidationError("QR payload is not valid JSON") from exc
        self.validate_qr_payload(payload)
        return KeyExchangePayload(
            identifier=str(payload["identifier"]),
            public_key=str(payload["public_key"]),
            fingerprint=str(payload["fingerprint"]),
            nonce=str(payload["nonce"]),
            created_at=str(payload["created_at"]),
            expires_at=str(payload["expires_at"]),
            checksum=str(payload["checksum"]),
        )

    def remember_contact(self, payload: KeyExchangePayload, *, name: str = "") -> int | None:
        if self.database is None:
            return None
        return self.database.upsert_contact(
            name=name or payload.identifier,
            identifier=payload.identifier,
            public_key=payload.public_key,
            key_fingerprint=payload.fingerprint,
            last_used_at=datetime.now(timezone.utc),
        )

    def validate_qr_payload(self, payload: Dict[str, Any]):
        if not isinstance(payload, dict):
            raise ImportValidationError("QR payload must be an object")
        required_fields = {
            "type",
            "version",
            "identifier",
            "public_key",
            "fingerprint",
            "nonce",
            "created_at",
            "expires_at",
            "checksum",
        }
        missing = sorted(required_fields.difference(payload))
        if missing:
            raise ImportValidationError(f"QR payload is missing fields: {', '.join(missing)}")
        if payload["type"] != "cryptosafe_key_exchange":
            raise ImportValidationError("QR payload type is not supported")
        if int(payload["version"]) != QR_PAYLOAD_VERSION:
            raise ImportValidationError("QR payload version is not supported")
        if self.fingerprint_public_key(str(payload["public_key"])) != str(payload["fingerprint"]):
            raise ImportValidationError("QR public key fingerprint does not match")
        if not hmac_compare(str(payload["checksum"]), self._checksum(payload)):
            raise ImportValidationError("QR payload checksum does not match")

        expires_at = datetime.fromisoformat(str(payload["expires_at"]))
        if expires_at < datetime.now(timezone.utc):
            raise ImportValidationError("QR payload has expired")

    def _checksum(self, payload: Dict[str, Any]) -> str:
        unsigned = {key: value for key, value in payload.items() if key != "checksum"}
        encoded = json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def hmac_compare(left: str, right: str) -> bool:
    return hmac.compare_digest(str(left), str(right))
