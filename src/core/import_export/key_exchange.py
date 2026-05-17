import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from ..events import Event, EventType
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
    def __init__(self, database=None, event_bus=None):
        self.database = database
        self.event_bus = event_bus
        self._seen_nonces: set[str] = set()

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
        self._publish(EventType.KEY_EXCHANGE_CREATED, {"identifier": payload["identifier"], "fingerprint": payload["fingerprint"]})
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
        self._remember_nonce(str(payload["nonce"]))
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
        contact_id = self.database.upsert_contact(
            name=name or payload.identifier,
            identifier=payload.identifier,
            public_key=payload.public_key,
            key_fingerprint=payload.fingerprint,
            last_used_at=datetime.now(timezone.utc),
        )
        self._publish(EventType.KEY_EXCHANGE_IMPORTED, {"identifier": payload.identifier, "fingerprint": payload.fingerprint})
        return contact_id

    def rotate_contact_key(self, *, identifier: str, public_key: str, name: str = "") -> int | None:
        payload = self.build_qr_payload(identifier=identifier, public_key=public_key)
        parsed = self.parse_qr_payload(self.serialize_qr_payload(payload))
        return self.remember_contact(parsed, name=name)

    def revoke_contact(self, identifier: str) -> bool:
        if self.database is None:
            return False
        return self.database.revoke_contact(identifier)

    def split_qr_payload(self, raw_payload: str, *, max_chunk_size: int = 512) -> List[str]:
        payload = str(raw_payload)
        chunk_size = max(128, int(max_chunk_size))
        chunks = [payload[index:index + chunk_size] for index in range(0, len(payload), chunk_size)] or [""]
        transfer_id = base64.urlsafe_b64encode(os.urandom(8)).decode("ascii").rstrip("=")
        full_checksum = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return [
            json.dumps(
                {
                    "type": "cryptosafe_qr_chunk",
                    "version": QR_PAYLOAD_VERSION,
                    "transfer_id": transfer_id,
                    "index": index,
                    "total": len(chunks),
                    "checksum": full_checksum,
                    "data": chunk,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            for index, chunk in enumerate(chunks)
        ]

    def assemble_qr_chunks(self, raw_chunks: List[str]) -> str:
        chunks = []
        for raw_chunk in raw_chunks:
            try:
                parsed = json.loads(raw_chunk)
            except json.JSONDecodeError as exc:
                raise ImportValidationError("QR chunk is not valid JSON") from exc
            if parsed.get("type") != "cryptosafe_qr_chunk":
                raise ImportValidationError("QR chunk type is not supported")
            chunks.append(parsed)
        if not chunks:
            raise ImportValidationError("QR chunks are empty")
        transfer_ids = {chunk.get("transfer_id") for chunk in chunks}
        totals = {int(chunk.get("total", 0)) for chunk in chunks}
        checksums = {chunk.get("checksum") for chunk in chunks}
        if len(transfer_ids) != 1 or len(totals) != 1 or len(checksums) != 1:
            raise ImportValidationError("QR chunks belong to different transfers")
        total = totals.pop()
        if total != len(chunks):
            raise ImportValidationError("QR chunks are incomplete")
        ordered = sorted(chunks, key=lambda chunk: int(chunk.get("index", -1)))
        if [int(chunk.get("index", -1)) for chunk in ordered] != list(range(total)):
            raise ImportValidationError("QR chunks are out of sequence")
        payload = "".join(str(chunk.get("data", "")) for chunk in ordered)
        expected_checksum = checksums.pop()
        if not hmac.compare_digest(hashlib.sha256(payload.encode("utf-8")).hexdigest(), str(expected_checksum)):
            raise ImportValidationError("QR chunk checksum does not match")
        return payload

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
        if str(payload["nonce"]) in self._seen_nonces:
            raise ImportValidationError("QR payload nonce has already been used")

    def _checksum(self, payload: Dict[str, Any]) -> str:
        unsigned = {key: value for key, value in payload.items() if key != "checksum"}
        encoded = json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def _remember_nonce(self, nonce: str):
        self._seen_nonces.add(str(nonce))

    def _publish(self, event_type: EventType, data: Dict[str, Any]):
        if self.event_bus is not None:
            self.event_bus.publish(Event(event_type, data))


def hmac_compare(left: str, right: str) -> bool:
    return hmac.compare_digest(str(left), str(right))
