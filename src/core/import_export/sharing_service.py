import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from .models import SharePermissions


class SharingService:
    def __init__(self, entry_manager, database=None, event_bus=None):
        self.entry_manager = entry_manager
        self.database = database
        self.event_bus = event_bus

    def build_share_metadata(
        self,
        *,
        entry_id: int,
        recipient: str,
        encryption_method: str,
        permissions: SharePermissions,
    ) -> Dict[str, Any]:
        share_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=permissions.as_dict()["expires_in_days"])
        metadata = {
            "share_id": share_id,
            "original_entry_id": int(entry_id),
            "recipient_info": str(recipient),
            "encryption_method": str(encryption_method),
            "permissions": permissions.as_dict(),
            "shared_at": now,
            "expires_at": expires_at,
        }
        metadata["package_checksum"] = self._metadata_checksum(metadata)
        return metadata

    def remember_share(self, metadata: Dict[str, Any]):
        if self.database is None:
            return
        self.database.add_shared_entry(
            share_id=metadata["share_id"],
            original_entry_id=metadata["original_entry_id"],
            encryption_method=metadata["encryption_method"],
            recipient_info=metadata["recipient_info"],
            permissions=metadata["permissions"],
            shared_at=metadata["shared_at"],
            expires_at=metadata["expires_at"],
            package_checksum=metadata.get("package_checksum", ""),
        )

    def _metadata_checksum(self, metadata: Dict[str, Any]) -> str:
        checksum_payload = "|".join(
            [
                str(metadata.get("share_id", "")),
                str(metadata.get("original_entry_id", "")),
                str(metadata.get("recipient_info", "")),
                str(metadata.get("encryption_method", "")),
            ]
        )
        return hashlib.sha256(checksum_payload.encode("utf-8")).hexdigest()
