from __future__ import annotations

from typing import Optional


class ClipboardMonitor:
    def __init__(self, adapter, service):
        self.adapter = adapter
        self.service = service
        self._last_observed: Optional[str] = None
        self._pending_mismatch_value: Optional[str] = None
        self._pending_mismatch_count = 0

    def _get_mismatch_threshold(self) -> int:
        try:
            security_level = str(self.service.get_settings().get("security_level", "basic")).strip().lower()
        except Exception:
            security_level = "basic"
        if security_level == "basic":
            return 2
        return 1

    def _reset_pending_mismatch(self):
        self._pending_mismatch_value = None
        self._pending_mismatch_count = 0

    def poll(self):
        if hasattr(self.service, "uses_system_clipboard") and not self.service.uses_system_clipboard():
            self._reset_pending_mismatch()
            self._last_observed = None
            return
        observed = self.adapter.get_clipboard_content()
        active = self.service.has_active_content()

        if not active:
            self._reset_pending_mismatch()
            self._last_observed = observed
            return

        if observed is None:
            return

        if self.service.matches_current_text(observed):
            self._reset_pending_mismatch()
            self._last_observed = observed
            return

        if observed == self._pending_mismatch_value:
            self._pending_mismatch_count += 1
        else:
            self._pending_mismatch_value = observed
            self._pending_mismatch_count = 1

        mismatch_threshold = self._get_mismatch_threshold()
        if self._pending_mismatch_count >= mismatch_threshold:
            reason = "external_clear" if observed == "" else "external_change"
            self.service.register_suspicious_activity(reason=reason, observed_value=observed)
            self._reset_pending_mismatch()
        self._last_observed = observed
