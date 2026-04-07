from __future__ import annotations

from typing import Optional


class ClipboardMonitor:
    def __init__(self, adapter, service):
        self.adapter = adapter
        self.service = service
        self._last_observed: Optional[str] = None

    def poll(self):
        observed = self.adapter.get_clipboard_content()
        active = self.service.has_active_content()

        if not active:
            self._last_observed = observed
            return

        if observed is None:
            return

        if not self.service.matches_current_text(observed):
            self.service.register_suspicious_activity(reason="external_change", observed_value=observed)
        self._last_observed = observed
