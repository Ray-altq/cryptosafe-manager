import gc
import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.clipboard import ClipboardService
from src.core.events import EventBus
from src.core.state_manager import StateManager
from src.database.db import Database


class NonRetainingClipboardAdapter:
    def copy_to_clipboard(self, data: str) -> bool:
        return True

    def clear_clipboard(self) -> bool:
        return True

    def get_clipboard_content(self):
        return None


def _wipe_buffer(buffer: bytearray):
    for index in range(len(buffer)):
        buffer[index] = 0


def _read_secret_from_stdin() -> bytearray:
    secret_input = bytearray()
    while True:
        chunk = sys.stdin.buffer.read(1)
        if not chunk or chunk == b"\n":
            break
        if chunk != b"\r":
            secret_input.extend(chunk)
    return secret_input


def _derive_password_bytes(seed_bytes: bytearray) -> bytearray:
    alphabet = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    state = 0xA5A5A5A5
    for value in seed_bytes:
        state = ((state << 5) ^ (state >> 2) ^ value) & 0xFFFFFFFF

    derived = bytearray(b"TEST3-")
    for _index in range(32):
        state = (1664525 * state + 1013904223) & 0xFFFFFFFF
        derived.append(alphabet[state % len(alphabet)])
    return derived


def main():
    seed_input = _read_secret_from_stdin()
    if not seed_input:
        raise SystemExit(2)
    secret_input = _derive_password_bytes(seed_input)
    _wipe_buffer(seed_input)

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        database = Database(str(temp_path / "clipboard-memory-dump.db"))
        try:
            state_manager = StateManager()
            state_manager.unlock()
            service = ClipboardService(
                NonRetainingClipboardAdapter(),
                database=database,
                state_manager=state_manager,
                bus=EventBus(),
            )
            service.configure(delivery_mode="memory_only")
            service.copy_secret_bytes(
                secret_input,
                data_type="password",
                source_label="Memory dump validation",
                wipe_input=True,
            )
            _wipe_buffer(secret_input)
            gc.collect()
            sys.stdout.write(json.dumps({"pid": os.getpid(), "status": "ready"}) + "\n")
            sys.stdout.flush()
            time.sleep(10)
            service.clear(reason="manual")
            gc.collect()
        finally:
            database.close()


if __name__ == "__main__":
    main()
