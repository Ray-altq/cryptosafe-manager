import json
import os
import subprocess
import sys
import time
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tests.test_clipboard import _contains_secret_in_process_memory, _derive_memory_dump_secret


class Sprint4Test3MemorySecurity(unittest.TestCase):
    def test_password_is_not_found_as_plaintext_in_clipboard_process_memory_dump(self):
        helper_path = Path(__file__).with_name("clipboard_memory_dump_helper.py")
        if not helper_path.exists():
            self.fail("Missing clipboard memory dump helper script")

        seed_bytes = f"sprint4-test3-{uuid.uuid4().hex}-{time.time_ns()}".encode("utf-8")
        expected_secret = _derive_memory_dump_secret(seed_bytes)
        process = subprocess.Popen(
            [sys.executable, str(helper_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        try:
            process.stdin.write(seed_bytes + b"\n")
            process.stdin.flush()
            process.stdin.close()

            ready_line = process.stdout.readline().decode("utf-8", errors="replace").strip()
            if not ready_line:
                stderr_output = process.stderr.read().decode("utf-8", errors="replace")
                self.fail(f"Helper did not become ready for memory dump test: {stderr_output}")

            ready_payload = json.loads(ready_line)
            self.assertEqual(ready_payload.get("status"), "ready")
            self.assertFalse(
                _contains_secret_in_process_memory(int(ready_payload["pid"]), expected_secret),
                "Sprint 4 TEST-3 failed: plaintext password was found in process memory dump",
            )
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()


if __name__ == "__main__":
    unittest.main()
