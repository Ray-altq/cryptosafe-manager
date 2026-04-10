import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.clipboard import platform_adapter


class FakeRoot:
    def __init__(self):
        self.clipboard_value = ""
        self.update_calls = 0

    def clipboard_clear(self):
        self.clipboard_value = ""

    def clipboard_append(self, value):
        self.clipboard_value = value

    def clipboard_get(self):
        return self.clipboard_value

    def update(self):
        self.update_calls += 1


class FakeProcessResult:
    def __init__(self, returncode=0, stdout=""):
        self.returncode = returncode
        self.stdout = stdout


class TestCompositeClipboardAdapter(unittest.TestCase):
    def test_copy_and_clear_return_true_when_any_adapter_succeeds(self):
        class AdapterA:
            def copy_to_clipboard(self, _data):
                return False

            def clear_clipboard(self):
                return False

            def get_clipboard_content(self):
                return None

        class AdapterB:
            def copy_to_clipboard(self, _data):
                return True

            def clear_clipboard(self):
                return True

            def get_clipboard_content(self):
                return "value"

        adapter = platform_adapter.CompositeClipboardAdapter([AdapterA(), AdapterB()])

        self.assertTrue(adapter.copy_to_clipboard("secret"))
        self.assertTrue(adapter.clear_clipboard())
        self.assertEqual(adapter.get_clipboard_content(), "value")


class TestCreatePlatformAdapter(unittest.TestCase):
    def test_create_platform_adapter_uses_windows_and_tk_fallbacks(self):
        root = FakeRoot()
        windows_adapter = object()
        tk_adapter = object()

        with patch.object(platform_adapter.os, "name", "nt"), patch.object(
            platform_adapter, "WindowsClipboardAdapter", return_value=windows_adapter
        ), patch.object(platform_adapter, "TkClipboardAdapter", return_value=tk_adapter), patch.object(
            platform_adapter, "PyperclipClipboardAdapter", side_effect=platform_adapter.ClipboardAdapterError("missing")
        ):
            adapter = platform_adapter.create_platform_adapter(root)

        self.assertIsInstance(adapter, platform_adapter.CompositeClipboardAdapter)
        self.assertEqual(adapter.adapters, [windows_adapter, tk_adapter])

    def test_create_platform_adapter_uses_pyperclip_when_platform_specific_adapter_missing(self):
        pyperclip_adapter = object()

        with patch.object(platform_adapter.os, "name", "posix"), patch.object(
            platform_adapter.sys, "platform", "unknown"
        ), patch.object(platform_adapter, "PyperclipClipboardAdapter", return_value=pyperclip_adapter):
            adapter = platform_adapter.create_platform_adapter()

        self.assertIsInstance(adapter, platform_adapter.CompositeClipboardAdapter)
        self.assertEqual(adapter.adapters, [pyperclip_adapter])

    def test_create_platform_adapter_raises_when_no_adapter_available(self):
        with patch.object(platform_adapter.os, "name", "posix"), patch.object(
            platform_adapter.sys, "platform", "unknown"
        ), patch.object(
            platform_adapter, "PyperclipClipboardAdapter", side_effect=platform_adapter.ClipboardAdapterError("missing")
        ):
            with self.assertRaises(platform_adapter.ClipboardAdapterError):
                platform_adapter.create_platform_adapter()

    def test_create_platform_adapter_passes_linux_selection_mode(self):
        linux_adapter = object()

        with patch.object(platform_adapter.os, "name", "posix"), patch.object(
            platform_adapter.sys, "platform", "linux"
        ), patch.object(
            platform_adapter, "LinuxClipboardAdapter", return_value=linux_adapter
        ) as linux_factory, patch.object(
            platform_adapter, "PyperclipClipboardAdapter", side_effect=platform_adapter.ClipboardAdapterError("missing")
        ):
            adapter = platform_adapter.create_platform_adapter(linux_selection_mode="primary")

        self.assertIsInstance(adapter, platform_adapter.CompositeClipboardAdapter)
        self.assertEqual(adapter.adapters, [linux_adapter])
        linux_factory.assert_called_once_with(selection_mode="primary")


class TestPlatformAdapters(unittest.TestCase):
    def test_tk_clipboard_adapter_roundtrip(self):
        root = FakeRoot()
        adapter = platform_adapter.TkClipboardAdapter(root)

        self.assertTrue(adapter.copy_to_clipboard("Secret!123"))
        self.assertEqual(adapter.get_clipboard_content(), "Secret!123")
        self.assertTrue(adapter.clear_clipboard())
        self.assertEqual(adapter.get_clipboard_content(), "")
        self.assertEqual(root.update_calls, 2)

    def test_linux_clipboard_adapter_falls_back_to_next_command_on_missing_binary(self):
        calls = []

        def fake_run(command, input=None, text=None, capture_output=None, check=None):
            calls.append(command)
            if command[0] == "wl-copy":
                raise FileNotFoundError("wl-copy not found")
            return FakeProcessResult(returncode=0)

        adapter = platform_adapter.LinuxClipboardAdapter()

        with patch.object(platform_adapter.subprocess, "run", side_effect=fake_run):
            result = adapter.copy_to_clipboard("Secret!123")

        self.assertTrue(result)
        self.assertEqual(calls[0], ["wl-copy"])
        self.assertEqual(calls[1], ["xclip", "-selection", "clipboard"])

    def test_linux_clipboard_adapter_reads_from_first_successful_backend(self):
        calls = []

        def fake_run(command, text=None, capture_output=None, check=None):
            calls.append(command)
            if command[0] == "wl-paste":
                raise FileNotFoundError("wl-paste not found")
            return FakeProcessResult(returncode=0, stdout="clipboard text")

        adapter = platform_adapter.LinuxClipboardAdapter()

        with patch.object(platform_adapter.subprocess, "run", side_effect=fake_run):
            value = adapter.get_clipboard_content()

        self.assertEqual(value, "clipboard text")
        self.assertEqual(calls[0], ["wl-paste", "-n"])
        self.assertEqual(calls[1], ["xclip", "-selection", "clipboard", "-o"])

    def test_linux_clipboard_adapter_uses_primary_selection_commands(self):
        calls = []

        def fake_run(command, input=None, text=None, capture_output=None, check=None):
            calls.append(command)
            return FakeProcessResult(returncode=0)

        adapter = platform_adapter.LinuxClipboardAdapter(selection_mode="primary")

        with patch.object(platform_adapter.subprocess, "run", side_effect=fake_run):
            result = adapter.copy_to_clipboard("Secret!123")

        self.assertTrue(result)
        self.assertEqual(calls[0], ["xclip", "-selection", "primary"])

    def test_linux_clipboard_adapter_reads_primary_selection_when_requested(self):
        calls = []

        def fake_run(command, text=None, capture_output=None, check=None):
            calls.append(command)
            return FakeProcessResult(returncode=0, stdout="primary text")

        adapter = platform_adapter.LinuxClipboardAdapter(selection_mode="primary")

        with patch.object(platform_adapter.subprocess, "run", side_effect=fake_run):
            value = adapter.get_clipboard_content()

        self.assertEqual(value, "primary text")
        self.assertEqual(calls[0], ["xclip", "-selection", "primary", "-o"])

    def test_linux_clipboard_adapter_writes_both_clipboard_and_primary_when_requested(self):
        calls = []

        def fake_run(command, input=None, text=None, capture_output=None, check=None):
            calls.append(command)
            return FakeProcessResult(returncode=0)

        adapter = platform_adapter.LinuxClipboardAdapter(selection_mode="both")

        with patch.object(platform_adapter.subprocess, "run", side_effect=fake_run):
            result = adapter.copy_to_clipboard("Secret!123")

        self.assertTrue(result)
        self.assertEqual(calls[0], ["wl-copy"])
        self.assertIn(["xclip", "-selection", "clipboard"], calls)
        self.assertIn(["xclip", "-selection", "primary"], calls)


if __name__ == "__main__":
    unittest.main()
