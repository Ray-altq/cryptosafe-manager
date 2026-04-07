from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from abc import ABC, abstractmethod
from typing import Optional


class ClipboardAdapterError(RuntimeError):
    pass


class ClipboardAdapter(ABC):
    @abstractmethod
    def copy_to_clipboard(self, data: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def clear_clipboard(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def get_clipboard_content(self) -> Optional[str]:
        raise NotImplementedError


class CompositeClipboardAdapter(ClipboardAdapter):
    def __init__(self, adapters: list[ClipboardAdapter]):
        self.adapters = adapters

    def copy_to_clipboard(self, data: str) -> bool:
        result = False
        for adapter in self.adapters:
            result = adapter.copy_to_clipboard(data) or result
        return result

    def clear_clipboard(self) -> bool:
        result = False
        for adapter in self.adapters:
            result = adapter.clear_clipboard() or result
        return result

    def get_clipboard_content(self) -> Optional[str]:
        for adapter in self.adapters:
            value = adapter.get_clipboard_content()
            if value is not None:
                return value
        return None


class WindowsClipboardAdapter(ClipboardAdapter):
    def copy_to_clipboard(self, data: str) -> bool:
        try:
            import win32clipboard  # type: ignore

            win32clipboard.OpenClipboard()
            win32clipboard.EmptyClipboard()
            win32clipboard.SetClipboardText(data, win32clipboard.CF_UNICODETEXT)
            win32clipboard.CloseClipboard()
            return True
        except Exception:
            return False

    def clear_clipboard(self) -> bool:
        try:
            import win32clipboard  # type: ignore

            win32clipboard.OpenClipboard()
            win32clipboard.EmptyClipboard()
            win32clipboard.CloseClipboard()
            return True
        except Exception:
            try:
                user32 = ctypes.windll.user32
                if not user32.OpenClipboard(None):
                    return False
                user32.EmptyClipboard()
                user32.CloseClipboard()
                return True
            except Exception:
                return False

    def get_clipboard_content(self) -> Optional[str]:
        try:
            import win32clipboard  # type: ignore

            win32clipboard.OpenClipboard()
            try:
                if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_UNICODETEXT):
                    return win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
            finally:
                win32clipboard.CloseClipboard()
        except Exception:
            return None
        return None


class MacOSClipboardAdapter(ClipboardAdapter):
    def copy_to_clipboard(self, data: str) -> bool:
        try:
            process = subprocess.run(["pbcopy"], input=data, text=True, capture_output=True, check=False)
            return process.returncode == 0
        except Exception:
            return False

    def clear_clipboard(self) -> bool:
        return self.copy_to_clipboard("")

    def get_clipboard_content(self) -> Optional[str]:
        try:
            process = subprocess.run(["pbpaste"], text=True, capture_output=True, check=False)
            if process.returncode == 0:
                return process.stdout
        except Exception:
            return None
        return None


class LinuxClipboardAdapter(ClipboardAdapter):
    def copy_to_clipboard(self, data: str) -> bool:
        commands = [["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]]
        for command in commands:
            try:
                process = subprocess.run(command, input=data, text=True, capture_output=True, check=False)
                if process.returncode == 0:
                    return True
            except FileNotFoundError:
                continue
            except Exception:
                return False
        return False

    def clear_clipboard(self) -> bool:
        return self.copy_to_clipboard("")

    def get_clipboard_content(self) -> Optional[str]:
        commands = [["wl-paste", "-n"], ["xclip", "-selection", "clipboard", "-o"], ["xsel", "--clipboard", "--output"]]
        for command in commands:
            try:
                process = subprocess.run(command, text=True, capture_output=True, check=False)
                if process.returncode == 0:
                    return process.stdout
            except FileNotFoundError:
                continue
            except Exception:
                return None
        return None


class PyperclipClipboardAdapter(ClipboardAdapter):
    def __init__(self):
        try:
            import pyperclip  # type: ignore
        except Exception as error:
            raise ClipboardAdapterError("Pyperclip недоступен") from error
        self.pyperclip = pyperclip

    def copy_to_clipboard(self, data: str) -> bool:
        try:
            self.pyperclip.copy(data)
            return True
        except Exception:
            return False

    def clear_clipboard(self) -> bool:
        return self.copy_to_clipboard("")

    def get_clipboard_content(self) -> Optional[str]:
        try:
            return self.pyperclip.paste()
        except Exception:
            return None


class TkClipboardAdapter(ClipboardAdapter):
    def __init__(self, root):
        self.root = root

    def copy_to_clipboard(self, data: str) -> bool:
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(data)
            self.root.update()
            return True
        except Exception:
            return False

    def clear_clipboard(self) -> bool:
        try:
            self.root.clipboard_clear()
            self.root.update()
            return True
        except Exception:
            return False

    def get_clipboard_content(self) -> Optional[str]:
        try:
            return self.root.clipboard_get()
        except Exception:
            return None


def create_platform_adapter(root=None) -> ClipboardAdapter:
    adapters: list[ClipboardAdapter] = []

    if os.name == "nt":
        adapters.append(WindowsClipboardAdapter())
    elif sys.platform == "darwin":
        adapters.append(MacOSClipboardAdapter())
    elif sys.platform.startswith("linux"):
        adapters.append(LinuxClipboardAdapter())

    if root is not None:
        adapters.append(TkClipboardAdapter(root))

    try:
        adapters.append(PyperclipClipboardAdapter())
    except ClipboardAdapterError:
        pass

    if not adapters:
        raise ClipboardAdapterError("Не удалось подобрать адаптер буфера обмена")
    return CompositeClipboardAdapter(adapters)
