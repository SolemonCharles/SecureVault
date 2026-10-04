"""Clipboard helper that keeps secrets out of Windows clipboard history/cloud sync.

On Windows we write the text plus the special formats that tell Win+V history
and Cloud Clipboard to ignore it. Elsewhere we fall back to Tk's clipboard.
"""
from __future__ import annotations

import sys
import time

_IS_WIN = sys.platform == "win32"

if _IS_WIN:
    import ctypes
    from ctypes import wintypes

    _u32 = ctypes.WinDLL("user32", use_last_error=True)
    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _u32.OpenClipboard.argtypes = [wintypes.HWND]
    _u32.OpenClipboard.restype = wintypes.BOOL
    _u32.CloseClipboard.restype = wintypes.BOOL
    _u32.EmptyClipboard.restype = wintypes.BOOL
    _u32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    _u32.SetClipboardData.restype = wintypes.HANDLE
    _u32.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
    _u32.RegisterClipboardFormatW.restype = wintypes.UINT
    _u32.GetClipboardSequenceNumber.restype = wintypes.DWORD
    _k32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    _k32.GlobalAlloc.restype = wintypes.HANDLE
    _k32.GlobalLock.argtypes = [wintypes.HANDLE]
    _k32.GlobalLock.restype = ctypes.c_void_p
    _k32.GlobalUnlock.argtypes = [wintypes.HANDLE]
    _k32.GlobalFree.argtypes = [wintypes.HANDLE]

    _CF_UNICODETEXT = 13
    _GMEM_MOVEABLE = 0x0002
    _PRIVATE_FORMATS = {
        "ExcludeClipboardContentFromMonitorProcessing": b"\x00\x00\x00\x00",
        "CanIncludeInClipboardHistory": b"\x00\x00\x00\x00",  # DWORD 0
        "CanUploadToCloudClipboard": b"\x00\x00\x00\x00",     # DWORD 0
    }

    def _open() -> None:
        for _ in range(10):  # another app may briefly hold the clipboard
            if _u32.OpenClipboard(None):
                return
            time.sleep(0.02)
        raise OSError("Could not open the clipboard")

    def _put(fmt: int, data: bytes) -> None:
        h = _k32.GlobalAlloc(_GMEM_MOVEABLE, len(data))
        if not h:
            raise MemoryError("GlobalAlloc failed")
        p = _k32.GlobalLock(h)
        ctypes.memmove(p, data, len(data))
        _k32.GlobalUnlock(h)
        if not _u32.SetClipboardData(fmt, h):
            _k32.GlobalFree(h)
            raise OSError("SetClipboardData failed")


class SecureClipboard:
    def __init__(self, tk_root):
        self._root = tk_root
        self._seq = None

    def copy(self, text: str) -> None:
        if _IS_WIN:
            _open()
            try:
                _u32.EmptyClipboard()
                _put(_CF_UNICODETEXT, (text + "\0").encode("utf-16-le"))
                for name, data in _PRIVATE_FORMATS.items():
                    _put(_u32.RegisterClipboardFormatW(name), data)
            finally:
                _u32.CloseClipboard()
            self._seq = _u32.GetClipboardSequenceNumber()
        else:
            self._root.clipboard_clear()
            self._root.clipboard_append(text)
            self._seq = text

    def clear_if_ours(self) -> None:
        """Clear only if the user hasn't copied something else since."""
        if self._seq is None:
            return
        if _IS_WIN:
            if _u32.GetClipboardSequenceNumber() == self._seq:
                _open()
                try:
                    _u32.EmptyClipboard()
                finally:
                    _u32.CloseClipboard()
        else:
            try:
                if self._root.clipboard_get() == self._seq:
                    self._root.clipboard_clear()
            except Exception:
                pass
        self._seq = None
