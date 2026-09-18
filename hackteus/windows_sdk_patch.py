"""Polyfills Windows para o cursor-sdk (Python < 3.12 / pipes)."""

from __future__ import annotations

import os
import sys


def apply_windows_sdk_patches() -> None:
    if sys.platform != "win32":
        return
    # os.get_blocking / set_blocking só existem no Windows a partir do 3.12
    if not hasattr(os, "get_blocking"):
        os.get_blocking = lambda fd: True  # type: ignore[attr-defined, assignment]
    if not hasattr(os, "set_blocking"):

        def _set_blocking(fd: int, blocking: bool) -> None:
            return None

        os.set_blocking = _set_blocking  # type: ignore[attr-defined, assignment]
