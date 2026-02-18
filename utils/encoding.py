#!/usr/bin/env python3
"""
Encoding helpers used by workflow entrypoints.
"""

from __future__ import annotations

import os
import sys


def ensure_utf8_stdio() -> None:
    """Best-effort UTF-8 setup for stdout/stderr across platforms."""
    os.environ.setdefault("PYTHONUTF8", "1")

    if os.name == "nt":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleCP(65001)
            kernel32.SetConsoleOutputCP(65001)
        except Exception:
            pass

    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is None:
            continue
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                continue
