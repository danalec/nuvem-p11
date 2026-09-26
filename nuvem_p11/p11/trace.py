"""Optional call tracing, enabled with ``NUVEM_P11_TRACE=<path>``.

Diagnostics for a PKCS#11 module are awkward: the caller is a browser, and the module's own
log has to stay byte-identical to the original's. This writes a separate, append-only trace
of what the caller actually asked for, which is what makes "my token is not offered" cases
debuggable.

Disabled unless the environment variable is set, so it costs nothing in normal use.
"""

from __future__ import annotations

import os
import threading
import time

_lock = threading.Lock()


def enabled() -> bool:
    return bool(os.environ.get("NUVEM_P11_TRACE"))


def trace(message: str) -> None:
    path = os.environ.get("NUVEM_P11_TRACE")
    if not path:
        return
    stamp = time.strftime("%H:%M:%S", time.localtime())
    with _lock:
        try:
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(f"{stamp} [{os.getpid()}] {message}\n")
        except OSError:
            pass


def describe(value: object) -> str:
    """Render an argument for the trace: pointers as hex, bytes as hex, the rest verbatim."""
    if isinstance(value, int):
        return f"{value:#x}"
    if isinstance(value, (bytes, bytearray)):
        data = bytes(value)
        return data.hex() if len(data) <= 64 else f"{data[:64].hex()}...({len(data)}B)"
    return str(value)
