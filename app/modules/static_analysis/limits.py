from __future__ import annotations

import os
from pathlib import Path

MAX_STATIC_BYTES = int(os.getenv('STATIC_ANALYSIS_MAX_BYTES', str(6 * 1024 * 1024)))


def read_bytes_capped(path: Path) -> tuple[bytes, int, bool]:
    size = path.stat().st_size
    if size <= MAX_STATIC_BYTES:
        return path.read_bytes(), size, False
    return path.read_bytes()[:MAX_STATIC_BYTES], size, True
