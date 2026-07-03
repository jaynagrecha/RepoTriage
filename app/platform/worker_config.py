from __future__ import annotations

import os


def _env_truthy(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return str(val).strip().lower() in {'1', 'true', 'yes', 'on'}


def dedicated_worker_mode() -> bool:
    """Separate Render worker service owns the queue (web must not process tasks)."""
    return _env_truthy('DEDICATED_WORKER', False)


def inline_worker_enabled() -> bool:
    """Process deep-analysis tasks inside the web process (default for single-service Render)."""
    if dedicated_worker_mode():
        return False
    return _env_truthy('WORKER_INLINE', True)
