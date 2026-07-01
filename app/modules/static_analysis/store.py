from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _root(base_dir: Path) -> Path:
    return base_dir / 'data' / 'static_analysis'


def _record_path(base_dir: Path, job_id: str, sha256: str) -> Path:
    safe_job = ''.join(ch for ch in job_id if ch.isalnum() or ch in '-_')
    return _root(base_dir) / safe_job / f'{sha256.lower()}.json'


def load_record(base_dir: Path, job_id: str, sha256: str) -> dict[str, Any] | None:
    path = _record_path(base_dir, job_id, sha256)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return None


def save_record(base_dir: Path, job_id: str, sha256: str, record: dict[str, Any]) -> None:
    path = _record_path(base_dir, job_id, sha256)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding='utf-8')


def public_record(record: dict[str, Any] | None) -> dict[str, Any] | None:
    if not record:
        return record
    public = dict(record)
    public.pop('local_path', None)
    return public
