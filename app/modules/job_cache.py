from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _cache_root(base_dir: Path) -> Path:
    return base_dir / 'data' / 'job_cache'


def _job_dir(base_dir: Path, job_id: str) -> Path:
    safe = ''.join(ch for ch in job_id if ch.isalnum() or ch in '-_')
    return _cache_root(base_dir) / safe


def _max_cached_bytes() -> int:
    try:
        return int(os.getenv('MAX_CACHED_FILE_BYTES', os.getenv('MAX_DOWNLOAD_BYTES', '50000000')))
    except Exception:
        return 50_000_000


def cache_job_inventory(base_dir: Path, job_id: str, inventory: list[dict]) -> dict[str, Any]:
    """Persist analyzable file bytes keyed by SHA256 for on-demand static analysis."""
    if not job_id:
        return {'cached': 0, 'skipped': 0, 'errors': []}
    root = _job_dir(base_dir, job_id)
    files_dir = root / 'files'
    files_dir.mkdir(parents=True, exist_ok=True)
    max_bytes = _max_cached_bytes()
    manifest_files: list[dict[str, Any]] = []
    cached = 0
    skipped = 0
    errors: list[str] = []

    seen_sha: set[str] = set()
    for item in inventory or []:
        sha256 = (item.get('sha256') or '').lower()
        if not sha256 or sha256 in seen_sha:
            continue
        seen_sha.add(sha256)
        local_path = item.get('local_path')
        size = int(item.get('size_bytes') or 0)
        entry = {
            'sha256': sha256,
            'filename': item.get('filename') or item.get('original_name') or item.get('path') or 'file',
            'display_name': item.get('original_name') or item.get('filename') or item.get('path') or 'file',
            'path': item.get('path') or item.get('filename') or '',
            'file_type': item.get('file_type') or 'Unknown',
            'size_bytes': size,
            'vt_verdict': item.get('vt_verdict'),
            'depth': item.get('depth', 0),
            'parent_archive': item.get('parent_archive'),
            'cached': False,
            'cache_path': None,
            'cache_reason': None,
        }
        if not local_path:
            entry['cache_reason'] = 'no_local_path'
            skipped += 1
            manifest_files.append(entry)
            continue
        src = Path(local_path)
        if not src.is_file():
            entry['cache_reason'] = 'file_missing'
            skipped += 1
            manifest_files.append(entry)
            continue
        if size <= 0:
            try:
                size = src.stat().st_size
                entry['size_bytes'] = size
            except Exception:
                pass
        if size > max_bytes:
            entry['cache_reason'] = f'exceeds_max_cached_bytes ({max_bytes})'
            skipped += 1
            manifest_files.append(entry)
            continue
        dest = files_dir / f'{sha256}.bin'
        try:
            shutil.copy2(src, dest)
            entry['cached'] = True
            entry['cache_path'] = str(dest)
            cached += 1
        except Exception as exc:
            entry['cache_reason'] = f'copy_failed: {exc.__class__.__name__}'
            errors.append(f'{entry["filename"]}: {entry["cache_reason"]}')
            skipped += 1
        manifest_files.append(entry)

    manifest = {
        'job_id': job_id,
        'cached_at': datetime.now(timezone.utc).isoformat(),
        'cached_files': cached,
        'skipped_files': skipped,
        'files': manifest_files,
        'errors': errors,
    }
    (root / 'manifest.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding='utf-8')
    return manifest


def load_manifest(base_dir: Path, job_id: str) -> dict[str, Any] | None:
    path = _job_dir(base_dir, job_id) / 'manifest.json'
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return None


def manifest_entry(base_dir: Path, job_id: str, sha256: str) -> dict[str, Any] | None:
    manifest = load_manifest(base_dir, job_id)
    if not manifest:
        return None
    target = sha256.lower()
    for item in manifest.get('files') or []:
        if (item.get('sha256') or '').lower() == target:
            return item
    return None


def cached_file_path(base_dir: Path, job_id: str, sha256: str) -> Path | None:
    entry = manifest_entry(base_dir, job_id, sha256)
    if not entry or not entry.get('cached'):
        return None
    path = Path(entry.get('cache_path') or (_job_dir(base_dir, job_id) / 'files' / f'{sha256.lower()}.bin'))
    return path if path.is_file() else None
