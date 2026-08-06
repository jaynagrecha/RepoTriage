from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class HuntState:
    """Persistent dedup + webhook queue under PLATFORM_DATA_DIR/data/repo_hunt."""

    def __init__(self, base_dir: Path):
        self.root = Path(base_dir) / 'data' / 'repo_hunt'
        self.root.mkdir(parents=True, exist_ok=True)
        self.seen_path = self.root / 'seen.json'
        self.queue_path = self.root / 'webhook_queue.json'
        self.meta_path = self.root / 'last_run.json'

    def _load(self, path: Path, default: Any) -> Any:
        if not path.exists():
            return default
        try:
            return json.loads(path.read_text(encoding='utf-8'))
        except Exception:
            return default

    def _save(self, path: Path, payload: Any) -> None:
        tmp = path.with_suffix('.tmp')
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding='utf-8')
        tmp.replace(path)

    def seen(self) -> dict[str, Any]:
        data = self._load(self.seen_path, {})
        return data if isinstance(data, dict) else {}

    def mark_seen(self, key: str, meta: dict[str, Any] | None = None) -> None:
        data = self.seen()
        data[key] = {
            'seen_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            **(meta or {}),
        }
        # Cap growth
        if len(data) > 5000:
            keep = sorted(data.items(), key=lambda kv: kv[1].get('seen_at') or '', reverse=True)[:4000]
            data = dict(keep)
        self._save(self.seen_path, data)

    def is_seen(self, key: str) -> bool:
        return key.lower() in {k.lower() for k in self.seen().keys()}

    def enqueue_webhook(self, item: dict[str, Any]) -> None:
        q = self._load(self.queue_path, [])
        if not isinstance(q, list):
            q = []
        q.append(item)
        self._save(self.queue_path, q[-500:])

    def drain_webhook_queue(self) -> list[dict[str, Any]]:
        q = self._load(self.queue_path, [])
        self._save(self.queue_path, [])
        return q if isinstance(q, list) else []

    def write_last_run(self, report: dict[str, Any]) -> None:
        self._save(self.meta_path, report)

    def last_run(self) -> dict[str, Any]:
        data = self._load(self.meta_path, {})
        return data if isinstance(data, dict) else {}
