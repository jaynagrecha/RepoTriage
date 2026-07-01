from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class PlatformDB:
    """SQLite persistence for v4 platform features (Render persistent disk friendly)."""

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        data_dir = Path(os.getenv('PLATFORM_DATA_DIR', str(base_dir / 'data')))
        data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = Path(os.getenv('PLATFORM_DB_PATH', str(data_dir / 'repotriage_platform.db')))
        self._lock = threading.RLock()
        self._init_schema()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            conn = sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('PRAGMA foreign_keys=ON')
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def _init_schema(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                '''
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    task_type TEXT NOT NULL,
                    job_id TEXT,
                    sha256 TEXT,
                    payload_json TEXT,
                    status TEXT NOT NULL DEFAULT 'queued',
                    result_json TEXT,
                    error TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status, created_at);

                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    tags_json TEXT,
                    notes TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS case_jobs (
                    case_id TEXT NOT NULL,
                    job_id TEXT NOT NULL,
                    linked_at TEXT NOT NULL,
                    PRIMARY KEY (case_id, job_id),
                    FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS job_notes (
                    note_id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL,
                    body TEXT NOT NULL,
                    author TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_job_notes_job ON job_notes(job_id);

                CREATE TABLE IF NOT EXISTS api_keys (
                    key_id TEXT PRIMARY KEY,
                    key_hash TEXT NOT NULL UNIQUE,
                    label TEXT,
                    daily_limit INTEGER,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT
                );

                CREATE TABLE IF NOT EXISTS file_fingerprints (
                    sha256 TEXT PRIMARY KEY,
                    ssdeep TEXT,
                    job_id TEXT,
                    filename TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS analysis_artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    artifact_type TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    version TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_artifacts_job_sha ON analysis_artifacts(job_id, sha256, artifact_type);
                '''
            )

    def insert_task(self, task_type: str, *, job_id: str | None = None, sha256: str | None = None, payload: dict | None = None) -> str:
        task_id = uuid.uuid4().hex
        now = _utc_now()
        with self.connect() as conn:
            conn.execute(
                'INSERT INTO tasks (task_id, task_type, job_id, sha256, payload_json, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (task_id, task_type, job_id, (sha256 or '').lower() or None, json.dumps(payload or {}), 'queued', now, now),
            )
        return task_id

    def claim_next_task(self) -> dict[str, Any] | None:
        now = _utc_now()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM tasks WHERE status='queued' ORDER BY created_at ASC LIMIT 1"
            ).fetchone()
            if not row:
                return None
            conn.execute(
                "UPDATE tasks SET status='running', started_at=?, updated_at=?, attempts=attempts+1 WHERE task_id=? AND status='queued'",
                (now, now, row['task_id']),
            )
            return dict(row)

    def complete_task(self, task_id: str, result: dict | None = None) -> None:
        now = _utc_now()
        with self.connect() as conn:
            conn.execute(
                "UPDATE tasks SET status='completed', result_json=?, error=NULL, completed_at=?, updated_at=? WHERE task_id=?",
                (json.dumps(result or {}), now, now, task_id),
            )

    def fail_task(self, task_id: str, error: str) -> None:
        now = _utc_now()
        with self.connect() as conn:
            conn.execute(
                "UPDATE tasks SET status='failed', error=?, completed_at=?, updated_at=? WHERE task_id=?",
                (error[:2000], now, now, task_id),
            )

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute('SELECT * FROM tasks WHERE task_id=?', (task_id,)).fetchone()
            return dict(row) if row else None

    def save_artifact(self, job_id: str, sha256: str, artifact_type: str, result: dict, version: str | None = None) -> str:
        artifact_id = uuid.uuid4().hex
        now = _utc_now()
        with self.connect() as conn:
            conn.execute(
                'INSERT INTO analysis_artifacts (artifact_id, job_id, sha256, artifact_type, result_json, version, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
                (artifact_id, job_id, sha256.lower(), artifact_type, json.dumps(result), version, now),
            )
        return artifact_id

    def get_artifact(self, job_id: str, sha256: str, artifact_type: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                'SELECT * FROM analysis_artifacts WHERE job_id=? AND sha256=? AND artifact_type=? ORDER BY created_at DESC LIMIT 1',
                (job_id, sha256.lower(), artifact_type),
            ).fetchone()
            if not row:
                return None
            out = dict(row)
            try:
                out['result'] = json.loads(out.pop('result_json') or '{}')
            except Exception:
                out['result'] = {}
            return out

    def upsert_fingerprint(self, sha256: str, ssdeep: str | None, job_id: str | None, filename: str | None) -> None:
        now = _utc_now()
        with self.connect() as conn:
            existing = conn.execute('SELECT sha256 FROM file_fingerprints WHERE sha256=?', (sha256.lower(),)).fetchone()
            if existing:
                conn.execute(
                    'UPDATE file_fingerprints SET ssdeep=COALESCE(?, ssdeep), job_id=?, filename=COALESCE(?, filename), last_seen=? WHERE sha256=?',
                    (ssdeep, job_id, filename, now, sha256.lower()),
                )
            else:
                conn.execute(
                    'INSERT INTO file_fingerprints (sha256, ssdeep, job_id, filename, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)',
                    (sha256.lower(), ssdeep, job_id, filename, now, now),
                )

    def similar_fingerprints(self, ssdeep: str, limit: int = 10) -> list[dict[str, Any]]:
        if not ssdeep:
            return []
        with self.connect() as conn:
            rows = conn.execute('SELECT sha256, ssdeep, job_id, filename, last_seen FROM file_fingerprints WHERE ssdeep IS NOT NULL').fetchall()
        try:
            import ssdeep  # type: ignore

            scored = []
            for row in rows:
                if not row['ssdeep']:
                    continue
                try:
                    score = ssdeep.compare(ssdeep, row['ssdeep'])
                except Exception:
                    continue
                if score >= 40:
                    scored.append({**dict(row), 'similarity': score})
            scored.sort(key=lambda x: x['similarity'], reverse=True)
            return scored[:limit]
        except Exception:
            return []
