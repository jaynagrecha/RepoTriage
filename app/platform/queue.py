from __future__ import annotations

from enum import Enum
from typing import Any

from .db import PlatformDB


class TaskStatus(str, Enum):
    QUEUED = 'queued'
    RUNNING = 'running'
    COMPLETED = 'completed'
    FAILED = 'failed'


class TaskQueue:
    def __init__(self, db: PlatformDB):
        self.db = db

    def enqueue(self, task_type: str, *, job_id: str | None = None, sha256: str | None = None, payload: dict | None = None) -> str:
        return self.db.insert_task(task_type, job_id=job_id, sha256=sha256, payload=payload or {})

    def claim(self) -> dict[str, Any] | None:
        return self.db.claim_next_task()

    def claim_task(self, task_id: str) -> dict[str, Any] | None:
        return self.db.claim_task(task_id)

    def complete(self, task_id: str, result: dict | None = None) -> None:
        self.db.complete_task(task_id, result)

    def fail(self, task_id: str, error: str) -> None:
        self.db.fail_task(task_id, error)

    def get(self, task_id: str) -> dict[str, Any] | None:
        return self.db.get_task(task_id)
