from __future__ import annotations

import asyncio
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from .platform import PlatformDB, TaskQueue
from .platform.worker_config import inline_worker_enabled
from .modules.blocklist_export import export_blocklist, job_diff
from .modules.integrations import ApiKeyManager, send_webhook
from .worker_main import PLATFORM_VERSION, process_task

router = APIRouter(prefix='/api/v4', tags=['v4'])


async def _process_inline(db: PlatformDB, task_id: str) -> None:
    queue = TaskQueue(db)
    task = queue.claim_task(task_id)
    if task:
        await process_task(db, task)


def _db(request: Request) -> PlatformDB:
    return request.app.state.platform_db


class CaseCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    tags: list[str] = Field(default_factory=list)
    notes: str = ''


class NoteCreate(BaseModel):
    body: str = Field(..., min_length=1, max_length=5000)
    author: str = ''


class DeepAnalysisRequest(BaseModel):
    force: bool = False


@router.get('/health')
async def v4_health(request: Request):
    return {
        'ok': True,
        'platform_version': PLATFORM_VERSION,
        'worker_mode': True,
        'worker_inline': inline_worker_enabled(),
        'deep_worker_active': getattr(request.app.state, 'deep_worker_active', inline_worker_enabled()),
        'db_path': str(_db(request).db_path),
    }


@router.post('/jobs/{job_id}/files/{sha256}/deep-analysis')
async def enqueue_deep_analysis(job_id: str, sha256: str, request: Request, body: DeepAnalysisRequest | None = None):
    db = _db(request)
    queue = TaskQueue(db)
    from .main import _load_job, _public_result
    from .modules.job_cache import manifest_entry

    job = _load_job(job_id)
    if not job or job.get('status') != 'completed':
        raise HTTPException(status_code=409, detail='Job must be completed')
    entry = manifest_entry(request.app.state.base_dir, job_id, sha256.lower())
    if not entry or not entry.get('cached'):
        raise HTTPException(status_code=409, detail='File not cached for analysis')

    existing = db.get_artifact(job_id, sha256, 'deep_analysis_bundle')
    if existing and not (body and body.force):
        return {'status': 'completed', 'artifact': existing}

    task_id = queue.enqueue(
        'deep_analysis',
        job_id=job_id,
        sha256=sha256.lower(),
        payload={
            'filename': entry.get('display_name') or entry.get('filename'),
            'file_type': entry.get('file_type'),
            'vt_verdict': entry.get('vt_verdict'),
        },
    )
    if inline_worker_enabled():
        asyncio.create_task(_process_inline(db, task_id))
    return {
        'status': 'queued',
        'task_id': task_id,
        'poll_url': f'/api/v4/tasks/{task_id}',
        'inline': inline_worker_enabled(),
    }


@router.get('/tasks/{task_id}')
async def get_task(task_id: str, request: Request):
    db = _db(request)
    task = TaskQueue(db).get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail='Task not found')
    out = dict(task)
    if out.get('result_json'):
        try:
            out['result'] = json.loads(out['result_json'])
        except Exception:
            out['result'] = {}
    return out


@router.get('/jobs/{job_id}/files/{sha256}/deep-analysis')
async def get_deep_analysis(job_id: str, sha256: str, request: Request):
    db = _db(request)
    art = db.get_artifact(job_id, sha256, 'deep_analysis_bundle')
    if art:
        return {'status': 'completed', 'artifact': art.get('result'), 'created_at': art.get('created_at')}
    task_rows = []
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT task_id, status, error, created_at, completed_at FROM tasks WHERE job_id=? AND sha256=? AND task_type='deep_analysis' ORDER BY created_at DESC LIMIT 1",
            (job_id, sha256.lower()),
        ).fetchall()
        task_rows = [dict(r) for r in rows]
    if task_rows:
        return {'status': task_rows[0]['status'], 'task': task_rows[0]}
    return {'status': 'not_started'}


@router.get('/jobs/{job_id}/files/{sha256}/artifacts/{artifact_type}')
async def get_artifact(job_id: str, sha256: str, artifact_type: str, request: Request):
    db = _db(request)
    art = db.get_artifact(job_id, sha256, artifact_type)
    if not art:
        raise HTTPException(status_code=404, detail='Artifact not found')
    return art


@router.get('/jobs/{job_id}/export/blocklist')
async def export_blocklist_route(job_id: str, request: Request, fmt: str = 'plain'):
    from .main import _load_job, _public_result

    job = _load_job(job_id)
    if not job or not job.get('result'):
        raise HTTPException(status_code=404, detail='Job not found')
    content = export_blocklist(_public_result(job['result']) or {}, fmt=fmt)
    media = 'text/plain' if fmt != 'suricata' else 'text/plain'
    return PlainTextResponse(content, media_type=media)


@router.get('/jobs/diff')
async def diff_jobs(job_a: str, job_b: str, request: Request):
    from .main import _load_job, _public_result

    a = _load_job(job_a)
    b = _load_job(job_b)
    if not a or not b or not a.get('result') or not b.get('result'):
        raise HTTPException(status_code=404, detail='Both completed jobs required')
    return job_diff(_public_result(a['result']) or {}, _public_result(b['result']) or {})


@router.post('/cases')
async def create_case(body: CaseCreate, request: Request):
    db = _db(request)
    case_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    with db.connect() as conn:
        conn.execute(
            'INSERT INTO cases (case_id, name, tags_json, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)',
            (case_id, body.name, json.dumps(body.tags), body.notes, now, now),
        )
    return {'case_id': case_id, 'name': body.name}


@router.get('/cases')
async def list_cases(request: Request):
    db = _db(request)
    with db.connect() as conn:
        rows = conn.execute('SELECT * FROM cases ORDER BY updated_at DESC LIMIT 100').fetchall()
    out = []
    for row in rows:
        item = dict(row)
        try:
            item['tags'] = json.loads(item.pop('tags_json') or '[]')
        except Exception:
            item['tags'] = []
        out.append(item)
    return {'cases': out}


@router.get('/cases/{case_id}')
async def get_case(case_id: str, request: Request):
    db = _db(request)
    with db.connect() as conn:
        row = conn.execute('SELECT * FROM cases WHERE case_id=?', (case_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail='Case not found')
        jobs = conn.execute('SELECT job_id, linked_at FROM case_jobs WHERE case_id=? ORDER BY linked_at DESC', (case_id,)).fetchall()
    case = dict(row)
    try:
        case['tags'] = json.loads(case.pop('tags_json') or '[]')
    except Exception:
        case['tags'] = []
    case['jobs'] = [dict(j) for j in jobs]
    return case


@router.post('/cases/{case_id}/jobs/{job_id}')
async def link_job(case_id: str, job_id: str, request: Request):
    db = _db(request)
    now = datetime.now(timezone.utc).isoformat()
    with db.connect() as conn:
        conn.execute('INSERT OR IGNORE INTO case_jobs (case_id, job_id, linked_at) VALUES (?, ?, ?)', (case_id, job_id, now))
    return {'linked': True}


@router.post('/jobs/{job_id}/notes')
async def add_note(job_id: str, body: NoteCreate, request: Request):
    db = _db(request)
    note_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    with db.connect() as conn:
        conn.execute(
            'INSERT INTO job_notes (note_id, job_id, body, author, created_at) VALUES (?, ?, ?, ?, ?)',
            (note_id, job_id, body.body, body.author, now),
        )
    return {'note_id': note_id}


@router.get('/jobs/{job_id}/notes')
async def list_notes(job_id: str, request: Request):
    db = _db(request)
    with db.connect() as conn:
        rows = conn.execute('SELECT * FROM job_notes WHERE job_id=? ORDER BY created_at DESC', (job_id,)).fetchall()
    return {'notes': [dict(r) for r in rows]}


@router.post('/admin/api-keys')
async def create_api_key(request: Request, label: str = 'default', daily_limit: int = 500):
    token = request.headers.get('x-admin-bypass-token')
    import os

    if token != os.getenv('ADMIN_BYPASS_TOKEN', '').strip() or not token:
        raise HTTPException(status_code=403, detail='Admin token required')
    mgr = ApiKeyManager(_db(request))
    return mgr.create_key(label, daily_limit)


@router.post('/webhooks/test')
async def test_webhook(request: Request):
    return await send_webhook('test.ping', {'ok': True})
