from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx


def _hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


class ApiKeyManager:
    def __init__(self, db):
        self.db = db

    def create_key(self, label: str, daily_limit: int = 100) -> dict[str, Any]:
        raw = secrets.token_urlsafe(32)
        key_id = uuid.uuid4().hex
        now = datetime.now(timezone.utc).isoformat()
        with self.db.connect() as conn:
            conn.execute(
                'INSERT INTO api_keys (key_id, key_hash, label, daily_limit, created_at) VALUES (?, ?, ?, ?, ?)',
                (key_id, _hash_key(raw), label, daily_limit, now),
            )
        return {'key_id': key_id, 'api_key': raw, 'label': label, 'daily_limit': daily_limit}

    def validate(self, raw: str | None) -> dict[str, Any] | None:
        if not raw:
            return None
        with self.db.connect() as conn:
            row = conn.execute('SELECT * FROM api_keys WHERE key_hash=?', (_hash_key(raw),)).fetchone()
            return dict(row) if row else None


async def send_webhook(event: str, payload: dict[str, Any]) -> dict[str, Any]:
    url = os.getenv('WEBHOOK_URL', '').strip()
    if not url:
        return {'sent': False, 'reason': 'WEBHOOK_URL not configured'}
    body = {'event': event, 'payload': payload, 'source': 'RepoTriage'}
    headers = {'Content-Type': 'application/json'}
    secret = os.getenv('WEBHOOK_SECRET', '').strip()
    if secret:
        sig = hmac.new(secret.encode(), json.dumps(body, sort_keys=True).encode(), hashlib.sha256).hexdigest()
        headers['X-RepoTriage-Signature'] = sig
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(url, json=body, headers=headers)
        return {'sent': resp.status_code < 400, 'status_code': resp.status_code}
