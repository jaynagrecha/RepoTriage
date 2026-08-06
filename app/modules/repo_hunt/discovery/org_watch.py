from __future__ import annotations

from typing import Any

import httpx

from ..config import RepoHuntConfig
from ..types import Candidate


async def _list_repos(client: httpx.AsyncClient, kind: str, name: str, limit: int = 20) -> list[dict[str, Any]]:
    if kind == 'org':
        url = f'https://api.github.com/orgs/{name}/repos'
    else:
        url = f'https://api.github.com/users/{name}/repos'
    resp = await client.get(url, params={'sort': 'pushed', 'direction': 'desc', 'per_page': limit})
    if resp.status_code >= 400:
        return []
    rows = resp.json()
    return rows if isinstance(rows, list) else []


async def _recent_js_files(
    client: httpx.AsyncClient,
    repo: str,
    *,
    min_bytes: int,
    max_bytes: int,
    limit: int = 15,
) -> list[Candidate]:
    # Code search scoped to repo is the most reliable way to find size-band JS quickly.
    q = f'repo:{repo} extension:js size:>{min_bytes} size:<{max_bytes}'
    resp = await client.get(
        'https://api.github.com/search/code',
        params={'q': q, 'per_page': min(30, limit)},
    )
    if resp.status_code >= 400:
        return []
    out: list[Candidate] = []
    for item in (resp.json().get('items') or [])[:limit]:
        path = (item.get('path') or '').strip()
        html_url = (item.get('html_url') or '').strip()
        if not html_url:
            continue
        out.append(
            Candidate(
                url=html_url,
                source='org_watch',
                path=path,
                repo=repo,
                html_url=html_url,
                sha=(item.get('sha') or None),
            )
        )
    return out


async def discover_watched_orgs_users(cfg: RepoHuntConfig) -> list[Candidate]:
    """A2 — watch configured orgs/users for newly pushed JS in the size band."""
    if not cfg.github_token or not (cfg.github_orgs or cfg.github_users):
        return []
    headers = {
        'Authorization': f'Bearer {cfg.github_token}',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'RepoTriage-RepoHunt',
    }
    out: list[Candidate] = []
    async with httpx.AsyncClient(timeout=40, headers=headers) as client:
        targets: list[tuple[str, str]] = [('org', o) for o in cfg.github_orgs] + [
            ('user', u) for u in cfg.github_users
        ]
        for kind, name in targets:
            repos = await _list_repos(client, kind, name, limit=12)
            for repo in repos[:12]:
                full = (repo.get('full_name') or '').strip()
                if not full:
                    continue
                out.extend(
                    await _recent_js_files(
                        client,
                        full,
                        min_bytes=cfg.min_bytes,
                        max_bytes=cfg.max_bytes,
                        limit=8,
                    )
                )
                if len(out) >= cfg.max_candidates:
                    return out[: cfg.max_candidates]
    return out[: cfg.max_candidates]
