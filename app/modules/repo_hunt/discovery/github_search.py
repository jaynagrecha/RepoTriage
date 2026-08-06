from __future__ import annotations

from typing import Any

import httpx

from ..config import RepoHuntConfig
from ..types import Candidate


async def discover_github_code_search(cfg: RepoHuntConfig) -> list[Candidate]:
    """A1 — GitHub code search for JsOutProx-like public files."""
    if not cfg.github_token:
        return []
    headers = {
        'Authorization': f'Bearer {cfg.github_token}',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'RepoTriage-RepoHunt',
    }
    params = {
        'q': cfg.search_query,
        'per_page': min(100, max(1, cfg.search_max_results)),
    }
    out: list[Candidate] = []
    async with httpx.AsyncClient(timeout=40, headers=headers) as client:
        resp = await client.get('https://api.github.com/search/code', params=params)
        if resp.status_code >= 400:
            return out
        items = (resp.json().get('items') or [])[: cfg.search_max_results]
        for item in items:
            repo = ((item.get('repository') or {}).get('full_name') or '').strip()
            path = (item.get('path') or '').strip()
            html_url = (item.get('html_url') or '').strip()
            # Prefer blob URL for Triage download/normalize
            blob = html_url
            if repo and path and '/blob/' not in html_url:
                blob = f'https://github.com/{repo}/blob/HEAD/{path}'
            if not blob:
                continue
            out.append(
                Candidate(
                    url=blob,
                    source='github_search',
                    path=path,
                    repo=repo,
                    html_url=html_url or blob,
                    sha=(item.get('sha') or None),
                    extra={'name': item.get('name'), 'score': item.get('score')},
                )
            )
    return out
