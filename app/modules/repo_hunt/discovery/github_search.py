from __future__ import annotations

import logging
from typing import Any

import httpx

from ...http_client import async_client
from ..config import RepoHuntConfig
from ..types import Candidate

LOG = logging.getLogger('repotriage.repo_hunt.github_search')


async def discover_github_code_search(cfg: RepoHuntConfig) -> list[Candidate]:
    """A1 — GitHub code search for JsOutProx-like public files (+ optional extra queries)."""
    if not cfg.github_token:
        return []
    queries = [cfg.search_query] + list(cfg.extra_search_queries or [])
    out: list[Candidate] = []
    seen: set[str] = set()
    for query in queries:
        q = (query or '').strip()
        if not q:
            continue
        try:
            batch = await _search_code(cfg, q)
        except Exception as exc:
            LOG.warning('github code search failed for %r: %s: %s', q, exc.__class__.__name__, exc)
            continue
        for c in batch:
            key = c.url.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(c)
            if len(out) >= cfg.max_candidates:
                return out
    return out


async def _search_code(cfg: RepoHuntConfig, query: str) -> list[Candidate]:
    headers = {
        'Authorization': f'Bearer {cfg.github_token}',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'RepoTriage-RepoHunt',
    }
    params = {
        'q': query,
        'per_page': min(100, max(1, cfg.search_max_results)),
    }
    out: list[Candidate] = []
    async with async_client(timeout=40, headers=headers) as client:
        resp = await client.get('https://api.github.com/search/code', params=params)
        if resp.status_code >= 400:
            return out
        items = (resp.json().get('items') or [])[: cfg.search_max_results]
        for item in items:
            repo = ((item.get('repository') or {}).get('full_name') or '').strip()
            path = (item.get('path') or '').strip()
            html_url = (item.get('html_url') or '').strip()
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
                    extra={'name': item.get('name'), 'score': item.get('score'), 'query': query},
                )
            )
    return out


async def discover_wu_github_repos(cfg: RepoHuntConfig) -> list[Candidate]:
    """Repo-name search for WU/MTCN keywords (common dropper-hosting pattern)."""
    if not cfg.github_token or not cfg.wu_hunt_enabled:
        return []
    headers = {
        'Authorization': f'Bearer {cfg.github_token}',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'RepoTriage-RepoHunt',
    }
    queries = cfg.wu_repo_search_queries or [
        'mtcn in:name',
        'westernunion in:name',
        'wupos in:name',
        'pagofacil in:name',
    ]
    out: list[Candidate] = []
    seen: set[str] = set()
    try:
        async with async_client(timeout=40, headers=headers) as client:
            for query in queries:
                try:
                    resp = await client.get(
                        'https://api.github.com/search/repositories',
                        params={'q': query, 'per_page': min(30, cfg.search_max_results)},
                    )
                except httpx.HTTPError as exc:
                    LOG.warning('github repo search failed for %r: %s: %s', query, exc.__class__.__name__, exc)
                    continue
                if resp.status_code >= 400:
                    continue
                for item in (resp.json().get('items') or [])[: cfg.search_max_results]:
                    full = (item.get('full_name') or '').strip()
                    html = (item.get('html_url') or '').strip()
                    if not full or not html:
                        continue
                    key = html.lower()
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append(
                        Candidate(
                            url=html,
                            source='github_repo_search_wu',
                            path='',
                            repo=full,
                            html_url=html,
                            extra={'query': query, 'name': item.get('name')},
                        )
                    )
                    if len(out) >= cfg.max_candidates:
                        return out
    except Exception as exc:
        LOG.warning('github WU repo discovery aborted: %s: %s', exc.__class__.__name__, exc)
        return out
    return out
