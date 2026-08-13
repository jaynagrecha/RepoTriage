"""Expand keyword-matched GitHub repos into recent file candidates.

For each repo: inspect the last N commits, keep the M newest unique file paths
(added/modified), and emit downloadable blob Candidates for VT scanning.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from ...http_client import async_client
from ..config import RepoHuntConfig
from ..types import Candidate

LOG = logging.getLogger('repotriage.repo_hunt.repo_commit_scan')

RULE_ID = 'FINANCIAL_REPO_VT_MALICIOUS'
RULE_NAME = 'FinancialRepoMaliciousFile'


def _parse_iso(ts: str | None) -> datetime:
    if not ts:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    text = str(ts).strip()
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _gh_headers(cfg: RepoHuntConfig) -> dict[str, str]:
    return {
        'Authorization': f'Bearer {cfg.github_token}',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'RepoTriage-RepoHunt',
    }


def select_newest_files(
    commit_payloads: list[dict[str, Any]],
    *,
    newest_files: int,
) -> list[dict[str, Any]]:
    """
    From newest→oldest commit detail payloads, keep first-seen paths (newest),
    then return up to ``newest_files`` entries.

    Each entry: path, sha (commit), committed_at, status.
    """
    seen: set[str] = set()
    ordered: list[dict[str, Any]] = []
    for detail in commit_payloads:
        commit_meta = detail.get('commit') or {}
        author = commit_meta.get('author') or {}
        committer = commit_meta.get('committer') or {}
        committed_at = committer.get('date') or author.get('date') or ''
        sha = (detail.get('sha') or '').strip()
        for f in detail.get('files') or []:
            path = (f.get('filename') or '').strip()
            status = (f.get('status') or '').strip().lower()
            if not path or not sha:
                continue
            if status == 'removed':
                continue
            key = path.lower()
            if key in seen:
                continue
            seen.add(key)
            ordered.append({
                'path': path,
                'sha': sha,
                'committed_at': committed_at,
                'status': status or 'modified',
            })
    # Already newest-first by commit walk; stable trim.
    return ordered[: max(0, int(newest_files))]


async def expand_repo_to_recent_files(
    cfg: RepoHuntConfig,
    repo_full_name: str,
    *,
    discovery_query: str = '',
    repo_html_url: str = '',
) -> list[Candidate]:
    """Last ``repo_watch_commits`` commits → top ``repo_watch_newest_files`` files."""
    if not cfg.github_token or '/' not in (repo_full_name or ''):
        return []
    owner, _, name = repo_full_name.partition('/')
    if not owner or not name:
        return []

    commits_n = max(1, int(cfg.repo_watch_commits))
    files_n = max(1, int(cfg.repo_watch_newest_files))
    headers = _gh_headers(cfg)
    base = f'https://api.github.com/repos/{owner}/{name}'

    try:
        async with async_client(timeout=45, headers=headers) as client:
            try:
                resp = await client.get(
                    f'{base}/commits',
                    params={'per_page': commits_n},
                )
            except httpx.HTTPError as exc:
                LOG.warning('commits list failed for %s: %s: %s', repo_full_name, exc.__class__.__name__, exc)
                return []
            if resp.status_code >= 400:
                LOG.warning('commits list HTTP %s for %s', resp.status_code, repo_full_name)
                return []

            summaries = (resp.json() or [])[:commits_n]
            details: list[dict[str, Any]] = []
            for summary in summaries:
                sha = (summary.get('sha') or '').strip()
                if not sha:
                    continue
                try:
                    detail_resp = await client.get(f'{base}/commits/{sha}')
                except httpx.HTTPError as exc:
                    LOG.warning('commit detail failed %s@%s: %s', repo_full_name, sha[:8], exc)
                    continue
                if detail_resp.status_code >= 400:
                    continue
                details.append(detail_resp.json() or {})

            chosen = select_newest_files(details, newest_files=files_n)
    except Exception as exc:
        LOG.warning('repo commit expand aborted for %s: %s: %s', repo_full_name, exc.__class__.__name__, exc)
        return []

    html_repo = (repo_html_url or f'https://github.com/{repo_full_name}').rstrip('/')
    out: list[Candidate] = []
    for item in chosen:
        path = item['path']
        sha = item['sha']
        blob = f'{html_repo}/blob/{sha}/{path}'
        out.append(
            Candidate(
                url=blob,
                source='financial_repo_watch',
                path=path,
                repo=repo_full_name,
                html_url=blob,
                sha=sha,
                extra={
                    'repo_watch_file': True,
                    'query': discovery_query,
                    'committed_at': item.get('committed_at'),
                    'commit_status': item.get('status'),
                    'repo_html_url': html_repo,
                    'name': path.rsplit('/', 1)[-1],
                },
            )
        )
    return out


async def expand_financial_repos(
    cfg: RepoHuntConfig,
    repos: list[Candidate],
) -> list[Candidate]:
    """Expand every keyword-matched repo Candidate into recent file Candidates."""
    files: list[Candidate] = []
    seen: set[str] = set()
    for repo_cand in repos:
        full = (repo_cand.repo or '').strip()
        if not full:
            continue
        batch = await expand_repo_to_recent_files(
            cfg,
            full,
            discovery_query=str((repo_cand.extra or {}).get('query') or ''),
            repo_html_url=repo_cand.html_url or repo_cand.url,
        )
        for c in batch:
            key = c.url.lower()
            if key in seen:
                continue
            seen.add(key)
            files.append(c)
    return files
