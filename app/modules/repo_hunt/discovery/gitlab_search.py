"""GitLab WU/financial project discovery + recent-file expansion.

Mirrors the GitHub financial repo watch:
  keyword-matched projects → last N commits → top M newest files → Candidates
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote

import httpx

from ...http_client import async_client
from ..config import RepoHuntConfig
from ..types import Candidate
from .repo_commit_scan import select_newest_files

LOG = logging.getLogger('repotriage.repo_hunt.gitlab_search')


def _gitlab_api_bases(cfg: RepoHuntConfig) -> list[tuple[str, str]]:
    """Return (api_base, web_base) pairs — gitlab.com plus optional self-hosted."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(web: str) -> None:
        web = (web or '').strip().rstrip('/')
        if not web:
            return
        key = web.lower()
        if key in seen:
            return
        seen.add(key)
        out.append((f'{web}/api/v4', web))

    add('https://gitlab.com')
    custom = (cfg.gitlab_base_url or '').strip().rstrip('/')
    if custom:
        add(custom)
    return out


def _gl_headers(cfg: RepoHuntConfig) -> dict[str, str]:
    headers = {
        'Accept': 'application/json',
        'User-Agent': 'RepoTriage-RepoHunt',
    }
    token = (cfg.gitlab_token or '').strip()
    if token:
        headers['PRIVATE-TOKEN'] = token
    return headers


def _gitlab_search_terms(cfg: RepoHuntConfig) -> list[str]:
    terms = list(cfg.gitlab_search_terms or [])
    return [t.strip() for t in terms if t and t.strip()]


def _reject_mtcnn_noise(term: str, project: dict[str, Any]) -> bool:
    """True when this mtcn hit is face-detection MTCNN noise."""
    if term.lower() != 'mtcn':
        return False
    blob = ' '.join([
        str(project.get('path_with_namespace') or ''),
        str(project.get('name') or ''),
        str(project.get('description') or ''),
    ]).lower()
    return 'mtcnn' in blob


def _diff_status(entry: dict[str, Any]) -> str:
    if entry.get('deleted_file'):
        return 'removed'
    if entry.get('new_file'):
        return 'added'
    if entry.get('renamed_file'):
        return 'renamed'
    return 'modified'


def gitlab_diffs_to_commit_payload(
    *,
    sha: str,
    committed_date: str,
    diffs: list[dict[str, Any]],
) -> dict[str, Any]:
    """Adapt GitLab commit+diff into the shape expected by ``select_newest_files``."""
    files = []
    for d in diffs or []:
        path = (d.get('new_path') or d.get('old_path') or '').strip()
        if not path:
            continue
        files.append({
            'filename': path,
            'status': _diff_status(d),
        })
    return {
        'sha': sha,
        'commit': {'committer': {'date': committed_date or ''}},
        'files': files,
    }


async def discover_wu_gitlab_projects(cfg: RepoHuntConfig) -> list[Candidate]:
    """Search GitLab projects by WU/financial keywords (gitlab.com + optional self-hosted)."""
    if not cfg.wu_hunt_enabled:
        return []
    if not cfg.gitlab_token:
        LOG.info('GitLab WU discovery skipped — GITLAB_TOKEN not set')
        return []

    terms = _gitlab_search_terms(cfg)
    if not terms:
        return []

    headers = _gl_headers(cfg)
    per_page = min(30, max(1, cfg.search_max_results))
    out: list[Candidate] = []
    seen: set[str] = set()

    try:
        async with async_client(timeout=40, headers=headers) as client:
            for api_base, web_base in _gitlab_api_bases(cfg):
                for term in terms:
                    try:
                        resp = await client.get(
                            f'{api_base}/projects',
                            params={
                                'search': term,
                                'order_by': 'last_activity_at',
                                'sort': 'desc',
                                'per_page': per_page,
                                'simple': 'true',
                            },
                        )
                    except httpx.HTTPError as exc:
                        LOG.warning(
                            'gitlab project search failed (%s %r): %s: %s',
                            web_base, term, exc.__class__.__name__, exc,
                        )
                        continue
                    if resp.status_code >= 400:
                        LOG.warning(
                            'gitlab project search HTTP %s (%s %r)',
                            resp.status_code, web_base, term,
                        )
                        continue
                    for item in (resp.json() or [])[: cfg.search_max_results]:
                        if not isinstance(item, dict):
                            continue
                        if _reject_mtcnn_noise(term, item):
                            continue
                        full = (item.get('path_with_namespace') or '').strip()
                        html = (item.get('web_url') or '').strip()
                        pid = item.get('id')
                        if not full or not html or pid is None:
                            continue
                        key = f'{web_base.lower()}::{full.lower()}'
                        if key in seen:
                            continue
                        seen.add(key)
                        out.append(
                            Candidate(
                                url=html,
                                source='gitlab_repo_search_wu',
                                path='',
                                repo=full,
                                html_url=html,
                                extra={
                                    'provider': 'gitlab',
                                    'query': term,
                                    'name': item.get('name'),
                                    'description': item.get('description') or '',
                                    'project_id': pid,
                                    'api_base': api_base,
                                    'web_base': web_base,
                                },
                            )
                        )
    except Exception as exc:
        LOG.warning('gitlab WU project discovery aborted: %s: %s', exc.__class__.__name__, exc)
        return out
    return out


async def expand_gitlab_project_to_recent_files(
    cfg: RepoHuntConfig,
    project: Candidate,
) -> list[Candidate]:
    """Last N commits → top M newest files for one GitLab project."""
    if not cfg.gitlab_token:
        return []
    extra = project.extra or {}
    api_base = str(extra.get('api_base') or '').rstrip('/')
    web_base = str(extra.get('web_base') or '').rstrip('/')
    project_id = extra.get('project_id')
    full = (project.repo or '').strip()
    if not api_base or project_id is None or not full:
        return []

    commits_n = max(1, int(cfg.repo_watch_commits))
    files_n = max(1, int(cfg.repo_watch_newest_files))
    headers = _gl_headers(cfg)
    pid = quote(str(project_id), safe='')

    try:
        async with async_client(timeout=45, headers=headers) as client:
            try:
                resp = await client.get(
                    f'{api_base}/projects/{pid}/repository/commits',
                    params={'per_page': commits_n},
                )
            except httpx.HTTPError as exc:
                LOG.warning('gitlab commits list failed for %s: %s', full, exc)
                return []
            if resp.status_code >= 400:
                LOG.warning('gitlab commits list HTTP %s for %s', resp.status_code, full)
                return []

            summaries = (resp.json() or [])[:commits_n]
            details: list[dict[str, Any]] = []
            for summary in summaries:
                if not isinstance(summary, dict):
                    continue
                sha = (summary.get('id') or '').strip()
                if not sha:
                    continue
                committed = (
                    summary.get('committed_date')
                    or summary.get('created_at')
                    or ''
                )
                try:
                    diff_resp = await client.get(
                        f'{api_base}/projects/{pid}/repository/commits/{sha}/diff',
                        params={'per_page': 100},
                    )
                except httpx.HTTPError as exc:
                    LOG.warning('gitlab commit diff failed %s@%s: %s', full, sha[:8], exc)
                    continue
                if diff_resp.status_code >= 400:
                    continue
                diffs = diff_resp.json() or []
                if not isinstance(diffs, list):
                    diffs = []
                details.append(
                    gitlab_diffs_to_commit_payload(
                        sha=sha,
                        committed_date=str(committed),
                        diffs=diffs,
                    )
                )

            chosen = select_newest_files(details, newest_files=files_n)
    except Exception as exc:
        LOG.warning('gitlab commit expand aborted for %s: %s: %s', full, exc.__class__.__name__, exc)
        return []

    html_repo = (project.html_url or project.url or f'{web_base}/{full}').rstrip('/')
    # Prefer project root URL (not a file URL) for blob construction
    if '/-/' in html_repo:
        html_repo = html_repo.split('/-/', 1)[0].rstrip('/')

    out: list[Candidate] = []
    query = str(extra.get('query') or '')
    for item in chosen:
        path = item['path']
        sha = item['sha']
        blob = f'{html_repo}/-/blob/{sha}/{path}'
        out.append(
            Candidate(
                url=blob,
                source='financial_repo_watch',
                path=path,
                repo=full,
                html_url=blob,
                sha=sha,
                extra={
                    'repo_watch_file': True,
                    'provider': 'gitlab',
                    'query': query,
                    'committed_at': item.get('committed_at'),
                    'commit_status': item.get('status'),
                    'repo_html_url': html_repo,
                    'name': path.rsplit('/', 1)[-1],
                    'project_id': project_id,
                    'api_base': api_base,
                    'web_base': web_base,
                },
            )
        )
    return out


async def expand_financial_gitlab_repos(
    cfg: RepoHuntConfig,
    projects: list[Candidate],
) -> list[Candidate]:
    files: list[Candidate] = []
    seen: set[str] = set()
    for proj in projects:
        batch = await expand_gitlab_project_to_recent_files(cfg, proj)
        for c in batch:
            key = c.url.lower()
            if key in seen:
                continue
            seen.add(key)
            files.append(c)
    return files
