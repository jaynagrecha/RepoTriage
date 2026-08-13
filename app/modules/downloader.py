from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse, unquote, quote
import os
import re
import uuid

import httpx


class DownloadError(Exception):
    pass


ALLOWED_DOWNLOAD_HOSTS = frozenset({
    'github.com',
    'www.github.com',
    'api.github.com',
    'raw.githubusercontent.com',
    'objects.githubusercontent.com',
    'codeload.github.com',
    'gist.github.com',
    'gist.githubusercontent.com',
    'gitlab.com',
    'www.gitlab.com',
})

_GITLAB_BLOB_MARKER = '/-/blob/'
_GITLAB_RAW_MARKER = '/-/raw/'
_GITLAB_TREE_MARKER = '/-/tree/'

_ARCHIVE_SUFFIXES = (
    '.7z', '.zip', '.rar', '.tar', '.tar.gz', '.tgz', '.gz', '.bz2', '.xz', '.cab',
    '.iso', '.img', '.dmg', '.apk', '.msi', '.exe', '.dll', '.js', '.vbs', '.ps1',
    '.bat', '.cmd', '.scr', '.jar', '.war', '.doc', '.docm', '.xls', '.xlsm', '.pptm',
    '.pdf', '.rtf', '.hta', '.lnk', '.wsf', '.jse',
)
_SKIP_ROOT_NAMES = frozenset({
    'readme', 'readme.md', 'readme.txt', 'license', 'license.md', 'licence', 'licence.md',
    '.gitignore', '.gitattributes', '.editorconfig', 'code_of_conduct.md', 'security.md',
    'contributing.md', 'changelog.md', 'changes.md',
})


def _gitlab_base_host() -> str | None:
    base = (os.getenv('GITLAB_BASE_URL') or '').strip().rstrip('/')
    if not base:
        return None
    return urlparse(base).netloc.lower().split(':', 1)[0] or None


def _configured_gitlab_hosts() -> frozenset[str]:
    hosts = {'gitlab.com', 'www.gitlab.com'}
    custom = _gitlab_base_host()
    if custom:
        hosts.add(custom)
    return frozenset(hosts)


def _is_gitlab_host(host: str) -> bool:
    host = (host or '').lower().split(':', 1)[0]
    return host in _configured_gitlab_hosts()


def _is_github_host(host: str) -> bool:
    host = (host or '').lower().split(':', 1)[0]
    return host in {
        'github.com', 'www.github.com', 'raw.githubusercontent.com',
        'gist.github.com', 'gist.githubusercontent.com',
    }


def _allowed_download_host(host: str, *, source_host: str | None = None) -> bool:
    host = (host or '').lower().split(':', 1)[0]
    if host in ALLOWED_DOWNLOAD_HOSTS:
        return True
    if host.endswith('.githubusercontent.com'):
        return True
    if _is_gitlab_host(host):
        return True
    if source_host and host == source_host.lower().split(':', 1)[0]:
        return True
    return False


def _github_token() -> str:
    return (os.getenv('GITHUB_TOKEN') or os.getenv('GH_TOKEN') or '').strip()


def _gitlab_token() -> str:
    return (os.getenv('GITLAB_TOKEN') or '').strip()


def _split_ref_and_path(segments: list[str]) -> tuple[str, str]:
    """Split URL segments after blob/raw/tree into (ref, file_or_dir_path)."""
    if not segments:
        raise DownloadError('Invalid URL: missing ref')
    if len(segments) >= 3 and segments[0] == 'refs' and segments[1] in {'heads', 'tags'}:
        # Prefer short ref name for raw.githubusercontent.com / GitLab raw compatibility
        ref = segments[2]
        file_path = '/'.join(segments[3:])
    else:
        ref = segments[0]
        file_path = '/'.join(segments[1:])
    if not ref:
        raise DownloadError('Invalid URL: missing ref')
    return ref, file_path


def _split_gitlab_ref_and_path(segments: list[str]) -> tuple[str, str]:
    if len(segments) < 2:
        raise DownloadError('Invalid GitLab file URL: missing ref or file path')
    ref, file_path = _split_ref_and_path(segments)
    if not file_path:
        raise DownloadError('Invalid GitLab file URL: missing ref or file path')
    return ref, file_path


def _gitlab_owner_repo(project_path: str) -> tuple[str, str]:
    parts = [p for p in (project_path or '').split('/') if p]
    if not parts:
        return '', ''
    if len(parts) == 1:
        return '', parts[0]
    return '/'.join(parts[:-1]), parts[-1]


def _gitlab_raw_url(host: str, project_path: str, ref: str, file_path: str) -> str:
    scheme = 'https'
    custom = (os.getenv('GITLAB_BASE_URL') or '').strip().rstrip('/')
    if custom:
        scheme = urlparse(custom).scheme or 'https'
        custom_host = urlparse(custom).netloc.lower().split(':', 1)[0]
        if custom_host and host == custom_host:
            return f'{custom}/{project_path}/-/raw/{ref}/{file_path}'
    return f'{scheme}://{host}/{project_path}/-/raw/{ref}/{file_path}'


def _looks_like_payload_name(name: str) -> bool:
    n = (name or '').lower()
    return any(n.endswith(suf) for suf in _ARCHIVE_SUFFIXES)


def _pick_repo_file(entries: list, *, prefer_name: str | None = None, provider: str = 'GitHub') -> dict:
    """Choose a single downloadable payload from a directory listing."""
    files = [e for e in entries if isinstance(e, dict) and e.get('type') == 'file' and e.get('name')]
    # GitLab tree API uses type=blob
    if not files:
        files = [
            e for e in entries
            if isinstance(e, dict) and e.get('type') == 'blob' and e.get('name')
        ]
        for e in files:
            e.setdefault('type', 'file')
    if not files:
        raise DownloadError(
            f'{provider} path has no downloadable files (only directories?). '
            'Paste a direct blob/raw file URL.'
        )

    prefer = (prefer_name or '').strip().lower()
    if prefer:
        for item in files:
            if str(item.get('name') or '').lower() == prefer:
                return item

    payloads = [f for f in files if _looks_like_payload_name(str(f.get('name') or ''))]
    if len(payloads) == 1:
        return payloads[0]
    if payloads:
        return max(payloads, key=lambda f: int(f.get('size') or 0))

    non_docs = [f for f in files if str(f.get('name') or '').lower() not in _SKIP_ROOT_NAMES]
    if len(non_docs) == 1:
        return non_docs[0]
    if len(files) == 1:
        return files[0]

    names = ', '.join(str(f.get('name')) for f in files[:15])
    raise DownloadError(
        f'{provider} path has multiple files — paste a specific blob/raw URL. '
        f'Candidates: {names}'
    )


# Back-compat alias used by tests
def _pick_github_repo_file(entries: list, *, prefer_name: str | None = None) -> dict:
    return _pick_repo_file(entries, prefer_name=prefer_name, provider='GitHub')


def normalize_gitlab_file_url(url: str) -> dict:
    url = url.strip()
    parsed = urlparse(url)
    host = parsed.netloc.lower().split(':', 1)[0]
    path = parsed.path

    if not _is_gitlab_host(host):
        raise DownloadError('GitLab host is not allowed. Configure GITLAB_BASE_URL for self-hosted instances.')

    # Direct file links
    for marker, source_type in (
        (_GITLAB_BLOB_MARKER, 'gitlab_blob'),
        (_GITLAB_RAW_MARKER, 'gitlab_raw'),
    ):
        if marker in path:
            prefix, rest = path.split(marker, 1)
            project_path = prefix.strip('/')
            if not project_path:
                raise DownloadError('Invalid GitLab file URL: missing project path')
            ref, file_path = _split_gitlab_ref_and_path([p for p in rest.strip('/').split('/') if p])
            owner, repo = _gitlab_owner_repo(project_path)
            return {
                'provider': 'gitlab',
                'source_type': source_type,
                'host': host,
                'project': project_path,
                'owner': owner,
                'repo': repo,
                'ref': ref,
                'branch': ref,
                'path': file_path,
                'download_url': _gitlab_raw_url(host, project_path, ref, file_path),
                'display_url': url,
            }

    # Tree / directory browse → resolve to a file
    if _GITLAB_TREE_MARKER in path:
        prefix, rest = path.split(_GITLAB_TREE_MARKER, 1)
        project_path = prefix.strip('/')
        if not project_path:
            raise DownloadError('Invalid GitLab tree URL: missing project path')
        segments = [p for p in rest.strip('/').split('/') if p]
        if not segments:
            raise DownloadError('Invalid GitLab tree URL: missing ref')
        ref, subpath = _split_ref_and_path(segments)
        owner, repo = _gitlab_owner_repo(project_path)
        return {
            'provider': 'gitlab',
            'source_type': 'gitlab_tree',
            'host': host,
            'project': project_path,
            'owner': owner,
            'repo': repo,
            'ref': ref,
            'branch': ref,
            'path': subpath,
            'download_url': '',
            'display_url': url,
            'needs_resolve': True,
        }

    # Project root / nested group project (no -/… marker)
    # Reject known non-file GitLab pages under the project.
    parts = [p for p in path.strip('/').split('/') if p]
    if not parts:
        raise DownloadError('Invalid GitLab URL: missing project path')
    blocked = {
        'issues', 'merge_requests', 'pipelines', 'jobs', 'wikis', 'snippets',
        'settings', 'activity', 'members', 'labels', 'milestones', 'boards',
    }
    if '-/' in path:
        # Unknown -/ resource (e.g. commits, jobs) — not a hosted file
        raise DownloadError(
            'Unsupported GitLab URL. Use blob/raw file URL, tree URL, or project URL '
            '(https://gitlab.com/group/project).'
        )
    if any(p in blocked for p in parts):
        raise DownloadError(
            'Unsupported GitLab URL (not a file host). Use blob/raw, tree, or project URL.'
        )

    project_path = '/'.join(parts)
    owner, repo = _gitlab_owner_repo(project_path)
    return {
        'provider': 'gitlab',
        'source_type': 'gitlab_project',
        'host': host,
        'project': project_path,
        'owner': owner,
        'repo': repo,
        'ref': None,
        'branch': None,
        'path': '',
        'download_url': '',
        'display_url': url,
        'needs_resolve': True,
    }


def normalize_github_file_url(url: str) -> dict:
    url = url.strip()
    parsed = urlparse(url)
    host = parsed.netloc.lower().split(':', 1)[0]
    path = parsed.path

    # gist.githubusercontent.com/<user>/<id>/raw/<commit>/<file>
    if host == 'gist.githubusercontent.com':
        parts = [p for p in path.strip('/').split('/') if p]
        if len(parts) < 5 or parts[2] != 'raw':
            raise DownloadError('Invalid gist.githubusercontent.com URL')
        return {
            'provider': 'github',
            'source_type': 'github_gist_raw',
            'owner': parts[0],
            'repo': parts[1],
            'branch': parts[3],
            'path': '/'.join(parts[4:]),
            'download_url': url.split('?', 1)[0],
            'display_url': url,
            'gist_id': parts[1],
        }

    # gist.github.com/<user>/<id>[/…]
    if host == 'gist.github.com':
        parts = [p for p in path.strip('/').split('/') if p]
        if len(parts) < 2:
            raise DownloadError('Invalid gist.github.com URL')
        owner, gist_id = parts[0], parts[1]
        # Direct raw link on gist.github.com
        if len(parts) >= 4 and parts[2] == 'raw':
            # /user/id/raw/<file> or /user/id/raw/<commit>/<file>
            rest = parts[3:]
            file_path = rest[-1] if rest else ''
            return {
                'provider': 'github',
                'source_type': 'github_gist_raw',
                'owner': owner,
                'repo': gist_id,
                'branch': None,
                'path': file_path,
                'download_url': f'https://gist.githubusercontent.com/{owner}/{gist_id}/raw/{("/".join(rest) if rest else "")}'.rstrip('/'),
                'display_url': url,
                'gist_id': gist_id,
            }
        return {
            'provider': 'github',
            'source_type': 'github_gist',
            'owner': owner,
            'repo': gist_id,
            'branch': None,
            'path': '',
            'download_url': '',
            'display_url': url,
            'gist_id': gist_id,
            'needs_resolve': True,
        }

    if host == 'raw.githubusercontent.com':
        parts = [p for p in path.strip('/').split('/') if p]
        if len(parts) < 4:
            raise DownloadError('Invalid raw.githubusercontent.com URL')
        owner, repo = parts[0], parts[1]
        rest = parts[2:]
        branch, file_path = _split_ref_and_path(rest)
        if not file_path:
            raise DownloadError('Invalid raw.githubusercontent.com URL: missing file path')
        raw = f'https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}'
        return {
            'provider': 'github',
            'source_type': 'github_raw',
            'owner': owner,
            'repo': repo,
            'branch': branch,
            'path': file_path,
            'download_url': raw,
            'display_url': url,
        }

    if host not in {'github.com', 'www.github.com'}:
        raise DownloadError(
            'Unsupported GitHub URL host. Use github.com, raw.githubusercontent.com, or gist.github.com.'
        )

    parts = [p for p in path.strip('/').split('/') if p]

    # owner/repo/blob/<ref>/path
    if len(parts) >= 4 and parts[2] == 'blob':
        owner, repo = parts[0], parts[1]
        branch, file_path = _split_ref_and_path(parts[3:])
        if not file_path:
            raise DownloadError('Invalid GitHub blob URL: missing file path')
        raw = f'https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}'
        return {
            'provider': 'github',
            'source_type': 'github_blob',
            'owner': owner,
            'repo': repo,
            'branch': branch,
            'path': file_path,
            'download_url': raw,
            'display_url': url,
        }

    # owner/repo/raw/<ref>/path  (includes refs/heads)
    if len(parts) >= 4 and parts[2] == 'raw':
        owner, repo = parts[0], parts[1]
        branch, file_path = _split_ref_and_path(parts[3:])
        if not file_path:
            raise DownloadError('Invalid GitHub raw URL: missing file path')
        raw = f'https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}'
        return {
            'provider': 'github',
            'source_type': 'github_raw_path',
            'owner': owner,
            'repo': repo,
            'branch': branch,
            'path': file_path,
            'download_url': raw,
            'display_url': url,
        }

    # owner/repo/releases/download/tag/asset  OR  releases/latest/download/asset
    if len(parts) >= 5 and parts[2] == 'releases' and 'download' in parts:
        owner, repo = parts[0], parts[1]
        file_path = parts[-1]
        return {
            'provider': 'github',
            'source_type': 'github_release_asset',
            'owner': owner,
            'repo': repo,
            'branch': None,
            'path': file_path,
            'download_url': url.split('?', 1)[0],
            'display_url': url,
        }

    # owner/repo/archive/<ref>.zip|.tar.gz  (repo archive is a hosted file)
    if len(parts) >= 4 and parts[2] == 'archive':
        owner, repo = parts[0], parts[1]
        archive_name = '/'.join(parts[3:])
        return {
            'provider': 'github',
            'source_type': 'github_archive',
            'owner': owner,
            'repo': repo,
            'branch': None,
            'path': archive_name,
            'download_url': url.split('?', 1)[0],
            'display_url': url,
        }

    # owner/repo/tree/<ref>[/subdir]
    if len(parts) >= 4 and parts[2] == 'tree':
        owner, repo = parts[0], parts[1]
        branch, subpath = _split_ref_and_path(parts[3:])
        return {
            'provider': 'github',
            'source_type': 'github_tree',
            'owner': owner,
            'repo': repo,
            'branch': branch,
            'path': subpath,
            'download_url': '',
            'display_url': url,
            'needs_resolve': True,
        }

    # owner/repo  (repository root)
    if len(parts) == 2:
        owner, repo = parts[0], parts[1]
        return {
            'provider': 'github',
            'source_type': 'github_repo',
            'owner': owner,
            'repo': repo,
            'branch': None,
            'path': '',
            'download_url': '',
            'display_url': url,
            'needs_resolve': True,
        }

    raise DownloadError(
        'Unsupported GitHub URL. Use blob/raw file URL, release asset, archive download, '
        'gist, tree, or repository URL (https://github.com/owner/repo).'
    )


def normalize_file_url(url: str) -> dict:
    url = (url or '').strip()
    if not url:
        raise DownloadError('file_url is required')
    parsed = urlparse(url)
    host = parsed.netloc.lower().split(':', 1)[0]
    path = parsed.path

    if _is_gitlab_host(host) or _GITLAB_BLOB_MARKER in path or _GITLAB_RAW_MARKER in path or _GITLAB_TREE_MARKER in path:
        return normalize_gitlab_file_url(url)
    if _is_github_host(host):
        return normalize_github_file_url(url)
    raise DownloadError(
        'Unsupported URL host. RepoTriage accepts GitHub and GitLab URLs that host a file '
        '(blob/raw/tree/repo/gist/release/archive).'
    )


async def _api_json(client: httpx.AsyncClient, url: str, headers: dict[str, str]) -> tuple[int, dict | list]:
    resp = await client.get(url, headers=headers)
    try:
        payload = resp.json()
    except Exception:
        payload = {}
    return resp.status_code, payload


async def resolve_github_repo_url(meta: dict) -> dict:
    """Resolve github.com/owner/repo, /tree/..., or gist to a concrete file download."""
    if not meta.get('needs_resolve'):
        return meta

    if meta.get('source_type') == 'github_gist' or meta.get('gist_id'):
        return await _resolve_github_gist(meta)

    owner = (meta.get('owner') or '').strip()
    repo = (meta.get('repo') or '').strip()
    if not owner or not repo:
        raise DownloadError('Invalid GitHub repository URL')

    headers = {
        'User-Agent': 'RepoTriage',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
    }
    token = _github_token()
    if token:
        headers['Authorization'] = f'Bearer {token}'

    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        branch = (meta.get('branch') or '').strip() or None
        if not branch:
            status, repo_info = await _api_json(client, f'https://api.github.com/repos/{owner}/{repo}', headers)
            if status == 404:
                hint = ' (private repo — set GITHUB_TOKEN)' if not token else ''
                raise DownloadError(f'GitHub repository not found or inaccessible: {owner}/{repo}{hint}')
            if status in {401, 403}:
                raise DownloadError(
                    f'GitHub API rejected repository lookup for {owner}/{repo} (HTTP {status}). '
                    'Check GITHUB_TOKEN scopes.'
                )
            if status >= 400 or not isinstance(repo_info, dict):
                raise DownloadError(f'GitHub repository lookup failed for {owner}/{repo} (HTTP {status})')
            branch = (repo_info.get('default_branch') or 'main').strip() or 'main'

        dir_path = (meta.get('path') or '').strip('/')
        contents_url = f'https://api.github.com/repos/{owner}/{repo}/contents'
        if dir_path:
            contents_url += '/' + quote(dir_path, safe='/')
        contents_url += f'?ref={quote(branch, safe="")}'

        status, listing = await _api_json(client, contents_url, headers)
        if status == 404:
            raise DownloadError(
                f'GitHub path not found in {owner}/{repo} @ {branch}'
                + (f' ({dir_path})' if dir_path else '')
            )
        if status in {401, 403}:
            raise DownloadError(f'GitHub Contents API rejected listing for {owner}/{repo} (HTTP {status})')
        if status >= 400:
            raise DownloadError(f'GitHub Contents API failed for {owner}/{repo} (HTTP {status})')

        if isinstance(listing, dict) and listing.get('type') == 'file':
            picked = listing
        elif isinstance(listing, list):
            picked = _pick_repo_file(listing, prefer_name=repo, provider='GitHub')
        else:
            raise DownloadError(f'Unexpected GitHub Contents API response for {owner}/{repo}')

    file_path = (picked.get('path') or picked.get('name') or '').strip()
    if not file_path:
        raise DownloadError(f'Could not resolve a file path in {owner}/{repo}')
    download_url = (picked.get('download_url') or '').strip()
    if not download_url:
        download_url = f'https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}'

    resolved = dict(meta)
    resolved.update({
        'branch': branch,
        'path': file_path,
        'download_url': download_url,
        'needs_resolve': False,
        'source_type': f"{meta.get('source_type') or 'github_repo'}_resolved",
        'resolved_from_repo': True,
        'resolved_file': file_path,
        'resolved_size': picked.get('size'),
    })
    return resolved


async def _resolve_github_gist(meta: dict) -> dict:
    gist_id = (meta.get('gist_id') or meta.get('repo') or '').strip()
    if not gist_id:
        raise DownloadError('Invalid GitHub gist URL')
    headers = {
        'User-Agent': 'RepoTriage',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
    }
    token = _github_token()
    if token:
        headers['Authorization'] = f'Bearer {token}'

    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        status, data = await _api_json(client, f'https://api.github.com/gists/{gist_id}', headers)
    if status == 404:
        raise DownloadError(f'GitHub gist not found or inaccessible: {gist_id}')
    if status >= 400 or not isinstance(data, dict):
        raise DownloadError(f'GitHub gist lookup failed (HTTP {status})')

    files = data.get('files') or {}
    if not isinstance(files, dict) or not files:
        raise DownloadError(f'GitHub gist {gist_id} has no files')

    entries = []
    for name, info in files.items():
        if not isinstance(info, dict):
            continue
        entries.append({
            'type': 'file',
            'name': name,
            'path': name,
            'size': int(info.get('size') or 0),
            'download_url': info.get('raw_url') or '',
        })
    picked = _pick_repo_file(entries, prefer_name=None, provider='GitHub gist')
    download_url = (picked.get('download_url') or '').strip()
    if not download_url:
        raise DownloadError(f'GitHub gist {gist_id} file has no raw URL')

    resolved = dict(meta)
    resolved.update({
        'path': picked.get('name') or picked.get('path'),
        'download_url': download_url,
        'needs_resolve': False,
        'source_type': 'github_gist_resolved',
        'resolved_from_repo': True,
        'resolved_file': picked.get('name'),
        'resolved_size': picked.get('size'),
    })
    return resolved


async def resolve_gitlab_project_url(meta: dict) -> dict:
    """Resolve GitLab project / tree URL to a concrete raw file download."""
    if not meta.get('needs_resolve'):
        return meta
    host = (meta.get('host') or 'gitlab.com').strip()
    project = (meta.get('project') or '').strip().strip('/')
    if not project:
        raise DownloadError('Invalid GitLab project URL')

    api_base = f'https://{host}/api/v4'
    custom = (os.getenv('GITLAB_BASE_URL') or '').strip().rstrip('/')
    if custom:
        custom_host = urlparse(custom).netloc.lower().split(':', 1)[0]
        if custom_host and host == custom_host:
            api_base = f'{custom}/api/v4'

    headers: dict[str, str] = {'User-Agent': 'RepoTriage'}
    token = _gitlab_token()
    if token:
        headers['PRIVATE-TOKEN'] = token

    project_id = quote(project, safe='')
    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        ref = (meta.get('ref') or meta.get('branch') or '').strip() or None
        if not ref:
            status, proj = await _api_json(client, f'{api_base}/projects/{project_id}', headers)
            if status == 404:
                hint = ' (private project — set GITLAB_TOKEN)' if not token else ''
                raise DownloadError(f'GitLab project not found or inaccessible: {project}{hint}')
            if status in {401, 403}:
                raise DownloadError(
                    f'GitLab API rejected project lookup for {project} (HTTP {status}). '
                    'Check GITLAB_TOKEN.'
                )
            if status >= 400 or not isinstance(proj, dict):
                raise DownloadError(f'GitLab project lookup failed for {project} (HTTP {status})')
            ref = (proj.get('default_branch') or 'main').strip() or 'main'

        dir_path = (meta.get('path') or '').strip('/')
        tree_url = f'{api_base}/projects/{project_id}/repository/tree?ref={quote(ref, safe="")}&per_page=100'
        if dir_path:
            tree_url += f'&path={quote(dir_path, safe="")}'

        status, listing = await _api_json(client, tree_url, headers)
        if status == 404:
            raise DownloadError(
                f'GitLab path not found in {project} @ {ref}'
                + (f' ({dir_path})' if dir_path else '')
            )
        if status in {401, 403}:
            raise DownloadError(f'GitLab repository tree rejected for {project} (HTTP {status})')
        if status >= 400:
            raise DownloadError(f'GitLab repository tree failed for {project} (HTTP {status})')
        if not isinstance(listing, list):
            raise DownloadError(f'Unexpected GitLab tree response for {project}')

        prefer = (meta.get('repo') or project.split('/')[-1] or '').strip()
        picked = _pick_repo_file(listing, prefer_name=prefer, provider='GitLab')
        file_path = (picked.get('path') or picked.get('name') or '').strip()
        if dir_path and file_path and not file_path.startswith(dir_path):
            file_path = f'{dir_path.rstrip("/")}/{file_path}'
        if not file_path:
            raise DownloadError(f'Could not resolve a file path in {project}')

    download_url = _gitlab_raw_url(host, project, ref, file_path)
    resolved = dict(meta)
    resolved.update({
        'ref': ref,
        'branch': ref,
        'path': file_path,
        'download_url': download_url,
        'needs_resolve': False,
        'source_type': f"{meta.get('source_type') or 'gitlab_project'}_resolved",
        'resolved_from_repo': True,
        'resolved_file': file_path,
    })
    return resolved


def _github_contents_api_url(meta: dict) -> str | None:
    owner = meta.get('owner')
    repo = meta.get('repo')
    path = meta.get('path')
    if not owner or not repo or not path:
        return None
    if meta.get('source_type') in {
        'github_release_asset', 'github_archive', 'github_gist_raw',
        'github_gist', 'github_gist_resolved',
    }:
        return None
    if meta.get('gist_id') and 'gist' in str(meta.get('source_type') or ''):
        return None
    encoded_path = quote(str(path), safe='/')
    api_url = f'https://api.github.com/repos/{owner}/{repo}/contents/{encoded_path}'
    branch = meta.get('branch')
    if branch:
        api_url += f'?ref={quote(str(branch), safe="")}'
    return api_url


def _download_headers(meta: dict, *, via_contents_api: bool = False) -> dict[str, str]:
    provider = meta.get('provider')
    if provider == 'gitlab':
        token = _gitlab_token()
        return {'PRIVATE-TOKEN': token} if token else {}
    if provider == 'github':
        headers: dict[str, str] = {'User-Agent': 'RepoTriage'}
        if via_contents_api:
            headers['Accept'] = 'application/vnd.github.raw'
            headers['X-GitHub-Api-Version'] = '2022-11-28'
        token = _github_token()
        if token:
            headers['Authorization'] = f'Bearer {token}'
        return headers
    return {}


def _resolve_download_target(meta: dict) -> tuple[str, dict[str, str], str]:
    if meta.get('provider') == 'github' and _github_token():
        api_url = _github_contents_api_url(meta)
        if api_url:
            headers = _download_headers(meta, via_contents_api=True)
            return api_url, headers, 'github_contents_api'
    return meta['download_url'], _download_headers(meta), meta.get('source_type') or 'direct'


def _github_raw_fallback_target(meta: dict) -> tuple[str, dict[str, str], str] | None:
    """Public/raw URL fallback when Contents API rejects the token (403/401)."""
    raw = (meta.get('download_url') or '').strip()
    if not raw or meta.get('provider') != 'github':
        return None
    # Prefer unauthenticated raw for public files — avoids bad/limited PAT 403s.
    return raw, {'User-Agent': 'RepoTriage'}, 'github_raw_fallback'


def _http_error_message(meta: dict, status_code: int, *, via: str) -> str:
    provider = meta.get('provider') or 'source'
    if provider == 'gitlab':
        if status_code == 401:
            return 'GitLab download failed: HTTP 401 (private repo — set GITLAB_TOKEN)'
        if status_code == 403:
            return 'GitLab download failed: HTTP 403 (access denied — check GITLAB_TOKEN or permissions)'
        return f'GitLab download failed: HTTP {status_code}'
    if provider == 'github':
        has_token = bool(_github_token())
        if status_code == 401:
            return 'GitHub download failed: HTTP 401 (set GITHUB_TOKEN with repo scope)'
        if status_code == 403:
            return 'GitHub download failed: HTTP 403 (token lacks access, or rate limited)'
        if status_code == 404:
            if not has_token:
                return (
                    'GitHub download failed: HTTP 404 '
                    '(file missing, or private repo — set GITHUB_TOKEN)'
                )
            return (
                'GitHub download failed: HTTP 404 '
                '(file missing, wrong ref, or token cannot access this repo)'
            )
        if via == 'github_contents_api':
            return f'GitHub Contents API failed: HTTP {status_code}'
        return f'GitHub download failed: HTTP {status_code}'
    return f'Download failed: HTTP {status_code}'


def safe_filename(name: str) -> str:
    name = unquote(name.split('/')[-1] or 'sample.bin')
    return re.sub(r'[^A-Za-z0-9._-]+', '_', name)[:180] or 'sample.bin'


async def download_file(url: str, out_dir: str | Path = 'downloads', max_bytes: int | None = None) -> dict:
    meta = normalize_file_url(url)
    if meta.get('needs_resolve'):
        if meta.get('provider') == 'github':
            meta = await resolve_github_repo_url(meta)
        elif meta.get('provider') == 'gitlab':
            meta = await resolve_gitlab_project_url(meta)

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    max_bytes = max_bytes or int(os.getenv('MAX_DOWNLOAD_BYTES', '50000000'))
    filename = safe_filename(meta.get('path') or meta.get('repo') or 'sample.bin')
    out_path = out_dir / f'{uuid.uuid4().hex}_{filename}'

    if not meta.get('download_url') and not _github_contents_api_url(meta):
        raise DownloadError('Could not resolve a downloadable file from the provided URL')

    download_url, headers, via = _resolve_download_target(meta)
    source_host = urlparse(meta['display_url']).netloc.lower().split(':', 1)[0]
    attempts: list[tuple[str, dict[str, str], str]] = [(download_url, headers, via)]
    raw_fallback = _github_raw_fallback_target(meta)
    if via == 'github_contents_api' and raw_fallback:
        attempts.append(raw_fallback)

    last_status = 0
    last_via = via
    async with httpx.AsyncClient(follow_redirects=True, timeout=45) as client:
        for attempt_url, attempt_headers, attempt_via in attempts:
            last_via = attempt_via
            downloaded = 0
            async with client.stream('GET', attempt_url, headers=attempt_headers) as resp:
                final_host = urlparse(str(resp.url)).netloc.lower().split(':', 1)[0]
                if not _allowed_download_host(final_host, source_host=source_host):
                    provider = meta.get('provider') or 'source'
                    raise DownloadError(
                        f'Download blocked: redirect left allowed {provider} hosts ({final_host})'
                    )
                if resp.status_code >= 400:
                    last_status = resp.status_code
                    # Contents API 401/403 with a limited/broken PAT → try public raw once.
                    if (
                        attempt_via == 'github_contents_api'
                        and resp.status_code in {401, 403}
                        and len(attempts) > 1
                    ):
                        continue
                    raise DownloadError(_http_error_message(meta, resp.status_code, via=attempt_via))
                with out_path.open('wb') as f:
                    async for chunk in resp.aiter_bytes(1024 * 256):
                        downloaded += len(chunk)
                        if downloaded > max_bytes:
                            try:
                                out_path.unlink(missing_ok=True)
                            except Exception:
                                pass
                            raise DownloadError(f'File exceeds safety limit of {max_bytes} bytes')
                        f.write(chunk)
            meta.update({
                'local_path': str(out_path),
                'filename': filename,
                'downloaded_bytes': downloaded,
                'download_via': attempt_via,
                'resolved_download_url': (
                    attempt_url if attempt_via != 'github_contents_api'
                    else attempt_url.split('?', 1)[0]
                ),
            })
            return meta

    raise DownloadError(_http_error_message(meta, last_status or 403, via=last_via))
