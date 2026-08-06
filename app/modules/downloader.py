from __future__ import annotations
from pathlib import Path
from urllib.parse import urlparse, unquote, quote
import os, re, uuid
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
    'gitlab.com',
    'www.gitlab.com',
})

_GITLAB_BLOB_MARKER = '/-/blob/'
_GITLAB_RAW_MARKER = '/-/raw/'


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


def _split_gitlab_ref_and_path(segments: list[str]) -> tuple[str, str]:
    if len(segments) < 2:
        raise DownloadError('Invalid GitLab file URL: missing ref or file path')
    if len(segments) >= 3 and segments[0] == 'refs' and segments[1] == 'heads':
        ref = '/'.join(segments[:3])
        file_path = '/'.join(segments[3:])
    else:
        ref = segments[0]
        file_path = '/'.join(segments[1:])
    if not ref or not file_path:
        raise DownloadError('Invalid GitLab file URL: missing ref or file path')
    return ref, file_path


def _gitlab_owner_repo(project_path: str) -> tuple[str, str]:
    """Split GitLab project path into owner (group/namespace) + repo (last segment)."""
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


def normalize_gitlab_file_url(url: str) -> dict:
    url = url.strip()
    parsed = urlparse(url)
    host = parsed.netloc.lower().split(':', 1)[0]
    path = parsed.path

    if not _is_gitlab_host(host):
        raise DownloadError('GitLab host is not allowed. Configure GITLAB_BASE_URL for self-hosted instances.')

    marker = None
    if _GITLAB_BLOB_MARKER in path:
        marker = _GITLAB_BLOB_MARKER
    elif _GITLAB_RAW_MARKER in path:
        marker = _GITLAB_RAW_MARKER
    else:
        raise DownloadError('Only GitLab blob and raw file URLs are supported')

    prefix, rest = path.split(marker, 1)
    project_path = prefix.strip('/')
    if not project_path:
        raise DownloadError('Invalid GitLab file URL: missing project path')

    ref, file_path = _split_gitlab_ref_and_path([part for part in rest.strip('/').split('/') if part])
    raw_url = _gitlab_raw_url(host, project_path, ref, file_path)
    source_type = 'gitlab_blob' if marker == _GITLAB_BLOB_MARKER else 'gitlab_raw'
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
        'download_url': raw_url,
        'display_url': url,
    }


_ARCHIVE_SUFFIXES = (
    '.7z', '.zip', '.rar', '.tar', '.tar.gz', '.tgz', '.gz', '.bz2', '.xz', '.cab',
    '.iso', '.img', '.dmg', '.apk', '.msi', '.exe', '.dll', '.js', '.vbs', '.ps1',
    '.bat', '.cmd', '.scr', '.jar', '.war', '.doc', '.docm', '.xls', '.xlsm', '.pptm',
)
_SKIP_ROOT_NAMES = frozenset({
    'readme', 'readme.md', 'readme.txt', 'license', 'license.md', 'licence', 'licence.md',
    '.gitignore', '.gitattributes', '.editorconfig', 'code_of_conduct.md', 'security.md',
    'contributing.md', 'changelog.md', 'changes.md',
})


def _looks_like_payload_name(name: str) -> bool:
    n = (name or '').lower()
    return any(n.endswith(suf) for suf in _ARCHIVE_SUFFIXES)


def _pick_github_repo_file(entries: list, *, prefer_name: str | None = None) -> dict:
    """Choose a single downloadable payload from a GitHub Contents API directory listing."""
    files = [e for e in entries if isinstance(e, dict) and e.get('type') == 'file' and e.get('name')]
    if not files:
        raise DownloadError('GitHub repository root has no downloadable files (only directories?). Paste a blob/raw file URL.')

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
        'GitHub repository has multiple files — paste a specific blob/raw URL. '
        f'Root candidates: {names}'
    )


def normalize_github_file_url(url: str) -> dict:
    url = url.strip()
    parsed = urlparse(url)
    host = parsed.netloc.lower().split(':', 1)[0]
    path = parsed.path

    if host == 'raw.githubusercontent.com':
        parts = path.strip('/').split('/')
        if len(parts) < 4:
            raise DownloadError('Invalid raw.githubusercontent.com URL')
        owner, repo, branch = parts[0], parts[1], parts[2]
        file_path = '/'.join(parts[3:])
        return {
            'provider': 'github',
            'source_type': 'github_raw',
            'owner': owner,
            'repo': repo,
            'branch': branch,
            'path': file_path,
            'download_url': url,
            'display_url': url,
        }

    if host in {'github.com', 'www.github.com'}:
        parts = [p for p in path.strip('/').split('/') if p]
        if len(parts) >= 5 and parts[2] == 'blob':
            owner, repo, branch = parts[0], parts[1], parts[3]
            file_path = '/'.join(parts[4:])
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
        if len(parts) >= 7 and parts[2] == 'raw' and parts[3] == 'refs' and parts[4] == 'heads':
            owner, repo, branch = parts[0], parts[1], parts[5]
            file_path = '/'.join(parts[6:])
            raw = f'https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}'
            return {
                'provider': 'github',
                'source_type': 'github_raw_refs_heads',
                'owner': owner,
                'repo': repo,
                'branch': branch,
                'path': file_path,
                'download_url': raw,
                'display_url': url,
            }
        if len(parts) >= 5 and parts[2] == 'raw':
            owner, repo, branch = parts[0], parts[1], parts[3]
            file_path = '/'.join(parts[4:])
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
        if len(parts) >= 5 and parts[2] == 'releases' and parts[3] == 'download':
            owner = parts[0]
            repo = parts[1]
            file_path = parts[-1] if parts else 'download.bin'
            return {
                'provider': 'github',
                'source_type': 'github_release_asset',
                'owner': owner,
                'repo': repo,
                'branch': None,
                'path': file_path,
                'download_url': url,
                'display_url': url,
            }
        # github.com/owner/repo[/] — resolve via API to a root payload file
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
        # github.com/owner/repo/tree/<ref>[/subdir...]
        if len(parts) >= 4 and parts[2] == 'tree':
            owner, repo = parts[0], parts[1]
            rest = parts[3:]
            if len(rest) >= 3 and rest[0] == 'refs' and rest[1] == 'heads':
                branch = '/'.join(rest[:3])
                subpath = '/'.join(rest[3:])
            else:
                branch = rest[0]
                subpath = '/'.join(rest[1:])
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

    raise DownloadError(
        'Unsupported GitHub URL format. Use a file blob/raw URL, a release asset URL, '
        'or a repository URL (https://github.com/owner/repo).'
    )


async def _github_api_json(client: httpx.AsyncClient, url: str, headers: dict[str, str]) -> tuple[int, dict | list]:
    resp = await client.get(url, headers=headers)
    try:
        payload = resp.json()
    except Exception:
        payload = {}
    return resp.status_code, payload


async def resolve_github_repo_url(meta: dict) -> dict:
    """Resolve github.com/owner/repo (or /tree/...) to a concrete file download target."""
    if not meta.get('needs_resolve'):
        return meta
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
            status, repo_info = await _github_api_json(
                client, f'https://api.github.com/repos/{owner}/{repo}', headers
            )
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

        status, listing = await _github_api_json(client, contents_url, headers)
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
            picked = _pick_github_repo_file(listing, prefer_name=repo)
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


def normalize_file_url(url: str) -> dict:
    url = url.strip()
    if not url:
        raise DownloadError('file_url is required')
    parsed = urlparse(url)
    host = parsed.netloc.lower().split(':', 1)[0]
    path = parsed.path

    if _is_gitlab_host(host) or _GITLAB_BLOB_MARKER in path or _GITLAB_RAW_MARKER in path:
        return normalize_gitlab_file_url(url)
    return normalize_github_file_url(url)


def _github_token() -> str:
    return (os.getenv('GITHUB_TOKEN') or os.getenv('GH_TOKEN') or '').strip()


def _gitlab_token() -> str:
    return (os.getenv('GITLAB_TOKEN') or '').strip()


def _github_contents_api_url(meta: dict) -> str | None:
    """Build GitHub Contents API URL for blob/raw file metadata."""
    owner = meta.get('owner')
    repo = meta.get('repo')
    path = meta.get('path')
    if not owner or not repo or not path:
        return None
    if meta.get('source_type') == 'github_release_asset':
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
    """
    Choose download URL + headers.

    Private GitHub repos require Contents API + GITHUB_TOKEN.
    Public GitHub keeps raw.githubusercontent.com (no token needed).
    """
    if meta.get('provider') == 'github' and _github_token():
        api_url = _github_contents_api_url(meta)
        if api_url:
            headers = _download_headers(meta, via_contents_api=True)
            return api_url, headers, 'github_contents_api'
    return meta['download_url'], _download_headers(meta), meta.get('source_type') or 'direct'


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
    if meta.get('needs_resolve') and meta.get('provider') == 'github':
        meta = await resolve_github_repo_url(meta)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    max_bytes = max_bytes or int(os.getenv('MAX_DOWNLOAD_BYTES', '50000000'))
    filename = safe_filename(meta.get('path') or meta.get('repo') or 'sample.bin')
    out_path = out_dir / f'{uuid.uuid4().hex}_{filename}'

    if not meta.get('download_url') and not _github_contents_api_url(meta):
        raise DownloadError('Could not resolve a downloadable file from the provided URL')

    download_url, headers, via = _resolve_download_target(meta)
    source_host = urlparse(meta['display_url']).netloc.lower().split(':', 1)[0]
    downloaded = 0
    async with httpx.AsyncClient(follow_redirects=True, timeout=45) as client:
        async with client.stream('GET', download_url, headers=headers) as resp:
            final_host = urlparse(str(resp.url)).netloc.lower().split(':', 1)[0]
            if not _allowed_download_host(final_host, source_host=source_host):
                provider = meta.get('provider') or 'source'
                raise DownloadError(f'Download blocked: redirect left allowed {provider} hosts ({final_host})')
            if resp.status_code >= 400:
                raise DownloadError(_http_error_message(meta, resp.status_code, via=via))
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
        'download_via': via,
        'resolved_download_url': download_url if via != 'github_contents_api' else download_url.split('?', 1)[0],
    })
    return meta
