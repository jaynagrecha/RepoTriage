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


def normalize_github_file_url(url: str) -> dict:
    url = url.strip()
    parsed = urlparse(url)
    host = parsed.netloc.lower()
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

    if host == 'github.com':
        parts = path.strip('/').split('/')
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
        if 'releases/download' in path:
            owner = parts[0] if len(parts) > 0 else ''
            repo = parts[1] if len(parts) > 1 else ''
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

    raise DownloadError('Unsupported GitHub URL format')


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
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    max_bytes = max_bytes or int(os.getenv('MAX_DOWNLOAD_BYTES', '50000000'))
    filename = safe_filename(meta.get('path') or 'sample.bin')
    out_path = out_dir / f'{uuid.uuid4().hex}_{filename}'

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
