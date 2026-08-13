import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.modules.downloader import (  # noqa: E402
    DownloadError,
    _github_contents_api_url,
    _http_error_message,
    _resolve_download_target,
    download_file,
    normalize_github_file_url,
)


class TestGitHubContentsApi(unittest.TestCase):
    def test_contents_api_url_from_blob(self):
        meta = normalize_github_file_url(
            'https://github.com/jaynagrecha/ak47/blob/main/main.py'
        )
        self.assertEqual(
            _github_contents_api_url(meta),
            'https://api.github.com/repos/jaynagrecha/ak47/contents/main.py?ref=main',
        )

    def test_contents_api_url_nested_path(self):
        meta = normalize_github_file_url(
            'https://github.com/acme/tools/blob/develop/src/a b/payload.bin'
        )
        url = _github_contents_api_url(meta)
        self.assertIn('/contents/src/a%20b/payload.bin?', url)
        self.assertTrue(url.endswith('ref=develop'))

    def test_release_asset_skips_contents_api(self):
        meta = normalize_github_file_url(
            'https://github.com/acme/tools/releases/download/v1/tool.exe'
        )
        self.assertIsNone(_github_contents_api_url(meta))

    @patch.dict(os.environ, {'GITHUB_TOKEN': 'ghp_test_token'}, clear=False)
    def test_resolve_uses_contents_api_when_token_set(self):
        meta = normalize_github_file_url(
            'https://github.com/jaynagrecha/ak47/blob/main/main.py'
        )
        url, headers, via = _resolve_download_target(meta)
        self.assertEqual(via, 'github_contents_api')
        self.assertTrue(url.startswith('https://api.github.com/repos/'))
        self.assertEqual(headers.get('Authorization'), 'Bearer ghp_test_token')
        self.assertEqual(headers.get('Accept'), 'application/vnd.github.raw')

    @patch.dict(os.environ, {'GITHUB_TOKEN': ''}, clear=False)
    def test_resolve_uses_raw_without_token(self):
        meta = normalize_github_file_url(
            'https://github.com/jaynagrecha/ak47/blob/main/main.py'
        )
        url, headers, via = _resolve_download_target(meta)
        self.assertEqual(via, 'github_blob')
        self.assertTrue(url.startswith('https://raw.githubusercontent.com/'))
        self.assertNotIn('Authorization', headers)

    @patch.dict(os.environ, {}, clear=False)
    def test_404_without_token_mentions_github_token(self):
        meta = {'provider': 'github'}
        with patch('app.modules.downloader._github_token', return_value=''):
            msg = _http_error_message(meta, 404, via='github_blob')
        self.assertIn('GITHUB_TOKEN', msg)
        self.assertIn('404', msg)


class _FakeStreamResp:
    def __init__(self, status_code: int, chunks: list[bytes], final_url: str):
        self.status_code = status_code
        self._chunks = chunks
        self.url = final_url

    async def aiter_bytes(self, _size: int):
        for chunk in self._chunks:
            yield chunk

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


class _FakeClient:
    def __init__(self, resp: _FakeStreamResp):
        self._resp = resp

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    def stream(self, method, url, headers=None):
        self.method = method
        self.url = url
        self.headers = headers or {}
        return self._resp


class _FakeMultiClient:
    """Stream client that returns different responses per URL."""

    def __init__(self, by_url: dict[str, _FakeStreamResp], default: _FakeStreamResp | None = None):
        self._by_url = by_url
        self._default = default
        self.calls: list[tuple[str, dict]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    def stream(self, method, url, headers=None):
        self.calls.append((url, headers or {}))
        resp = self._by_url.get(url) or self._default
        if resp is None:
            raise AssertionError(f'unexpected url {url}')
        # Remember last for assertions
        self.url = url
        self.headers = headers or {}
        return resp


class TestGitHubDownloadIntegration(unittest.IsolatedAsyncioTestCase):
    @patch.dict(os.environ, {'GITHUB_TOKEN': 'ghp_test_token'}, clear=False)
    async def test_download_file_uses_contents_api(self):
        payload = b'print("private")\n'
        resp = _FakeStreamResp(
            200,
            [payload],
            'https://api.github.com/repos/jaynagrecha/ak47/contents/main.py?ref=main',
        )
        client = _FakeClient(resp)
        with tempfile.TemporaryDirectory() as tmp:
            with patch('app.modules.downloader.httpx.AsyncClient', return_value=client):
                meta = await download_file(
                    'https://github.com/jaynagrecha/ak47/blob/main/main.py',
                    out_dir=tmp,
                )
            self.assertEqual(meta['download_via'], 'github_contents_api')
            self.assertEqual(meta['downloaded_bytes'], len(payload))
            self.assertTrue(Path(meta['local_path']).is_file())
            self.assertEqual(Path(meta['local_path']).read_bytes(), payload)
            self.assertEqual(client.headers.get('Authorization'), 'Bearer ghp_test_token')
            self.assertIn('/repos/jaynagrecha/ak47/contents/main.py', client.url)

    @patch.dict(os.environ, {'GITHUB_TOKEN': 'ghp_test_token'}, clear=False)
    async def test_download_file_falls_back_to_raw_on_contents_403(self):
        payload = b'PK\x03\x04apk-bytes'
        contents_url = 'https://api.github.com/repos/officialappss/moneytransfer/contents/moneytransfer.apk?ref=main'
        raw_url = 'https://raw.githubusercontent.com/officialappss/moneytransfer/main/moneytransfer.apk'
        client = _FakeMultiClient({
            contents_url: _FakeStreamResp(403, [], contents_url),
            raw_url: _FakeStreamResp(200, [payload], raw_url),
        })
        with tempfile.TemporaryDirectory() as tmp:
            with patch('app.modules.downloader.httpx.AsyncClient', return_value=client):
                meta = await download_file(
                    'https://github.com/officialappss/moneytransfer/blob/main/moneytransfer.apk',
                    out_dir=tmp,
                )
            self.assertEqual(meta['download_via'], 'github_raw_fallback')
            self.assertEqual(Path(meta['local_path']).read_bytes(), payload)
            self.assertEqual(len(client.calls), 2)
            self.assertIn('/contents/', client.calls[0][0])
            self.assertTrue(client.calls[1][0].startswith('https://raw.githubusercontent.com/'))

    @patch.dict(os.environ, {'GITHUB_TOKEN': 'ghp_test_token'}, clear=False)
    async def test_download_file_private_404_message(self):
        resp = _FakeStreamResp(
            404,
            [],
            'https://api.github.com/repos/jaynagrecha/ak47/contents/main.py?ref=main',
        )
        client = _FakeClient(resp)
        with tempfile.TemporaryDirectory() as tmp:
            with patch('app.modules.downloader.httpx.AsyncClient', return_value=client):
                with self.assertRaises(DownloadError) as ctx:
                    await download_file(
                        'https://github.com/jaynagrecha/ak47/blob/main/main.py',
                        out_dir=tmp,
                    )
        self.assertIn('404', str(ctx.exception))
        self.assertIn('token cannot access', str(ctx.exception))


if __name__ == '__main__':
    unittest.main()
