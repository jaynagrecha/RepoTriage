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
