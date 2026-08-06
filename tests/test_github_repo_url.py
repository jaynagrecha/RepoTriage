import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.modules.downloader import (  # noqa: E402
    DownloadError,
    _pick_github_repo_file,
    download_file,
    normalize_github_file_url,
    resolve_github_repo_url,
)


class TestGitHubRepoUrlNormalize(unittest.TestCase):
    def test_repo_root_url(self):
        meta = normalize_github_file_url('https://github.com/prestige005/mtcn_details_jpg.7z')
        self.assertEqual(meta['source_type'], 'github_repo')
        self.assertEqual(meta['owner'], 'prestige005')
        self.assertEqual(meta['repo'], 'mtcn_details_jpg.7z')
        self.assertTrue(meta['needs_resolve'])

    def test_tree_url(self):
        meta = normalize_github_file_url('https://github.com/acme/drop/tree/main/payloads')
        self.assertEqual(meta['source_type'], 'github_tree')
        self.assertEqual(meta['branch'], 'main')
        self.assertEqual(meta['path'], 'payloads')
        self.assertTrue(meta['needs_resolve'])

    def test_www_github_repo(self):
        meta = normalize_github_file_url('https://www.github.com/acme/tool.zip')
        self.assertEqual(meta['owner'], 'acme')
        self.assertEqual(meta['repo'], 'tool.zip')


class TestPickRepoFile(unittest.TestCase):
    def test_prefer_repo_name_match(self):
        entries = [
            {'type': 'file', 'name': 'README.md', 'size': 10, 'path': 'README.md'},
            {'type': 'file', 'name': 'mtcn_details_jpg.7z', 'size': 100, 'path': 'mtcn_details_jpg.7z'},
            {'type': 'file', 'name': 'notes.txt', 'size': 5, 'path': 'notes.txt'},
        ]
        picked = _pick_github_repo_file(entries, prefer_name='mtcn_details_jpg.7z')
        self.assertEqual(picked['name'], 'mtcn_details_jpg.7z')

    def test_single_archive(self):
        entries = [
            {'type': 'file', 'name': 'README.md', 'size': 10, 'path': 'README.md'},
            {'type': 'file', 'name': 'drop.zip', 'size': 50, 'path': 'drop.zip'},
        ]
        picked = _pick_github_repo_file(entries, prefer_name='other')
        self.assertEqual(picked['name'], 'drop.zip')

    def test_ambiguous_raises(self):
        entries = [
            {'type': 'file', 'name': 'a.bin', 'size': 1, 'path': 'a.bin'},
            {'type': 'file', 'name': 'b.bin', 'size': 2, 'path': 'b.bin'},
        ]
        with self.assertRaises(DownloadError) as ctx:
            _pick_github_repo_file(entries, prefer_name='nope')
        self.assertIn('multiple files', str(ctx.exception).lower())


class _JsonResp:
    def __init__(self, status_code: int, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class _ResolveClient:
    def __init__(self, routes: dict):
        self.routes = routes

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, url, headers=None):
        for key, resp in self.routes.items():
            if key in str(url):
                return resp
        return _JsonResp(404, {'message': 'Not Found'})


class TestResolveGitHubRepo(unittest.IsolatedAsyncioTestCase):
    @patch.dict(os.environ, {'GITHUB_TOKEN': 'ghp_test'}, clear=False)
    async def test_repo_not_found_message(self):
        meta = normalize_github_file_url('https://github.com/prestige005/mtcn_details_jpg.7z')
        client = _ResolveClient({
            '/repos/prestige005/mtcn_details_jpg.7z': _JsonResp(404, {'message': 'Not Found'}),
        })
        with patch('app.modules.downloader.httpx.AsyncClient', return_value=client):
            with self.assertRaises(DownloadError) as ctx:
                await resolve_github_repo_url(meta)
        self.assertIn('not found or inaccessible', str(ctx.exception).lower())
        self.assertIn('prestige005/mtcn_details_jpg.7z', str(ctx.exception))

    @patch.dict(os.environ, {'GITHUB_TOKEN': 'ghp_test'}, clear=False)
    async def test_resolve_picks_matching_root_file(self):
        meta = normalize_github_file_url('https://github.com/prestige005/mtcn_details_jpg.7z')
        client = _ResolveClient({
            '/repos/prestige005/mtcn_details_jpg.7z/contents': _JsonResp(200, [
                {'type': 'file', 'name': 'README.md', 'path': 'README.md', 'size': 12, 'download_url': 'https://raw.githubusercontent.com/prestige005/mtcn_details_jpg.7z/main/README.md'},
                {
                    'type': 'file',
                    'name': 'mtcn_details_jpg.7z',
                    'path': 'mtcn_details_jpg.7z',
                    'size': 999,
                    'download_url': 'https://raw.githubusercontent.com/prestige005/mtcn_details_jpg.7z/main/mtcn_details_jpg.7z',
                },
            ]),
            '/repos/prestige005/mtcn_details_jpg.7z': _JsonResp(200, {'default_branch': 'main'}),
        })
        with patch('app.modules.downloader.httpx.AsyncClient', return_value=client):
            resolved = await resolve_github_repo_url(meta)
        self.assertEqual(resolved['path'], 'mtcn_details_jpg.7z')
        self.assertEqual(resolved['branch'], 'main')
        self.assertTrue(resolved['resolved_from_repo'])
        self.assertFalse(resolved.get('needs_resolve'))


if __name__ == '__main__':
    unittest.main()
