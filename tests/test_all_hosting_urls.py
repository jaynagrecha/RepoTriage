import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.modules.downloader import (  # noqa: E402
    DownloadError,
    normalize_file_url,
    normalize_github_file_url,
    normalize_gitlab_file_url,
    resolve_gitlab_project_url,
)


class TestGitHubAllFileUrlShapes(unittest.TestCase):
    def test_blob_refs_heads(self):
        meta = normalize_github_file_url(
            'https://github.com/acme/tools/blob/refs/heads/main/drop/payload.7z'
        )
        self.assertEqual(meta['branch'], 'main')
        self.assertEqual(meta['path'], 'drop/payload.7z')
        self.assertIn('/main/drop/payload.7z', meta['download_url'])

    def test_raw_refs_heads(self):
        meta = normalize_github_file_url(
            'https://github.com/acme/tools/raw/refs/heads/develop/a.bin'
        )
        self.assertEqual(meta['branch'], 'develop')
        self.assertEqual(meta['path'], 'a.bin')

    def test_latest_release_download(self):
        meta = normalize_github_file_url(
            'https://github.com/acme/tools/releases/latest/download/tool.exe'
        )
        self.assertEqual(meta['source_type'], 'github_release_asset')
        self.assertEqual(meta['path'], 'tool.exe')

    def test_archive_zip(self):
        meta = normalize_github_file_url(
            'https://github.com/acme/tools/archive/refs/heads/main.zip'
        )
        self.assertEqual(meta['source_type'], 'github_archive')
        self.assertTrue(meta['download_url'].endswith('main.zip'))

    def test_gist(self):
        meta = normalize_github_file_url('https://gist.github.com/alice/abcdef123456')
        self.assertEqual(meta['source_type'], 'github_gist')
        self.assertTrue(meta['needs_resolve'])
        self.assertEqual(meta['gist_id'], 'abcdef123456')

    def test_gist_githubusercontent(self):
        meta = normalize_github_file_url(
            'https://gist.githubusercontent.com/alice/abcdef123456/raw/deadbeef/payload.js'
        )
        self.assertEqual(meta['source_type'], 'github_gist_raw')
        self.assertEqual(meta['path'], 'payload.js')


class TestGitLabAllFileUrlShapes(unittest.TestCase):
    def test_project_root(self):
        meta = normalize_file_url('https://gitlab.com/group/sub/project')
        self.assertEqual(meta['provider'], 'gitlab')
        self.assertEqual(meta['project'], 'group/sub/project')
        self.assertTrue(meta['needs_resolve'])

    def test_tree_refs_heads(self):
        meta = normalize_gitlab_file_url(
            'https://gitlab.com/org/repo/-/tree/refs/heads/main/bin'
        )
        self.assertEqual(meta['ref'], 'main')
        self.assertEqual(meta['path'], 'bin')

    def test_blob_still_works(self):
        meta = normalize_file_url('https://gitlab.com/a/b/-/blob/main/x.zip?ref_type=heads')
        self.assertEqual(meta['path'], 'x.zip')
        self.assertFalse(meta.get('needs_resolve'))


class _JsonResp:
    def __init__(self, status_code: int, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class _Client:
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


class TestGitLabResolve(unittest.IsolatedAsyncioTestCase):
    @patch.dict(os.environ, {'GITLAB_TOKEN': 'glpat-test'}, clear=False)
    async def test_resolve_project_picks_archive(self):
        meta = normalize_gitlab_file_url('https://gitlab.com/zohair222/file01')
        client = _Client({
            '/api/v4/projects/zohair222%2Ffile01/repository/tree': _JsonResp(200, [
                {'type': 'blob', 'name': 'README.md', 'path': 'README.md', 'size': 10},
                {'type': 'blob', 'name': 'drop.7z', 'path': 'drop.7z', 'size': 500},
            ]),
            '/api/v4/projects/zohair222%2Ffile01': _JsonResp(200, {'default_branch': 'main'}),
        })
        with patch('app.modules.downloader.httpx.AsyncClient', return_value=client):
            resolved = await resolve_gitlab_project_url(meta)
        self.assertEqual(resolved['path'], 'drop.7z')
        self.assertEqual(resolved['branch'], 'main')
        self.assertIn('/-/raw/main/drop.7z', resolved['download_url'])
        self.assertFalse(resolved.get('needs_resolve'))

    @patch.dict(os.environ, {'GITLAB_TOKEN': ''}, clear=False)
    async def test_project_not_found(self):
        meta = normalize_gitlab_file_url('https://gitlab.com/missing/proj')
        client = _Client({
            '/api/v4/projects/missing%2Fproj': _JsonResp(404, {'message': '404'}),
        })
        with patch('app.modules.downloader.httpx.AsyncClient', return_value=client):
            with self.assertRaises(DownloadError) as ctx:
                await resolve_gitlab_project_url(meta)
        self.assertIn('not found', str(ctx.exception).lower())


if __name__ == '__main__':
    unittest.main()
