import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.main import build_summary  # noqa: E402
from app.modules.vt_lookup import lookup_file_hash  # noqa: E402


class _FakeResp:
    def __init__(self, status_code: int, payload: dict | None = None, headers: dict | None = None):
        self.status_code = status_code
        self._payload = payload or {}
        self.headers = headers or {}

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self, resp: _FakeResp):
        self._resp = resp

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, *args, **kwargs):
        return self._resp


class TestVtSoftFail(unittest.IsolatedAsyncioTestCase):
    @patch.dict(os.environ, {'VT_API_KEY': 'vt-test-key'}, clear=False)
    async def test_rate_limit_returns_status_not_raise(self):
        resp = _FakeResp(429, headers={'Retry-After': '60'})
        with tempfile.TemporaryDirectory() as tmp:
            with patch('app.modules.vt_lookup.httpx.AsyncClient', return_value=_FakeClient(resp)):
                result = await lookup_file_hash('a' * 64, Path(tmp))
        self.assertEqual(result['status'], 'rate_limited')
        self.assertIn('rate limit', result['message'].lower())
        self.assertEqual(result['verdict'], 'unknown')

    @patch.dict(os.environ, {'VT_API_KEY': 'vt-test-key'}, clear=False)
    async def test_auth_error_returns_status_not_raise(self):
        resp = _FakeResp(401)
        with tempfile.TemporaryDirectory() as tmp:
            with patch('app.modules.vt_lookup.httpx.AsyncClient', return_value=_FakeClient(resp)):
                result = await lookup_file_hash('b' * 64, Path(tmp))
        self.assertEqual(result['status'], 'auth_error')
        self.assertIn('VT_API_KEY', result['message'])

    def test_build_summary_mentions_rate_limit(self):
        text = build_summary(
            {'filename': 'main.py'},
            {'sha256': 'abc'},
            'Python script',
            {'status': 'rate_limited', 'message': 'VirusTotal API rate limit reached', 'verdict': 'unknown'},
        )
        self.assertIn('rate limit', text.lower())
        self.assertNotIn('VirusTotal verdict:', text)


if __name__ == '__main__':
    unittest.main()
