import os
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.modules.http_client import ssl_verify  # noqa: E402
from app.modules.repo_hunt.config import RepoHuntConfig  # noqa: E402
from app.modules.repo_hunt.discovery import github_search  # noqa: E402
from app.modules.repo_hunt.pipeline import collect_candidates  # noqa: E402
from app.modules.repo_hunt.state import HuntState  # noqa: E402


class TestSslVerify(unittest.TestCase):
    def test_prefer_certifi_by_default(self):
        with patch.dict(os.environ, {'HTTPX_PREFER_CERTIFI': 'true'}, clear=False):
            os.environ.pop('HTTPX_VERIFY', None)
            os.environ.pop('SSL_VERIFY', None)
            value = ssl_verify()
        self.assertIsInstance(value, str)
        self.assertTrue(Path(value).is_file())

    def test_explicit_disable(self):
        with patch.dict(os.environ, {'HTTPX_VERIFY': 'false'}, clear=False):
            self.assertIs(ssl_verify(), False)


class TestGithubSearchSoftFail(unittest.IsolatedAsyncioTestCase):
    async def test_ssl_error_returns_empty(self):
        cfg = replace(
            RepoHuntConfig.from_env(),
            github_token='tok',
            search_query='extension:js',
            extra_search_queries=[],
        )

        class BoomClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            async def get(self, *args, **kwargs):
                raise github_search.httpx.ConnectError(
                    '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate'
                )

        with patch('app.modules.repo_hunt.discovery.github_search.async_client', return_value=BoomClient()):
            out = await github_search.discover_github_code_search(cfg)
        self.assertEqual(out, [])


class TestCollectCandidatesSoftFail(unittest.IsolatedAsyncioTestCase):
    async def test_discovery_errors_do_not_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            state = HuntState(base)
            cfg = replace(RepoHuntConfig.from_env(), github_token='tok', enabled=True)

            async def boom(*args, **kwargs):
                raise RuntimeError('ssl boom')

            with patch('app.modules.repo_hunt.pipeline.discover_github_code_search', side_effect=boom), \
                 patch('app.modules.repo_hunt.pipeline.discover_wu_github_repos', new=AsyncMock(return_value=[])), \
                 patch('app.modules.repo_hunt.pipeline.expand_financial_repos', new=AsyncMock(return_value=[])), \
                 patch('app.modules.repo_hunt.pipeline.discover_wu_gitlab_projects', new=AsyncMock(return_value=[])), \
                 patch('app.modules.repo_hunt.pipeline.expand_financial_gitlab_repos', new=AsyncMock(return_value=[])), \
                 patch('app.modules.repo_hunt.pipeline.discover_watched_orgs_users', new=AsyncMock(return_value=[])), \
                 patch('app.modules.repo_hunt.pipeline.discover_webhook_queue', return_value=[]):
                candidates, sources, errors = await collect_candidates(cfg, state)
            self.assertEqual(candidates, [])
            self.assertTrue(any('ssl boom' in e for e in errors))
            self.assertEqual(sources.get('discovery_errors'), 1)


if __name__ == '__main__':
    unittest.main()
