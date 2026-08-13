from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.modules.repo_hunt.config import RepoHuntConfig  # noqa: E402
from app.modules.repo_hunt.discovery.gitlab_search import (  # noqa: E402
    _reject_mtcnn_noise,
    gitlab_diffs_to_commit_payload,
)
from app.modules.repo_hunt.discovery.repo_commit_scan import (  # noqa: E402
    RULE_ID,
    select_newest_files,
)
from app.modules.repo_hunt.pipeline import run_repo_hunt  # noqa: E402
from app.modules.repo_hunt.types import Candidate  # noqa: E402


class TestGitlabDiffAdapt(unittest.TestCase):
    def test_diffs_map_and_select(self):
        payload = gitlab_diffs_to_commit_payload(
            sha='deadbeef',
            committed_date='2026-08-13T12:00:00.000Z',
            diffs=[
                {'new_path': 'drop/Wu_Receipt.7z', 'new_file': True},
                {'new_path': 'README.md', 'deleted_file': False},
                {'old_path': 'gone.bin', 'new_path': 'gone.bin', 'deleted_file': True},
            ],
        )
        chosen = select_newest_files([payload], newest_files=5)
        paths = [x['path'] for x in chosen]
        self.assertEqual(paths, ['drop/Wu_Receipt.7z', 'README.md'])
        self.assertNotIn('gone.bin', paths)

    def test_mtcnn_noise_filter(self):
        self.assertTrue(_reject_mtcnn_noise('mtcn', {
            'path_with_namespace': 'ai/mtcnn-demo',
            'name': 'MTCNN',
            'description': 'face detection',
        }))
        self.assertFalse(_reject_mtcnn_noise('mtcn', {
            'path_with_namespace': 'drop/mtcn-codes',
            'name': 'mtcn',
            'description': 'western union codes',
        }))
        self.assertFalse(_reject_mtcnn_noise('westernunion', {
            'path_with_namespace': 'ai/mtcnn-demo',
            'name': 'x',
            'description': '',
        }))


class TestGitlabFinancialPipeline(unittest.IsolatedAsyncioTestCase):
    async def test_gitlab_repo_watch_file_alerts(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            payload = b'PK\x03\x04gitlab-archive'

            async def fake_download(url, out_dir):
                out = Path(out_dir)
                out.mkdir(parents=True, exist_ok=True)
                path = out / 'Wu_Receipt.7z'
                path.write_bytes(payload)
                return {'local_path': str(path), 'filename': 'Wu_Receipt.7z', 'path': 'drop/Wu_Receipt.7z'}

            async def fake_vt(sha256, hit, cfg, *, base_dir=None):
                hit.vt_confirm = {
                    'status': 'found',
                    'verdict': 'malicious',
                    'malicious': 3,
                    'permalink': f'https://www.virustotal.com/gui/file/{sha256}',
                }
                return hit

            cand = Candidate(
                url='https://gitlab.com/evil/wu_receipt/-/blob/abc/drop/Wu_Receipt.7z',
                source='financial_repo_watch',
                path='drop/Wu_Receipt.7z',
                repo='evil/wu_receipt',
                html_url='https://gitlab.com/evil/wu_receipt/-/blob/abc/drop/Wu_Receipt.7z',
                sha='abc',
                extra={
                    'repo_watch_file': True,
                    'provider': 'gitlab',
                    'query': 'wu_receipt',
                    'name': 'Wu_Receipt.7z',
                },
            )
            cfg = RepoHuntConfig(
                enabled=True,
                min_bytes=500 * 1024,
                max_bytes=1024 * 1024,
                github_token='',
                github_orgs=[],
                github_users=[],
                search_query='x',
                extra_search_queries=[],
                search_max_results=5,
                wu_hunt_enabled=True,
                wu_repo_search_queries=[],
                gitlab_token='glpat-x',
                gitlab_base_url='',
                gitlab_search_terms=['wu_receipt'],
                repo_watch_commits=10,
                repo_watch_newest_files=5,
                vt_confirm=True,
                vt_api_key='vt',
                vt_livehunt_rule_id='',
                vt_livehunt_wu_rule_id='20744291635',
                webhook_secret='',
                smtp_host='',
                smtp_port=587,
                smtp_user='',
                smtp_password='',
                smtp_from='',
                smtp_to='',
                smtp_use_tls=True,
                triage_base_url='https://repotriage.example',
                max_candidates=10,
                max_findings_email=10,
                analysis_alert_email=True,
            )
            with patch('app.modules.repo_hunt.pipeline.discover_github_code_search', new=AsyncMock(return_value=[])), \
                 patch('app.modules.repo_hunt.pipeline.discover_wu_github_repos', new=AsyncMock(return_value=[])), \
                 patch('app.modules.repo_hunt.pipeline.expand_financial_repos', new=AsyncMock(return_value=[])), \
                 patch('app.modules.repo_hunt.pipeline.discover_wu_gitlab_projects', new=AsyncMock(return_value=[])), \
                 patch('app.modules.repo_hunt.pipeline.expand_financial_gitlab_repos', new=AsyncMock(return_value=[cand])), \
                 patch('app.modules.repo_hunt.pipeline.discover_watched_orgs_users', new=AsyncMock(return_value=[])), \
                 patch('app.modules.repo_hunt.pipeline.discover_webhook_queue', return_value=[]), \
                 patch('app.modules.repo_hunt.pipeline.download_file', new=AsyncMock(side_effect=fake_download)), \
                 patch('app.modules.repo_hunt.pipeline.confirm_with_virustotal', new=AsyncMock(side_effect=fake_vt)):
                report = await run_repo_hunt(base, cfg=cfg, send=False)

            self.assertTrue(report['ok'])
            self.assertEqual(report['sources'].get('financial_repo_watch_gitlab'), 1)
            self.assertEqual(report['wu_findings'], 1)
            self.assertEqual(report['findings'][0]['detection']['rule'], RULE_ID)
            self.assertEqual(report['findings'][0]['candidate']['extra'].get('provider'), 'gitlab')


if __name__ == '__main__':
    unittest.main()
