from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.modules.repo_hunt.config import RepoHuntConfig  # noqa: E402
from app.modules.repo_hunt.discovery.repo_commit_scan import (  # noqa: E402
    RULE_ID,
    select_newest_files,
)
from app.modules.repo_hunt.pipeline import run_repo_hunt  # noqa: E402
from app.modules.repo_hunt.state import HuntState  # noqa: E402
from app.modules.repo_hunt.types import Candidate  # noqa: E402


class TestSelectNewestFiles(unittest.TestCase):
    def test_keeps_newest_unique_paths(self):
        commits = [
            {
                'sha': 'aaa',
                'commit': {'committer': {'date': '2026-08-13T10:00:00Z'}},
                'files': [
                    {'filename': 'drop/Wu_Receipt.7z', 'status': 'added'},
                    {'filename': 'README.md', 'status': 'modified'},
                ],
            },
            {
                'sha': 'bbb',
                'commit': {'committer': {'date': '2026-08-13T09:00:00Z'}},
                'files': [
                    {'filename': 'older.bin', 'status': 'added'},
                    {'filename': 'README.md', 'status': 'modified'},  # already seen
                    {'filename': 'gone.exe', 'status': 'removed'},
                ],
            },
            {
                'sha': 'ccc',
                'commit': {'committer': {'date': '2026-08-13T08:00:00Z'}},
                'files': [
                    {'filename': 'a.bin', 'status': 'added'},
                    {'filename': 'b.bin', 'status': 'added'},
                    {'filename': 'c.bin', 'status': 'added'},
                ],
            },
        ]
        chosen = select_newest_files(commits, newest_files=5)
        paths = [x['path'] for x in chosen]
        self.assertEqual(paths, [
            'drop/Wu_Receipt.7z',
            'README.md',
            'older.bin',
            'a.bin',
            'b.bin',
        ])
        self.assertNotIn('gone.exe', paths)
        self.assertEqual(chosen[0]['sha'], 'aaa')


class TestFinancialRepoWatchPipeline(unittest.IsolatedAsyncioTestCase):
    async def test_emails_on_vt_malicious_without_filename_tokens(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            payload = b'PK\x03\x04fake-archive-bytes'

            async def fake_download(url, out_dir):
                out = Path(out_dir)
                out.mkdir(parents=True, exist_ok=True)
                path = out / 'Wu_Receipt_System_Screenshot.7z'
                path.write_bytes(payload)
                return {
                    'local_path': str(path),
                    'filename': 'Wu_Receipt_System_Screenshot.7z',
                    'path': 'drop/Wu_Receipt_System_Screenshot.7z',
                }

            async def fake_vt(sha256, hit, cfg, *, base_dir=None):
                hit.vt_confirm = {
                    'status': 'found',
                    'verdict': 'malicious',
                    'malicious': 2,
                    'permalink': f'https://www.virustotal.com/gui/file/{sha256}',
                    'names': ['Wu_Receipt_System_Screenshot.7z'],
                }
                hit.notes = list(hit.notes) + ['VT confirm: verdict=malicious']
                return hit

            cand = Candidate(
                url='https://github.com/evil/wu_receipt_bait/blob/abc/drop/Wu_Receipt_System_Screenshot.7z',
                source='financial_repo_watch',
                path='drop/Wu_Receipt_System_Screenshot.7z',
                repo='evil/wu_receipt_bait',
                html_url='https://github.com/evil/wu_receipt_bait/blob/abc/drop/Wu_Receipt_System_Screenshot.7z',
                sha='abc',
                extra={
                    'repo_watch_file': True,
                    'query': 'wu_receipt in:name,description',
                    'name': 'Wu_Receipt_System_Screenshot.7z',
                },
            )

            cfg = RepoHuntConfig(
                enabled=True,
                min_bytes=500 * 1024,
                max_bytes=1024 * 1024,
                github_token='tok',
                github_orgs=[],
                github_users=[],
                search_query='x',
                extra_search_queries=[],
                search_max_results=5,
                wu_hunt_enabled=True,
                wu_repo_search_queries=[],
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
                 patch('app.modules.repo_hunt.pipeline.expand_financial_repos', new=AsyncMock(return_value=[cand])), \
                 patch('app.modules.repo_hunt.pipeline.discover_watched_orgs_users', new=AsyncMock(return_value=[])), \
                 patch('app.modules.repo_hunt.pipeline.discover_webhook_queue', return_value=[]), \
                 patch('app.modules.repo_hunt.pipeline.download_file', new=AsyncMock(side_effect=fake_download)), \
                 patch('app.modules.repo_hunt.pipeline.confirm_with_virustotal', new=AsyncMock(side_effect=fake_vt)):
                report = await run_repo_hunt(base, cfg=cfg, send=False)

            self.assertTrue(report['ok'])
            self.assertEqual(report['financial_repo_files'], 1)
            self.assertEqual(report['wu_findings'], 1)
            self.assertEqual(report['new_findings'], 1)
            self.assertEqual(report['findings'][0]['detection']['rule'], RULE_ID)
            self.assertEqual(report['findings'][0]['filename'], 'Wu_Receipt_System_Screenshot.7z')
            # Filename has no LiveHunt mtcn_/westernunion token — still alerted.
            self.assertTrue(HuntState(base).is_seen(report['findings'][0]['sha256']))


if __name__ == '__main__':
    unittest.main()
