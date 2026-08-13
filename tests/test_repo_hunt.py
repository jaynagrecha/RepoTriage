from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.modules.repo_hunt.config import RepoHuntConfig  # noqa: E402
from app.modules.repo_hunt.detect.local_jsoutprox import scan_bytes  # noqa: E402
from app.modules.repo_hunt.notify.smtp_mailer import build_analysis_wu_alert_email, build_findings_email  # noqa: E402
from app.modules.repo_hunt.pipeline import run_repo_hunt  # noqa: E402
from app.modules.repo_hunt.state import HuntState  # noqa: E402
from app.modules.repo_hunt.types import Candidate, DetectionHit, Finding  # noqa: E402


def _jsoutprox_payload(size: int = 520_000) -> bytes:
    core = (
        "var _0xabcd=['x'];"
        "var a=['\\x61'];"
        "eval(function(_0x){return String(parseInt(_0x,16));});"
        "new RegExp('x');"
        "(parseInt(_0x10,16));"
    ).encode()
    pad = b'/' + b'A' * max(0, size - len(core) - 1)
    return core + pad


class TestLocalJsOutProx(unittest.TestCase):
    def test_matches_size_and_strings(self):
        data = _jsoutprox_payload()
        hit = scan_bytes(data, path='dropper.js')
        self.assertIsNotNone(hit)
        assert hit is not None
        self.assertEqual(hit.rule, 'potential_jsoutprox_js')
        self.assertEqual(set(hit.matched_strings), {'s1', 's2', 's3', 's4', 's5', 's6'})

    def test_rejects_small_file(self):
        data = _jsoutprox_payload(size=1000)
        self.assertIsNone(scan_bytes(data, path='tiny.js'))

    def test_rejects_missing_string(self):
        data = _jsoutprox_payload().replace(b'eval(function(_0x', b'eval(function(x')
        self.assertIsNone(scan_bytes(data, path='dropper.js'))


class TestHuntStateQueue(unittest.TestCase):
    def test_webhook_queue_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = HuntState(Path(tmp))
            state.enqueue_webhook({'url': 'https://github.com/a/b/blob/main/x.js', 'src': 'repotrace'})
            items = state.drain_webhook_queue()
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0]['url'], 'https://github.com/a/b/blob/main/x.js')
            self.assertEqual(state.drain_webhook_queue(), [])


class TestSmtpMessage(unittest.TestCase):
    def test_build_email(self):
        cfg = RepoHuntConfig.from_env()
        finding = Finding(
            candidate=Candidate(url='https://github.com/a/b/blob/main/x.js', source='webhook', repo='a/b', path='x.js'),
            sha256='a' * 64,
            filename='x.js',
            detection=DetectionHit(
                rule='potential_jsoutprox_js',
                matched_strings=['s1', 's2', 's3', 's4', 's5', 's6'],
                filesize=520000,
                local_match=True,
                vt_confirm={'status': 'not_found'},
            ),
            triage_url='https://triage.example/?url=1',
        )
        msg = build_findings_email([finding], cfg, run_meta={'sources': {'webhook': 1}, 'candidates': 1, 'local_matches': 1})
        plain = msg.get_body(preferencelist=('plain',)).get_content()
        html = msg.get_body(preferencelist=('html',)).get_content()
        self.assertIn('potential_jsoutprox_js', msg['Subject'])
        self.assertIn('a/b', plain)
        self.assertIn('potential_jsoutprox_js', plain)
        self.assertIn('DETECT_GTI_MaliciousFilesWithWUKeywords', plain)
        self.assertIn('multipart/alternative', msg.get_content_type())
        self.assertIn('RepoTriage', html)
        self.assertIn('Open VirusTotal', html)
        self.assertNotIn('scheduled scan', msg['Subject'])

        wu_msg = build_analysis_wu_alert_email(
            cfg=cfg,
            job_id='scheduled-hunt',
            source_url='repo-hunt-5min-scan',
            hits=[{
                'filename': 'mtcn_details_jpg.js',
                'sha256': 'b' * 64,
                'matched_keywords': ['mtcn_'],
                'vt_verdict': 'malicious',
                'vt_malicious': 4,
                'popular_threat_label': 'trojan.remcos/abtrojan',
                'family_labels': ['remcos', 'abtrojan'],
                'vt_link': 'https://www.virustotal.com/gui/file/' + ('b' * 64),
            }],
            triage_url='https://repotriage.onrender.com/?url=1',
            scan_mode='scheduled',
        )
        wu_plain = wu_msg.get_body(preferencelist=('plain',)).get_content()
        wu_html = wu_msg.get_body(preferencelist=('html',)).get_content()
        self.assertIn('WU/Financial', wu_msg['Subject'])
        self.assertIn('scheduled scan', wu_msg['Subject'])
        self.assertIn('mtcn_details_jpg.js', wu_plain)
        self.assertIn('MALICIOUS', wu_html)
        self.assertIn('jpg masquerading', wu_html)
        self.assertIn('Open in RepoTriage', wu_html)
        self.assertIn('trojan.remcos/abtrojan', wu_html)


class TestPipelineWebhookHit(unittest.IsolatedAsyncioTestCase):
    async def test_webhook_candidate_produces_finding_without_email(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            state = HuntState(base)
            state.enqueue_webhook({
                'url': 'https://github.com/acme/tools/blob/main/payload.js',
                'repo': 'acme/tools',
                'path': 'payload.js',
                'src': 'repotrace',
            })
            payload = _jsoutprox_payload()

            async def fake_download(url, out_dir):
                out = Path(out_dir)
                out.mkdir(parents=True, exist_ok=True)
                path = out / 'payload.js'
                path.write_bytes(payload)
                return {'local_path': str(path), 'filename': 'payload.js', 'path': 'payload.js'}

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
                gitlab_token='',
                gitlab_base_url='',
                gitlab_search_terms=[],
                repo_watch_commits=10,
                repo_watch_newest_files=5,
                vt_confirm=False,
                vt_api_key='',
                vt_livehunt_rule_id='24949411305',
                vt_livehunt_wu_rule_id='20744291635',
                webhook_secret='secret',
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
                analysis_alert_email=False,
            )
            with patch('app.modules.repo_hunt.pipeline.download_file', new=AsyncMock(side_effect=fake_download)):
                report = await run_repo_hunt(base, cfg=cfg, send=False)

            self.assertTrue(report['ok'])
            self.assertEqual(report['sources'].get('webhook'), 1)
            self.assertEqual(report['local_matches'], 1)
            self.assertEqual(report['new_findings'], 1)
            self.assertEqual(report['findings'][0]['detection']['rule'], 'potential_jsoutprox_js')
            self.assertIn('auto=1', report['findings'][0]['triage_url'])


if __name__ == '__main__':
    unittest.main()
