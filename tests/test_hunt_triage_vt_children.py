from __future__ import annotations

import sys
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.main import AnalyzeRequest  # noqa: E402
from app.modules.repo_hunt.config import RepoHuntConfig  # noqa: E402
from app.modules.repo_hunt.pipeline import _triage_link  # noqa: E402


class TestHuntTriageVtChildren(unittest.TestCase):
    def test_analyze_request_defaults_vt_children_true(self):
        req = AnalyzeRequest(file_url='https://github.com/a/b/blob/main/x.apk')
        self.assertTrue(req.vt_children)

    def test_analyze_request_can_disable_vt_children(self):
        req = AnalyzeRequest(file_url='https://github.com/a/b/blob/main/x.apk', vt_children=False)
        self.assertFalse(req.vt_children)

    def test_hunt_triage_link_disables_vt_children(self):
        cfg = RepoHuntConfig.from_env()
        from dataclasses import replace
        cfg = replace(cfg, triage_base_url='https://repotriage.example')
        link = _triage_link(cfg, 'https://github.com/a/b/blob/main/remittance.apk')
        qs = parse_qs(urlparse(link).query)
        self.assertEqual(qs.get('vt_children'), ['0'])
        self.assertEqual(qs.get('auto'), ['1'])
        self.assertEqual(qs.get('src'), ['repo_hunt'])


if __name__ == '__main__':
    unittest.main()
