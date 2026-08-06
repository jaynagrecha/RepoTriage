import sys
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.modules.repo_hunt.analysis_alerts import (  # noqa: E402
    collect_wu_hits_from_analysis,
    maybe_send_analysis_wu_alert,
)
from app.modules.repo_hunt.config import RepoHuntConfig  # noqa: E402
from app.modules.repo_hunt.detect.wu_keywords import (  # noqa: E402
    RULE_ID,
    evaluate_wu_from_vt,
    match_wu_names,
    scan_wu_names,
)


class TestWuKeywords(unittest.TestCase):
    def test_mtcn_underscore(self):
        self.assertTrue(match_wu_names(['mtcn_details_jpg.7z']))
        self.assertIn('mtcn_', match_wu_names(['mtcn_details_jpg.7z'])[0])

    def test_western_union_variants(self):
        self.assertTrue(match_wu_names(['WesternUnion_drop.js']))
        self.assertTrue(match_wu_names(['western_union_invoice.pdf']))
        self.assertTrue(match_wu_names(['western union receipt.bin']))

    def test_wupos_pagofacil(self):
        self.assertTrue(match_wu_names(['wupos_payload.zip']))
        self.assertTrue(match_wu_names(['pagofacil_ref.7z']))

    def test_requires_malicious_for_full_rule(self):
        hit = evaluate_wu_from_vt(
            local_names=['mtcn_drop.js'],
            vt_report={'status': 'found', 'verdict': 'clean/undetected', 'malicious': 0},
        )
        self.assertIsNone(hit)
        hit = evaluate_wu_from_vt(
            local_names=['mtcn_drop.js'],
            vt_report={
                'status': 'found',
                'verdict': 'malicious',
                'malicious': 6,
                'names': ['sleestakk_payload_1.js'],
                'permalink': 'https://www.virustotal.com/gui/file/abc',
            },
        )
        self.assertIsNotNone(hit)
        self.assertEqual(hit.rule, RULE_ID)
        self.assertGreater(hit.vt_confirm.get('malicious'), 0)

    def test_scan_wu_names_prefilter(self):
        hit = scan_wu_names(['foo_mtcn_bar.bin'], filesize=12)
        self.assertIsNotNone(hit)
        self.assertEqual(hit.rule, RULE_ID)


class TestAnalysisWuHits(unittest.TestCase):
    def test_collect_from_inventory(self):
        result = {
            'source': {'display_url': 'https://gitlab.com/z/file01', 'repo': 'file01'},
            'vt': {'status': 'found', 'verdict': 'malicious', 'malicious': 9},
            'files': [
                {
                    'filename': 'TT_Ref_mtcn_details.jpg.7z',
                    'path': 'TT_Ref_mtcn_details.jpg.7z',
                    'sha256': 'a' * 64,
                    'vt_verdict': 'malicious',
                    'vt_malicious': 9,
                    'vt_link': 'https://www.virustotal.com/gui/file/aa',
                    'vt_names': ['mtcn_payload.js'],
                    'vt_family_labels': ['remcos'],
                    'size_bytes': 1000,
                }
            ],
        }
        hits = collect_wu_hits_from_analysis(result)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['rule'], RULE_ID)
        self.assertTrue(any('mtcn' in k.lower() for k in hits[0]['matched_keywords']))

    def test_alert_skipped_without_smtp(self):
        cfg = replace(
            RepoHuntConfig.from_env(),
            smtp_host='',
            smtp_to='',
            smtp_from='',
            analysis_alert_email=True,
        )
        out = maybe_send_analysis_wu_alert(
            {
                'source': {'display_url': 'https://github.com/a/b'},
                'files': [{
                    'filename': 'mtcn_x.js',
                    'sha256': 'b' * 64,
                    'vt_verdict': 'malicious',
                    'vt_malicious': 3,
                }],
            },
            cfg=cfg,
        )
        self.assertTrue(out.get('skipped'))
        self.assertEqual(out.get('reason'), 'smtp_not_configured')


if __name__ == '__main__':
    unittest.main()
