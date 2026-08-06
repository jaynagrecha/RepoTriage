import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.modules.analyst_report_html import render_analyst_report_html  # noqa: E402
from app.modules.cti_fusion import build_analyst_report  # noqa: E402


def _sample_result() -> dict:
    return {
        'source': {
            'display_url': 'https://gitlab.com/semoria2026/met2026/-/raw/main/mtcn_details.jpg.7z',
            'owner': 'semoria2026',
            'repo': 'met2026',
            'filename': 'mtcn_details.jpg.7z',
        },
        'root_file': {
            'filename': 'mtcn_details.jpg.7z',
            'sha256': '446893d7c8d90844a4ffddf70ca6f85d4a36125d1eae30d4cccf7048e654214e',
        },
        'files': [{
            'filename': 'mtcn_details_jpg.js',
            'original_name': 'mtcn_details_jpg.js',
            'file_type': 'JavaScript',
            'sha256': 'ec5c57cc5dde6ec182a9fd38a0b3ad201f725e6fb2173615a2f1b8e114702a2b',
            'vt_verdict': 'malicious',
            'vt_link': 'https://www.virustotal.com/gui/file/ec5c57cc5dde6ec182a9fd38a0b3ad201f725e6fb2173615a2f1b8e114702a2b',
        }],
        'file_stats': {'malicious': 1, 'total_listed': 2, 'iocs': 3},
        'vt': {
            'verdict': 'malicious',
            'detections_summary': '23/60',
            'popular_threat_label': 'trojan.remcos/abtrojan',
            'family_labels': ['remcos', 'abtrojan'],
        },
        'cti_dashboard': {
            'risk': 'Critical',
            'primary_family': 'remcos',
            'ioc_count': 3,
            'mitre_count': 2,
            'families': [{'name': 'remcos', 'count': 2, 'sources': ['VirusTotal']}],
        },
        'attack_narrative': {
            'risk': 'Critical',
            'narrative_bullets': ['Archive delivered a dual-extension JS dropper.'],
            'likely_objectives': ['Remote access / C2'],
            'recommended_actions': ['Block contacted domains', 'Hunt for Remcos'],
        },
        'infrastructure': {
            'vt_contacted': [{
                'indicator': 'melissalawrenceks.dds.net',
                'type': 'VT Contacted Domain',
                'confidence': 'Medium',
                'source': 'VirusTotal',
            }],
            'probable_c2': [],
        },
        'relations': {
            'graph_summary': {
                'execution_parents': 1,
                'dropped_files': 3,
                'bundled_files': 1,
                'extracted_children': 1,
                'dual_extensions': 2,
            },
            'dual_extensions': [{
                'filename': 'mtcn_details_jpg.js',
                'label': 'jpg masquerading as → .js',
            }],
        },
        'mitre': {
            'techniques': [{
                'id': 'T1105',
                'name': 'Ingress Tool Transfer',
                'tactic': 'Command and Control',
                'confidence': 'High',
            }],
        },
        'campaign_analysis': {
            'candidate': 'Unknown campaign / insufficient evidence',
            'confidence_band': 'Low',
            'confidence_score': 20,
            'evidence': [],
        },
        'threat_actor_assessment': {
            'primary_assessment': 'Unknown',
            'confidence_band': 'Low',
            'confidence_score': 10,
            'analyst_note': 'No defensible attribution.',
            'evidence': [],
        },
        'iocs': {'domains': ['melissalawrenceks.dds.net'], 'urls': [], 'ips': []},
        'threat_intel': {
            'threatfox': {'found': [], 'summary': {}},
            'malwarebazaar': {'summary': {'found': 0}, 'results': []},
            'urlhaus': {'summary': {'found': 0}, 'results': []},
        },
    }


class TestAnalystReportHtml(unittest.TestCase):
    def test_render_is_full_document(self):
        html = render_analyst_report_html(_sample_result(), generated_at='2026-08-06T00:00:00+00:00')
        self.assertTrue(html.startswith('<!DOCTYPE html>'))
        self.assertIn('RepoTriage', html)
        self.assertIn('Analyst Report', html)
        self.assertIn('mtcn_details.jpg.7z', html)
        self.assertIn('remcos', html)
        self.assertIn('Critical', html)
        self.assertIn('jpg masquerading', html)
        self.assertIn('melissalawrenceks.dds.net', html)
        self.assertIn('T1105', html)
        self.assertIn('Relations Snapshot', html)
        self.assertIn('query-only', html)
        self.assertNotIn('<br># RepoTriage', html)

    def test_build_analyst_report_uses_template(self):
        report = build_analyst_report(_sample_result())
        self.assertEqual(report.get('format'), 'templated_html_v1')
        self.assertIn('# RepoTriage Analyst Report', report['markdown'])
        self.assertIn('<!DOCTYPE html>', report['html'])
        self.assertIn('Overall Risk', report['html'])


if __name__ == '__main__':
    unittest.main()
