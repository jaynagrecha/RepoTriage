import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.modules.repo_hunt.config import RepoHuntConfig  # noqa: E402
from app.modules.repo_hunt.notify.email_templates import (  # noqa: E402
    render_wu_alert_html,
    render_wu_alert_text,
)
from app.modules.repo_hunt.notify.smtp_mailer import build_analysis_wu_alert_email  # noqa: E402


class TestWuEmailTemplate(unittest.TestCase):
    def test_html_has_structured_cards_and_ctas(self):
        hits = [{
            'filename': 'mtcn_details.jpg.7z',
            'url': 'https://gitlab.com/semoria2026/met2026/-/raw/main/mtcn_details.jpg.7z',
            'sha256': '446893d7c8d90844a4ffddf70ca6f85d4a36125d1eae30d4cccf7048e654214e',
            'matched_keywords': ['mtcn'],
            'vt_verdict': 'malicious',
            'vt_malicious': 23,
            'popular_threat_label': 'trojan.remcos/abtrojan',
            'family_labels': ['remcos', 'abtrojan', 'suschil'],
            'vt_link': 'https://www.virustotal.com/gui/file/446893d7c8d90844a4ffddf70ca6f85d4a36125d1eae30d4cccf7048e654214e',
            'triage_url': 'https://repotriage.onrender.com/?url=demo',
        }]
        html = render_wu_alert_html(
            title='WU/MTCN analysis alert',
            subtitle='Western Union / MTCN malicious filename rule',
            mode='analyze',
            job_id='245af326c9dd43c8a2bdd9606f69c99d',
            source_url=hits[0]['url'],
            triage_url=hits[0]['triage_url'],
            rule_id='20744291635',
            hits=hits,
        )
        self.assertIn('RepoTriage', html)
        self.assertIn('mtcn_details.jpg.7z', html)
        self.assertIn('jpg masquerading', html)
        self.assertIn('MALICIOUS', html)
        self.assertIn('VT malicious=23', html)
        self.assertIn('Open VirusTotal', html)
        self.assertIn('Open in RepoTriage', html)
        self.assertIn('remcos', html)
        # Escaping sanity
        self.assertNotIn('<script>', html)

        text = render_wu_alert_text(
            header='RepoTriage analysis alert',
            mode='analyze',
            job_id='245af326c9dd43c8a2bdd9606f69c99d',
            source_url=hits[0]['url'],
            triage_url=hits[0]['triage_url'],
            rule_id='20744291635',
            hits=hits,
        )
        self.assertIn('mtcn_details.jpg.7z', text)
        self.assertIn('jpg masquerading', text)

    def test_multipart_message(self):
        cfg = RepoHuntConfig.from_env()
        msg = build_analysis_wu_alert_email(
            cfg=cfg,
            job_id='job1',
            source_url='https://example.com/a.7z',
            hits=[{
                'filename': 'mtcn_details_jpg.js',
                'sha256': 'ab' * 32,
                'matched_keywords': ['mtcn_'],
                'vt_verdict': 'malicious',
                'vt_malicious': 22,
            }],
            triage_url='https://repotriage.onrender.com/?job=job1',
            scan_mode='analyze',
        )
        self.assertEqual(msg.get_content_type(), 'multipart/alternative')
        self.assertIsNotNone(msg.get_body(preferencelist=('html',)))
        self.assertIsNotNone(msg.get_body(preferencelist=('plain',)))


if __name__ == '__main__':
    unittest.main()
