import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.main import _public_result, _public_job, get_client_ip, APP_VERSION  # noqa: E402
from app.modules.downloader import _allowed_download_host  # noqa: E402
from app.modules.extractor import _read_limited, ExtractionError  # noqa: E402
from app.modules.ioc_extractor import extract_iocs_from_file, classify_infrastructure  # noqa: E402
from app.modules.narrative import _risk_level  # noqa: E402
import io


class TestPublicSanitization(unittest.TestCase):
    def test_public_result_strips_local_paths(self):
        raw = {
            'source': {'local_path': '/secret/quarantine/x.bin', 'filename': 'x.bin'},
            'extraction': {'extract_dir': '/secret/extracted/case_1'},
            'files': [{'filename': 'x.bin', 'local_path': '/secret/quarantine/x.bin'}],
        }
        public = _public_result(raw)
        self.assertNotIn('local_path', public['source'])
        self.assertNotIn('extract_dir', public['extraction'])
        self.assertNotIn('local_path', public['files'][0])

    def test_public_job_strips_client_ip(self):
        job = {'job_id': 'abc', 'client_ip': '203.0.113.5', 'status': 'completed', 'result': None}
        public = _public_job(job)
        self.assertNotIn('client_ip', public)


class TestDownloaderHosts(unittest.TestCase):
    def test_github_hosts_allowed(self):
        self.assertTrue(_allowed_download_host('raw.githubusercontent.com'))
        self.assertTrue(_allowed_download_host('objects.githubusercontent.com'))
        self.assertFalse(_allowed_download_host('evil.example.com'))


class TestExtractorReadLimit(unittest.TestCase):
    def test_read_limited_enforces_cap(self):
        data = b'a' * 50
        stream = io.BytesIO(data)
        with self.assertRaises(ExtractionError):
            _read_limited(stream, 10)


class TestIocExtractor(unittest.TestCase):
    def test_missing_file_returns_empty(self):
        self.assertEqual(extract_iocs_from_file('/no/such/file.bin')['urls'], [])

    def test_classify_infrastructure_has_expected_buckets(self):
        infra = classify_infrastructure({'urls': [], 'domains': [], 'ips': []})
        for key in ('payload_delivery', 'malware_downloads', 'known_bad_infrastructure'):
            self.assertIn(key, infra)


class TestNarrativeRisk(unittest.TestCase):
    def test_abusech_matches_affect_risk(self):
        result = {
            'files': [{'vt_verdict': 'clean'}],
            'file_stats': {'iocs': 0},
            'infrastructure': {},
            'threat_intel': {
                'abusech': {
                    'matches': {'threatfox': 2, 'malwarebazaar': 2, 'urlhaus': 0},
                }
            },
        }
        self.assertIn(_risk_level(result), {'Critical', 'High', 'Medium'})


class TestVersion(unittest.TestCase):
    def test_app_version_present(self):
        self.assertTrue(APP_VERSION.startswith('2.2'))


if __name__ == '__main__':
    unittest.main()
