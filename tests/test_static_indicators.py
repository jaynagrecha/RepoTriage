import unittest
from app.modules.static_analysis.indicators import build_extracted_indicators


class TestExtractedIndicators(unittest.TestCase):
    def test_collects_urls_from_multiple_sources(self):
        report = {
            'universal': {
                'iocs': {'urls': ['http://evil.example/a'], 'domains': [], 'ips': []},
                'strings_sample': ['callback http://hidden.example/b/path'],
                'suspicious_strings': [],
            },
            'typed_analysis': {
                'pattern_matches': [{'pattern': 'network_callback', 'match': 'http://script.example/c'}],
                'links': [],
            },
            'deobfuscation': {
                'recovered': [{'method': 'base64', 'decoded_preview': 'download http://decoded.example/d'}],
            },
        }
        out = build_extracted_indicators(report)
        self.assertGreaterEqual(out['counts']['urls'], 3)
        self.assertIn('http://evil.example/a', out['urls'])
        self.assertTrue(out['has_network_indicators'])


if __name__ == '__main__':
    unittest.main()
