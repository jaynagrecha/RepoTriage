import unittest
from app.modules.static_analysis.versioning import is_stale_record, STATIC_ANALYSIS_VERSION


class TestStaticAnalysisVersioning(unittest.TestCase):
    def test_stale_when_version_mismatch(self):
        record = {'status': 'completed', 'analysis_version': '2.3.0', 'profile': {'category': 'script'}}
        self.assertTrue(is_stale_record(record))

    def test_stale_when_js_misclassified_as_binary(self):
        record = {
            'status': 'completed',
            'analysis_version': STATIC_ANALYSIS_VERSION,
            'filename': 'dropper.pdf.js',
            'profile': {'category': 'binary', 'extension': 'bin'},
            'functions': [{'name': 'offset_0'}],
            'typed_analysis': {},
        }
        self.assertTrue(is_stale_record(record))

    def test_fresh_when_current(self):
        record = {
            'status': 'completed',
            'analysis_version': STATIC_ANALYSIS_VERSION,
            'filename': 'dropper.pdf.js',
            'profile': {'category': 'script', 'extension': 'js'},
            'typed_analysis': {'logic_summary': ['x']},
        }
        self.assertFalse(is_stale_record(record))


if __name__ == '__main__':
    unittest.main()
