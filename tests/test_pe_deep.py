import tempfile
import unittest
from pathlib import Path

from app.modules.deep_analysis.pe_deep import _classify_imports


class TestPeDeepClassification(unittest.TestCase):
    def test_virtualalloc_alone_is_informational(self):
        imports = ['kernel32.dll:virtualalloc', 'kernel32.dll:virtualprotect', 'msvcrt.dll:malloc']
        out = _classify_imports(imports, packer_hints=[])
        self.assertEqual(len(out['high_risk_imports']), 0)
        self.assertEqual(len(out['informational_imports']), 2)
        self.assertIn('anti_analysis', out['categories_not_detected'])
        self.assertIn('network', out['categories_not_detected'])

    def test_virtualalloc_with_writeprocessmemory_is_high(self):
        imports = ['kernel32.dll:virtualalloc', 'kernel32.dll:writeprocessmemory']
        out = _classify_imports(imports, packer_hints=[])
        self.assertGreaterEqual(len(out['high_risk_imports']), 1)
        self.assertIn('process_injection', out['categories_detected'])


if __name__ == '__main__':
    unittest.main()
