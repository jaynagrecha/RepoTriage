import unittest
from pathlib import Path
import tempfile

from app.modules.family_parser import parse_family_indicators


class TestFamilyParser(unittest.TestCase):
    def test_detects_powershell_dropper_as_weak_hint(self):
        with tempfile.NamedTemporaryFile('w', suffix='.ps1', delete=False) as f:
            f.write('powershell -EncodedCommand FromBase64String DownloadString IEX')
            path = Path(f.name)
        try:
            result = parse_family_indicators(path)
            self.assertEqual(result['match_count'], 0)
            self.assertGreaterEqual(result['weak_match_count'], 1)
            families = {m['family'] for m in result['family_matches']}
            self.assertIn('powershell_dropper', families)
        finally:
            path.unlink(missing_ok=True)


if __name__ == '__main__':
    unittest.main()
