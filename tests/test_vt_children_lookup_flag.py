from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class TestVtChildrenLookupDefault(unittest.TestCase):
    def test_default_disabled(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('VT_CHILDREN_LOOKUP', None)
            enabled = str(os.getenv('VT_CHILDREN_LOOKUP', 'false')).strip().lower() in {
                '1', 'true', 'yes', 'on',
            }
        self.assertFalse(enabled)

    def test_can_enable(self):
        with patch.dict(os.environ, {'VT_CHILDREN_LOOKUP': 'true'}, clear=False):
            enabled = str(os.getenv('VT_CHILDREN_LOOKUP', 'false')).strip().lower() in {
                '1', 'true', 'yes', 'on',
            }
        self.assertTrue(enabled)


if __name__ == '__main__':
    unittest.main()
