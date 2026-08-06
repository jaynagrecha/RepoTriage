"""Prove CTI pipeline surfaces exact ThreatFox/URLHaus matches (mocked live APIs)."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.main import integrate_abusech_infrastructure, integrate_threatfox_infrastructure  # noqa: E402
from app.modules.cti_query_policy import select_malware_ioc_candidates, should_query_threatfox  # noqa: E402
from app.modules.ioc_extractor import extract_iocs_from_file  # noqa: E402
from app.modules.threatfox import enrich_iocs, normalize_result  # noqa: E402

FIXTURE = ROOT / 'tests' / 'fixtures' / 'cti_known_bad_sample.js'
KNOWN_URL = 'http://203.0.113.77/jsoutprox/gate.php'


class TestCtiKnownBadFixture(unittest.TestCase):
    def test_fixture_extracts_queryable_url(self):
        iocs = extract_iocs_from_file(FIXTURE)
        self.assertIn(KNOWN_URL, iocs.get('urls') or [])
        # Platform noise must not be the only candidate
        candidates = select_malware_ioc_candidates(iocs, limit=20)
        self.assertIn(KNOWN_URL, candidates)
        allowed, reason = should_query_threatfox(KNOWN_URL)
        self.assertTrue(allowed, reason)

    def test_platform_urls_still_skipped(self):
        allowed, reason = should_query_threatfox('https://github.com/foo/bar/blob/main/x.js')
        self.assertFalse(allowed)
        self.assertEqual(reason, 'platform_url')
        allowed, reason = should_query_threatfox('evil-c2.biz')
        self.assertFalse(allowed)
        self.assertEqual(reason, 'domain_only_not_queried')


class TestCtiPipelineProof(unittest.IsolatedAsyncioTestCase):
    async def test_enrich_and_infra_merge_show_probable_c2(self):
        iocs = extract_iocs_from_file(FIXTURE)
        tf_payload = {
            'query_status': 'ok',
            'data': [{
                'id': '999001',
                'ioc': KNOWN_URL,
                'ioc_type': 'url',
                'threat_type': 'botnet_cc',
                'malware': 'jsoutprox',
                'malware_printable': 'JsOutProx',
                'confidence_level': 90,
                'first_seen': '2026-01-01 00:00:00',
                'last_seen': None,
                'reference': None,
                'tags': ['jsoutprox'],
                'reporter': 'repotriage-fixture',
            }],
        }

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            with patch('app.modules.threatfox.lookup_ioc', new_callable=AsyncMock) as mocked:
                mocked.return_value = normalize_result(KNOWN_URL, tf_payload, cache_hit=False)
                enriched = await enrich_iocs(iocs, base)

        self.assertGreater(enriched['summary']['found'], 0)
        self.assertGreater(enriched['summary']['match_count'], 0)
        self.assertGreaterEqual(enriched['summary']['probable_c2'], 1)

        infra = {
            'probable_c2': [],
            'control_channels': [],
            'exfil_channels': [],
            'config_sources': [],
            'payload_delivery': [],
            'malware_downloads': [],
            'known_bad_infrastructure': [],
        }
        merged = integrate_threatfox_infrastructure(infra, enriched)
        self.assertTrue(any(r.get('indicator') == KNOWN_URL for r in merged['probable_c2']))
        hit = next(r for r in merged['probable_c2'] if r.get('indicator') == KNOWN_URL)
        self.assertEqual(hit.get('source'), 'ThreatFox')
        self.assertIn('jsoutprox', str(hit.get('malware') or '').lower())

    async def test_urlhaus_match_merges_to_payload_delivery(self):
        urlhaus = {
            'results': [{
                'found': True,
                'indicator': KNOWN_URL,
                'url': KNOWN_URL,
                'threat': 'malware_download',
                'families': ['JsOutProx'],
                'url_status': 'online',
                'link': 'https://urlhaus.abuse.ch/url/1/',
            }],
        }
        infra = integrate_abusech_infrastructure(
            {'payload_delivery': [], 'probable_c2': [], 'known_bad_infrastructure': []},
            urlhaus,
            {'matches': []},
            {'matches': []},
        )
        self.assertTrue(any(r.get('indicator') == KNOWN_URL for r in infra['payload_delivery']))
        self.assertEqual(infra['payload_delivery'][0]['source'], 'URLHaus')


if __name__ == '__main__':
    unittest.main()
