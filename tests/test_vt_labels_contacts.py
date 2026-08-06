import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.main import (  # noqa: E402
    integrate_vt_infrastructure,
    merge_vt_contacts_into_iocs,
    _vt_inventory_fields,
)
from app.modules.downloader import normalize_gitlab_file_url  # noqa: E402
from app.modules.vt_lookup import (  # noqa: E402
    _family_from_attrs,
    _normalize_file_report,
    enrich_vt_contacts,
    lookup_file_hash,
)


class _FakeResp:
    def __init__(self, status_code: int, payload: dict | None = None, headers: dict | None = None):
        self.status_code = status_code
        self._payload = payload or {}
        self.headers = headers or {}

    def json(self):
        return self._payload


class _RoutingClient:
    def __init__(self, routes: dict):
        self._routes = routes

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, url, *args, **kwargs):
        for key, resp in self._routes.items():
            if key in str(url):
                return resp
        return _FakeResp(404)


class TestGitLabOwnerRepo(unittest.TestCase):
    def test_nested_group_sets_owner_and_repo(self):
        meta = normalize_gitlab_file_url(
            'https://gitlab.com/acme/security/tools/-/blob/main/samples/payload.zip'
        )
        self.assertEqual(meta['owner'], 'acme/security')
        self.assertEqual(meta['repo'], 'tools')
        self.assertEqual(meta['project'], 'acme/security/tools')

    def test_simple_project_sets_owner_repo(self):
        meta = normalize_gitlab_file_url(
            'https://gitlab.com/zohair222/file01/-/raw/main/TT_Ref.7z'
        )
        self.assertEqual(meta['owner'], 'zohair222')
        self.assertEqual(meta['repo'], 'file01')


class TestVtFamilyAndNames(unittest.TestCase):
    def test_popular_threat_classification_fields(self):
        attrs = {
            'popular_threat_classification': {
                'suggested_threat_label': 'trojan.remcos/malcode',
                'popular_threat_name': [
                    {'value': 'remcos', 'count': 12},
                    {'value': 'malcode', 'count': 8},
                    {'value': 'sonbokil', 'count': 3},
                ],
                'popular_threat_category': [
                    {'value': 'trojan', 'count': 20},
                    {'value': 'downloader', 'count': 4},
                ],
            },
            'last_analysis_stats': {'malicious': 10, 'suspicious': 1, 'harmless': 0, 'undetected': 50},
            'last_analysis_results': {},
            'meaningful_name': 'sleestakk_payload_1.js',
            'names': ['sleestakk_payload_1.js', 'payload.jpg'],
            'tags': ['javascript'],
        }
        family = _family_from_attrs(attrs, [])
        self.assertEqual(family['popular_threat_label'], 'trojan.remcos/malcode')
        self.assertEqual(family['family_labels'], ['remcos', 'malcode', 'sonbokil'])
        self.assertEqual(family['threat_categories'], ['trojan', 'downloader'])
        self.assertEqual(family['primary_family'], 'remcos')

        report = _normalize_file_report('ab' * 32, {'data': {'attributes': attrs}})
        self.assertEqual(report['original_filename'], 'sleestakk_payload_1.js')
        self.assertIn('sleestakk_payload_1.js', report['names'])
        self.assertEqual(report['popular_threat_label'], 'trojan.remcos/malcode')
        self.assertEqual(report['family_labels'], ['remcos', 'malcode', 'sonbokil'])
        self.assertEqual(report['schema'], 3)

    def test_vt_inventory_fields(self):
        fields = _vt_inventory_fields({
            'status': 'found',
            'verdict': 'malicious',
            'malicious': 5,
            'suspicious': 0,
            'permalink': 'https://www.virustotal.com/gui/file/abc',
            'names': ['sleestakk_payload_1.js'],
            'original_filename': 'sleestakk_payload_1.js',
            'popular_threat_label': 'trojan.remcos/malcode',
            'family_labels': ['remcos', 'malcode', 'sonbokil'],
            'contacted_domains': ['deubsjoinpawmderl.ddns.net'],
            'contacted_ips': ['178.255.148.207'],
        })
        self.assertEqual(fields['vt_original_filename'], 'sleestakk_payload_1.js')
        self.assertEqual(fields['vt_family_labels'], ['remcos', 'malcode', 'sonbokil'])
        self.assertEqual(fields['vt_contacted_domains'], ['deubsjoinpawmderl.ddns.net'])


class TestVtContactsMerge(unittest.TestCase):
    def test_merge_and_infra(self):
        iocs = {'urls': [], 'domains': [], 'ips': [], 'emails': [], 'discord_webhooks': [], 'telegram': [], 'wallets': [], 'ioc_details': {}}
        reports = [{
            'status': 'found',
            'sha256': 'aa' * 32,
            'permalink': 'https://www.virustotal.com/gui/file/aa',
            'contacted_domains': ['deubsjoinpawmderl.ddns.net'],
            'contacted_ips': ['178.255.148.207'],
            'contacted_urls': ['http://deubsjoinpawmderl.ddns.net:8072/gate'],
        }]
        merged = merge_vt_contacts_into_iocs(iocs, reports)
        self.assertIn('deubsjoinpawmderl.ddns.net', merged['domains'])
        self.assertIn('178.255.148.207', merged['ips'])
        self.assertTrue(any('8072' in u for u in merged['urls']))

        infra = integrate_vt_infrastructure({}, reports)
        indicators = {row['indicator'] for row in infra['probable_c2']}
        self.assertIn('deubsjoinpawmderl.ddns.net', indicators)
        self.assertIn('178.255.148.207', indicators)


class TestVtContactsEnrich(unittest.IsolatedAsyncioTestCase):
    @patch.dict(os.environ, {'VT_API_KEY': 'vt-test-key'}, clear=False)
    async def test_lookup_fetches_relationships(self):
        sha = 'c' * 64
        file_payload = {
            'data': {
                'attributes': {
                    'last_analysis_stats': {'malicious': 3, 'suspicious': 0, 'harmless': 0, 'undetected': 40},
                    'last_analysis_results': {
                        'Google': {'category': 'malicious', 'result': 'Detected'},
                    },
                    'popular_threat_classification': {
                        'suggested_threat_label': 'trojan.remcos/malcode',
                        'popular_threat_name': [{'value': 'remcos', 'count': 5}],
                        'popular_threat_category': [{'value': 'trojan', 'count': 5}],
                    },
                    'meaningful_name': 'sleestakk_payload_1.js',
                    'names': ['sleestakk_payload_1.js'],
                    'tags': ['javascript'],
                }
            }
        }
        routes = {
            f'/files/{sha}/contacted_domains': _FakeResp(200, {'data': [{'id': 'deubsjoinpawmderl.ddns.net'}]}),
            f'/files/{sha}/contacted_ips': _FakeResp(200, {'data': [{'id': '178.255.148.207'}]}),
            f'/files/{sha}/contacted_urls': _FakeResp(200, {'data': [{'id': 'http://deubsjoinpawmderl.ddns.net:8072/'}]}),
            f'/files/{sha}': _FakeResp(200, file_payload),
        }
        with tempfile.TemporaryDirectory() as tmp:
            with patch('app.modules.vt_lookup.httpx.AsyncClient', return_value=_RoutingClient(routes)):
                result = await lookup_file_hash(sha, Path(tmp))
        self.assertEqual(result['status'], 'found')
        self.assertEqual(result['popular_threat_label'], 'trojan.remcos/malcode')
        self.assertEqual(result['original_filename'], 'sleestakk_payload_1.js')
        self.assertEqual(result['contacted_domains'], ['deubsjoinpawmderl.ddns.net'])
        self.assertEqual(result['contacted_ips'], ['178.255.148.207'])
        self.assertTrue(result['contacts_fetched'])
        self.assertTrue(result['relations_fetched'])
        self.assertEqual(result['schema'], 3)

        # Second call should skip re-fetch when relations already populated (schema >= 3)
        report = {
            'status': 'found',
            'sha256': sha,
            'schema': 3,
            'relations_fetched': True,
            'contacts_fetched': True,
            'contacted_domains': ['x.com'],
            'contacted_ips': [],
            'relations': {},
        }
        out = await enrich_vt_contacts(report, Path(tempfile.gettempdir()))
        self.assertEqual(out['contacted_domains'], ['x.com'])


if __name__ == '__main__':
    unittest.main()
