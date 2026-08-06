import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.main import _annotate_dual_extension, _build_relations_view  # noqa: E402
from app.modules.filename_signals import detect_dual_extension, scan_names_for_dual_extension  # noqa: E402
from app.modules.vt_lookup import (  # noqa: E402
    _normalize_relation_item,
    enrich_vt_relations,
    lookup_file_hash,
)


class _FakeResp:
    def __init__(self, status_code: int, payload: dict | None = None):
        self.status_code = status_code
        self._payload = payload or {}
        self.headers = {}

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


class TestDualExtension(unittest.TestCase):
    def test_stem_masquerade_js(self):
        hit = detect_dual_extension('mtcn_details_jpg.js')
        self.assertIsNotNone(hit)
        self.assertEqual(hit['real_extension'], 'js')
        self.assertIn('jpg', hit['claimed_extensions'])
        self.assertEqual(hit['severity'], 'High')

    def test_multi_dot_archive(self):
        hit = detect_dual_extension('photo.jpg.7z')
        self.assertIsNotNone(hit)
        self.assertEqual(hit['real_extension'], '7z')
        self.assertIn('jpg', hit['claimed_extensions'])

    def test_pdf_exe(self):
        hit = detect_dual_extension('invoice.pdf.exe')
        self.assertIsNotNone(hit)
        self.assertEqual(hit['real_extension'], 'exe')
        self.assertIn('pdf', hit['claimed_extensions'])

    def test_benign_single_ext(self):
        self.assertIsNone(detect_dual_extension('readme.md'))
        self.assertIsNone(detect_dual_extension('payload.js'))

    def test_scan_dedup(self):
        hits = scan_names_for_dual_extension([
            'a/mtcn_details_jpg.js',
            'mtcn_details_jpg.js',
            'other_jpg.js',
        ])
        self.assertEqual(len(hits), 2)


class TestNormalizeRelationItem(unittest.TestCase):
    def test_execution_parent_file(self):
        row = {
            'id': 'ab' * 32,
            'type': 'file',
            'attributes': {
                'meaningful_name': 'sleestak_payload_1.zip',
                'names': ['sleestak_payload_1.zip'],
                'type_description': '7ZIP',
                'last_analysis_stats': {
                    'malicious': 16, 'suspicious': 0, 'harmless': 10, 'undetected': 36,
                },
            },
        }
        item = _normalize_relation_item(row, 'execution_parents')
        self.assertEqual(item['name'], 'sleestak_payload_1.zip')
        self.assertEqual(item['malicious'], 16)
        self.assertEqual(item['detections'], '16/62')
        self.assertIn('virustotal.com/gui/file/', item['permalink'])

    def test_bundled_dual_ext(self):
        row = {
            'id': 'cd' * 32,
            'type': 'file',
            'attributes': {
                'meaningful_name': 'mtcn_details_jpg.js',
                'names': ['mtcn_details_jpg.js'],
                'type_description': 'JavaScript',
                'last_analysis_stats': {
                    'malicious': 22, 'suspicious': 0, 'harmless': 0, 'undetected': 38,
                },
            },
        }
        item = _normalize_relation_item(row, 'bundled_files')
        self.assertTrue(item.get('dual_extension'))
        self.assertEqual(item['dual_extension']['real_extension'], 'js')


class TestBuildRelationsView(unittest.TestCase):
    def test_merges_local_extracted_and_dual(self):
        inventory = [
            {'filename': 'metzt_details.jpg.7z', 'sha256': 'aa' * 32},
            {
                'filename': 'mtcn_details_jpg.js',
                'original_name': 'mtcn_details_jpg.js',
                'sha256': 'bb' * 32,
                'file_type': 'JavaScript',
                'parent_archive': 'metzt_details.jpg.7z',
                'depth': 1,
            },
        ]
        _annotate_dual_extension(inventory[0])
        _annotate_dual_extension(inventory[1])
        self.assertTrue(inventory[0].get('dual_extension'))
        self.assertTrue(inventory[1].get('dual_extension'))

        vt = {
            'sha256': 'aa' * 32,
            'permalink': 'https://www.virustotal.com/gui/file/' + ('aa' * 32),
            'relations': {
                'execution_parents': [{
                    'name': 'sleestak_payload_1.zip',
                    'sha256': 'ee' * 32,
                    'detections': '16/62',
                    'malicious': 16,
                }],
                'dropped_files': [{
                    'name': 'remit_copy_00000005487010_07152026_jpg.js',
                    'sha256': 'ff' * 32,
                    'detections': '22/60',
                    'dual_extension': detect_dual_extension('remit_copy_00000005487010_07152026_jpg.js'),
                }],
                'bundled_files': [],
                'compressed_parents': [],
                'itw_urls': [],
                'itw_domains': [],
                'contacted_domains': [],
                'contacted_ips': [],
                'contacted_urls': [],
            },
            'dual_extensions': [],
            'relations_graph_summary': {'execution_parents': 1, 'dropped_files': 1},
        }
        view = _build_relations_view(vt, inventory, {'filename': 'metzt_details.jpg.7z'})
        self.assertEqual(len(view['execution_parents']), 1)
        self.assertEqual(len(view['dropped_files']), 1)
        self.assertEqual(len(view['extracted_children']), 1)
        self.assertGreaterEqual(view['graph_summary']['dual_extensions'], 1)
        self.assertGreaterEqual(len(view['dual_extensions']), 1)
        self.assertEqual(view['extracted_children'][0]['source'], 'local_extraction')


class TestVtRelationsEnrich(unittest.IsolatedAsyncioTestCase):
    @patch.dict(os.environ, {'VT_API_KEY': 'vt-test-key'}, clear=False)
    async def test_lookup_fetches_full_relations(self):
        sha = 'd' * 64
        file_payload = {
            'data': {
                'attributes': {
                    'last_analysis_stats': {
                        'malicious': 10, 'suspicious': 0, 'harmless': 0, 'undetected': 50,
                    },
                    'last_analysis_results': {},
                    'meaningful_name': 'metzt_details.jpg.7z',
                    'names': ['metzt_details.jpg.7z', 'mtcn_details_jpg.js'],
                    'tags': ['archive'],
                }
            }
        }
        parent = {
            'data': [{
                'id': 'e' * 64,
                'type': 'file',
                'attributes': {
                    'meaningful_name': 'sleestak_payload_1.zip',
                    'names': ['sleestak_payload_1.zip'],
                    'type_description': '7ZIP',
                    'last_analysis_stats': {
                        'malicious': 16, 'suspicious': 0, 'harmless': 10, 'undetected': 36,
                    },
                },
            }]
        }
        dropped = {
            'data': [{
                'id': 'f' * 64,
                'type': 'file',
                'attributes': {
                    'meaningful_name': 'remit_copy_jpg.js',
                    'names': ['remit_copy_jpg.js'],
                    'type_description': 'JavaScript',
                    'last_analysis_stats': {
                        'malicious': 22, 'suspicious': 0, 'harmless': 0, 'undetected': 38,
                    },
                },
            }]
        }
        routes = {
            f'/files/{sha}/execution_parents': _FakeResp(200, parent),
            f'/files/{sha}/dropped_files': _FakeResp(200, dropped),
            f'/files/{sha}/contacted_domains': _FakeResp(200, {
                'data': [{'id': 'assets.adobe-us.com', 'type': 'domain'}],
            }),
            f'/files/{sha}': _FakeResp(200, file_payload),
        }
        with tempfile.TemporaryDirectory() as tmp:
            with patch('app.modules.vt_lookup.httpx.AsyncClient', return_value=_RoutingClient(routes)):
                result = await lookup_file_hash(sha, Path(tmp))

        self.assertEqual(result['status'], 'found')
        self.assertEqual(result['schema'], 3)
        self.assertTrue(result['relations_fetched'])
        self.assertEqual(len(result['relations']['execution_parents']), 1)
        self.assertEqual(result['relations']['execution_parents'][0]['name'], 'sleestak_payload_1.zip')
        self.assertEqual(len(result['relations']['dropped_files']), 1)
        self.assertTrue(result['relations']['dropped_files'][0].get('dual_extension'))
        self.assertIn('assets.adobe-us.com', result['contacted_domains'])
        self.assertGreaterEqual(result['relations_graph_summary']['dual_extensions'], 1)

        # Cached / already-fetched path should not wipe relations
        cached = {
            'status': 'found',
            'sha256': sha,
            'schema': 3,
            'relations_fetched': True,
            'relations': {'execution_parents': [{'name': 'keep-me'}]},
            'contacted_domains': ['keep.example'],
        }
        out = await enrich_vt_relations(cached, Path(tempfile.gettempdir()))
        self.assertEqual(out['relations']['execution_parents'][0]['name'], 'keep-me')
        self.assertEqual(out['contacted_domains'], ['keep.example'])


if __name__ == '__main__':
    unittest.main()
