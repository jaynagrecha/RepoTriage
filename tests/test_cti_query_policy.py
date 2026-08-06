import unittest

from app.modules.cti_fusion import build_campaign_analysis, build_cti_dashboard
from app.modules.cti_query_policy import (
    filter_threatfox_matches,
    select_malware_ioc_candidates,
    should_query_threatfox,
    should_query_urlhaus,
    should_query_urlhaus_host,
    threatfox_match_is_exact,
    vt_sourced_domains,
)
from app.modules.cti_fusion import build_infrastructure_graph
from app.modules.ioc_extractor import classify_infrastructure
from app.modules.narrative import _risk_level


class TestCtiQueryPolicy(unittest.TestCase):
    def test_skips_bare_github_com(self):
        allowed, reason = should_query_threatfox('github.com')
        self.assertFalse(allowed)
        self.assertEqual(reason, 'domain_only_not_queried')

    def test_skips_platform_full_url(self):
        url = 'https://github.com/user/repo/blob/main/payload.js'
        allowed, reason = should_query_threatfox(url)
        self.assertFalse(allowed)
        self.assertEqual(reason, 'platform_url')

    def test_allows_non_platform_malware_url(self):
        allowed, reason = should_query_threatfox('https://evil-c2.example/a.js')
        self.assertTrue(allowed)
        self.assertEqual(reason, 'exact_url')

    def test_skips_standalone_domains_in_candidate_list(self):
        iocs = {
            'urls': ['https://evil.example/x'],
            'domains': ['evil.example', 'github.com'],
            'ips': ['8.8.8.8'],
            'emails': ['a@b.com'],
            'wallets': ['0x' + 'a' * 40],
        }
        cands = select_malware_ioc_candidates(iocs)
        self.assertIn('https://evil.example/x', cands)
        self.assertIn('8.8.8.8', cands)
        self.assertNotIn('evil.example', cands)
        self.assertNotIn('github.com', cands)

    def test_includes_vt_contacted_domains(self):
        iocs = {
            'urls': [],
            'domains': ['melissalawrenceks.dds.net', 'assets.adobe-us.com', 'noise.example'],
            'ips': [],
            'ioc_details': {
                'domains': [
                    {'indicator': 'melissalawrenceks.dds.net', 'sources': ['VirusTotal:abc']},
                    {'indicator': 'assets.adobe-us.com', 'sources': ['VirusTotal:abc']},
                    {'indicator': 'noise.example', 'sources': ['static']},
                ],
            },
        }
        self.assertEqual(
            set(vt_sourced_domains(iocs)),
            {'melissalawrenceks.dds.net', 'assets.adobe-us.com'},
        )
        cands = select_malware_ioc_candidates(iocs)
        self.assertIn('melissalawrenceks.dds.net', cands)
        self.assertNotIn('noise.example', cands)
        allowed, reason = should_query_threatfox('melissalawrenceks.dds.net', allow_domain=True)
        self.assertTrue(allowed)
        self.assertEqual(reason, 'high_signal_domain')
        host_ok, host_reason = should_query_urlhaus_host('melissalawrenceks.dds.net')
        self.assertTrue(host_ok)
        self.assertEqual(host_reason, 'high_signal_host')

    def test_urlhaus_rejects_domain_only_on_url_api(self):
        allowed, reason = should_query_urlhaus('evil.example.com')
        self.assertFalse(allowed)
        self.assertEqual(reason, 'urlhaus_requires_full_url')

    def test_urlhaus_skips_platform_url(self):
        allowed, reason = should_query_urlhaus('https://github.com/x/y')
        self.assertFalse(allowed)
        self.assertEqual(reason, 'platform_url')

    def test_filter_threatfox_keeps_exact_only(self):
        indicator = 'https://evil.example.com/a.js'
        matches = [
            {'ioc': 'https://evil.example.com/a.js', 'malware': 'js.clearfake'},
            {'ioc': 'https://other.example.com/b.js', 'malware': 'js.clearfake'},
        ]
        out = filter_threatfox_matches(indicator, matches)
        self.assertEqual(len(out), 1)
        self.assertTrue(threatfox_match_is_exact(indicator, out[0]['ioc']))


class TestClassifyInfrastructure(unittest.TestCase):
    def test_no_keyword_probable_c2(self):
        infra = classify_infrastructure({
            'urls': ['https://evil.example/update.php?cmd=1'],
            'ips': ['8.8.8.8'],
            'domains': ['evil.example'],
        })
        self.assertEqual(infra['probable_c2'], [])
        self.assertEqual(len(infra['exfil_channels']), 0)

    def test_discord_webhook_exfil_only(self):
        infra = classify_infrastructure({'discord_webhooks': ['https://discord.com/api/webhooks/1/x']})
        self.assertEqual(len(infra['exfil_channels']), 1)


class TestCtiFusionExactAttribution(unittest.TestCase):
    def _result_with_wildcard_style_tf(self):
        return {
            'files': [{'vt_verdict': 'clean', 'sha256': 'abc'}],
            'file_stats': {'malicious': 0, 'iocs': 5},
            'vt': {'family': {'name': 'Unknown'}, 'verdict': 'clean'},
            'threat_intel': {
                'threatfox': {
                    'found': [{
                        'indicator': 'github.com',
                        'matches': [
                            {'ioc': 'https://github.com/atoragivapo50/x/raw/main/a.js', 'malware': 'js.clearfake', 'confidence_level': 100, 'threat_type': 'payload_delivery', 'infrastructure_role': 'Payload Delivery'},
                        ],
                    }],
                    'summary': {'found': 1, 'match_count': 1},
                },
                'malwarebazaar': {'summary': {'found': 0}, 'results': []},
                'urlhaus': {'summary': {'found': 0}, 'results': []},
            },
            'infrastructure': {},
            'iocs': {'urls': ['https://github.com/yyasha/smsbomb/blob/master/sms_with_threading.py']},
        }

    def test_wildcard_threatfox_does_not_set_clearfake_family(self):
        dash = build_cti_dashboard(self._result_with_wildcard_style_tf())
        self.assertEqual(dash['primary_family'], 'Unknown')
        self.assertEqual(dash['threatfox_matches'], 0)
        self.assertIn(dash['risk'], {'Low', 'Medium'})

    def test_campaign_unknown_without_anchor(self):
        camp = build_campaign_analysis(self._result_with_wildcard_style_tf())
        self.assertEqual(camp['candidate'], 'Unknown campaign / insufficient evidence')


class TestNarrativeRiskExactOnly(unittest.TestCase):
    def test_heuristic_infra_no_longer_critical(self):
        result = {
            'files': [{'vt_verdict': 'clean'}],
            'file_stats': {'iocs': 0},
            'infrastructure': {'probable_c2': [{'indicator': 'https://evil.example/update', 'type': 'Probable C2'}]},
            'threat_intel': {
                'threatfox': {'found': []},
                'malwarebazaar': {'summary': {'found': 0}, 'results': []},
                'urlhaus': {'summary': {'found': 0}, 'results': []},
                'abusech': {'matches': {'threatfox': 5, 'malwarebazaar': 0, 'urlhaus': 0}},
            },
        }
        self.assertEqual(_risk_level(result), 'Low')


class TestInfrastructureGraphProvenance(unittest.TestCase):
    def test_dedupes_vt_domain_and_cti_status(self):
        result = {
            'root_file': {'filename': 'sample.7z', 'sha256': 'aa' * 32},
            'files': [{'filename': 'sample.7z', 'sha256': 'aa' * 32, 'vt_verdict': 'malicious'}],
            'file_stats': {'malicious': 1},
            'iocs': {
                'domains': ['melissalawrenceks.dds.net'],
                'urls': [],
                'ips': ['193.181.35.217'],
                'ioc_details': {
                    'domains': [{'indicator': 'melissalawrenceks.dds.net', 'sources': ['VirusTotal:deadbeef']}],
                    'ips': [{'indicator': '193.181.35.217', 'sources': ['VirusTotal:deadbeef']}],
                },
            },
            'infrastructure': {
                'vt_contacted': [{
                    'indicator': 'melissalawrenceks.dds.net',
                    'type': 'VT Contacted Domain',
                    'source': 'VirusTotal',
                }],
                'probable_c2': [{
                    'indicator': '193.181.35.217',
                    'type': 'Botnet C2',
                    'source': 'FeodoTracker',
                    'malware': 'remcos',
                }],
            },
            'threat_intel': {
                'threatfox': {
                    'lookups': [{
                        'indicator': 'melissalawrenceks.dds.net',
                        'status': 'not_found',
                        'match_count': 0,
                    }],
                    'found': [],
                },
                'urlhaus': {
                    'results': [{
                        'indicator': 'melissalawrenceks.dds.net',
                        'indicator_type': 'domain/host',
                        'found': True,
                        'families': ['remcos'],
                    }],
                },
                'feodo': {'matches': [{'ip': '193.181.35.217', 'malware': 'remcos'}]},
                'sslbl': {'matches': []},
                'malwarebazaar': {'summary': {'found': 0}, 'results': []},
            },
            'vt': {'family': {'name': 'remcos'}, 'verdict': 'malicious'},
        }
        g = build_infrastructure_graph(result)
        domain_nodes = [n for n in g['nodes'] if n['type'] == 'domain' and 'melissalawrenceks' in n['label']]
        self.assertEqual(len(domain_nodes), 1)
        self.assertEqual(domain_nodes[0]['meta'].get('cti_status'), 'matched')
        self.assertTrue(domain_nodes[0]['meta'].get('vt_contacted'))
        self.assertGreaterEqual(g['summary']['cti_matched_nodes'], 1)
        self.assertGreaterEqual(g['summary']['vt_contacted_nodes'], 1)
        labels = {(e['from'], e['label'], e['to']) for e in g['edges']}
        self.assertTrue(any(e[1] == 'vt contacted' for e in labels))


if __name__ == '__main__':
    unittest.main()
