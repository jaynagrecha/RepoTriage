import unittest

from app.modules.cti_fusion import build_campaign_analysis, build_cti_dashboard
from app.modules.cti_query_policy import (
    filter_threatfox_matches,
    should_query_threatfox,
    should_query_urlhaus,
    threatfox_match_is_exact,
)
from app.modules.narrative import _risk_level


class TestCtiQueryPolicy(unittest.TestCase):
    def test_skips_bare_github_com(self):
        allowed, reason = should_query_threatfox('github.com')
        self.assertFalse(allowed)
        self.assertEqual(reason, 'platform_host')

    def test_allows_full_github_file_url(self):
        url = 'https://github.com/user/repo/blob/main/payload.js'
        allowed, reason = should_query_threatfox(url)
        self.assertTrue(allowed)
        self.assertEqual(reason, 'exact_url')

    def test_urlhaus_rejects_domain_only(self):
        allowed, reason = should_query_urlhaus('evil.example.com')
        self.assertFalse(allowed)
        self.assertEqual(reason, 'urlhaus_requires_full_url')

    def test_urlhaus_allows_full_url(self):
        allowed, _ = should_query_urlhaus('https://evil.example.com/a/b.zip')
        self.assertTrue(allowed)

    def test_filter_threatfox_keeps_exact_only(self):
        indicator = 'https://evil.example.com/a.js'
        matches = [
            {'ioc': 'https://evil.example.com/a.js', 'malware': 'js.clearfake'},
            {'ioc': 'https://other.example.com/b.js', 'malware': 'js.clearfake'},
        ]
        out = filter_threatfox_matches(indicator, matches)
        self.assertEqual(len(out), 1)
        self.assertTrue(threatfox_match_is_exact(indicator, out[0]['ioc']))


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
    def test_broad_abuse_counts_no_longer_critical(self):
        result = {
            'files': [{'vt_verdict': 'clean'}],
            'file_stats': {'iocs': 0},
            'infrastructure': {'probable_c2': [{'indicator': 'https://github.com/other/repo', 'type': 'Probable C2'}]},
            'threat_intel': {
                'threatfox': {'found': []},
                'malwarebazaar': {'summary': {'found': 0}, 'results': []},
                'urlhaus': {'summary': {'found': 0}, 'results': []},
                'abusech': {'matches': {'threatfox': 5, 'malwarebazaar': 0, 'urlhaus': 0}},
            },
        }
        self.assertEqual(_risk_level(result), 'Low')


if __name__ == '__main__':
    unittest.main()
