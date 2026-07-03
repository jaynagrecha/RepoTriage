import unittest

from app.modules.detection_policy import (
    combine_deep_verdict,
    family_verdict,
    sandbox_lite_verdict,
    static_verdict_from_score,
    yara_verdict,
)


class TestStaticVerdictPolicy(unittest.TestCase):
    def test_benign_dll_like_signals_stay_clean(self):
        signals = [
            {'label': 'informational_import', 'weight': 2, 'category': 'binary'},
            {'label': 'embedded_iocs', 'weight': 6, 'category': 'network'},
        ]
        score = sum(s['weight'] for s in signals)
        self.assertEqual(static_verdict_from_score(signals, score), 'clean')

    def test_single_url_does_not_reach_suspicious(self):
        signals = [{'label': 'extracted_urls', 'weight': 4, 'category': 'network'}]
        self.assertEqual(static_verdict_from_score(signals, 4), 'clean')

    def test_dropper_combo_reaches_malicious(self):
        signals = [
            {'label': 'windows_script_dropper', 'weight': 45, 'category': 'malware'},
            {'label': 'powershell_downloader', 'weight': 42, 'category': 'malware'},
        ]
        score = sum(s['weight'] for s in signals)
        self.assertEqual(static_verdict_from_score(signals, score), 'malicious')

    def test_entropy_alone_stays_clean(self):
        signals = [{'label': 'high_entropy', 'weight': 8, 'category': 'packing'}]
        self.assertEqual(static_verdict_from_score(signals, 8), 'clean')


class TestYaraPolicy(unittest.TestCase):
    def test_single_anti_debug_is_review_not_malicious(self):
        matches = [{'rule': 'Suspicious_PE_AntiAnalysis'}]
        self.assertEqual(yara_verdict(matches), 'needs_review')

    def test_dropper_rule_is_malicious(self):
        matches = [{'rule': 'Suspicious_WScript_Dropper'}]
        self.assertEqual(yara_verdict(matches), 'malicious')


class TestSandboxPolicy(unittest.TestCase):
    def test_embedded_urls_alone_not_suspicious(self):
        result = {'mode': 'static_behavioral', 'behaviors': []}
        self.assertEqual(sandbox_lite_verdict(result), 'clean')

    def test_single_anti_debug_is_review(self):
        result = {'mode': 'static_behavioral', 'behaviors': ['anti_debug']}
        self.assertEqual(sandbox_lite_verdict(result), 'needs_review')

    def test_script_download_plus_shell_is_malicious(self):
        result = {
            'mode': 'script_behavioral',
            'behaviors': ['download', 'shell'],
            'script': {'logic_summary': ['download']},
        }
        self.assertEqual(sandbox_lite_verdict(result), 'malicious')


class TestFamilyPolicy(unittest.TestCase):
    def test_weak_iex_only_family_ignored(self):
        hints = {
            'family_matches': [{'family': 'powershell_dropper', 'hits': 1}],
            'match_count': 0,
        }
        self.assertIsNone(family_verdict(hints))

    def test_two_strong_families_suspicious(self):
        hints = {
            'family_matches': [
                {'family': 'asyncrat', 'hits': 1},
                {'family': 'remcos', 'hits': 1},
            ],
        }
        self.assertEqual(family_verdict(hints), 'suspicious')


class TestCombinedDeepVerdict(unittest.TestCase):
    def test_lua51_like_pe_stays_clean_or_review(self):
        verdict, evidence = combine_deep_verdict(
            static={'static_verdict': {'verdict': 'clean', 'score': 8, 'signals': []}},
            yara={'matches': []},
            sandbox_lite={'mode': 'static_behavioral', 'behaviors': [], 'verdict': 'clean'},
            file_intel={'malwarebazaar': {'found': False}},
            ioc_reputation={'results': []},
            family_hints={'family_matches': [], 'match_count': 0},
            deep_exclusive={
                'pe': {
                    'informational_imports': [
                        {'import': 'kernel32.dll:virtualalloc', 'category': 'process_injection'},
                    ],
                    'high_risk_imports': [],
                },
            },
        )
        self.assertIn(verdict, {'clean', 'needs_review'})
        self.assertFalse(any(e.get('tier') == 'strong' and e.get('source') == 'pe_imports' for e in evidence))

    def test_malwarebazaar_plus_yara_dropper_is_malicious(self):
        verdict, _ = combine_deep_verdict(
            static={'static_verdict': {'verdict': 'needs_review', 'score': 10, 'signals': []}},
            yara={'matches': [{'rule': 'Suspicious_WScript_Dropper'}]},
            sandbox_lite={'mode': 'script_behavioral', 'behaviors': ['download'], 'script': {}},
            file_intel={'malwarebazaar': {'found': True, 'family': 'emotet'}},
            ioc_reputation={'results': []},
            family_hints={'family_matches': []},
            deep_exclusive={'script': {'kill_chain_phases': []}},
        )
        self.assertEqual(verdict, 'malicious')

    def test_single_vt_url_not_malicious(self):
        verdict, _ = combine_deep_verdict(
            static={'static_verdict': {'verdict': 'clean', 'score': 0, 'signals': []}},
            yara={'matches': []},
            sandbox_lite={'behaviors': [], 'mode': 'static_behavioral'},
            file_intel={'malwarebazaar': {'found': False}},
            ioc_reputation={'results': [{'malicious': 1, 'url': 'http://example.com'}]},
            family_hints={'family_matches': []},
            deep_exclusive={},
        )
        self.assertNotEqual(verdict, 'malicious')


if __name__ == '__main__':
    unittest.main()
