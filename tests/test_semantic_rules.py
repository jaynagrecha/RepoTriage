import unittest

from app.modules.deep_analysis.semantic_rules import PURPOSE_RULES, build_purpose_rules


class TestPurposeRuleCatalog(unittest.TestCase):
    def test_at_least_one_hundred_rules(self):
        rules = build_purpose_rules()
        self.assertGreaterEqual(len(rules), 100)
        self.assertGreaterEqual(len(PURPOSE_RULES), 100)

    def test_unique_rule_ids(self):
        ids = [r.rule_id for r in PURPOSE_RULES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_all_rules_have_required_fields(self):
        for rule in PURPOSE_RULES:
            self.assertTrue(rule.rule_id)
            self.assertTrue(rule.behavior_title)
            self.assertTrue(rule.requires)
            self.assertIn(rule.threat_category, {
                'malware', 'abuse_tool', 'dual_use_security_tool', 'unknown',
            })


if __name__ == '__main__':
    unittest.main()
