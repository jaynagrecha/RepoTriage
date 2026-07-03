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
        self.assertGreaterEqual(len(signals['auth_sms_api_urls']), 2)

        bundle = {
            'combined_verdict': 'needs_review',
            'deep_exclusive': {'script': script},
        }
        behavior = interpret_behavior(bundle, sample_text=SMS_BOMB_SNIPPET)
        self.assertEqual(behavior['behavior_class'], 'sms_otp_abuse')
        self.assertEqual(behavior['threat_category'], 'abuse_tool')
        self.assertIn('SMS/OTP', behavior['summary'])
        self.assertIn('phone', behavior['summary'].lower())
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


LINPEAS_SNIPPET = '''
# LinPEAS-style local enumeration
printf $B"Linux Privesc Checklist: "$Y"https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist\\n"$NC
knw_grps="\\|(lpadmin)\\|\\|(cdrom)\\|\\|(plugdev)\\|\\|(nogroup\\)" #https://www.togaware.com/linux/survivor/Standard_Groups.html
sidG2="/ncsa_auth$|/netpr$|/netkit-rcp$|/netkit-rlogin$|/netkit-rsh$|/netreport$|/netstat$"
#To update sidVB: curl https://github.com/GTFOBins/GTFOBins.github.io/tree/master/_gtfobins 2>/dev/null
sidVB='/apt-get$|/apt$|/aria2c$|/arp$|/ash$|/awk$|/base32$|/base64$|/bash$|/bpftrace$|/bundler$|/busctl$|/busybox$'
sudoVB=" \\"|env_keep\\+=LD_PRELOAD|apt-get$|apt$|aria2c$|arp$|ash$|awk$|base64$|bash$|busybox$|cat$|chmod$|chown$|cp$"
sudocapsB="/apt-get|/apt|/aria2c|/arp|/ash|/awk|/base64|/bash|/busybox|/cat|/chmod|/chown|/cpulimit|/crontab/"
INTERESTING_RELEVANT_NAMES=".env|.google_authenticator|.history|.bashrc|.htpasswd|.gitconfig|id_rsa|id_dsa"
https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation/linux-privilege-escalation-basic-tools/kernel-exploits
https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation/linux-privilege-escalation-basic-tools/sudo-version
https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation/linux-privilege-escalation-basic-tools/dmesg-signature-verification-failed
https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation/linux-privilege-escalation-basic-tools/capabilities
https://gtfobins.github.io/gtfobins/curl/
'''


class TestLinPeasBehavior(unittest.TestCase):
    def test_linpeas_not_classified_as_sms_abuse(self):
        script = {
            'c2_urls': [
                'https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist',
                'https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation/linux-privilege-escalation-basic-tools/kernel-exploits',
                'https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation/linux-privilege-escalation-basic-tools/dmesg-signature-verification-failed',
                'https://gtfobins.github.io/gtfobins/curl/',
                'https://www.togaware.com/linux/survivor/Standard_Groups.html',
            ],
            'http_calls': [
                {'method': 'GET', 'url': 'https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist', 'purpose': 'reference'},
                {'method': 'GET', 'url': 'https://gtfobins.github.io/gtfobins/curl/', 'purpose': 'reference'},
            ],
            'commands_reconstructed': [
                'printf $B"Linux Privesc Checklist: "$Y"https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist\\n"$NC',
                'sidVB=\'/apt-get$|/apt$|/aria2c$|/bash$|/busybox$\'',
                'sudoVB=" \\"|env_keep\\+=LD_PRELOAD|apt-get$|bash$|cat$|chmod$"',
            ],
            'language': 'script',
            'obfuscation_score': 0,
        }
        signals = extract_script_signals(LINPEAS_SNIPPET, script)
        self.assertGreaterEqual(signals['privesc_score'], 10)
        self.assertGreaterEqual(len(signals['documentation_urls']), 2)
        self.assertEqual(len(signals['auth_sms_api_urls']), 0)
        self.assertFalse(signals['has_phone_fields'])

        bundle = {
            'combined_verdict': 'malicious',
            'deep_exclusive': {'script': script},
        }
        behavior = interpret_behavior(bundle, sample_text=LINPEAS_SNIPPET)
        self.assertEqual(behavior['behavior_class'], 'linux_privesc_enum')
        self.assertNotEqual(behavior['behavior_class'], 'sms_otp_abuse')
        self.assertEqual(behavior['threat_category'], 'dual_use_security_tool')
        self.assertEqual(behavior['behavior_title'], 'Linux privilege-escalation enumerator')
        self.assertIn('privilege-escalation', behavior['summary'].lower())
        self.assertTrue(behavior['summary'].lower().startswith('this behaves like a linux'))
        self.assertNotIn('sms', behavior['summary'].lower())
        self.assertNotIn('otp', behavior['summary'].lower())
        joined = ' '.join(behavior['what_it_does'] + [behavior.get('vt_context') or '']).lower()
        self.assertNotIn('sms', joined)
        self.assertNotIn('otp', joined)

    def test_hacktricks_signature_verification_url_not_auth_sms(self):
        from app.modules.deep_analysis.behavior import is_auth_sms_api_url, is_documentation_url

        url = 'https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation/linux-privilege-escalation-basic-tools/dmesg-signature-verification-failed'
        self.assertTrue(is_documentation_url(url))
        self.assertFalse(is_auth_sms_api_url(url))


BF_XOR_SNIPPET = '''
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
require 'msf/core'
class MetasploitModule < Msf::Auxiliary
  def run
    # brute-force XOR decode helper
  end
end
'''


class TestMetasploitModuleBehavior(unittest.TestCase):
    def test_bf_xor_classified_as_metasploit_module(self):
        family_hints = {
            'primary_family_hint': 'metasploit',
            'family_matches': [{'family': 'metasploit', 'hits': 4, 'sample': 'Metasploit'}],
        }
        script = {
            'c2_urls': [
                'http://metasploit.com/download',
                'https://github.com/rapid7/metasploit-framework',
            ],
            'http_calls': [],
            'commands_reconstructed': [
                '# This module requires Metasploit: http://metasploit.com/download',
                '# Current source: https://github.com/rapid7/metasploit-framework',
            ],
            'language': 'script',
            'obfuscation_score': 1,
        }
        signals = extract_script_signals(
            BF_XOR_SNIPPET,
            script,
            family_hints=family_hints,
            filename='bf_xor.rb',
        )
        self.assertGreaterEqual(signals['metasploit_score'], 8)
        self.assertEqual(signals['metasploit_module_role'], 'brute-force XOR / decode auxiliary')

        bundle = {
            'combined_verdict': 'needs_review',
            'filename': 'bf_xor.rb',
            'family_hints': family_hints,
            'deep_exclusive': {'script': script},
        }
        behavior = interpret_behavior(bundle, sample_text=BF_XOR_SNIPPET)
        self.assertEqual(behavior['behavior_class'], 'metasploit_module')
        self.assertEqual(behavior['behavior_title'], 'Metasploit Framework module')
        self.assertEqual(behavior['threat_category'], 'dual_use_security_tool')
        self.assertIn('metasploit', behavior['summary'].lower())
        self.assertIn('msfconsole', behavior['summary'].lower())
        self.assertNotEqual(behavior['behavior_class'], 'unknown_script')


if __name__ == '__main__':
    unittest.main()
