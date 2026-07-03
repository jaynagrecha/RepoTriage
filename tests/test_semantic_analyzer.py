import unittest

from app.modules.deep_analysis.semantic import analyze_semantic
from app.modules.deep_analysis.behavior import interpret_behavior


ENCDECSHELLCODE = '''
import argparse
from sys import argv, stdout, exit

parser = argparse.ArgumentParser(description="Encrypting & Decrypting Shellcode")
parser.add_argument('-s', '--shellcode', help='Shellcode To Encrypt & Decrypt')
parser.add_argument('-k', '--key', help='Key Of The Shellcode To Encrypt & Decrpyt', default='key')
parser.add_argument('-o', '--option', help='Argument For Encrypting or Decrypting The Shellcode')

args = parser.parse_args()

def EncryptShellcode(shellcode, key):
    shellcode_encrypted_hex = []
    for x in range(0, len(shellcode_decrypted_hex)):
        shellcode_encrypted_hex.append(hex(ord(shellcode_decrypted_hex[x].decode('hex')) ^ ord(key[d])))
    shellcode_replaced_hex += shellcode_encrypted_hex[y].replace('0x', r'\\x')
    return shellcode_replaced_hex

def DecryptShellcode(shellcode, key):
    shellcode_decrypted = []
    for z in range(len(shellcode_xor_headers)):
        shellcode_decrypted.append(hex(ord(shellcode_xor_headers[z].decode('hex')) ^ ord(key[0])))
    return shellcode_replaced_hex

if __name__ == '__main__':
    if args.option == "encrypt":
        print("Encrypted Shellcode = " + EncryptShellcode(args.shellcode, args.key))
    elif args.option == "decrypt":
        print("Decrypted Shellcode = " + DecryptShellcode(args.shellcode, args.key))
'''


class TestSemanticAnalyzer(unittest.TestCase):
    def test_encdecshellcode_classified_by_capabilities(self):
        result = analyze_semantic(
            None,
            filename='encdecshellcode.py',
            sample_text=ENCDECSHELLCODE,
        )
        self.assertTrue(result['ast_parsed'])
        self.assertEqual(result['purpose_rule_id'], 'shellcode_encoder_utility')
        self.assertEqual(result['behavior_class'], 'shellcode_tool')
        self.assertIn('shellcode', result['summary'].lower())
        self.assertIn('xor', result['summary'].lower())
        cap_ids = {c['id'] for c in result['capabilities']}
        self.assertIn('crypto_xor', cap_ids)
        self.assertIn('shellcode_transform', cap_ids)
        self.assertIn('cli_interface', cap_ids)
        self.assertNotIn('network_http', cap_ids)

    def test_encdecshellcode_deep_behavior_uses_semantic(self):
        bundle = {
            'combined_verdict': 'needs_review',
            'filename': 'encdecshellcode.py',
            'family_hints': {},
            'semantic': analyze_semantic(None, filename='encdecshellcode.py', sample_text=ENCDECSHELLCODE),
            'deep_exclusive': {
                'script': {
                    'language': 'python',
                    'obfuscation_score': 2,
                    'kill_chain_phases': [{'phase': 'decode', 'label': 'De-obfuscation / decoding'}],
                    'commands_reconstructed': [],
                    'http_calls': [],
                },
            },
        }
        behavior = interpret_behavior(bundle, sample_text=ENCDECSHELLCODE)
        self.assertEqual(behavior['interpretation_source'], 'semantic_capability')
        self.assertEqual(behavior['behavior_class'], 'shellcode_tool')
        self.assertNotEqual(behavior['behavior_class'], 'unknown_script')
        self.assertIn('encode/decode', behavior['behavior_title'].lower())

    def test_unknown_script_gets_composed_summary(self):
        snippet = '''
def add(a, b):
    return a + b

if __name__ == "__main__":
    print(add(1, 2))
'''
        result = analyze_semantic(None, filename='add.py', sample_text=snippet)
        self.assertTrue(result['ast_parsed'])
        self.assertIsNone(result['purpose_rule_id'])
        self.assertEqual(result['inference_method'], 'capability_compose')
        self.assertIn('python', result['summary'].lower())


if __name__ == '__main__':
    unittest.main()
