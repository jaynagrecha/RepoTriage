import json
import os
import unittest
from unittest.mock import AsyncMock, patch

from app.modules.deep_analysis.llm_semantic import enrich_semantic_with_llm, llm_configured, _validate_llm_output
from app.modules.deep_analysis.semantic import analyze_semantic


ENCDECSHELLCODE = '''
import argparse
parser = argparse.ArgumentParser(description="Encrypting & Decrypting Shellcode")
def EncryptShellcode(shellcode, key):
    return hex(ord('a') ^ ord('b'))
if __name__ == '__main__':
    print(EncryptShellcode("\\x41", "key"))
'''


class TestLlmSemantic(unittest.TestCase):
    def test_llm_disabled_without_key(self):
        with patch.dict(os.environ, {'OPENAI_API_KEY': '', 'SEMANTIC_LLM_ENABLED': 'true'}, clear=False):
            self.assertFalse(llm_configured())

    def test_validate_rejects_hallucinated_c2(self):
        semantic = analyze_semantic(None, filename='x.py', sample_text=ENCDECSHELLCODE)
        with self.assertRaises(ValueError):
            _validate_llm_output(
                {'summary': 'This connects to a C2 beacon and exfiltrates data.'},
                semantic,
            )

    def test_enrich_applies_llm_when_configured(self):
        semantic = analyze_semantic(None, filename='encdecshellcode.py', sample_text=ENCDECSHELLCODE)
        llm_payload = {
            'behavior_title': 'Shellcode XOR encoder CLI',
            'summary': 'Offline Python CLI that XOR-encodes shellcode bytes for lab use.',
            'what_it_does': ['Parses CLI args for shellcode and key', 'Applies XOR locally'],
            'threat_category': 'dual_use_security_tool',
            'recommended_action': 'Use in isolated lab only.',
            'confidence': 'high',
        }

        async def run():
            with patch.dict(os.environ, {'OPENAI_API_KEY': 'test-key', 'SEMANTIC_LLM_ENABLED': 'true'}, clear=False):
                with patch(
                    'app.modules.deep_analysis.llm_semantic._call_openai',
                    new=AsyncMock(return_value=json.dumps(llm_payload)),
                ):
                    return await enrich_semantic_with_llm(
                        semantic,
                        filename='encdecshellcode.py',
                        sample_text=ENCDECSHELLCODE,
                    )

        import asyncio
        result = asyncio.run(run())
        self.assertEqual(result['llm']['status'], 'ok')
        self.assertIn('Offline Python CLI', result['summary'])
        self.assertEqual(result['confidence'], 'high')


if __name__ == '__main__':
    unittest.main()
