import unittest

from app.modules.deep_analysis.semantic import analyze_semantic
from app.modules.deep_analysis.behavior import interpret_behavior


JSENCRYPTER_IML = '''<?xml version="1.0" encoding="UTF-8"?>
<module org.jetbrains.idea.maven.project.MavenProjectsManager.isMavenModule="true" type="JAVA_MODULE" version="4">
  <component name="NewModuleRootManager" LANGUAGE_LEVEL="JDK_1_5">
    <output url="file://$MODULE_DIR$/target/classes" />
    <output-test url="file://$MODULE_DIR$/target/test-classes" />
    <content url="file://$MODULE_DIR$">
      <sourceFolder url="file://$MODULE_DIR$/src/main/java" isTestSource="false" />
      <excludeFolder url="file://$MODULE_DIR$/target" />
    </content>
    <orderEntry type="inheritedJdk" />
    <orderEntry type="sourceFolder" forTests="false" />
    <orderEntry type="library" name="Maven: net.portswigger.burp.extender:burp-extender-api:1.7.22" level="project" />
  </component>
</module>
'''


class TestConfigSemantic(unittest.TestCase):
    def test_iml_classified_as_idea_module_not_script(self):
        result = analyze_semantic(
            None,
            filename='jsEncrypter.iml',
            sample_text=JSENCRYPTER_IML,
        )
        self.assertEqual(result['purpose_rule_id'], 'idea_module_config')
        self.assertEqual(result['behavior_class'], 'config_metadata')
        self.assertIn('IntelliJ', result['behavior_title'])
        self.assertIn('not executable', result['summary'].lower())
        self.assertIn('burp', result['summary'].lower())
        cap_ids = {c['id'] for c in result['capabilities']}
        self.assertIn('idea_module_descriptor', cap_ids)
        self.assertNotIn('crypto_generic', cap_ids)
        self.assertNotIn('network_http', cap_ids)
        joined = ' '.join(result['what_it_does']).lower()
        self.assertIn('source roots', joined)
        self.assertIn('burp', joined)
        self.assertNotIn('not observed in source', joined)
        self.assertNotIn('utility script', result['summary'].lower())

    def test_iml_deep_behavior_no_unknown_script_fallback(self):
        semantic = analyze_semantic(None, filename='jsEncrypter.iml', sample_text=JSENCRYPTER_IML)
        bundle = {
            'combined_verdict': 'clean',
            'filename': 'jsEncrypter.iml',
            'family_hints': {},
            'semantic': semantic,
            'deep_exclusive': {
                'script': {
                    'language': 'script',
                    'obfuscation_score': 0,
                    'kill_chain_phases': [],
                    'commands_reconstructed': [],
                    'http_calls': [],
                },
            },
        }
        behavior = interpret_behavior(bundle, sample_text=JSENCRYPTER_IML)
        self.assertEqual(behavior['interpretation_source'], 'semantic_capability')
        self.assertEqual(behavior['behavior_class'], 'config_metadata')
        joined = ' '.join(behavior.get('what_it_does') or [])
        self.assertNotIn('No strong behavioral template matched', joined)

    def test_generic_python_no_contradictory_summary_tail(self):
        snippet = '''
def add(a, b):
    return a + b

if __name__ == "__main__":
    print(add(1, 2))
'''
        result = analyze_semantic(None, filename='add.py', sample_text=snippet)
        summary = result['summary'].lower()
        self.assertNotIn('utility script', summary)
        self.assertNotIn('no network http client', summary)
        self.assertNotIn('detected.', summary.split('primary behavior')[-1])


class TestMarshalStubSemantic(unittest.TestCase):
    def test_marshal_exec_stub_detected(self):
        sample = "import marshal\nexec(marshal.loads(b'\\x00\\x00\\x00\\x00\\xe3\\x00\\x00\\x00'))\n"
        result = analyze_semantic(None, filename='HxWhatsApp.py', sample_text=sample)
        self.assertEqual(result.get('purpose_rule_id'), 'python_marshal_stub')
        self.assertIn('marshal', result['summary'].lower())
        self.assertIn('exec', result['summary'].lower())


if __name__ == '__main__':
    unittest.main()
