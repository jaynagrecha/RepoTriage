import unittest
from app.modules.blocklist_export import export_blocklist, job_diff


class TestBlocklistExport(unittest.TestCase):
    def test_plain_blocklist(self):
        job = {
            'iocs': {'urls': ['http://evil.example/a'], 'domains': ['bad.example'], 'ips': ['203.0.113.1']},
            'files': [{'sha256': 'abc'}],
        }
        out = export_blocklist(job, 'plain')
        self.assertIn('url:http://evil.example/a', out)
        self.assertIn('domain:bad.example', out)
        self.assertIn('sha256:abc', out)

    def test_job_diff(self):
        a = {'files': [{'sha256': '1'}], 'iocs': {'urls': ['http://a']}, 'vt': {'verdict': 'clean'}}
        b = {'files': [{'sha256': '1'}, {'sha256': '2'}], 'iocs': {'urls': ['http://a', 'http://b']}, 'vt': {'verdict': 'malicious'}}
        d = job_diff(a, b)
        self.assertEqual(len(d['files_added']), 1)
        self.assertIn('http://b', d['new_urls'])


if __name__ == '__main__':
    unittest.main()
