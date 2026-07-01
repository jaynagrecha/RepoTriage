import tempfile
import unittest
from pathlib import Path

from app.platform import PlatformDB, TaskQueue


class TestPlatformDB(unittest.TestCase):
    def test_task_queue_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            db = PlatformDB(base)
            queue = TaskQueue(db)
            task_id = queue.enqueue('deep_analysis', job_id='j1', sha256='abc', payload={'filename': 'x.js'})
            claimed = queue.claim()
            self.assertEqual(claimed['task_id'], task_id)
            queue.complete(task_id, {'ok': True})
            task = queue.get(task_id)
            self.assertEqual(task['status'], 'completed')


if __name__ == '__main__':
    unittest.main()
