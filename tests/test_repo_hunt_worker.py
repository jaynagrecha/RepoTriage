import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))

import repo_hunt_worker as worker  # noqa: E402


class TestRepoHuntWorkerLock(unittest.TestCase):
    def test_lock_exclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / 'worker.lock'
            fd1 = worker._acquire_lock(lock)
            self.assertIsNotNone(fd1)
            if fd1 == -1:
                self.skipTest('fcntl unavailable')
            fd2 = worker._acquire_lock(lock)
            self.assertIsNone(fd2)
            worker._release_lock(fd1, lock)
            fd3 = worker._acquire_lock(lock)
            self.assertIsNotNone(fd3)
            worker._release_lock(fd3, lock)


class TestRepoHuntWorkerOnce(unittest.IsolatedAsyncioTestCase):
    async def test_run_once_success(self):
        fake = {'ok': True, 'email': {'ok': True, 'skipped': True, 'reason': 'no_new_findings'}}
        with patch('repo_hunt_worker.run_repo_hunt', new=AsyncMock(return_value=fake)) as mocked:
            code = await worker._run_once(Path('.'), cfg=object())  # type: ignore[arg-type]
        self.assertEqual(code, 0)
        mocked.assert_awaited()

    @patch.dict(os.environ, {'REPO_HUNT_LOOP': 'false'}, clear=False)
    async def test_main_one_shot(self):
        fake = {'ok': True, 'email': {'ok': True, 'skipped': True}}
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {'PLATFORM_DATA_DIR': tmp}, clear=False):
                with patch('repo_hunt_worker.run_repo_hunt', new=AsyncMock(return_value=fake)):
                    with patch('repo_hunt_worker.RepoHuntConfig.from_env') as cfg_factory:
                        cfg_factory.return_value = object()
                        code = await worker.main()
        self.assertEqual(code, 0)


if __name__ == '__main__':
    unittest.main()
