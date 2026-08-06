#!/usr/bin/env python3
"""RepoTriage repository hunt + SMTP alerts.

Modes:
  - one-shot (default): run once and exit (cron-friendly)
  - loop (REPO_HUNT_LOOP=true): continuous 24/7 scanning with sleep between cycles
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(ROOT / '.env')

from app.modules.repo_hunt import RepoHuntConfig, run_repo_hunt  # noqa: E402


def _bool(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return str(val).strip().lower() in {'1', 'true', 'yes', 'on'}


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default


def _acquire_lock(lock_path: Path) -> int | None:
    """Non-blocking exclusive lock so overlapping cycles cannot stack."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o644)
    try:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        return None
    except Exception:
        # Windows / no fcntl — best-effort continue without lock
        try:
            os.close(fd)
        except Exception:
            pass
        return -1
    os.write(fd, f'{os.getpid()}\n'.encode())
    return fd


def _release_lock(fd: int | None, lock_path: Path) -> None:
    if fd is None or fd < 0:
        return
    try:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_UN)
    except Exception:
        pass
    try:
        os.close(fd)
    except Exception:
        pass
    try:
        lock_path.unlink(missing_ok=True)
    except Exception:
        pass


async def _run_once(base: Path, cfg: RepoHuntConfig) -> int:
    report = await run_repo_hunt(base, cfg=cfg, send=True)
    print(json.dumps(report, indent=2, default=str), flush=True)
    if not report.get('ok') and report.get('error'):
        return 2
    if report.get('email') and report['email'].get('ok') is False and not report['email'].get('skipped'):
        return 3
    return 0


async def main() -> int:
    base = Path(os.getenv('PLATFORM_DATA_DIR') or ROOT)
    cfg = RepoHuntConfig.from_env()
    loop = _bool('REPO_HUNT_LOOP', False)
    # Default 5 minutes — near-continuous without burning GitHub/VT quotas
    interval = max(60, _int('REPO_HUNT_INTERVAL_SECONDS', 300))
    lock_path = base / 'data' / 'repo_hunt' / 'worker.lock'

    if not loop:
        fd = _acquire_lock(lock_path)
        if fd is None:
            print(json.dumps({'ok': False, 'skipped': True, 'reason': 'another_hunt_running'}), flush=True)
            return 0
        try:
            return await _run_once(base, cfg)
        finally:
            _release_lock(fd, lock_path)

    print(
        json.dumps({
            'ok': True,
            'mode': 'loop',
            'interval_seconds': interval,
            'enabled': cfg.enabled,
            'smtp_ready': cfg.smtp_ready(),
            'message': 'RepoTriage hunt worker running 24/7',
        }),
        flush=True,
    )

    while True:
        cycle_started = time.time()
        fd = _acquire_lock(lock_path)
        if fd is None:
            print(json.dumps({'ok': True, 'skipped': True, 'reason': 'another_hunt_running'}), flush=True)
        else:
            try:
                code = await _run_once(base, cfg)
                if code not in {0, 3}:
                    print(json.dumps({'ok': False, 'cycle_exit': code}), flush=True)
            except Exception as exc:
                print(json.dumps({
                    'ok': False,
                    'error': f'{exc.__class__.__name__}: {exc}',
                }), flush=True)
            finally:
                _release_lock(fd, lock_path)

        elapsed = time.time() - cycle_started
        sleep_for = max(5.0, interval - elapsed)
        print(json.dumps({
            'ok': True,
            'event': 'sleep',
            'seconds': round(sleep_for, 1),
            'next_cycle_in': round(sleep_for, 1),
        }), flush=True)
        await asyncio.sleep(sleep_for)


if __name__ == '__main__':
    raise SystemExit(asyncio.run(main()))
