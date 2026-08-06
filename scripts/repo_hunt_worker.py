#!/usr/bin/env python3
"""Cron/worker entrypoint for RepoTriage repository hunt + SMTP alerts."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(ROOT / '.env')

from app.modules.repo_hunt import RepoHuntConfig, run_repo_hunt  # noqa: E402


async def main() -> int:
    base = Path(os.getenv('PLATFORM_DATA_DIR') or ROOT)
    cfg = RepoHuntConfig.from_env()
    report = await run_repo_hunt(base, cfg=cfg, send=True)
    print(json.dumps(report, indent=2, default=str))
    if not report.get('ok') and report.get('error'):
        return 2
    if report.get('email') and report['email'].get('ok') is False and not report['email'].get('skipped'):
        return 3
    return 0


if __name__ == '__main__':
    raise SystemExit(asyncio.run(main()))
