#!/usr/bin/env python3
"""CLI smoke test for live Abuse.ch CTI (requires ABUSECH_API_KEY)."""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.modules.cti_selftest import run_cti_selftest  # noqa: E402


async def main() -> int:
    with tempfile.TemporaryDirectory(prefix='repotriage-cti-') as tmp:
        report = await run_cti_selftest(Path(tmp))
    print(json.dumps(report, indent=2, default=str))
    return 0 if report.get('ok') else 1


if __name__ == '__main__':
    raise SystemExit(asyncio.run(main()))
