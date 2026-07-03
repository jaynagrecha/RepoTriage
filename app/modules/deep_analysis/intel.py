from __future__ import annotations

from pathlib import Path
from typing import Any

from ..malwarebazaar import lookup_hash
from ..threatfox import enrich_iocs


async def enrich_file_intel(sha256: str, filename: str, base_dir: Path, iocs: dict[str, Any] | None = None) -> dict[str, Any]:
    file_row = {'sha256': sha256, 'filename': filename, 'path': filename}
    mb = await lookup_hash(file_row, base_dir)

    tf_result: dict[str, Any] = {'status': 'skipped', 'matches': []}
    if iocs:
        try:
            tf_result = await enrich_iocs(iocs, base_dir)
        except Exception as exc:
            tf_result = {'status': 'error', 'error': exc.__class__.__name__, 'matches': []}

    return {
        'malwarebazaar': mb,
        'threatfox': {
            'status': tf_result.get('status'),
            'match_count': len(tf_result.get('matches') or []),
            'matches': (tf_result.get('matches') or [])[:10],
        },
    }
