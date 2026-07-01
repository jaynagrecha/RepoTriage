from __future__ import annotations

from typing import Any

# Bump when analysis logic changes so stale cached reports are re-run automatically.
STATIC_ANALYSIS_VERSION = '2.3.2'


def is_stale_record(record: dict[str, Any] | None) -> bool:
    if not record:
        return False
    if record.get('status') != 'completed':
        return False
    if record.get('analysis_version') != STATIC_ANALYSIS_VERSION:
        return True
    profile = record.get('profile') or {}
    filename = (record.get('filename') or '').lower()
    if profile.get('category') in {'binary', 'unknown'} and filename.endswith(('.js', '.vbs', '.ps1', '.hta', '.wsf')):
        return True
    if profile.get('category') == 'binary' and (record.get('functions') or [{}])[0].get('name') == 'offset_0':
        typed = record.get('typed_analysis') or {}
        if not typed.get('logic_summary') and not typed.get('pattern_matches'):
            return True
    return False
