from __future__ import annotations

import struct
import zipfile
from pathlib import Path
from typing import Any


def analyze_archive(path: Path) -> dict[str, Any]:
    ext = path.suffix.lower().lstrip('.')
    if path.read_bytes()[:2] == b'PK':
        return _analyze_zip(path)
    return {
        'format': ext or 'archive',
        'note': 'Archive structure inspected at header level; child members are analyzed separately when extracted.',
    }


def _analyze_zip(path: Path) -> dict[str, Any]:
    members: list[dict[str, Any]] = []
    suspicious_names: list[str] = []
    try:
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist()[:200]:
                name = info.filename
                members.append({
                    'name': name,
                    'compressed_size': info.compress_size,
                    'file_size': info.file_size,
                    'is_dir': name.endswith('/'),
                })
                lower = name.lower()
                if any(x in lower for x in ('.exe', '.dll', '.js', '.vbs', '.ps1', '.bat', '.hta', '.scr', '.cmd')):
                    suspicious_names.append(name)
            return {
                'format': 'zip',
                'member_count': len(members),
                'members_preview': members[:40],
                'suspicious_members': suspicious_names[:30],
                'logic_summary': ['Archive contains executable/script payloads'] if suspicious_names else [],
            }
    except Exception as exc:
        return {'format': 'zip', 'error': exc.__class__.__name__}
