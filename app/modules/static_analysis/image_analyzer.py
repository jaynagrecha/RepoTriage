from __future__ import annotations

import struct
from pathlib import Path
from typing import Any


def analyze_image(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    ext = path.suffix.lower().lstrip('.')
    result: dict[str, Any] = {'format': ext or 'image', 'embedded_payload_hint': False, 'logic_summary': []}
    if raw.startswith(b'\x89PNG') and len(raw) > 24:
        width, height = struct.unpack('>II', raw[16:24])
        result.update({'width': width, 'height': height, 'container': 'png'})
    elif raw[:3] == b'\xff\xd8\xff':
        result.update({'container': 'jpeg'})
    elif raw.startswith(b'GIF8'):
        result.update({'container': 'gif'})
    trailing = raw[-4096:] if len(raw) > 4096 else raw
    if b'MZ' in trailing or b'PK' in trailing or b'<?php' in trailing or b'<script' in trailing.lower():
        result['embedded_payload_hint'] = True
        result['logic_summary'].append('Image contains trailing embedded executable/script-like data')
    if len(raw) > 1024 and raw.count(b'\x00') / len(raw) > 0.2:
        result['logic_summary'].append('Image has unusually high null-byte density (possible appended payload)')
    return result
