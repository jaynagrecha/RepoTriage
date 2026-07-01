from __future__ import annotations

import re
from pathlib import Path
from typing import Any


def analyze_text(path: Path) -> dict[str, Any]:
    text = path.read_bytes().decode('utf-8', errors='ignore')
    lines = text.splitlines()
    urls = re.findall(r'https?://[^\s\'"]+', text)[:30]
    commands = len(re.findall(r'(?i)(cmd\.exe|powershell|wget|curl|bash|sh -c|python -c)', text))
    encoded = len(re.findall(r'(?i)(base64|rot13|xor|chr\()', text))
    return {
        'format': 'text',
        'line_count': len(lines),
        'links': urls,
        'command_markers': commands,
        'obfuscation_markers': encoded,
        'preview': '\n'.join(lines[:20])[:1000],
        'logic_summary': ['Text file contains command execution markers'] if commands else [],
    }
