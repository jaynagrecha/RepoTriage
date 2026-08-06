"""Local JsOutProx-style detector (VirusTotal LiveHunt rule without vt module)."""

from __future__ import annotations

from dataclasses import dataclass

from ..types import DetectionHit

# Mirrors the LiveHunt strings (Chetan Birajdar / JsOutProx family heuristics).
REQUIRED_STRINGS: tuple[tuple[str, str], ...] = (
    ('s1', 'var _0x'),
    ('s2', "['\\x"),
    ('s3', 'eval(function(_0x'),
    ('s4', 'new RegExp'),
    ('s5', 'String'),
    ('s6', '(parseInt(_0x'),
)

# Alternate s2 forms commonly seen in obfuscators
ALT_S2 = ('["\\x', "['\\\\x", '["\\\\x')


@dataclass(frozen=True, slots=True)
class SizeBand:
    min_bytes: int = 500 * 1024
    max_bytes: int = 1024 * 1024


def looks_like_javascript(path: str, data: bytes) -> bool:
    name = (path or '').lower()
    if name.endswith(('.js', '.mjs', '.cjs', '.javascript')):
        return True
    head = data[:4000].decode('utf-8', errors='ignore').lstrip()
    if head.startswith(('#!', '//', '/*', 'var ', 'function ', 'const ', 'let ', '(function')):
        return True
    sample = data[:8000].decode('utf-8', errors='ignore')
    return 'var _0x' in sample or 'function' in sample


def scan_bytes(
    data: bytes,
    *,
    path: str = '',
    min_bytes: int = 500 * 1024,
    max_bytes: int = 1024 * 1024,
) -> DetectionHit | None:
    size = len(data)
    if size < min_bytes or size > max_bytes:
        return None
    if not looks_like_javascript(path, data):
        return None

    text = data.decode('utf-8', errors='ignore')
    matched: list[str] = []
    for key, needle in REQUIRED_STRINGS:
        if key == 's2':
            if any(alt in text for alt in (needle, *ALT_S2)):
                matched.append(key)
            continue
        if needle in text:
            matched.append(key)

    required_keys = {k for k, _ in REQUIRED_STRINGS}
    if set(matched) != required_keys:
        return None

    return DetectionHit(
        rule='potential_jsoutprox_js',
        matched_strings=sorted(matched),
        filesize=size,
        local_match=True,
        notes=['Local prefilter matched all JsOutProx LiveHunt strings + size band'],
    )
