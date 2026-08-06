"""Filename deception signals (dual extension, masquerade)."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

# Trailing real extension → claimed/masquerade stem tokens often seen in droppers
_REAL_CODE_EXTS = {
    'js', 'jse', 'mjs', 'cjs', 'vbs', 'vbe', 'wsf', 'wsh', 'ps1', 'psd1', 'psm1',
    'bat', 'cmd', 'hta', 'exe', 'dll', 'scr', 'com', 'pif', 'msi', 'jar', 'apk',
}
_IMAGE_DOC_CLAIM = {
    'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'tif', 'tiff', 'svg', 'ico',
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf', 'mp3',
    'mp4', 'avi', 'mov', 'wav',
}
_ARCHIVE_CLAIM = {'zip', '7z', 'rar', 'tar', 'gz', 'tgz', 'bz2', 'xz', 'cab', 'iso'}


def _split_extensions(name: str) -> list[str]:
    base = PurePosixPath((name or '').strip()).name.lower()
    if not base or '.' not in base:
        return []
    parts = [p for p in base.split('.') if p]
    if len(parts) < 2:
        return []
    # parts[0] is stem-ish; rest are extensions
    return parts[1:]


def detect_dual_extension(name: str | None) -> dict | None:
    """
    Detect dual-extension / type-masquerade filenames.

    Examples:
      mtcn_details_jpg.js      → claims jpg, real js
      remit_..._jpg.js         → claims jpg, real js
      invoice.pdf.exe          → claims pdf, real exe
      photo.jpg.7z             → claims jpg, real 7z archive
    """
    raw = (name or '').strip()
    if not raw:
        return None
    base = PurePosixPath(raw).name
    lower = base.lower()
    exts = _split_extensions(lower)
    if len(exts) < 1:
        return None

    real = exts[-1]
    claimed: list[str] = []

    # Multi-dot: file.jpg.js
    if len(exts) >= 2:
        claimed = exts[:-1]
    else:
        # Single real ext but stem embeds another type: foo_jpg.js / foo-jpg.js
        stem = lower[: -(len(real) + 1)]
        for token in _IMAGE_DOC_CLAIM | _ARCHIVE_CLAIM:
            if re.search(rf'(^|[_\-.]){re.escape(token)}($|[_\-.])', stem):
                claimed.append(token)

    if not claimed:
        return None

    # Only flag when real type conflicts with claimed presentation
    conflict = False
    if real in _REAL_CODE_EXTS and any(c in _IMAGE_DOC_CLAIM or c in _ARCHIVE_CLAIM for c in claimed):
        conflict = True
    if real in _ARCHIVE_CLAIM and any(c in _IMAGE_DOC_CLAIM for c in claimed):
        conflict = True
    if real in _IMAGE_DOC_CLAIM and any(c in _REAL_CODE_EXTS for c in claimed):
        conflict = True
    if not conflict and len(exts) >= 2:
        # Generic multi-extension still useful to surface
        conflict = True

    if not conflict:
        return None

    return {
        'filename': base,
        'real_extension': real,
        'claimed_extensions': claimed,
        'label': f"{'.'.join(claimed)} masquerading as → .{real}" if claimed else f'dual extension → .{real}',
        'severity': 'High' if real in _REAL_CODE_EXTS else 'Medium',
    }


def scan_names_for_dual_extension(names: list[str | None]) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for n in names:
        hit = detect_dual_extension(n)
        if not hit:
            continue
        key = hit['filename'].lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(hit)
    return out
