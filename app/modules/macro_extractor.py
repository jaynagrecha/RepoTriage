from __future__ import annotations

import re
import zipfile
from pathlib import Path
from typing import Any


def extract_office_macros(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {'format': 'office', 'macros_detected': False, 'vba_modules': [], 'logic_summary': []}
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            if any('vbaProject.bin' in n for n in names):
                result['macros_detected'] = True
                result['logic_summary'].append('Office document contains VBA macro project (vbaProject.bin).')
            for name in names:
                if not name.endswith('.xml'):
                    continue
                try:
                    text = zf.read(name)[:500_000].decode('utf-8', errors='ignore')
                except Exception:
                    continue
                if 'macro' in name.lower() or 'vba' in text.lower()[:5000]:
                    result['vba_modules'].append({'part': name, 'size': len(text)})
                for url in re.findall(r'https?://[^\s\'\"<>]+', text)[:10]:
                    result.setdefault('urls', []).append(url)
    except Exception as exc:
        result['error'] = exc.__class__.__name__
    if result.get('urls'):
        result['logic_summary'].append(f"Macro/document parts reference {len(result['urls'])} URL(s).")
    return result
