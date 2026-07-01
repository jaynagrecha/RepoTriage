from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any


def r2_available() -> bool:
    binary = (os.getenv('R2_BINARY') or 'r2').strip() or 'r2'
    return shutil.which(binary) is not None


def _r2_cmd(path: Path, commands: str, timeout: int) -> str:
    binary = (os.getenv('R2_BINARY') or 'r2').strip() or 'r2'
    cmd = [binary, '-q', '-e', 'scr.color=false', '-c', commands, str(path)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError((proc.stderr or proc.stdout or 'r2 failed').strip()[:300])
    return proc.stdout


def analyze_with_r2(path: Path, timeout: int = 120) -> dict[str, Any]:
    timeout = int(os.getenv('STATIC_ANALYSIS_R2_TIMEOUT', str(timeout)))
    _r2_cmd(path, 'aaa', timeout)
    functions_raw = _r2_cmd(path, 'aflj', timeout)
    imports_raw = _r2_cmd(path, 'iij', timeout)
    strings_raw = _r2_cmd(path, 'izj', timeout)
    functions = _safe_json(functions_raw, [])
    imports = _safe_json(imports_raw, [])
    strings = _safe_json(strings_raw, [])

    analyzed_functions: list[dict[str, Any]] = []
    for fn in functions[:25]:
        name = fn.get('name') or fn.get('offset')
        if not name:
            continue
        try:
            disasm = _r2_cmd(path, f'pdf @ {name}', timeout)[:4000]
            decomp = ''
            try:
                decomp = _r2_cmd(path, f'pdc @ {name}', timeout)[:4000]
            except Exception:
                decomp = ''
            analyzed_functions.append({
                'name': name,
                'size': fn.get('size'),
                'offset': fn.get('offset'),
                'logic_summary': _summarize_disasm(disasm, decomp),
                'disassembly_preview': disasm[:1500],
                'decompilation_preview': decomp[:1500] if decomp else None,
            })
        except Exception as exc:
            analyzed_functions.append({'name': name, 'error': exc.__class__.__name__})

    return {
        'engine': 'radare2',
        'function_count': len(functions),
        'import_count': len(imports),
        'string_count': len(strings),
        'functions': analyzed_functions,
        'imports_preview': imports[:40],
        'strings_preview': [s.get('string') for s in strings[:40] if isinstance(s, dict)],
    }


def _safe_json(raw: str, default: Any) -> Any:
    try:
        return json.loads(raw or 'null') or default
    except Exception:
        return default


def _summarize_disasm(disasm: str, decomp: str) -> list[str]:
    text = f'{disasm}\n{decomp}'.lower()
    tags = []
    mapping = {
        'network': ('socket', 'connect', 'wininet', 'urlmon', 'internetread'),
        'injection': ('virtualalloc', 'writeprocessmemory', 'createremotethread', 'ntcreatethreadex'),
        'anti_debug': ('isdebuggerpresent', 'checkremotedebuggerpresent', 'ntqueryinformationprocess'),
        'process_spawn': ('createprocess', 'shellexecute', 'winexec', 'system('),
        'crypto': ('crypt', 'aes', 'rsa', 'bcrypt'),
        'obfuscation': ('xor', 'rol', 'ror', 'not ', 'nop'),
    }
    for label, needles in mapping.items():
        if any(n in text for n in needles):
            tags.append(label)
    return tags
