from __future__ import annotations

import re
from typing import Any


def extract_structure(language: str, text: str) -> dict[str, Any]:
    fn = {
        'python': _structure_python_fallback,
        'javascript': _structure_javascript,
        'powershell': _structure_powershell,
        'ruby': _structure_ruby,
        'shell': _structure_shell,
        'batch': _structure_batch,
        'vbscript': _structure_vbscript,
    }.get(language, _structure_generic)
    return fn(text)


def _structure_generic(text: str) -> dict[str, Any]:
    functions: list[dict[str, Any]] = []
    for match in re.finditer(
        r'(?:function\s+([A-Za-z_$][\w$]*)|def\s+([A-Za-z_][\w]*)|sub\s+([A-Za-z_][\w]*))',
        text,
        re.I,
    ):
        name = next(g for g in match.groups() if g)
        functions.append({'name': name, 'class': None, 'args': [], 'doc': ''})
        if len(functions) >= 30:
            break
    entry = 'script'
    if re.search(r'argparse|getopt|sys\.argv|ArgumentParser', text, re.I):
        entry = 'cli'
    return {'functions': functions, 'entry_point': entry, 'imports': [], 'parsed': bool(functions)}


def _structure_python_fallback(text: str) -> dict[str, Any]:
    return _structure_generic(text)


def _structure_javascript(text: str) -> dict[str, Any]:
    functions: list[dict[str, Any]] = []
    imports: list[str] = []
    for m in re.finditer(r'(?:function\s+([A-Za-z_$][\w$]*)|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)', text):
        functions.append({'name': m.group(1) or m.group(2), 'class': None, 'args': [], 'doc': ''})
    for m in re.finditer(r'(?:require\s*\(\s*[\'"]([^\'"]+)[\'"]|import\s+.*?from\s+[\'"]([^\'"]+)[\'"])', text):
        imports.append(m.group(1) or m.group(2))
    entry = 'cli' if re.search(r'process\.argv|yargs|commander', text) else 'script'
    if re.search(r'module\.exports|export\s+(?:default|function|const)', text):
        entry = 'library' if entry == 'script' else entry
    return {'functions': functions[:30], 'entry_point': entry, 'imports': imports[:20], 'parsed': True}


def _structure_powershell(text: str) -> dict[str, Any]:
    functions: list[dict[str, Any]] = []
    for m in re.finditer(r'function\s+([A-Za-z0-9_-]+)', text, re.I):
        functions.append({'name': m.group(1), 'class': None, 'args': [], 'doc': ''})
    entry = 'cli' if re.search(r'param\s*\(', text, re.I) else 'script'
    return {'functions': functions[:30], 'entry_point': entry, 'imports': [], 'parsed': True}


def _structure_ruby(text: str) -> dict[str, Any]:
    functions: list[dict[str, Any]] = []
    classes: list[str] = []
    for m in re.finditer(r'class\s+([A-Za-z_][\w]*)', text):
        classes.append(m.group(1))
    for m in re.finditer(r'def\s+([A-Za-z_][\w!?]*)', text):
        functions.append({'name': m.group(1), 'class': classes[-1] if classes else None, 'args': [], 'doc': ''})
    entry = 'library' if re.search(r'class\s+MetasploitModule|module\s+Msf', text) else 'script'
    return {'functions': functions[:30], 'entry_point': entry, 'imports': re.findall(r"require\s+['\"]([^'\"]+)['\"]", text)[:15], 'parsed': True}


def _structure_shell(text: str) -> dict[str, Any]:
    functions: list[dict[str, Any]] = []
    for m in re.finditer(r'(?:function\s+)?([A-Za-z_][\w]*)\s*\(\)\s*\{', text):
        functions.append({'name': m.group(1), 'class': None, 'args': [], 'doc': ''})
    entry = 'cli' if text.startswith('#!') else 'script'
    return {'functions': functions[:20], 'entry_point': entry, 'imports': [], 'parsed': True}


def _structure_batch(text: str) -> dict[str, Any]:
    return {'functions': [], 'entry_point': 'script', 'imports': [], 'parsed': bool(text.strip())}


def _structure_vbscript(text: str) -> dict[str, Any]:
    functions: list[dict[str, Any]] = []
    for m in re.finditer(r'(?:Sub|Function)\s+([A-Za-z_][\w]*)', text, re.I):
        functions.append({'name': m.group(1), 'class': None, 'args': [], 'doc': ''})
    return {'functions': functions[:20], 'entry_point': 'script', 'imports': [], 'parsed': True}


def merge_ast_and_structure(ast_info: dict[str, Any], structure: dict[str, Any]) -> dict[str, Any]:
    if ast_info.get('parsed'):
        return ast_info
    if structure.get('parsed'):
        return {
            'parsed': True,
            'functions': structure.get('functions') or [],
            'imports': structure.get('imports') or [],
            'entry_point': structure.get('entry_point') or 'script',
            'calls': [],
            'argparse': structure.get('entry_point') == 'cli',
        }
    return ast_info
