from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path
from typing import Any


def analyze_document(path: Path, profile_ext: str) -> dict[str, Any]:
    ext = profile_ext or path.suffix.lower().lstrip('.')
    raw = path.read_bytes()
    text = raw.decode('utf-8', errors='ignore')
    result: dict[str, Any] = {'format': ext or 'document', 'embedded_objects': [], 'links': [], 'macros_detected': False}

    if ext == 'pdf' or raw.startswith(b'%PDF'):
        result.update(_analyze_pdf(raw, text))
    elif ext in {'html', 'htm', 'xhtml', 'svg'} or text.lstrip().startswith('<!'):
        result.update(_analyze_html(text))
    elif ext in {'xml', 'xsl', 'xslt'} or text.lstrip().startswith('<?xml'):
        result.update(_analyze_xml(text))
    elif ext in {'json'} or text.lstrip().startswith(('{', '[')):
        result.update(_analyze_json(text))
    elif ext in {'yaml', 'yml', 'ini', 'cfg', 'conf', 'env', 'toml', 'properties', 'csv', 'tsv', 'md'}:
        result.update(_analyze_structured_text(text, ext))
    elif ext in {'docx', 'xlsx', 'pptx', 'docm', 'xlsm', 'pptm', 'odt', 'ods'}:
        result.update(_analyze_office_zip(path))
    else:
        result.update(_analyze_structured_text(text, ext or 'text'))
    return result


def _analyze_pdf(raw: bytes, text: str) -> dict[str, Any]:
    js_actions = len(re.findall(r'/JavaScript|/JS|/OpenAction|/AA', text, re.I))
    embeds = len(re.findall(r'/EmbeddedFile|/Launch|/URI', text, re.I))
    urls = re.findall(r'https?://[^\s<>"]+', text)[:30]
    return {
        'format': 'pdf',
        'javascript_actions': js_actions,
        'embedded_references': embeds,
        'links': urls,
        'macros_detected': js_actions > 0,
        'logic_summary': ['PDF contains JavaScript or launch actions'] if js_actions or embeds else [],
    }


def _analyze_html(text: str) -> dict[str, Any]:
    scripts = re.findall(r'<script[^>]*>(.*?)</script>', text, re.I | re.S)
    urls = re.findall(r'https?://[^\s\'"<>]+', text)[:40]
    iframe_count = len(re.findall(r'<iframe\b', text, re.I))
    return {
        'format': 'html',
        'script_blocks': len(scripts),
        'script_preview': [s.strip()[:300] for s in scripts[:5]],
        'links': urls,
        'iframe_count': iframe_count,
        'logic_summary': ['HTML embeds executable script content'] if scripts else [],
    }


def _analyze_xml(text: str) -> dict[str, Any]:
    ext_refs = len(re.findall(r'<!ENTITY|SYSTEM\s+["\']', text, re.I))
    scripts = len(re.findall(r'<script|javascript:', text, re.I))
    return {
        'format': 'xml',
        'external_entity_refs': ext_refs,
        'script_markers': scripts,
        'logic_summary': ['XML references external entities'] if ext_refs else [],
    }


def _analyze_json(text: str) -> dict[str, Any]:
    summary = {'format': 'json', 'parsed': False, 'keys': [], 'logic_summary': []}
    try:
        payload = json.loads(text)
        summary['parsed'] = True
        summary['keys'] = _json_keys(payload)[:40]
        blob_text = json.dumps(payload)[:10000]
        if any(x in blob_text.lower() for x in ('powershell', 'cmd', 'http://', 'https://', 'base64')):
            summary['logic_summary'].append('JSON contains suspicious command or network indicators')
    except Exception as exc:
        summary['parse_error'] = exc.__class__.__name__
    return summary


def _json_keys(obj: Any, prefix: str = '', out: list[str] | None = None, depth: int = 0) -> list[str]:
    out = out or []
    if depth > 4 or len(out) > 60:
        return out
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = f'{prefix}.{key}' if prefix else str(key)
            out.append(path)
            _json_keys(value, path, out, depth + 1)
    elif isinstance(obj, list):
        for idx, value in enumerate(obj[:20]):
            _json_keys(value, f'{prefix}[{idx}]', out, depth + 1)
    return out


def _analyze_structured_text(text: str, ext: str) -> dict[str, Any]:
    lines = text.splitlines()
    urls = re.findall(r'https?://[^\s\'"]+', text)[:30]
    secrets = len(re.findall(r'(?i)(api[_-]?key|password|secret|token)\s*[:=]', text))
    return {
        'format': ext,
        'line_count': len(lines),
        'links': urls,
        'secret_markers': secrets,
        'logic_summary': ['Config/text file exposes secret markers'] if secrets else [],
    }


def _analyze_office_zip(path: Path) -> dict[str, Any]:
    result = {'format': 'office_open_xml', 'embedded_parts': [], 'macros_detected': False, 'logic_summary': []}
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            result['embedded_parts'] = names[:40]
            if any('vbaProject.bin' in n or 'macros/' in n.lower() for n in names):
                result['macros_detected'] = True
                result['logic_summary'].append('Office document contains VBA macro project')
            if any(n.endswith('.xml') and 'external' in n.lower() for n in names):
                result['logic_summary'].append('Office document references external XML relationships')
    except Exception as exc:
        result['error'] = exc.__class__.__name__
    return result
