from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .archive_analyzer import analyze_archive
from .binary_analyzer import analyze_binary
from .deobfuscator import deobfuscate_bytes
from .document_analyzer import analyze_document
from .image_analyzer import analyze_image
from .script_analyzer import analyze_script
from .text_analyzer import analyze_text
from .types import FileProfile, classify_file
from .universal import analyze_universal
from .verdict import build_verdict


class StaticAnalysisError(Exception):
    pass


def _env_truthy(name: str, default: bool = True) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return str(val).strip().lower() in {'1', 'true', 'yes', 'on'}


def _merge_functions(*groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for group in groups:
        for fn in group or []:
            name = str(fn.get('name') or fn.get('offset') or len(merged))
            if name in seen:
                continue
            seen.add(name)
            merged.append(fn)
            if len(merged) >= 50:
                return merged
    return merged


def _correlate(report: dict[str, Any]) -> dict[str, Any]:
    universal = report.get('universal') or {}
    typed = report.get('typed_analysis') or {}
    deob = report.get('deobfuscation') or {}
    links: list[dict[str, Any]] = []

    suspicious_strings = universal.get('suspicious_strings') or []
    iocs = universal.get('iocs') or {}
    if suspicious_strings and (iocs.get('urls') or iocs.get('ips')):
        links.append({'type': 'strings_to_iocs', 'detail': 'Suspicious strings corroborate extracted network IOCs'})

    recovered = deob.get('recovered') or []
    if recovered and (typed.get('pattern_matches') or typed.get('logic_summary')):
        links.append({'type': 'deobfuscation_to_behavior', 'detail': 'Recovered decoded content aligns with suspicious behavior markers'})

    fn_tags = []
    for fn in report.get('functions') or []:
        fn_tags.extend(fn.get('logic_tags') or fn.get('logic_summary') or [])
    if fn_tags and suspicious_strings:
        links.append({'type': 'functions_to_strings', 'detail': 'Function-level behavior tags overlap suspicious string indicators'})

    return {
        'links': links,
        'function_count': len(report.get('functions') or []),
        'recovered_artifacts': len(recovered),
        'ioc_counts': {
            'urls': len(iocs.get('urls') or []),
            'domains': len(iocs.get('domains') or []),
            'ips': len(iocs.get('ips') or []),
        },
    }


def _typed_analysis(path: Path, profile: FileProfile) -> dict[str, Any]:
    category = profile.category
    if category == 'script' or (profile.is_text_like and path.suffix.lower().lstrip('.') in {'js', 'ps1', 'vbs', 'bat', 'cmd', 'py', 'php', 'hta', 'sh'}):
        return analyze_script(path)
    if category in {'pdf', 'markup', 'structured_text', 'document'}:
        return analyze_document(path, profile.extension)
    if category in {'archive', 'java_archive', 'compressed'}:
        return analyze_archive(path)
    if category == 'image':
        return analyze_image(path)
    if category in {'text'} or profile.is_text_like:
        return analyze_text(path)
    if category in {'pe', 'elf', 'macho', 'binary', 'unknown'}:
        return analyze_binary(path, category)
    return analyze_text(path)


def analyze_file(path: Path, *, filename: str | None = None, declared_type: str | None = None, sha256: str | None = None) -> dict[str, Any]:
    if not _env_truthy('STATIC_ANALYSIS_ENABLED', True):
        raise StaticAnalysisError('Static analysis is disabled')

    if not path.is_file():
        raise StaticAnalysisError('Cached file not found')

    profile = classify_file(path, declared_type)
    universal = analyze_universal(path)
    raw = path.read_bytes()
    deobfuscation = deobfuscate_bytes(raw)
    typed = _typed_analysis(path, profile)

    functions = _merge_functions(
        typed.get('functions') or [],
        (typed.get('r2') or {}).get('functions') or [],
    )

    report = {
        'status': 'completed',
        'analyzed_at': datetime.now(timezone.utc).isoformat(),
        'filename': filename or path.name,
        'sha256': (sha256 or '').lower() or None,
        'profile': {
            'category': profile.category,
            'mime_hint': profile.mime_hint,
            'extension': profile.extension,
            'is_text_like': profile.is_text_like,
            'analyzers': list(profile.analyzers),
        },
        'universal': universal,
        'deobfuscation': deobfuscation,
        'typed_analysis': typed,
        'functions': functions,
    }
    report['correlation'] = _correlate(report)
    report['static_verdict'] = build_verdict(report)
    return report


async def analyze_file_async(path: Path, **kwargs: Any) -> dict[str, Any]:
    timeout = int(os.getenv('STATIC_ANALYSIS_TIMEOUT', '180'))
    return await asyncio.wait_for(asyncio.to_thread(analyze_file, path, **kwargs), timeout=timeout)
