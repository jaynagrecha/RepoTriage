from __future__ import annotations

import base64
import binascii
import codecs
import re
import urllib.parse
from typing import Any


BASE64_RE = re.compile(r'(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
HEX_RE = re.compile(r'\b(?:[0-9a-fA-F]{2}){16,}\b')
CHR_CONCAT_RE = re.compile(r'(?:chr\s*\(\s*\d+\s*\)\s*[+&^|]){3,}', re.I)
POWERSHELL_B64_RE = re.compile(r'(?:-EncodedCommand|-enc|-e)\s+([A-Za-z0-9+/=]{20,})', re.I)
JS_FROMCHAR_RE = re.compile(r'String\.fromCharCode\s*\(([\d,\s]+)\)', re.I)


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(1 for b in data if b in (9, 10, 13) or 32 <= b <= 126) / len(data)


def _candidate(value: str, method: str, source: str) -> dict[str, Any] | None:
    text = (value or '').strip()
    if len(text) < 8:
        return None
    if _printable_ratio(text.encode('utf-8', errors='ignore')) < 0.7:
        return None
    return {'method': method, 'source_preview': source[:120], 'decoded_preview': text[:500], 'decoded_length': len(text)}


def try_base64_decode(token: str) -> str | None:
    try:
        padded = token + '=' * ((4 - len(token) % 4) % 4)
        raw = base64.b64decode(padded, validate=False)
        if _printable_ratio(raw) < 0.75:
            return None
        return raw.decode('utf-8', errors='ignore')
    except Exception:
        return None


def try_hex_decode(token: str) -> str | None:
    try:
        raw = binascii.unhexlify(token)
        if _printable_ratio(raw) < 0.75:
            return None
        return raw.decode('utf-8', errors='ignore')
    except Exception:
        return None


def try_xor_single_byte(data: bytes) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    if len(data) < 16:
        return hits
    for key in range(1, 256):
        decoded = bytes(b ^ key for b in data[:512])
        ratio = _printable_ratio(decoded)
        if ratio >= 0.92:
            text = decoded.decode('utf-8', errors='ignore')
            if any(x in text.lower() for x in ('http', 'powershell', 'cmd', 'exec', 'shell', 'download', 'payload')):
                hits.append({'method': f'xor_single_byte_key_{key}', 'decoded_preview': text[:500], 'confidence': round(ratio, 3)})
        if len(hits) >= 5:
            break
    return hits


def decode_powershell_encoded(text: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for match in POWERSHELL_B64_RE.finditer(text):
        try:
            raw = base64.b64decode(match.group(1))
            decoded = raw.decode('utf-16le', errors='ignore')
            item = _candidate(decoded, 'powershell_encoded_command', match.group(0))
            if item:
                results.append(item)
        except Exception:
            continue
    return results


def decode_js_fromcharcode(text: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for match in JS_FROMCHAR_RE.finditer(text):
        nums = [int(x.strip()) for x in match.group(1).split(',') if x.strip().isdigit()]
        if len(nums) < 4:
            continue
        decoded = ''.join(chr(n % 256) for n in nums)
        item = _candidate(decoded, 'js_fromcharcode', match.group(0))
        if item:
            results.append(item)
    return results


def deobfuscate_text(text: str) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for token in BASE64_RE.findall(text)[:40]:
        decoded = try_base64_decode(token)
        item = _candidate(decoded or '', 'base64', token) if decoded else None
        if item:
            findings.append(item)
    for token in HEX_RE.findall(text)[:20]:
        decoded = try_hex_decode(token)
        item = _candidate(decoded or '', 'hex', token) if decoded else None
        if item:
            findings.append(item)
    try:
        url_decoded = urllib.parse.unquote(text[:5000])
        if url_decoded != text[:5000] and len(url_decoded) > 20:
            item = _candidate(url_decoded, 'url_decode', text[:120])
            if item:
                findings.append(item)
    except Exception:
        pass
    try:
        rot = codecs.decode(text[:2000], 'rot_13')
        if rot != text[:2000] and any(x in rot.lower() for x in ('http', 'exec', 'powershell', 'cmd')):
            item = _candidate(rot, 'rot13', text[:120])
            if item:
                findings.append(item)
    except Exception:
        pass
    findings.extend(decode_powershell_encoded(text))
    findings.extend(decode_js_fromcharcode(text))
    if CHR_CONCAT_RE.search(text):
        findings.append({'method': 'chr_concat_obfuscation', 'source_preview': CHR_CONCAT_RE.search(text).group(0)[:120], 'decoded_preview': 'chr()-based string building detected', 'decoded_length': 0})
    return {'attempts': len(findings), 'recovered': findings[:25]}


def deobfuscate_bytes(data: bytes) -> dict[str, Any]:
    text = data.decode('utf-8', errors='ignore')
    result = deobfuscate_text(text)
    xor_hits = try_xor_single_byte(data[:2048])
    if xor_hits:
        result['xor_candidates'] = xor_hits
    return result
