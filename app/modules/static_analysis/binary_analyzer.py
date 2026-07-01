from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import pefile  # type: ignore
except Exception:  # pragma: no cover
    pefile = None

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64  # type: ignore
except Exception:  # pragma: no cover
    Cs = None

from .r2_analyzer import analyze_with_r2, r2_available


SUSPICIOUS_IMPORTS = {
    'virtualalloc', 'virtualprotect', 'writeprocessmemory', 'readprocessmemory',
    'createremotethread', 'ntcreatethreadex', 'openprocess', 'createprocessa', 'createprocessw',
    'winexec', 'shellexecutexw', 'shellexecutea', 'urlmon', 'wininet', 'internetopenurl',
    'internetreadfile', 'isdebuggerpresent', 'checkremotedebuggerpresent', 'ntqueryinformationprocess',
    'cryptencrypt', 'cryptdecrypt', 'bcryptencrypt', 'bcryptdecrypt', 'regsetvalueex',
}


def analyze_binary(path: Path, category: str) -> dict[str, Any]:
    result: dict[str, Any] = {'category': category, 'engine': 'python'}
    if category == 'pe' and pefile is not None:
        result.update(_analyze_pe(path))
    elif category == 'elf':
        result.update(_analyze_elf_header(path))
    else:
        result.update(_analyze_generic_binary(path))

    if r2_available():
        try:
            r2 = analyze_with_r2(path)
            result['r2'] = r2
            result['engine'] = 'radare2+python'
            result['functions'] = r2.get('functions') or result.get('functions') or []
        except Exception as exc:
            result['r2_error'] = str(exc)[:200]
    return result


def _analyze_pe(path: Path) -> dict[str, Any]:
    pe = pefile.PE(str(path), fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
    imports: list[str] = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = (entry.dll or b'').decode('utf-8', errors='ignore')
            for imp in entry.imports[:80]:
                name = imp.name.decode('utf-8', errors='ignore') if imp.name else f'ord_{imp.ordinal}'
                imports.append(f'{dll}:{name}'.lower())
    sections = [{'name': s.Name.decode('utf-8', errors='ignore').strip('\x00'), 'size': s.SizeOfRawData} for s in pe.sections[:20]]
    suspicious = [imp for imp in imports if any(x in imp for x in SUSPICIOUS_IMPORTS)]
    entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    machine = pe.FILE_HEADER.Machine
    mode = CS_MODE_64 if machine == 0x8664 else CS_MODE_32
    disasm = _disassemble_pe_entry(path, pe, entry, mode)
    functions = [{
        'name': 'entry_point',
        'offset': entry,
        'logic_summary': _logic_from_disasm(disasm),
        'disassembly_preview': disasm[:1500],
    }]
    if suspicious:
        functions.append({'name': 'imports_summary', 'logic_summary': ['suspicious_imports'], 'imports': suspicious[:30]})
    return {
        'format': 'pe',
        'entry_point': entry,
        'imports': imports[:80],
        'suspicious_imports': suspicious[:30],
        'sections': sections,
        'functions': functions,
        'logic_summary': _logic_from_imports(suspicious),
    }


def _analyze_elf_header(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()[:128]
    disasm = _disassemble_offset(path.read_bytes()[:512], 0, CS_MODE_64 if raw[4] == 2 else CS_MODE_32)
    return {
        'format': 'elf',
        'header_hex': raw[:32].hex(),
        'functions': [{'name': 'file_start', 'disassembly_preview': disasm[:1500], 'logic_summary': _logic_from_disasm(disasm)}],
    }


def _analyze_generic_binary(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    disasm = _disassemble_offset(data[:1024], 0, CS_MODE_64)
    return {
        'format': 'binary',
        'functions': [{'name': 'offset_0', 'disassembly_preview': disasm[:1500], 'logic_summary': _logic_from_disasm(disasm)}],
    }


def _disassemble_pe_entry(path: Path, pe: Any, entry: int, mode: int) -> str:
    try:
        offset = pe.get_offset_from_rva(entry)
        with path.open('rb') as handle:
            handle.seek(offset)
            code = handle.read(512)
        return _disassemble_offset(code, entry, mode)
    except Exception:
        return ''


def _disassemble_offset(code: bytes, address: int, mode: int) -> str:
    if Cs is None or not code:
        return ''
    lines = []
    md = Cs(CS_ARCH_X86, mode)
    md.detail = False
    for ins in md.disasm(code, address):
        lines.append(f'0x{ins.address:x}: {ins.mnemonic} {ins.op_str}'.strip())
        if len(lines) >= 80:
            break
    return '\n'.join(lines)


def _logic_from_disasm(disasm: str) -> list[str]:
    text = disasm.lower()
    tags = []
    if any(x in text for x in ('call', 'jmp')):
        tags.append('control_flow')
    if 'xor' in text:
        tags.append('obfuscation')
    if any(x in text for x in ('push', 'mov', 'lea')):
        tags.append('setup')
    return tags


def _logic_from_imports(imports: list[str]) -> list[str]:
    tags = []
    joined = ' '.join(imports)
    if any(x in joined for x in ('virtualalloc', 'writeprocessmemory', 'createremotethread')):
        tags.append('process_injection')
    if any(x in joined for x in ('wininet', 'urlmon', 'internet')):
        tags.append('network_capability')
    if any(x in joined for x in ('isdebuggerpresent', 'ntqueryinformationprocess')):
        tags.append('anti_debug')
    if any(x in joined for x in ('crypt', 'bcrypt')):
        tags.append('crypto_capability')
    return tags
