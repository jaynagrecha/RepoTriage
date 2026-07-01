from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FileProfile:
    category: str
    mime_hint: str
    extension: str
    magic: bytes
    is_text_like: bool
    analyzers: tuple[str, ...]


SCRIPT_EXTENSIONS = frozenset({
    'js', 'jsx', 'mjs', 'cjs', 'ts', 'vbs', 'vbe', 'wsf', 'wsh', 'ps1', 'psm1', 'psd1',
    'bat', 'cmd', 'sh', 'bash', 'zsh', 'fish', 'py', 'pyw', 'pyc', 'pyo', 'php', 'phtml',
    'rb', 'pl', 'pm', 'lua', 'go', 'rs', 'java', 'cs', 'swift', 'kt', 'kts', 'scala',
    'asp', 'aspx', 'jsp', 'hta', 'reg', 'inf', 'scf', 'lnk', 'url',
})

DOCUMENT_EXTENSIONS = frozenset({
    'pdf', 'html', 'htm', 'xhtml', 'xml', 'xsl', 'xslt', 'json', 'yaml', 'yml', 'toml',
    'ini', 'cfg', 'conf', 'config', 'properties', 'csv', 'tsv', 'md', 'markdown', 'rtf',
    'doc', 'docx', 'docm', 'xls', 'xlsx', 'xlsm', 'ppt', 'pptx', 'pptm', 'odt', 'ods',
    'eml', 'msg', 'svg', 'sql', 'env',
})

ARCHIVE_EXTENSIONS = frozenset({
    'zip', 'jar', 'war', 'ear', 'apk', '7z', 'rar', 'tar', 'gz', 'bz2', 'xz', 'tgz', 'cab', 'iso',
})

IMAGE_EXTENSIONS = frozenset({
    'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'ico', 'tif', 'tiff', 'heic', 'heif',
})

BINARY_EXTENSIONS = frozenset({
    'exe', 'dll', 'sys', 'scr', 'cpl', 'ocx', 'drv', 'efi', 'so', 'dylib', 'bin', 'elf',
    'msi', 'msp', 'com', 'obj', 'o', 'a', 'lib', 'wasm',
})


def _read_magic(path: Path, size: int = 16) -> bytes:
    try:
        with path.open('rb') as handle:
            return handle.read(size)
    except Exception:
        return b''


def _is_mostly_text(sample: bytes) -> bool:
    if not sample:
        return False
    printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b <= 126)
    return printable / len(sample) >= 0.85


def classify_file(path: Path, declared_type: str | None = None) -> FileProfile:
    magic = _read_magic(path)
    ext = path.suffix.lower().lstrip('.')
    declared = (declared_type or '').lower()

    if magic.startswith(b'MZ'):
        return FileProfile('pe', 'application/x-pe', ext or 'exe', magic, False, ('binary', 'universal'))
    if magic.startswith(b'\x7fELF'):
        return FileProfile('elf', 'application/x-elf', ext or 'elf', magic, False, ('binary', 'universal'))
    if magic[:4] in {b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe'}:
        return FileProfile('macho', 'application/x-mach-o', ext or 'macho', magic, False, ('binary', 'universal'))
    if magic.startswith(b'PK'):
        category = 'java_archive' if ext in {'jar', 'war', 'ear'} else 'archive'
        return FileProfile(category, 'application/zip', ext or 'zip', magic, False, ('archive', 'universal'))
    if magic.startswith(b'7z\xbc\xaf\x27\x1c'):
        return FileProfile('archive', 'application/x-7z-compressed', ext or '7z', magic, False, ('archive', 'universal'))
    if magic.startswith(b'Rar!'):
        return FileProfile('archive', 'application/x-rar', ext or 'rar', magic, False, ('archive', 'universal'))
    if magic.startswith(b'%PDF'):
        return FileProfile('pdf', 'application/pdf', ext or 'pdf', magic, False, ('document', 'universal'))
    if magic.startswith(b'\x89PNG'):
        return FileProfile('image', 'image/png', ext or 'png', magic, False, ('image', 'universal'))
    if magic[:3] == b'\xff\xd8\xff':
        return FileProfile('image', 'image/jpeg', ext or 'jpg', magic, False, ('image', 'universal'))
    if magic.startswith(b'GIF8'):
        return FileProfile('image', 'image/gif', ext or 'gif', magic, False, ('image', 'universal'))
    if magic.startswith(b'BM'):
        return FileProfile('image', 'image/bmp', ext or 'bmp', magic, False, ('image', 'universal'))
    if magic.startswith(b'RIFF') and magic[8:12] == b'WEBP':
        return FileProfile('image', 'image/webp', ext or 'webp', magic, False, ('image', 'universal'))
    if magic.startswith(b'\x1f\x8b'):
        return FileProfile('compressed', 'application/gzip', ext or 'gz', magic, False, ('archive', 'universal'))
    if magic.startswith(b'#!'):
        return FileProfile('script', 'text/x-script', ext or 'sh', magic, True, ('script', 'universal'))
    if magic.startswith(b'<?xml') or magic.startswith(b'<html') or magic.startswith(b'<!DOC'):
        return FileProfile('markup', 'text/html', ext or 'html', magic, True, ('document', 'universal'))
    if magic.startswith(b'{') or magic.startswith(b'['):
        return FileProfile('structured_text', 'application/json', ext or 'json', magic, True, ('document', 'universal'))

    sample = magic
    try:
        with path.open('rb') as handle:
            sample = handle.read(4096)
    except Exception:
        pass

    if ext in SCRIPT_EXTENSIONS or 'script' in declared:
        return FileProfile('script', 'text/x-script', ext, magic, True, ('script', 'universal'))
    if ext in DOCUMENT_EXTENSIONS or any(x in declared for x in ('pdf', 'html', 'json', 'xml', 'document')):
        return FileProfile('document', 'text/plain', ext, magic, _is_mostly_text(sample), ('document', 'universal'))
    if ext in ARCHIVE_EXTENSIONS or 'archive' in declared:
        return FileProfile('archive', 'application/octet-stream', ext, magic, False, ('archive', 'universal'))
    if ext in IMAGE_EXTENSIONS or 'image' in declared:
        return FileProfile('image', 'application/octet-stream', ext, magic, False, ('image', 'universal'))
    if ext in BINARY_EXTENSIONS or 'executable' in declared or 'pe ' in declared:
        return FileProfile('binary', 'application/octet-stream', ext, magic, False, ('binary', 'universal'))

    if _is_mostly_text(sample):
        return FileProfile('text', 'text/plain', ext or 'txt', magic, True, ('text', 'universal'))

    return FileProfile('unknown', 'application/octet-stream', ext or 'bin', magic, False, ('binary', 'universal'))
