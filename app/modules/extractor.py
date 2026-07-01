from __future__ import annotations

import hashlib
import io
import os
import re
import tarfile
import tempfile
import zipfile
from pathlib import Path

try:
    import py7zr  # type: ignore
except Exception:  # pragma: no cover
    py7zr = None
try:
    import rarfile  # type: ignore
except Exception:  # pragma: no cover
    rarfile = None

ARCHIVE_EXTS = {'.zip', '.jar', '.war', '.ear', '.docx', '.xlsx', '.pptx', '.7z', '.rar', '.tar', '.gz', '.tgz'}
WINDOWS_RESERVED = {
    'CON', 'PRN', 'AUX', 'NUL',
    'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
    'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9',
}
INVALID_WIN_CHARS = r'<>:"/\\|?*'


class ExtractionError(Exception):
    pass


def _read_limited(stream, max_bytes: int) -> bytes:
    """Read stream in chunks, enforcing a hard decompressed-size ceiling."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = stream.read(1024 * 256)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise ExtractionError('Archive member exceeds extraction byte limit during read')
        chunks.append(chunk)
    return b''.join(chunks)


def is_archive(path: str | Path) -> bool:
    p = Path(path)
    suffixes = [s.lower() for s in p.suffixes]
    if p.suffix.lower() in ARCHIVE_EXTS:
        return True
    if suffixes[-2:] in [['.tar', '.gz']]:
        return True
    try:
        if p.exists() and zipfile.is_zipfile(p):
            return True
        if p.exists() and tarfile.is_tarfile(p):
            return True
    except Exception:
        pass
    return False


def _sha12(value: str) -> str:
    return hashlib.sha1(value.encode('utf-8', 'ignore')).hexdigest()[:12]


def _hash_bytes(data: bytes) -> dict:
    return {
        'md5': hashlib.md5(data).hexdigest(),
        'sha1': hashlib.sha1(data).hexdigest(),
        'sha256': hashlib.sha256(data).hexdigest(),
        'size_bytes': len(data),
    }


def sanitize_component(name: str, *, max_len: int = 72) -> str:
    """Return a Windows-safe single filename component for display only."""
    base = str(name or 'file.bin').replace('\\', '/').split('/')[-1]
    base = ''.join('_' if ch in INVALID_WIN_CHARS else ch for ch in base)
    base = re.sub(r'[\x00-\x1f\x7f]+', '_', base)
    base = re.sub(r'\s+', '_', base).strip(' ._')
    if not base:
        base = 'file.bin'
    stem = Path(base).stem or 'file'
    suffix = ''.join(Path(base).suffixes)[:20]
    if stem.upper() in WINDOWS_RESERVED:
        stem = f'file_{stem}'
    stem = stem[:max_len]
    safe = f'{stem}{suffix}' if suffix and not stem.endswith(suffix) else stem
    return safe[: max_len + 24] or 'file.bin'


def _candidate_name(original_member_name: str, source_archive: Path) -> str:
    """Return a flat, neutral quarantine filename without path separators.

    The original extension is never preserved in storage. The real original name is
    retained only in metadata/UI. This prevents extension-based accidental launching
    and reduces endpoint security interference.
    """
    original_member_name = str(original_member_name or 'file.bin')
    safe_base = sanitize_component(original_member_name, max_len=48)
    base_no_ext = Path(safe_base).stem or 'sample'
    token = _sha12(str(source_archive) + ':' + original_member_name)
    return f'{token}_{base_no_ext}.rtq'


def _validate_member_name(member_name: str) -> str:
    raw = str(member_name or '')
    normalized = raw.replace('\\', '/').lstrip('/')
    parts = [part for part in normalized.split('/') if part]
    if not parts or any(part == '..' for part in parts):
        raise ExtractionError(f'Unsafe archive path blocked: {member_name}')
    if re.match(r'^[a-zA-Z]:', raw) or raw.startswith('\\') or raw.startswith('//'):
        raise ExtractionError(f'Unsafe archive path blocked: {member_name}')
    return '/'.join(parts)


def _safe_target(base: Path, member_name: str, source_archive: Path) -> Path:
    canonical = _validate_member_name(member_name)
    target = (base / _candidate_name(canonical, source_archive)).resolve()
    base_resolved = base.resolve()
    try:
        target.relative_to(base_resolved)
    except ValueError:
        raise ExtractionError(f'Unsafe archive path blocked: {member_name}')
    return target


def _write_quarantine_bytes(data: bytes, dst_path: Path) -> tuple[bool, str | None]:
    """Best-effort write to neutral quarantine file.

    Analysis must not depend on this write succeeding. If AV quarantines/blocks the
    file, the caller still has the bytes-derived hashes and can continue VT/CTI.
    """
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = dst_path.with_suffix(dst_path.suffix + '.part')
    try:
        with tmp_path.open('wb') as dst:
            dst.write(data)
        if dst_path.exists():
            dst_path.unlink()
        tmp_path.replace(dst_path)
        return True, None
    except PermissionError as e:
        return False, 'blocked or quarantined by local security software during write'
    except OSError as e:
        return False, f'file write failed: {e}'
    finally:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except Exception:
            pass


def _clean_reason(reason: str) -> str:
    reason = str(reason or 'unknown error')
    reason = reason.replace(str(Path.cwd()), '<cwd>')
    reason = re.sub(r"[A-Za-z]:\\[^\n\r']+", '<local quarantine path>', reason)
    return reason


def _record_error(errors: list[str], archive_path: Path, member: str, reason: str) -> None:
    member_display = sanitize_component(member, max_len=120)
    errors.append(f'{archive_path.name} :: {member_display} :: {_clean_reason(reason)}')


def _record_from_bytes(
    *,
    data: bytes,
    original: str,
    source_archive: Path,
    out_dir: Path,
    errors: list[str],
) -> dict:
    canonical = _validate_member_name(original)
    target = _safe_target(out_dir, canonical, source_archive)
    hashes = _hash_bytes(data)
    written, write_error = _write_quarantine_bytes(data, target)
    if not written and write_error:
        _record_error(errors, source_archive, original, f'File captured in-memory; quarantine write {write_error}')
    return {
        'filename': sanitize_component(original),
        'original_name': original,
        'path': sanitize_component(original),
        'stored_name': target.name if written else None,
        'local_path': str(target) if written and target.exists() else None,
        'extracted_to_disk': bool(written and target.exists()),
        'blocked_by_local_av': not bool(written and target.exists()),
        'analysis_note': None if written else 'File was read from archive and hashed in memory, but local quarantine write failed/was blocked.',
        'md5': hashes['md5'],
        'sha1': hashes['sha1'],
        'sha256': hashes['sha256'],
        'size_bytes': hashes['size_bytes'],
        'is_archive': bool(written and target.exists() and is_archive(target)),
        'sanitized': sanitize_component(original) != str(original).replace('\\', '/').split('/')[-1],
    }


def _extract_zip(path: Path, out_dir: Path, max_files: int, max_total_bytes: int, errors: list[str]) -> list[dict]:
    extracted: list[dict] = []
    total = 0
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            if len(extracted) >= max_files:
                break
            original = info.filename
            try:
                if int(info.file_size or 0) > max_total_bytes:
                    raise ExtractionError('Single member exceeds extraction byte limit')
                total += int(info.file_size or 0)
                if total > max_total_bytes:
                    raise ExtractionError('Archive extraction byte limit exceeded')
                with z.open(info) as src:
                    data = _read_limited(src, max_total_bytes)
                rec = _record_from_bytes(data=data, original=original, source_archive=path, out_dir=out_dir, errors=errors)
                extracted.append(rec)
            except Exception as e:
                _record_error(errors, path, original, str(e))
                continue
    return extracted


def _extract_tar(path: Path, out_dir: Path, max_files: int, max_total_bytes: int, errors: list[str]) -> list[dict]:
    extracted: list[dict] = []
    total = 0
    with tarfile.open(path) as t:
        for member in t.getmembers():
            if not member.isfile():
                continue
            if len(extracted) >= max_files:
                break
            original = member.name
            try:
                if int(member.size or 0) > max_total_bytes:
                    raise ExtractionError('Single member exceeds extraction byte limit')
                total += int(member.size or 0)
                if total > max_total_bytes:
                    raise ExtractionError('Archive extraction byte limit exceeded')
                src = t.extractfile(member)
                if src is None:
                    raise ExtractionError('Could not open tar member')
                with src:
                    data = _read_limited(src, max_total_bytes)
                rec = _record_from_bytes(data=data, original=original, source_archive=path, out_dir=out_dir, errors=errors)
                extracted.append(rec)
            except Exception as e:
                _record_error(errors, path, original, str(e))
                continue
    return extracted


def _extract_rar(path: Path, out_dir: Path, max_files: int, max_total_bytes: int, errors: list[str]) -> list[dict]:
    if rarfile is None:
        raise ExtractionError('RAR extraction requires rarfile and an unrar backend')
    extracted: list[dict] = []
    total = 0
    with rarfile.RarFile(path) as r:
        for info in r.infolist():
            if info.isdir():
                continue
            if len(extracted) >= max_files:
                break
            original = info.filename
            try:
                size = int(info.file_size or 0)
                if size > max_total_bytes:
                    raise ExtractionError('Single member exceeds extraction byte limit')
                total += size
                if total > max_total_bytes:
                    raise ExtractionError('Archive extraction byte limit exceeded')
                with r.open(info) as src:
                    data = _read_limited(src, max_total_bytes)
                rec = _record_from_bytes(data=data, original=original, source_archive=path, out_dir=out_dir, errors=errors)
                extracted.append(rec)
            except Exception as e:
                _record_error(errors, path, original, str(e))
                continue
    return extracted


def _extract_7z(path: Path, out_dir: Path, max_files: int, max_total_bytes: int, errors: list[str]) -> list[dict]:
    if py7zr is None:
        raise ExtractionError('7z extraction requires py7zr')
    extracted: list[dict] = []
    total = 0
    with tempfile.TemporaryDirectory(prefix='rt_7z_') as tmp:
        tmp_dir = Path(tmp)
        with py7zr.SevenZipFile(path, mode='r') as archive:
            names = archive.getnames()[:max_files]
            archive.extract(path=tmp_dir, targets=names)
        for f in tmp_dir.rglob('*'):
            if not f.is_file():
                continue
            original = str(f.relative_to(tmp_dir))
            if len(extracted) >= max_files:
                break
            try:
                size = f.stat().st_size
                if size > max_total_bytes:
                    raise ExtractionError('Single member exceeds extraction byte limit')
                total += size
                if total > max_total_bytes:
                    raise ExtractionError('Archive extraction byte limit exceeded')
                data = f.read_bytes()
                if len(data) > max_total_bytes:
                    raise ExtractionError('Archive member exceeds extraction byte limit during read')
                rec = _record_from_bytes(data=data, original=original, source_archive=path, out_dir=out_dir, errors=errors)
                extracted.append(rec)
            except Exception as e:
                _record_error(errors, path, original, str(e))
                continue
    return extracted


def extract_recursive(
    root_file: str | Path,
    base_extract_dir: str | Path,
    *,
    max_depth: int = 3,
    max_files: int = 250,
    max_total_bytes: int = 100_000_000,
) -> dict:
    root = Path(root_file)
    base = Path(base_extract_dir)
    case_dir = base / f'case_{_sha12(str(root.resolve()))}'
    case_dir.mkdir(parents=True, exist_ok=True)

    queue: list[tuple[Path, int, str]] = [(root, 0, root.name)]
    extracted_records: list[dict] = []
    errors: list[str] = []
    seen_archives: set[str] = set()

    while queue and len(extracted_records) < max_files:
        archive_path, depth, parent_label = queue.pop(0)
        try:
            key = str(archive_path.resolve())
        except Exception:
            key = str(archive_path)
        if key in seen_archives:
            continue
        seen_archives.add(key)
        if depth >= max_depth or not is_archive(archive_path):
            continue

        out_dir = case_dir
        try:
            suffix = archive_path.suffix.lower()
            remaining = max_files - len(extracted_records)
            if zipfile.is_zipfile(archive_path) or suffix in {'.zip', '.jar', '.war', '.ear', '.docx', '.xlsx', '.pptx'}:
                files = _extract_zip(archive_path, out_dir, remaining, max_total_bytes, errors)
            elif tarfile.is_tarfile(archive_path) or suffix in {'.tar', '.gz', '.tgz'}:
                files = _extract_tar(archive_path, out_dir, remaining, max_total_bytes, errors)
            elif suffix == '.7z':
                files = _extract_7z(archive_path, out_dir, remaining, max_total_bytes, errors)
            elif suffix == '.rar':
                files = _extract_rar(archive_path, out_dir, remaining, max_total_bytes, errors)
            else:
                files = []
        except Exception as e:
            errors.append(f'{archive_path.name} :: archive open/extract failed :: {_clean_reason(str(e))}')
            continue

        for rec in files:
            rec['parent_archive'] = parent_label
            rec['depth'] = depth + 1
            extracted_records.append(rec)
            # Recursive extraction is possible only if the child was written to disk.
            if rec.get('is_archive') and rec.get('local_path') and depth + 1 < max_depth and len(extracted_records) < max_files:
                queue.append((Path(rec['local_path']), depth + 1, sanitize_component(rec.get('original_name') or rec.get('filename'))))

    return {
        'enabled': True,
        'root_is_archive': is_archive(root),
        'extract_dir': str(case_dir),
        'analysis_mode': os.getenv('ANALYSIS_MODE', 'local_dev'),
        'server_side_analysis': os.getenv('SERVER_ANALYSIS_MODE', 'false').lower() == 'true',
        'quarantine_mode': True,
        'metadata_first': True,
        'files': extracted_records,
        'errors': errors,
        'max_depth': max_depth,
        'max_files': max_files,
    }
