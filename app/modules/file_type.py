from pathlib import Path

def guess_file_type(path):
    p=Path(path)
    ext=p.suffix.lower().lstrip('.') or 'unknown'
    try:
        with p.open('rb') as f:
            sig=f.read(16)
    except Exception:
        sig=b''
    if sig.startswith(b'MZ'):
        return 'PE executable'
    if sig.startswith(b'PK'):
        return 'ZIP/JAR/DOCX-style archive'
    if sig.startswith(b'7z\xbc\xaf\x27\x1c'):
        return '7z archive'
    if sig.startswith(b'Rar!'):
        return 'RAR archive'
    if sig.startswith(b'%PDF'):
        return 'PDF document'
    return ext.upper() if ext!='unknown' else 'Unknown/binary'
