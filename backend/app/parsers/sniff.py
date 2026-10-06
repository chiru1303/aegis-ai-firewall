"""
MIME Sniffing and Safe Ingestion Security Utilities for Aegis AI Firewall.
Provides magic-byte content type detection, decompression bomb protection,
and resource limit enforcement without executing untrusted code or fetching remote URLs.
"""
import io
import re
import zipfile
from typing import Tuple, Optional

# Security thresholds
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_UNCOMPRESSED_ZIP_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_COMPRESSION_RATIO = 100.0
MAX_ZIP_ENTRIES = 10000

MAGIC_SIGNATURES = [
    (b'%PDF-', 'application/pdf'),
    (b'\x89PNG\r\n\x1a\n', 'image/png'),
    (b'\xff\xd8\xff', 'image/jpeg'),
    (b'GIF87a', 'image/gif'),
    (b'GIF89a', 'image/gif'),
    (b'II*\x00', 'image/tiff'),
    (b'MM\x00*', 'image/tiff'),
]

def sniff_mime_type(content: bytes, filename: str = "") -> str:
    """
    Sniffs authoritative MIME type by inspecting magic byte signatures and content structure,
    preventing extension-spoofing attacks (e.g., evil.exe renamed to safe.pdf).
    """
    if not content:
        return 'text/plain'

    # 1. Exact binary magic signatures
    for sig, mime in MAGIC_SIGNATURES:
        if content.startswith(sig):
            return mime

    # WebP check (RIFF....WEBP)
    if len(content) >= 12 and content.startswith(b'RIFF') and content[8:12] == b'WEBP':
        return 'image/webp'

    # ZIP / DOCX check
    if content.startswith(b'PK\x03\x04') or content.startswith(b'PK\x05\x06') or content.startswith(b'PK\x07\x08'):
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as z:
                names = z.namelist()
                if '[Content_Types].xml' in names or any(n.startswith('word/') for n in names):
                    return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        except Exception:
            pass
        return 'application/zip'

    # Strip leading whitespace/BOM for text analysis
    sample = content[:4096].lstrip(b'\xef\xbb\xbf \t\r\n')
    sample_str = sample.decode('utf-8', errors='ignore').strip()

    # XML check
    if sample.startswith(b'<?xml') or sample.startswith(b'<svg'):
        return 'application/xml'

    # HTML check
    sample_lower = sample_str.lower()
    if (
        sample_lower.startswith('<!doctype html')
        or sample_lower.startswith('<html')
        or sample_lower.startswith('<head')
        or sample_lower.startswith('<body')
        or (sample_lower.startswith('<') and ('<div' in sample_lower or '<p' in sample_lower or '<script' in sample_lower or '<style' in sample_lower))
    ):
        return 'text/html'

    # JSON check
    if (sample_str.startswith('{') and sample_str.endswith('}')) or (sample_str.startswith('[') and sample_str.endswith(']')):
        try:
            import json
            json.loads(content.decode('utf-8', errors='replace'))
            return 'application/json'
        except Exception:
            pass
    elif sample_str.startswith('{') or sample_str.startswith('['):
        # Potential partial/valid JSON
        try:
            import json
            json.loads(content.decode('utf-8', errors='replace'))
            return 'application/json'
        except Exception:
            pass

    # Email (.eml) check
    header_patterns = [r'^From:\s', r'^Subject:\s', r'^Date:\s', r'^Received:\s', r'^MIME-Version:\s']
    matched_headers = sum(1 for p in header_patterns if re.search(p, sample_str, re.MULTILINE | re.IGNORECASE))
    if matched_headers >= 2:
        return 'message/rfc822'

    # Code / Markdown / Text based on filename or content
    fn_lower = filename.lower()
    if fn_lower.endswith(('.md', '.markdown')):
        return 'text/markdown'
    if fn_lower.endswith(('.py', '.js', '.ts', '.java', '.c', '.cpp', '.go', '.rb', '.php', '.sh')):
        return 'text/x-code'
    if fn_lower.endswith('.json'):
        return 'application/json'
    if fn_lower.endswith(('.html', '.htm')):
        return 'text/html'
    if fn_lower.endswith('.xml'):
        return 'application/xml'
    if fn_lower.endswith(('.eml', '.msg')):
        return 'message/rfc822'

    # Default fallback to plain text if decodable, else application/octet-stream
    try:
        content[:1024].decode('utf-8')
        return 'text/plain'
    except UnicodeDecodeError:
        return 'application/octet-stream'


def check_zip_bomb(
    content: bytes,
    max_uncompressed: int = MAX_UNCOMPRESSED_ZIP_BYTES,
    max_ratio: float = MAX_COMPRESSION_RATIO,
    max_entries: int = MAX_ZIP_ENTRIES,
) -> Tuple[bool, Optional[str]]:
    """
    Checks zip archives (DOCX, ZIP, etc.) for decompression bomb attacks
    by analyzing compression ratio and total uncompressed volume safely in memory.
    Returns (is_safe, failure_reason).
    Only inspects content that is actually a zip archive (PK magic bytes).
    Non-zip content is considered safe by default.
    """
    # Only check actual zip archives — non-zip files are not zip bombs
    if not content or not (content.startswith(b'PK\x03\x04') or content.startswith(b'PK\x05\x06') or content.startswith(b'PK\x07\x08')):
        return True, None

    try:
        with zipfile.ZipFile(io.BytesIO(content)) as z:
            infolist = z.infolist()
            if len(infolist) > max_entries:
                return False, f"Archive contains {len(infolist)} files (limit: {max_entries})"

            total_uncompressed = 0
            for info in infolist:
                total_uncompressed += info.file_size
                if info.compress_size > 0:
                    ratio = info.file_size / info.compress_size
                    if ratio > max_ratio and info.file_size > 1024 * 1024:
                        return False, f"Zip bomb detected in '{info.filename}' (compression ratio {ratio:.1f}:1 exceeds {max_ratio}:1)"

            if total_uncompressed > max_uncompressed:
                return False, f"Total uncompressed size ({total_uncompressed} bytes) exceeds safety limit ({max_uncompressed} bytes)"

        return True, None
    except zipfile.BadZipFile:
        return False, "Malformed or corrupted zip archive"
    except Exception as e:
        return False, f"Archive inspection error: {str(e)}"
