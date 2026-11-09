"""
corrupt_scanner.py
Read-only corruption checks used by OSSYStrimmer.py.

This module uses only Python's standard library. It does not repair, delete,
move, or modify files. Some formats cannot be fully validated without their
own application; results are basic integrity checks, not proof that a file is
safe or usable.
"""

from dataclasses import dataclass
import os
import string
import zipfile

CHUNK = 1024 * 1024  # 1 MiB


@dataclass
class ScanResult:
    status: str
    detail: str
    size: int = 0


# Directories that are generally noisy, virtual, or unsafe/unhelpful to walk.
_SKIP_DIR_NAMES = {
    "$recycle.bin", "system volume information", "windowsapps",
    "system32", "winsxs", "__pycache__", ".git", ".svn",
    "node_modules", ".venv", "venv",
}


def should_skip_dir(path, _seen=None):
    """Return True for common system/virtual/cache directories."""
    name = os.path.basename(os.path.normpath(path)).lower()
    if name in _SKIP_DIR_NAMES:
        return True
    # Avoid traversing Windows reparse-point-like symlink directories.
    try:
        return os.path.islink(path)
    except OSError:
        return True


def system_roots():
    """Return roots for mounted drives/volumes."""
    if os.name == "nt":
        return [
            f"{letter}:\\"
            for letter in string.ascii_uppercase
            if os.path.exists(f"{letter}:\\")
        ]
    return ["/"]


def _read_head(path, amount=32):
    with open(path, "rb") as stream:
        return stream.read(amount)


def _check_png(path, size):
    # PNG signature and final IEND chunk marker.
    if size < 20:
        return "PNG file is too small to be valid"
    with open(path, "rb") as stream:
        head = stream.read(8)
        if head != b"\x89PNG\r\n\x1a\n":
            return "invalid PNG signature"
        stream.seek(-12, os.SEEK_END)
        tail = stream.read(12)
    if len(tail) != 12 or tail[4:] != b"IEND":
        return "PNG end marker (IEND) is missing or truncated"
    return None


def _check_jpeg(path, size):
    if size < 4:
        return "JPEG file is too small to be valid"
    with open(path, "rb") as stream:
        if stream.read(2) != b"\xff\xd8":
            return "invalid JPEG start marker"
        stream.seek(-2, os.SEEK_END)
        if stream.read(2) != b"\xff\xd9":
            return "JPEG end marker is missing or truncated"
    return None


def _check_pdf(path, size):
    if size < 8:
        return "PDF file is too small to be valid"
    with open(path, "rb") as stream:
        head = stream.read(1024)
        stream.seek(max(0, size - 2048))
        tail = stream.read()
    if b"%PDF-" not in head:
        return "PDF header is missing"
    if b"%%EOF" not in tail:
        return "PDF end-of-file marker is missing or truncated"
    return None


def _check_zip_container(path):
    try:
        with zipfile.ZipFile(path, "r") as archive:
            bad_member = archive.testzip()
            if bad_member is not None:
                return f"ZIP member failed CRC check: {bad_member}"
    except (zipfile.BadZipFile, EOFError, OSError, RuntimeError) as exc:
        return f"invalid or damaged ZIP container: {exc}"
    return None


def _check_gif(path, size):
    if size < 14:
        return "GIF file is too small to be valid"
    with open(path, "rb") as stream:
        head = stream.read(6)
        stream.seek(-1, os.SEEK_END)
        trailer = stream.read(1)
    if head not in (b"GIF87a", b"GIF89a"):
        return "invalid GIF signature"
    if trailer != b";":
        return "GIF trailer is missing or file is truncated"
    return None


def _check_bmp(path, size):
    if size < 26:
        return "BMP file is too small to be valid"
    with open(path, "rb") as stream:
        header = stream.read(14)
    if header[:2] != b"BM":
        return "invalid BMP signature"
    declared_size = int.from_bytes(header[2:6], "little")
    if declared_size and declared_size > size:
        return "BMP header declares more bytes than the file contains"
    return None


def _check_riff(path, size, expected):
    if size < 12:
        return f"{expected} file is too small to be valid"
    with open(path, "rb") as stream:
        header = stream.read(12)
    if header[:4] != b"RIFF" or header[8:12] != expected:
        return f"invalid {expected.decode('ascii', 'replace')} RIFF header"
    declared_size = int.from_bytes(header[4:8], "little") + 8
    if declared_size > size:
        return "RIFF header declares more bytes than the file contains"
    return None


def scan_file(path, _sample_limit=500, flag_empty=False):
    """
    Return ScanResult(status, detail, size).

    The second and third arguments match the calling convention in
    OSSYStrimmer.py. _sample_limit is retained for compatibility.
    """
    try:
        size = os.path.getsize(path)
        if not os.path.isfile(path):
            return ScanResult("warning", "not a regular file", size)
        if size == 0:
            if flag_empty:
                return ScanResult("warning", "empty (0-byte) file", 0)
            return ScanResult("ok", "empty file (not reported)", 0)

        ext = os.path.splitext(path)[1].lower()
        head = _read_head(path, 16)

        if ext == ".png":
            problem = _check_png(path, size)
        elif ext in (".jpg", ".jpeg"):
            problem = _check_jpeg(path, size)
        elif ext == ".pdf":
            problem = _check_pdf(path, size)
        elif ext == ".gif":
            problem = _check_gif(path, size)
        elif ext == ".bmp":
            problem = _check_bmp(path, size)
        elif ext in (".wav", ".avi", ".webp"):
            expected = {".wav": b"WAVE", ".avi": b"AVI ", ".webp": b"WEBP"}[ext]
            problem = _check_riff(path, size, expected)
        elif ext in (".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".odt", ".ods", ".odp"):
            problem = _check_zip_container(path)
        else:
            problem = None

        if problem:
            return ScanResult("corrupted", problem, size)

        # Catch a few obvious extension/signature mismatches.
        if ext in (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".pdf", ".zip"):
            signatures = {
                ".png": b"\x89PNG\r\n\x1a\n",
                ".jpg": b"\xff\xd8",
                ".jpeg": b"\xff\xd8",
                ".gif": (b"GIF87a", b"GIF89a"),
                ".bmp": b"BM",
                ".pdf": b"%PDF-",
                ".zip": b"PK",
            }
            expected = signatures[ext]
            matches = any(head.startswith(sig) for sig in expected) if isinstance(expected, tuple) else head.startswith(expected)
            if not matches:
                return ScanResult("warning", f"file extension {ext} does not match its expected signature", size)

        return ScanResult("ok", "basic integrity checks passed", size)

    except PermissionError:
        return ScanResult("error", "permission denied", 0)
    except FileNotFoundError:
        return ScanResult("error", "file not found", 0)
    except OSError as exc:
        return ScanResult("error", f"could not read file: {exc}", 0)
