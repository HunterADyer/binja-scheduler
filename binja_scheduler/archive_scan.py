"""Recursive archive scanner for binja-scheduler."""

from __future__ import annotations

import bz2
import gzip
import hashlib
import lzma
import shutil
import struct
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from binja_scheduler.models import DiscoveredBinary, ScanResult

_ELF_MAGIC = b"\x7fELF"
_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
}
_PE_MAGIC = b"MZ"


def discover_binaries(
    input_path: Path,
    *,
    max_unpack_depth: int = 4,
    min_size: int = 1024,
) -> ScanResult:
    """Discover binaries from a directory or recursively-unpacked archive."""

    root = input_path.expanduser().resolve()
    result = ScanResult(input_path=root)

    if not root.exists():
        result.errors.append(f"Input does not exist: {root}")
        return result

    if root.is_dir():
        _scan_directory(
            root,
            logical_root=str(root),
            result=result,
            depth=0,
            max_unpack_depth=max_unpack_depth,
            min_size=min_size,
            in_archive=False,
        )
        return result

    if _is_archive(root):
        _scan_archive(
            root,
            archive_logical=str(root),
            result=result,
            depth=0,
            max_unpack_depth=max_unpack_depth,
            min_size=min_size,
        )
        return result

    _maybe_add_binary(root, str(root), result, min_size=min_size)
    return result


def _scan_archive(
    archive_path: Path,
    *,
    archive_logical: str,
    result: ScanResult,
    depth: int,
    max_unpack_depth: int,
    min_size: int,
) -> None:
    if depth > max_unpack_depth:
        result.errors.append(f"Max unpack depth exceeded: {archive_logical}")
        return

    tmp = _unpack_archive(archive_path)
    if tmp is None:
        result.errors.append(f"Failed to unpack archive: {archive_logical}")
        return

    result._temp_dirs.append(tmp)
    unpack_root = Path(tmp.name)
    _scan_directory(
        unpack_root,
        logical_root=archive_logical,
        result=result,
        depth=depth,
        max_unpack_depth=max_unpack_depth,
        min_size=min_size,
        in_archive=True,
    )


def _scan_directory(
    root: Path,
    *,
    logical_root: str,
    result: ScanResult,
    depth: int,
    max_unpack_depth: int,
    min_size: int,
    in_archive: bool,
) -> None:
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue

        rel = path.relative_to(root).as_posix()
        logical_path = _join_logical(logical_root, rel, in_archive=in_archive)

        if _is_archive(path):
            if depth >= max_unpack_depth:
                result.errors.append(f"Skipped nested archive at max depth: {logical_path}")
            else:
                _scan_archive(
                    path,
                    archive_logical=logical_path,
                    result=result,
                    depth=depth + 1,
                    max_unpack_depth=max_unpack_depth,
                    min_size=min_size,
                )
            continue

        _maybe_add_binary(path, logical_path, result, min_size=min_size)


def _join_logical(root: str, rel: str, *, in_archive: bool) -> str:
    if in_archive:
        return f"{root}!{rel}"
    return str(PurePosixPath(root) / rel)


def _maybe_add_binary(path: Path, logical_path: str, result: ScanResult, *, min_size: int) -> None:
    try:
        size = path.stat().st_size
    except OSError as exc:
        result.errors.append(f"{logical_path}: {exc}")
        return

    if size < min_size:
        return

    fmt = _identify_format(path)
    if fmt is None:
        return

    result.binaries.append(DiscoveredBinary(
        real_path=path,
        logical_path=logical_path,
        file_name=path.name,
        format=fmt,
        size_bytes=size,
        sha256=_file_sha256(path),
    ))


def _identify_format(path: Path) -> str | None:
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
    except OSError:
        return None

    if magic[:4] == _ELF_MAGIC:
        return "elf"
    if magic[:4] in _MACHO_MAGICS:
        return "macho"
    if magic[:2] == _PE_MAGIC:
        try:
            with open(path, "rb") as f:
                f.seek(0x3C)
                pe_offset = struct.unpack("<I", f.read(4))[0]
                f.seek(pe_offset)
                if f.read(4) == b"PE\x00\x00":
                    return "pe"
        except (OSError, struct.error):
            return None
    return None


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_archive(path: Path) -> bool:
    if not path.exists() or not path.is_file():
        return False

    name = path.name.lower()
    if name.endswith((".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".gz", ".bz2", ".xz")):
        return True

    try:
        with open(path, "rb") as f:
            magic = f.read(4)
    except OSError:
        return False

    return magic[:4] == b"PK\x03\x04" or magic[:2] == b"\x1f\x8b"


def _unpack_archive(path: Path):
    tmp = tempfile.TemporaryDirectory(prefix="binja_scheduler_")
    tmp_root = Path(tmp.name)
    name = path.name.lower()

    try:
        if zipfile.is_zipfile(str(path)):
            with zipfile.ZipFile(path, "r") as zf:
                for info in zf.infolist():
                    normalized = info.filename.replace("\\", "/")
                    if normalized != info.filename:
                        info.filename = normalized
                    zf.extract(info, tmp_root)
            return tmp

        if tarfile.is_tarfile(str(path)):
            with tarfile.open(path, "r:*") as tf:
                tf.extractall(tmp_root, filter="data")
            return tmp

        if name.endswith(".gz") and not name.endswith(".tar.gz"):
            out = tmp_root / path.stem
            with gzip.open(path, "rb") as fin, open(out, "wb") as fout:
                shutil.copyfileobj(fin, fout)
            return tmp

        if name.endswith(".bz2") and not name.endswith(".tar.bz2"):
            out = tmp_root / path.stem
            with bz2.open(path, "rb") as fin, open(out, "wb") as fout:
                shutil.copyfileobj(fin, fout)
            return tmp

        if name.endswith(".xz") and not name.endswith(".tar.xz"):
            out = tmp_root / path.stem
            with lzma.open(path, "rb") as fin, open(out, "wb") as fout:
                shutil.copyfileobj(fin, fout)
            return tmp
    except Exception:
        tmp.cleanup()
        return None

    tmp.cleanup()
    return None
