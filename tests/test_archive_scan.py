from __future__ import annotations

import gzip
import tarfile
import zipfile
from pathlib import Path

from binja_scheduler.archive_scan import discover_binaries


def _write_elf(path: Path, *, payload_size: int = 4096) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\x7fELF" + b"\x00" * payload_size)


def test_discover_binaries_finds_nested_zip_and_gzip_payloads(tmp_path: Path) -> None:
    outer_dir = tmp_path / "outer"
    _write_elf(outer_dir / "root.bin")
    _write_elf(outer_dir / "inner_src" / "nested.bin")

    inner_zip = outer_dir / "nested.zip"
    with zipfile.ZipFile(inner_zip, "w") as zf:
        zf.write(outer_dir / "inner_src" / "nested.bin", arcname="nested.bin")

    gz_path = outer_dir / "gzip.bin.gz"
    with gzip.open(gz_path, "wb") as fout:
        fout.write((outer_dir / "root.bin").read_bytes())

    outer_zip = tmp_path / "bundle.zip"
    with zipfile.ZipFile(outer_zip, "w") as zf:
        zf.write(outer_dir / "root.bin", arcname="root.bin")
        zf.write(inner_zip, arcname="nested.zip")
        zf.write(gz_path, arcname="gzip.bin.gz")
        zf.writestr("notes.txt", "not a binary")

    scan = discover_binaries(outer_zip, max_unpack_depth=3, min_size=64)
    try:
        assert scan.errors == []
        logical_paths = sorted(binary.logical_path for binary in scan.binaries)
        assert logical_paths == [
            f"{outer_zip}!gzip.bin.gz!gzip.bin",
            f"{outer_zip}!nested.zip!nested.bin",
            f"{outer_zip}!root.bin",
        ]
        assert all(binary.format == "elf" for binary in scan.binaries)
    finally:
        scan.cleanup()


def test_discover_binaries_reports_max_depth_skip(tmp_path: Path) -> None:
    lvl3_dir = tmp_path / "lvl3_src"
    _write_elf(lvl3_dir / "deep.bin")

    lvl3_zip = tmp_path / "lvl3.zip"
    with zipfile.ZipFile(lvl3_zip, "w") as zf:
        zf.write(lvl3_dir / "deep.bin", arcname="deep.bin")

    lvl2_zip = tmp_path / "lvl2.zip"
    with zipfile.ZipFile(lvl2_zip, "w") as zf:
        zf.write(lvl3_zip, arcname="lvl3.zip")

    lvl1_zip = tmp_path / "lvl1.zip"
    with zipfile.ZipFile(lvl1_zip, "w") as zf:
        zf.write(lvl2_zip, arcname="lvl2.zip")

    scan = discover_binaries(lvl1_zip, max_unpack_depth=1, min_size=64)
    try:
        assert scan.binaries == []
        assert any("Skipped nested archive at max depth" in error for error in scan.errors)
    finally:
        scan.cleanup()


def test_discover_binaries_reports_corrupt_archive(tmp_path: Path) -> None:
    bad_zip = tmp_path / "broken.zip"
    bad_zip.write_bytes(b"this is not a valid zip archive")

    scan = discover_binaries(bad_zip, min_size=1)
    try:
        assert scan.binaries == []
        assert any("Failed to unpack archive" in error for error in scan.errors)
    finally:
        scan.cleanup()


def test_discover_binaries_finds_binaries_inside_tar(tmp_path: Path) -> None:
    src_dir = tmp_path / "tar_src"
    _write_elf(src_dir / "payload.bin")

    tar_path = tmp_path / "bundle.tar"
    with tarfile.open(tar_path, "w") as tf:
        tf.add(src_dir / "payload.bin", arcname="payload.bin")

    scan = discover_binaries(tar_path, min_size=64)
    try:
        assert len(scan.binaries) == 1
        assert scan.binaries[0].logical_path == f"{tar_path}!payload.bin"
        assert scan.binaries[0].format == "elf"
    finally:
        scan.cleanup()
