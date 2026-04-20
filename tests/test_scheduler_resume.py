from __future__ import annotations

import json
from pathlib import Path

from binja_scheduler.models import AttemptRecord, DiscoveredBinary, JobRecord, ScanResult, SchedulerConfig
from binja_scheduler.scheduler import _build_jobs, run_scheduler


def _make_binary(path: Path, sha256: str = "a" * 64) -> DiscoveredBinary:
    path.write_bytes(b"\x7fELF" + b"\x00" * 4096)
    return DiscoveredBinary(
        real_path=path,
        logical_path=str(path),
        file_name=path.name,
        format="elf",
        size_bytes=path.stat().st_size,
        sha256=sha256,
    )


def _metadata_job(binary: DiscoveredBinary, bndb_path: Path, *, status: str, attempt_status: str) -> JobRecord:
    return JobRecord(
        sha256=binary.sha256,
        size_bytes=binary.size_bytes,
        format=binary.format,
        source_path=binary.real_path,
        logical_paths=[binary.logical_path],
        bndb_path=bndb_path,
        status=status,
        completed_pass="easy-pass" if attempt_status == "success" else "",
        attempts=[
            AttemptRecord(
                pass_name="easy-pass",
                analysis_threads=1,
                timeout_seconds=120,
                started_at="2026-04-19T00:00:00+00:00",
                completed_at="2026-04-19T00:01:00+00:00" if attempt_status != "running" else "",
                elapsed_seconds=60.0 if attempt_status != "running" else 0.0,
                status=attempt_status,
                output_path=str(bndb_path),
            )
        ],
    )


def test_build_jobs_does_not_reuse_failed_bndb(tmp_path: Path) -> None:
    binary = _make_binary(tmp_path / "sample.bin")
    bndb_path = tmp_path / f"{binary.sha256}.bndb"
    bndb_path.write_text("stale")

    scan = ScanResult(input_path=tmp_path, binaries=[binary])
    existing = {
        binary.sha256: _metadata_job(binary, bndb_path, status="failed", attempt_status="timeout")
    }

    jobs = _build_jobs(scan, tmp_path, existing_jobs=existing, force=False)

    assert len(jobs) == 1
    assert jobs[0].status == "pending"
    assert jobs[0].used_existing_bndb is False


def test_build_jobs_marks_running_attempt_as_interrupted(tmp_path: Path) -> None:
    binary = _make_binary(tmp_path / "sample.bin")
    bndb_path = tmp_path / f"{binary.sha256}.bndb"
    bndb_path.write_text("stale")

    scan = ScanResult(input_path=tmp_path, binaries=[binary])
    existing = {
        binary.sha256: _metadata_job(binary, bndb_path, status="running", attempt_status="running")
    }

    jobs = _build_jobs(scan, tmp_path, existing_jobs=existing, force=False)

    assert len(jobs) == 1
    assert jobs[0].status == "pending"
    assert jobs[0].attempts[-1].status == "interrupted"
    assert "Interrupted before completion" in jobs[0].attempts[-1].error


def test_run_scheduler_resumes_interrupted_job(tmp_path: Path, monkeypatch) -> None:
    binary = _make_binary(tmp_path / "sample.bin")
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    bndb_path = output_dir / f"{binary.sha256}.bndb"
    metadata_path = output_dir / "metadata.json"

    existing = {
        "schema_version": 1,
        "jobs": [
            _metadata_job(binary, bndb_path, status="running", attempt_status="running").to_dict()
        ],
    }
    metadata_path.write_text(json.dumps(existing, indent=2))

    scan = ScanResult(input_path=tmp_path, binaries=[binary])

    monkeypatch.setattr("binja_scheduler.scheduler.discover_binaries", lambda *args, **kwargs: scan)

    def fake_run_one_job(job, pass_config, started_at_iso):
        bndb_path.write_text("fresh")
        return AttemptRecord(
            pass_name=pass_config.name,
            analysis_threads=pass_config.analysis_threads,
            timeout_seconds=pass_config.timeout_seconds,
            started_at=started_at_iso,
            completed_at="2026-04-19T00:02:00+00:00",
            elapsed_seconds=12.0,
            status="success",
            output_path=str(job.bndb_path),
        )

    monkeypatch.setattr("binja_scheduler.scheduler._run_one_job", fake_run_one_job)

    summary = run_scheduler(
        SchedulerConfig(
            input_path=tmp_path,
            output_dir=output_dir,
            metadata_path=metadata_path,
            retry_threads=(4,),
        )
    )

    assert summary["jobs_succeeded"] == 1
    data = json.loads(metadata_path.read_text())
    job = data["jobs"][0]
    assert job["status"] == "success"
    assert job["attempts"][0]["status"] == "interrupted"
    assert job["attempts"][-1]["status"] == "success"
