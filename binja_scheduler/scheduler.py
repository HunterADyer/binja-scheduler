"""Two-pass Binary Ninja scheduler."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from binja_scheduler.archive_scan import discover_binaries
from binja_scheduler.models import (
    AttemptRecord,
    JobRecord,
    PassConfig,
    SchedulerConfig,
)

METADATA_VERSION = 1


def _worker_module_name() -> str:
    return os.environ.get("BINJA_SCHEDULER_WORKER_MODULE", "binja_scheduler.worker")


def run_scheduler(config: SchedulerConfig) -> dict:
    """Run the scheduler and emit metadata to disk."""

    output_dir = config.output_dir.expanduser().resolve()
    metadata_path = config.metadata_path.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)

    scan = discover_binaries(
        config.input_path,
        max_unpack_depth=config.max_unpack_depth,
        min_size=config.min_size,
    )

    try:
        existing_jobs = _load_existing_jobs(metadata_path) if config.resume and not config.force else {}
        jobs = _build_jobs(scan, output_dir, existing_jobs=existing_jobs, force=config.force)
        _write_metadata(metadata_path, config, scan.errors, jobs)

        initial_pass = PassConfig(
            name="easy-pass",
            analysis_threads=1,
            timeout_seconds=config.initial_timeout_seconds,
            concurrency=max(1, config.initial_concurrency),
        )
        pending = [job for job in jobs if job.status == "pending"]
        if pending:
            pending = _run_pass(pending, initial_pass, metadata_path, config, scan.errors, jobs)

        for index, threads in enumerate(config.retry_threads, start=1):
            if not pending:
                break
            retry_pass = PassConfig(
                name=f"retry-pass-{index}",
                analysis_threads=int(threads),
                timeout_seconds=None,
                concurrency=max(1, config.retry_concurrency),
            )
            pending = _run_pass(pending, retry_pass, metadata_path, config, scan.errors, jobs)

        for job in pending:
            if job.status != "success":
                job.status = "failed"

        _write_metadata(metadata_path, config, scan.errors, jobs)
        return _summary(jobs, scan.errors, metadata_path)
    finally:
        scan.cleanup()


def _build_jobs(
    scan,
    output_dir: Path,
    *,
    existing_jobs: dict[str, JobRecord],
    force: bool,
) -> list[JobRecord]:
    by_hash: dict[str, JobRecord] = {}

    for binary in scan.binaries:
        job = by_hash.get(binary.sha256)
        if job is None:
            previous = existing_jobs.get(binary.sha256)
            if previous is not None and not force:
                job = previous
                job.source_path = binary.real_path
                job.size_bytes = binary.size_bytes
                job.format = binary.format
                job.bndb_path = output_dir / f"{binary.sha256}.bndb"
                job.logical_paths = list(job.logical_paths)
            else:
                job = JobRecord(
                    sha256=binary.sha256,
                    size_bytes=binary.size_bytes,
                    format=binary.format,
                    source_path=binary.real_path,
                    logical_paths=[],
                    bndb_path=output_dir / f"{binary.sha256}.bndb",
                )
            by_hash[binary.sha256] = job
        if binary.logical_path not in job.logical_paths:
            job.logical_paths.append(binary.logical_path)

    for job in by_hash.values():
        interrupted = _normalize_resumed_job(job)
        if _can_reuse_existing_bndb(
            job,
            from_metadata=job.sha256 in existing_jobs,
            force=force,
            interrupted=interrupted,
        ):
            job.status = "success"
            if not job.completed_pass:
                job.completed_pass = "existing"
            job.used_existing_bndb = True
        elif force:
            job.status = "pending"
            job.completed_pass = ""
            job.used_existing_bndb = False
        elif job.status != "success":
            job.status = "pending"

    return sorted(by_hash.values(), key=lambda job: (job.size_bytes, job.sha256))


def _run_pass(
    jobs: list[JobRecord],
    pass_config: PassConfig,
    metadata_path: Path,
    scheduler_config: SchedulerConfig,
    scan_errors: list[str],
    all_jobs: list[JobRecord],
) -> list[JobRecord]:
    pending = sorted(jobs, key=lambda job: (job.size_bytes, job.sha256))

    with ThreadPoolExecutor(max_workers=pass_config.concurrency) as executor:
        futures = {}
        for job in pending:
            running_attempt = AttemptRecord(
                pass_name=pass_config.name,
                analysis_threads=pass_config.analysis_threads,
                timeout_seconds=pass_config.timeout_seconds,
                started_at=datetime.now(timezone.utc).isoformat(),
                status="running",
                output_path=str(job.bndb_path),
            )
            job.attempts.append(running_attempt)
            job.status = "running"
            _write_metadata(metadata_path, scheduler_config, scan_errors, all_jobs)
            futures[executor.submit(_run_one_job, job, pass_config, running_attempt.started_at)] = job

        for future in as_completed(futures):
            job = futures[future]
            attempt = future.result()
            job.attempts[-1] = attempt

            if attempt.status == "success":
                job.status = "success"
                job.completed_pass = pass_config.name
            else:
                job.status = "pending"

            _write_metadata(metadata_path, scheduler_config, scan_errors, all_jobs)

    return [job for job in pending if job.status != "success"]


def _run_one_job(job: JobRecord, pass_config: PassConfig, started_at_iso: str) -> AttemptRecord:
    started_at = datetime.fromisoformat(started_at_iso)
    started_monotonic = time.monotonic()

    cmd = [
        sys.executable,
        "-m",
        _worker_module_name(),
        "--binary",
        str(job.source_path),
        "--output",
        str(job.bndb_path),
        "--analysis-threads",
        str(pass_config.analysis_threads),
    ]

    try:
        run_kwargs = {
            "capture_output": True,
            "text": True,
            "check": False,
        }
        if pass_config.timeout_seconds is not None:
            run_kwargs["timeout"] = pass_config.timeout_seconds
        proc = subprocess.run(cmd, **run_kwargs)
        completed_at = datetime.now(timezone.utc)
        elapsed = time.monotonic() - started_monotonic

        payload = _parse_worker_payload(proc.stdout)
        if proc.returncode == 0 and payload.get("status") == "success":
            return AttemptRecord(
                pass_name=pass_config.name,
                analysis_threads=pass_config.analysis_threads,
                timeout_seconds=pass_config.timeout_seconds,
                started_at=started_at_iso,
                completed_at=completed_at.isoformat(),
                elapsed_seconds=elapsed,
                status="success",
                output_path=str(job.bndb_path),
            )

        _cleanup_failed_output(job.bndb_path)
        error = payload.get("error") or _compact_error(proc.stderr) or f"exit {proc.returncode}"
        return AttemptRecord(
            pass_name=pass_config.name,
            analysis_threads=pass_config.analysis_threads,
            timeout_seconds=pass_config.timeout_seconds,
            started_at=started_at_iso,
            completed_at=completed_at.isoformat(),
            elapsed_seconds=elapsed,
            status="error",
            error=error,
            output_path=str(job.bndb_path),
        )
    except subprocess.TimeoutExpired:
        completed_at = datetime.now(timezone.utc)
        elapsed = time.monotonic() - started_monotonic
        _cleanup_failed_output(job.bndb_path)
        return AttemptRecord(
            pass_name=pass_config.name,
            analysis_threads=pass_config.analysis_threads,
            timeout_seconds=pass_config.timeout_seconds,
            started_at=started_at_iso,
            completed_at=completed_at.isoformat(),
            elapsed_seconds=elapsed,
            status="timeout",
            error=f"Timed out after {pass_config.timeout_seconds}s",
            output_path=str(job.bndb_path),
        )
    except Exception as exc:
        completed_at = datetime.now(timezone.utc)
        elapsed = time.monotonic() - started_monotonic
        _cleanup_failed_output(job.bndb_path)
        return AttemptRecord(
            pass_name=pass_config.name,
            analysis_threads=pass_config.analysis_threads,
            timeout_seconds=pass_config.timeout_seconds,
            started_at=started_at_iso,
            completed_at=completed_at.isoformat(),
            elapsed_seconds=elapsed,
            status="error",
            error=str(exc),
            output_path=str(job.bndb_path),
        )


def _parse_worker_payload(stdout: str) -> dict:
    text = (stdout or "").strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}


def _compact_error(stderr: str) -> str:
    text = (stderr or "").strip()
    if not text:
        return ""
    return text.splitlines()[-1][:400]


def _cleanup_failed_output(path: Path) -> None:
    try:
        if path.exists():
            path.unlink()
    except OSError:
        pass


def _load_existing_jobs(metadata_path: Path) -> dict[str, JobRecord]:
    if not metadata_path.exists():
        return {}

    try:
        data = json.loads(metadata_path.read_text())
    except Exception:
        return {}

    jobs: dict[str, JobRecord] = {}
    for item in data.get("jobs", []):
        try:
            job = JobRecord.from_dict(item)
        except Exception:
            continue
        if job.sha256:
            jobs[job.sha256] = job
    return jobs


def _normalize_resumed_job(job: JobRecord) -> bool:
    if not job.attempts:
        return False

    last = job.attempts[-1]
    interrupted = False
    if last.status == "running":
        interrupted = True
        last.status = "interrupted"
        last.completed_at = datetime.now(timezone.utc).isoformat()
        if last.error:
            last.error = f"{last.error}; interrupted before completion"
        else:
            last.error = "Interrupted before completion; eligible for resume"

    if job.status == "running":
        job.status = "pending"
        interrupted = True

    return interrupted


def _can_reuse_existing_bndb(
    job: JobRecord,
    *,
    from_metadata: bool,
    force: bool,
    interrupted: bool,
) -> bool:
    if force or interrupted or not job.bndb_path.exists():
        return False

    if from_metadata:
        if job.status != "success" and not job.used_existing_bndb:
            return False
        if not job.attempts:
            return True
        return job.attempts[-1].status == "success"

    return False


def _write_metadata(
    metadata_path: Path,
    scheduler_config: SchedulerConfig,
    scan_errors: list[str],
    jobs: list[JobRecord],
) -> None:
    data = {
        "schema_version": METADATA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run_state": _run_state(jobs),
        "config": {
            "input_path": str(scheduler_config.input_path.expanduser().resolve()),
            "output_dir": str(scheduler_config.output_dir.expanduser().resolve()),
            "metadata_path": str(scheduler_config.metadata_path.expanduser().resolve()),
            "initial_timeout_seconds": scheduler_config.initial_timeout_seconds,
            "initial_concurrency": scheduler_config.initial_concurrency,
            "retry_concurrency": scheduler_config.retry_concurrency,
            "retry_threads": list(scheduler_config.retry_threads),
            "max_unpack_depth": scheduler_config.max_unpack_depth,
            "min_size": scheduler_config.min_size,
            "resume": scheduler_config.resume,
            "force": scheduler_config.force,
        },
        "summary": _summary(jobs, scan_errors, metadata_path),
        "scan_errors": scan_errors,
        "jobs": [job.to_dict() for job in jobs],
    }
    tmp_path = metadata_path.with_name(f".{metadata_path.name}.tmp")
    tmp_path.write_text(json.dumps(data, indent=2))
    os.replace(tmp_path, metadata_path)


def _summary(jobs: list[JobRecord], scan_errors: list[str], metadata_path: Path) -> dict:
    total = len(jobs)
    succeeded = sum(1 for job in jobs if job.status == "success")
    failed = sum(1 for job in jobs if job.status == "failed")
    pending = sum(1 for job in jobs if job.status == "pending")
    reused = sum(1 for job in jobs if job.used_existing_bndb)
    return {
        "metadata_path": str(metadata_path),
        "jobs_total": total,
        "jobs_succeeded": succeeded,
        "jobs_failed": failed,
        "jobs_pending": pending,
        "jobs_reused_existing_bndb": reused,
        "scan_error_count": len(scan_errors),
    }


def _run_state(jobs: list[JobRecord]) -> str:
    if any(job.status in {"pending", "running"} for job in jobs):
        return "in_progress"
    if any(job.status == "failed" for job in jobs):
        return "completed_with_failures"
    return "completed"
