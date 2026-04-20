"""Shared data models for binja-scheduler."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class DiscoveredBinary:
    """One binary found during recursive archive scanning."""

    real_path: Path
    logical_path: str
    file_name: str
    format: str
    size_bytes: int
    sha256: str


@dataclass
class ScanResult:
    """Archive scan output plus owned temp directories."""

    input_path: Path
    binaries: list[DiscoveredBinary] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    _temp_dirs: list[Any] = field(default_factory=list, repr=False)

    def cleanup(self) -> None:
        """Delete temporary unpack directories."""

        for tmp in reversed(self._temp_dirs):
            try:
                tmp.cleanup()
            except Exception:
                pass
        self._temp_dirs.clear()


@dataclass(slots=True)
class AttemptRecord:
    """One scheduler attempt for a single binary."""

    pass_name: str
    analysis_threads: int
    timeout_seconds: int | None
    started_at: str
    status: str
    completed_at: str = ""
    elapsed_seconds: float = 0.0
    error: str = ""
    output_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "pass_name": self.pass_name,
            "analysis_threads": self.analysis_threads,
            "timeout_seconds": self.timeout_seconds,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "status": self.status,
            "error": self.error,
            "output_path": self.output_path,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttemptRecord":
        return cls(
            pass_name=str(data.get("pass_name", "")),
            analysis_threads=int(data.get("analysis_threads", 1)),
            timeout_seconds=data.get("timeout_seconds"),
            started_at=str(data.get("started_at", "")),
            completed_at=str(data.get("completed_at", "")),
            elapsed_seconds=float(data.get("elapsed_seconds", 0.0) or 0.0),
            status=str(data.get("status", "error")),
            error=str(data.get("error", "")),
            output_path=str(data.get("output_path", "")),
        )


@dataclass
class JobRecord:
    """Scheduler state for one deduplicated binary hash."""

    sha256: str
    size_bytes: int
    format: str
    source_path: Path
    logical_paths: list[str]
    bndb_path: Path
    status: str = "pending"
    completed_pass: str = ""
    attempts: list[AttemptRecord] = field(default_factory=list)
    used_existing_bndb: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "format": self.format,
            "source_path": str(self.source_path),
            "logical_paths": sorted(self.logical_paths),
            "bndb_path": str(self.bndb_path),
            "status": self.status,
            "completed_pass": self.completed_pass,
            "used_existing_bndb": self.used_existing_bndb,
            "attempts": [attempt.to_dict() for attempt in self.attempts],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "JobRecord":
        return cls(
            sha256=str(data.get("sha256", "")),
            size_bytes=int(data.get("size_bytes", 0)),
            format=str(data.get("format", "")),
            source_path=Path(str(data.get("source_path", ""))),
            logical_paths=list(data.get("logical_paths", [])),
            bndb_path=Path(str(data.get("bndb_path", ""))),
            status=str(data.get("status", "pending")),
            completed_pass=str(data.get("completed_pass", "")),
            attempts=[AttemptRecord.from_dict(item) for item in data.get("attempts", [])],
            used_existing_bndb=bool(data.get("used_existing_bndb", False)),
        )


@dataclass(slots=True)
class PassConfig:
    """One scheduler pass."""

    name: str
    analysis_threads: int
    timeout_seconds: int | None
    concurrency: int


@dataclass(slots=True)
class SchedulerConfig:
    """High-level scheduler configuration."""

    input_path: Path
    output_dir: Path
    metadata_path: Path
    initial_timeout_seconds: int = 120
    initial_concurrency: int = 1
    retry_concurrency: int = 1
    retry_threads: tuple[int, ...] = (4,)
    max_unpack_depth: int = 4
    min_size: int = 1024
    resume: bool = True
    force: bool = False
