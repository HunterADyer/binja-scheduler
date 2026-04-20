"""CLI for binja-scheduler."""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from binja_scheduler.models import SchedulerConfig
from binja_scheduler.scheduler import run_scheduler

RUNTIME_SCHEMA_VERSION = 1
DEFAULT_RUNTIME_NAME = "runtime.json"
DEFAULT_LOG_NAME = "scheduler.log"
_KNOWN_COMMANDS = {"run", "start", "status", "stop", "logs"}


def _parse_retry_threads(value: str) -> tuple[int, ...]:
    parts = [item.strip() for item in value.split(",") if item.strip()]
    if not parts:
        return (4,)
    return tuple(int(item) for item in parts)


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _runtime_path(output_dir: Path) -> Path:
    return output_dir / DEFAULT_RUNTIME_NAME


def _log_path(output_dir: Path) -> Path:
    return output_dir / DEFAULT_LOG_NAME


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp")
    tmp_path.write_text(json.dumps(data, indent=2))
    os.replace(tmp_path, path)


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def _pid_is_running(pid: int | None) -> bool:
    if not pid or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_for_process_exit(pid: int, *, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    while time.monotonic() < deadline:
        if not _pid_is_running(pid):
            return True
        time.sleep(0.1)
    return not _pid_is_running(pid)


def _resolve_output_paths(args: argparse.Namespace) -> tuple[Path, Path]:
    output_dir = args.output_dir.expanduser().resolve()
    metadata_path = args.metadata.expanduser().resolve() if args.metadata else (output_dir / "metadata.json")
    return output_dir, metadata_path


def _build_config(args: argparse.Namespace) -> SchedulerConfig:
    output_dir, metadata_path = _resolve_output_paths(args)
    return SchedulerConfig(
        input_path=args.input.expanduser().resolve(),
        output_dir=output_dir,
        metadata_path=metadata_path,
        initial_timeout_seconds=args.initial_timeout_seconds,
        initial_concurrency=args.initial_concurrency,
        retry_concurrency=args.retry_concurrency,
        retry_threads=_parse_retry_threads(args.retry_threads),
        max_unpack_depth=args.max_unpack_depth,
        min_size=args.min_size,
        resume=args.resume,
        force=args.force,
    )


def _runtime_record(
    *,
    pid: int | None,
    status: str,
    launch_mode: str,
    output_dir: Path,
    metadata_path: Path,
    log_path: Path,
    command: list[str] | None = None,
    last_exit_code: int | None = None,
    error: str = "",
) -> dict[str, Any]:
    return {
        "schema_version": RUNTIME_SCHEMA_VERSION,
        "generated_at": _timestamp(),
        "pid": pid,
        "status": status,
        "launch_mode": launch_mode,
        "output_dir": str(output_dir),
        "metadata_path": str(metadata_path),
        "log_path": str(log_path),
        "command": command or [],
        "last_exit_code": last_exit_code,
        "error": error,
    }


def _build_child_command(args: argparse.Namespace) -> list[str]:
    output_dir, metadata_path = _resolve_output_paths(args)
    cmd = [
        sys.executable,
        "-m",
        "binja_scheduler",
        "run",
        "--input",
        str(args.input.expanduser().resolve()),
        "--output-dir",
        str(output_dir),
        "--metadata",
        str(metadata_path),
        "--initial-timeout-seconds",
        str(args.initial_timeout_seconds),
        "--retry-threads",
        args.retry_threads,
        "--initial-concurrency",
        str(args.initial_concurrency),
        "--retry-concurrency",
        str(args.retry_concurrency),
        "--max-unpack-depth",
        str(args.max_unpack_depth),
        "--min-size",
        str(args.min_size),
    ]
    if args.resume:
        cmd.append("--resume")
    else:
        cmd.append("--no-resume")
    if args.force:
        cmd.append("--force")
    return cmd


def _read_log_tail(path: Path, *, lines: int) -> str:
    if not path.exists():
        return ""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return "".join(deque(f, maxlen=max(1, lines)))


def _read_runtime_status(output_dir: Path, metadata_path: Path) -> dict[str, Any]:
    runtime_path = _runtime_path(output_dir)
    runtime = _load_json(runtime_path)
    metadata = _load_json(metadata_path)

    pid = runtime.get("pid")
    try:
        pid = int(pid) if pid is not None else None
    except (TypeError, ValueError):
        pid = None

    process_running = _pid_is_running(pid)
    runtime_status = str(runtime.get("status", "missing"))
    if pid and not process_running and runtime_status in {"starting", "running"}:
        runtime_status = "stale"

    return {
        "output_dir": str(output_dir),
        "runtime_path": str(runtime_path),
        "metadata_path": str(metadata_path),
        "log_path": runtime.get("log_path", str(_log_path(output_dir))),
        "pid": pid,
        "process_running": process_running,
        "runtime_status": runtime_status,
        "launch_mode": runtime.get("launch_mode", ""),
        "last_exit_code": runtime.get("last_exit_code"),
        "run_state": metadata.get("run_state", ""),
        "summary": metadata.get("summary", {}),
        "resume_recommended": bool(metadata.get("run_state") == "in_progress" and not process_running),
    }


def _handle_run(args: argparse.Namespace) -> int:
    config = _build_config(args)
    output_dir = config.output_dir
    metadata_path = config.metadata_path
    runtime_path = _runtime_path(output_dir)
    log_path = _log_path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    existing_runtime = _load_json(runtime_path)
    existing_pid = existing_runtime.get("pid")
    try:
        existing_pid = int(existing_pid) if existing_pid is not None else None
    except (TypeError, ValueError):
        existing_pid = None
    if existing_pid and existing_pid != os.getpid() and _pid_is_running(existing_pid):
        print(json.dumps({
            "error": f"Scheduler already running for output dir {output_dir}",
            "pid": existing_pid,
            "runtime_path": str(runtime_path),
        }, indent=2))
        return 1

    launch_mode = os.environ.get("BINJA_SCHEDULER_LAUNCH_MODE", "foreground")
    command = [sys.executable, "-m", "binja_scheduler", "run", *sys.argv[2:]]
    _write_json(
        runtime_path,
        _runtime_record(
            pid=os.getpid(),
            status="running",
            launch_mode=launch_mode,
            output_dir=output_dir,
            metadata_path=metadata_path,
            log_path=log_path,
            command=command,
        ),
    )

    final_status = "crashed"
    exit_code = 1
    try:
        summary = run_scheduler(config)
        exit_code = 0 if summary["jobs_failed"] == 0 else 1
        final_status = "completed" if exit_code == 0 else "completed_with_failures"
        print(json.dumps(summary, indent=2))
        return exit_code
    finally:
        _write_json(
            runtime_path,
            _runtime_record(
                pid=None,
                status=final_status,
                launch_mode=launch_mode,
                output_dir=output_dir,
                metadata_path=metadata_path,
                log_path=log_path,
                command=command,
                last_exit_code=exit_code,
            ),
        )


def _handle_start(args: argparse.Namespace) -> int:
    output_dir, metadata_path = _resolve_output_paths(args)
    runtime_path = _runtime_path(output_dir)
    log_path = _log_path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    current = _read_runtime_status(output_dir, metadata_path)
    if current["process_running"]:
        print(json.dumps({
            "error": f"Scheduler already running for output dir {output_dir}",
            "pid": current["pid"],
            "runtime_path": current["runtime_path"],
        }, indent=2))
        return 1

    project_root = _project_root()
    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(project_root) if not existing_pythonpath else f"{project_root}{os.pathsep}{existing_pythonpath}"
    env["BINJA_SCHEDULER_LAUNCH_MODE"] = "detached"
    cmd = _build_child_command(args)

    with open(os.devnull, "rb") as stdin_fp, open(log_path, "a", encoding="utf-8") as log_fp:
        proc = subprocess.Popen(
            cmd,
            stdin=stdin_fp,
            stdout=log_fp,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True,
            cwd=str(project_root),
            env=env,
        )

    _write_json(
        runtime_path,
        _runtime_record(
            pid=proc.pid,
            status="starting",
            launch_mode="detached",
            output_dir=output_dir,
            metadata_path=metadata_path,
            log_path=log_path,
            command=cmd,
        ),
    )

    print(json.dumps({
        "status": "started",
        "pid": proc.pid,
        "runtime_path": str(runtime_path),
        "metadata_path": str(metadata_path),
        "log_path": str(log_path),
        "command": cmd,
    }, indent=2))
    return 0


def _handle_status(args: argparse.Namespace) -> int:
    output_dir, metadata_path = _resolve_output_paths(args)
    print(json.dumps(_read_runtime_status(output_dir, metadata_path), indent=2))
    return 0


def _handle_stop(args: argparse.Namespace) -> int:
    output_dir, metadata_path = _resolve_output_paths(args)
    runtime_path = _runtime_path(output_dir)
    runtime = _load_json(runtime_path)
    current = _read_runtime_status(output_dir, metadata_path)
    pid = current["pid"]

    if not current["process_running"]:
        status = "already_stopped"
        if current["runtime_status"] in {"running", "starting", "stale"}:
            _write_json(
                runtime_path,
                _runtime_record(
                    pid=None,
                    status="stopped",
                    launch_mode=str(runtime.get("launch_mode", "")),
                    output_dir=output_dir,
                    metadata_path=metadata_path,
                    log_path=Path(str(runtime.get("log_path", _log_path(output_dir)))),
                    command=list(runtime.get("command", [])),
                    last_exit_code=runtime.get("last_exit_code"),
                    error="No running process remained at stop time",
                ),
            )
            status = "stopped_stale_runtime"

        print(json.dumps({
            "status": status,
            "runtime_path": str(runtime_path),
            "pid": pid,
        }, indent=2))
        return 0

    stop_signal = signal.SIGKILL if args.force else signal.SIGTERM
    try:
        os.killpg(pid, stop_signal)
    except ProcessLookupError:
        _write_json(
            runtime_path,
            _runtime_record(
                pid=None,
                status="stopped",
                launch_mode=str(runtime.get("launch_mode", "")),
                output_dir=output_dir,
                metadata_path=metadata_path,
                log_path=Path(str(runtime.get("log_path", _log_path(output_dir)))),
                command=list(runtime.get("command", [])),
                last_exit_code=runtime.get("last_exit_code"),
                error="Process exited before stop signal was delivered",
            ),
        )
        print(json.dumps({
            "status": "stopped_race",
            "pid": pid,
            "runtime_path": str(runtime_path),
        }, indent=2))
        return 0

    forced_kill = False
    if not args.force and not _wait_for_process_exit(pid, timeout_seconds=args.grace_seconds):
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        forced_kill = True
        if not _wait_for_process_exit(pid, timeout_seconds=max(1.0, args.grace_seconds)):
            print(json.dumps({
                "status": "stop_failed",
                "pid": pid,
                "runtime_path": str(runtime_path),
            }, indent=2))
            return 1

    _write_json(
        runtime_path,
        _runtime_record(
            pid=None,
            status="stopped",
            launch_mode=str(runtime.get("launch_mode", "")),
            output_dir=output_dir,
            metadata_path=metadata_path,
            log_path=Path(str(runtime.get("log_path", _log_path(output_dir)))),
            command=list(runtime.get("command", [])),
            last_exit_code=-int(signal.SIGKILL if forced_kill or args.force else signal.SIGTERM),
            error="Stopped by user request",
        ),
    )
    print(json.dumps({
        "status": "stopped",
        "pid": pid,
        "forced_kill": forced_kill or args.force,
        "runtime_path": str(runtime_path),
    }, indent=2))
    return 0


def _handle_logs(args: argparse.Namespace) -> int:
    output_dir = args.output_dir.expanduser().resolve()
    log_path = _log_path(output_dir)
    tail = _read_log_tail(log_path, lines=args.lines)
    if not tail:
        print(f"No log output available at {log_path}")
        return 0
    print(tail, end="" if tail.endswith("\n") else "\n")
    return 0


def _add_run_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--input", type=Path, required=True, help="Directory or archive to scan")
    parser.add_argument("--output-dir", type=Path, required=True, help="Directory for flattened hash-named BNDBs")
    parser.add_argument("--metadata", type=Path, default=None, help="Metadata JSON path (default: <output-dir>/metadata.json)")
    parser.add_argument("--initial-timeout-seconds", type=int, default=120, help="Timeout for the easy pass")
    parser.add_argument("--retry-threads", default="4", help="Comma-separated BN thread ladder for retry passes")
    parser.add_argument("--initial-concurrency", type=int, default=1, help="Concurrent jobs in the easy pass")
    parser.add_argument("--retry-concurrency", type=int, default=1, help="Concurrent jobs in retry passes")
    parser.add_argument("--max-unpack-depth", type=int, default=4, help="Maximum nested archive unpack depth")
    parser.add_argument("--min-size", type=int, default=1024, help="Skip files smaller than this many bytes")
    parser.add_argument("--resume", dest="resume", action="store_true", default=True, help="Resume from existing metadata when available (default)")
    parser.add_argument("--no-resume", dest="resume", action="store_false", help="Ignore existing metadata and rebuild scheduler state from the current scan")
    parser.add_argument("--force", action="store_true", help="Rebuild BNDBs even when the target file already exists")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="binja-scheduler",
        description="Two-pass Binary Ninja BNDB scheduler for directories and archives",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run the scheduler in the foreground")
    _add_run_options(run_parser)
    run_parser.set_defaults(handler=_handle_run)

    start_parser = subparsers.add_parser("start", help="Launch the scheduler detached from the terminal")
    _add_run_options(start_parser)
    start_parser.set_defaults(handler=_handle_start)

    status_parser = subparsers.add_parser("status", help="Inspect the current runtime and metadata state")
    status_parser.add_argument("--output-dir", type=Path, required=True, help="Scheduler output directory")
    status_parser.add_argument("--metadata", type=Path, default=None, help="Metadata JSON path (default: <output-dir>/metadata.json)")
    status_parser.set_defaults(handler=_handle_status)

    stop_parser = subparsers.add_parser("stop", help="Stop a detached scheduler run")
    stop_parser.add_argument("--output-dir", type=Path, required=True, help="Scheduler output directory")
    stop_parser.add_argument("--metadata", type=Path, default=None, help="Metadata JSON path (default: <output-dir>/metadata.json)")
    stop_parser.add_argument("--grace-seconds", type=float, default=5.0, help="Wait this long after SIGTERM before escalating to SIGKILL")
    stop_parser.add_argument("--force", action="store_true", help="Send SIGKILL immediately instead of SIGTERM")
    stop_parser.set_defaults(handler=_handle_stop)

    logs_parser = subparsers.add_parser("logs", help="Print the tail of scheduler.log")
    logs_parser.add_argument("--output-dir", type=Path, required=True, help="Scheduler output directory")
    logs_parser.add_argument("--lines", type=int, default=40, help="Number of lines to print from the end of the log")
    logs_parser.set_defaults(handler=_handle_logs)

    return parser


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    parser = _build_parser()
    if not raw_argv:
        parser.print_help()
        return 1
    if raw_argv[0] not in _KNOWN_COMMANDS and raw_argv[0] not in {"-h", "--help"}:
        raw_argv = ["run", *raw_argv]
    args = parser.parse_args(raw_argv)
    return args.handler(args)
