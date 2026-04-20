from __future__ import annotations

import json
from io import StringIO
from pathlib import Path
from contextlib import redirect_stdout

from binja_scheduler.cli import DEFAULT_RUNTIME_NAME, main


def test_start_launches_detached_process(tmp_path: Path, monkeypatch) -> None:
    launched: dict = {}

    class FakePopen:
        def __init__(self, cmd, **kwargs):
            launched["cmd"] = cmd
            launched["kwargs"] = kwargs
            self.pid = 4242

    monkeypatch.setattr("binja_scheduler.cli.subprocess.Popen", FakePopen)

    output = StringIO()
    with redirect_stdout(output):
        rc = main([
            "start",
            "--input",
            str(tmp_path),
            "--output-dir",
            str(tmp_path / "out"),
            "--retry-threads",
            "4,8",
        ])

    assert rc == 0
    assert launched["kwargs"]["start_new_session"] is True
    assert launched["kwargs"]["close_fds"] is True
    assert launched["kwargs"]["stderr"] is not None
    assert launched["cmd"][:3] == [launched["cmd"][0], "-m", "binja_scheduler"]
    assert launched["cmd"][3] == "run"

    runtime_path = tmp_path / "out" / DEFAULT_RUNTIME_NAME
    runtime = json.loads(runtime_path.read_text())
    assert runtime["pid"] == 4242
    assert runtime["status"] == "starting"
    assert runtime["launch_mode"] == "detached"


def test_status_reports_runtime_and_metadata(tmp_path: Path, monkeypatch) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "runtime.json").write_text(json.dumps({
        "pid": 9999,
        "status": "running",
        "launch_mode": "detached",
        "log_path": str(out_dir / "scheduler.log"),
    }))
    (out_dir / "metadata.json").write_text(json.dumps({
        "run_state": "in_progress",
        "summary": {
            "jobs_total": 3,
            "jobs_succeeded": 1,
            "jobs_failed": 0,
        },
    }))

    monkeypatch.setattr("binja_scheduler.cli._pid_is_running", lambda pid: False)

    output = StringIO()
    with redirect_stdout(output):
        rc = main(["status", "--output-dir", str(out_dir)])

    assert rc == 0
    payload = json.loads(output.getvalue())
    assert payload["runtime_status"] == "stale"
    assert payload["resume_recommended"] is True
    assert payload["summary"]["jobs_total"] == 3


def test_run_writes_final_runtime_state(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("binja_scheduler.cli.run_scheduler", lambda config: {
        "jobs_total": 1,
        "jobs_succeeded": 1,
        "jobs_failed": 0,
        "jobs_pending": 0,
        "jobs_reused_existing_bndb": 0,
        "scan_error_count": 0,
        "metadata_path": str(config.metadata_path),
    })

    output = StringIO()
    with redirect_stdout(output):
        rc = main([
            "run",
            "--input",
            str(tmp_path),
            "--output-dir",
            str(tmp_path / "out"),
        ])

    assert rc == 0
    runtime = json.loads((tmp_path / "out" / "runtime.json").read_text())
    assert runtime["pid"] is None
    assert runtime["status"] == "completed"
    assert runtime["last_exit_code"] == 0


def test_stop_updates_runtime_when_process_is_running(tmp_path: Path, monkeypatch) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    runtime_path = out_dir / "runtime.json"
    runtime_path.write_text(json.dumps({
        "pid": 4242,
        "status": "running",
        "launch_mode": "detached",
        "log_path": str(out_dir / "scheduler.log"),
        "command": ["python", "-m", "binja_scheduler", "run"],
    }))
    (out_dir / "metadata.json").write_text(json.dumps({
        "run_state": "in_progress",
        "summary": {},
    }))

    signals: list[tuple[int, int]] = []
    monkeypatch.setattr("binja_scheduler.cli.os.killpg", lambda pid, sig: signals.append((pid, sig)))
    monkeypatch.setattr("binja_scheduler.cli._pid_is_running", lambda pid: True)
    monkeypatch.setattr("binja_scheduler.cli._wait_for_process_exit", lambda pid, timeout_seconds: True)

    output = StringIO()
    with redirect_stdout(output):
        rc = main(["stop", "--output-dir", str(out_dir)])

    assert rc == 0
    assert signals == [(4242, 15)]
    runtime = json.loads(runtime_path.read_text())
    assert runtime["pid"] is None
    assert runtime["status"] == "stopped"
    assert runtime["last_exit_code"] == -15


def test_logs_prints_tail_of_scheduler_log(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "scheduler.log").write_text("one\ntwo\nthree\n")

    output = StringIO()
    with redirect_stdout(output):
        rc = main(["logs", "--output-dir", str(out_dir), "--lines", "2"])

    assert rc == 0
    assert output.getvalue() == "two\nthree\n"
