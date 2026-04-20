from __future__ import annotations

import json
import os
import signal
import time
from pathlib import Path

from binja_scheduler.cli import main
from binja_scheduler.models import SchedulerConfig
from binja_scheduler.scheduler import run_scheduler


def _write_elf(path: Path, *, payload_size: int = 4096) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\x7fELF" + b"\x00" * payload_size)


def _write_fake_worker(module_path: Path) -> None:
    module_path.write_text(
        "\n".join(
            [
                "from __future__ import annotations",
                "import argparse",
                "import json",
                "import os",
                "import time",
                "from pathlib import Path",
                "",
                "def main() -> int:",
                "    parser = argparse.ArgumentParser()",
                "    parser.add_argument('--binary', type=Path, required=True)",
                "    parser.add_argument('--output', type=Path, required=True)",
                "    parser.add_argument('--analysis-threads', type=int, required=True)",
                "    args = parser.parse_args()",
                "    mode = os.environ.get('FAKE_WORKER_MODE', 'success')",
                "    sleep_seconds = float(os.environ.get('FAKE_WORKER_SLEEP_SECONDS', '0'))",
                "    if sleep_seconds:",
                "        time.sleep(sleep_seconds)",
                "    if mode == 'timeout_then_success' and args.analysis_threads == 1:",
                "        time.sleep(2.0)",
                "    elif mode == 'always_error':",
                "        print(json.dumps({'status': 'error', 'error': 'synthetic failure'}))",
                "        return 1",
                "    args.output.parent.mkdir(parents=True, exist_ok=True)",
                "    args.output.write_text(f'fake-bndb:{args.analysis_threads}')",
                "    print(json.dumps({",
                "        'status': 'success',",
                "        'output_path': str(args.output),",
                "        'analysis_threads': args.analysis_threads,",
                "    }))",
                "    return 0",
                "",
                "if __name__ == '__main__':",
                "    raise SystemExit(main())",
            ]
        )
    )


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text())


def _wait_for(predicate, *, timeout: float = 10.0, interval: float = 0.1) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(interval)
    raise AssertionError("Timed out waiting for condition")


def _reap_child(pid: int) -> bool:
    try:
        waited_pid, _ = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return True
    return waited_pid == pid


def test_run_scheduler_retries_timeout_with_higher_thread_count(tmp_path: Path, monkeypatch) -> None:
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "out"
    metadata_path = output_dir / "metadata.json"
    worker_dir = tmp_path / "worker"
    worker_dir.mkdir()
    _write_fake_worker(worker_dir / "fake_worker.py")
    _write_elf(input_dir / "sample.bin")

    monkeypatch.setenv("BINJA_SCHEDULER_WORKER_MODULE", "fake_worker")
    monkeypatch.setenv("PYTHONPATH", str(worker_dir))
    monkeypatch.setenv("FAKE_WORKER_MODE", "timeout_then_success")

    summary = run_scheduler(
        SchedulerConfig(
            input_path=input_dir,
            output_dir=output_dir,
            metadata_path=metadata_path,
            initial_timeout_seconds=1,
            retry_threads=(4,),
        )
    )

    assert summary["jobs_succeeded"] == 1
    data = _read_json(metadata_path)
    assert data["summary"]["jobs_failed"] == 0
    job = data["jobs"][0]
    assert job["status"] == "success"
    assert [attempt["status"] for attempt in job["attempts"]] == ["timeout", "success"]
    assert [attempt["analysis_threads"] for attempt in job["attempts"]] == [1, 4]
    assert job["completed_pass"] == "retry-pass-1"
    assert Path(job["bndb_path"]).read_text() == "fake-bndb:4"


def test_detached_start_can_resume_after_interruption(tmp_path: Path, monkeypatch) -> None:
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "out"
    worker_dir = tmp_path / "worker"
    metadata_path = output_dir / "metadata.json"
    runtime_path = output_dir / "runtime.json"
    worker_dir.mkdir()
    _write_fake_worker(worker_dir / "fake_worker.py")
    _write_elf(input_dir / "sample.bin")

    current_pythonpath = os.environ.get("PYTHONPATH", "")
    monkeypatch.setenv("BINJA_SCHEDULER_WORKER_MODULE", "fake_worker")
    monkeypatch.setenv(
        "PYTHONPATH",
        str(worker_dir) if not current_pythonpath else f"{worker_dir}{os.pathsep}{current_pythonpath}",
    )
    monkeypatch.setenv("FAKE_WORKER_SLEEP_SECONDS", "5")

    assert main([
        "start",
        "--input",
        str(input_dir),
        "--output-dir",
        str(output_dir),
    ]) == 0

    _wait_for(lambda: metadata_path.exists() and _read_json(metadata_path).get("run_state") == "in_progress")
    _wait_for(lambda: runtime_path.exists() and _read_json(runtime_path).get("pid"))
    pid = int(_read_json(runtime_path)["pid"])
    os.killpg(pid, signal.SIGKILL)
    _wait_for(lambda: _reap_child(pid))

    monkeypatch.delenv("FAKE_WORKER_SLEEP_SECONDS", raising=False)

    assert main([
        "start",
        "--input",
        str(input_dir),
        "--output-dir",
        str(output_dir),
    ]) == 0

    _wait_for(lambda: metadata_path.exists() and _read_json(metadata_path).get("run_state") == "completed")
    data = _read_json(metadata_path)
    job = data["jobs"][0]
    assert job["status"] == "success"
    assert job["attempts"][0]["status"] == "interrupted"
    assert job["attempts"][1]["status"] == "success"
    runtime = _read_json(runtime_path)
    assert runtime["status"] == "completed"
    assert runtime["last_exit_code"] == 0
