"""Binary Ninja analysis worker subprocess."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path


def analyze_binary(binary_path: Path, output_path: Path, *, analysis_threads: int) -> dict:
    """Analyze one binary and save a BNDB."""

    import binaryninja as bn

    settings = bn.Settings()
    settings.set_integer("analysis.limits.workerThreadCount", int(analysis_threads))

    started = time.monotonic()
    bv = bn.load(str(binary_path))
    if bv is None:
        raise RuntimeError(f"Binary Ninja failed to open {binary_path}")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        bv.update_analysis_and_wait()
        if output_path.exists():
            output_path.unlink()
        created = bv.create_database(str(output_path))
        if created is False:
            raise RuntimeError(f"Binary Ninja failed to create BNDB {output_path}")
    finally:
        try:
            bv.file.close()
        except Exception:
            pass

    return {
        "status": "success",
        "binary_path": str(binary_path),
        "output_path": str(output_path),
        "analysis_threads": int(analysis_threads),
        "elapsed_seconds": time.monotonic() - started,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--analysis-threads", type=int, required=True)
    args = parser.parse_args()

    try:
        result = analyze_binary(
            args.binary.expanduser().resolve(),
            args.output.expanduser().resolve(),
            analysis_threads=args.analysis_threads,
        )
        print(json.dumps(result))
        return 0
    except Exception as exc:
        print(json.dumps({
            "status": "error",
            "binary_path": str(args.binary),
            "output_path": str(args.output),
            "analysis_threads": args.analysis_threads,
            "error": str(exc),
        }))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
