# binja-scheduler

`binja-scheduler` is a small standalone headless Binary Ninja scheduler that:

- accepts a directory or archive as input
- recursively unpacks nested archives
- discovers ELF, PE, and Mach-O binaries
- deduplicates binaries by SHA-256
- writes hash-named `.bndb` files into one flat output directory
- emits a metadata JSON file mapping original inputs to generated BNDBs

The initial heuristic is intentionally simple and predictable:

1. easy pass: one BN analysis thread, 120 second timeout
2. retry passes: a configurable thread ladder, no timeout

By default, binaries are processed in ascending size order so the quick wins
finish first.

## What It Does

Point it at a directory or archive and it will:

1. recursively unpack nested archives
2. identify ELF, PE, and Mach-O binaries
3. hash and flatten them into one BNDB output directory
4. run an easy pass first
5. retry only the failures with a higher Binary Ninja thread count
6. persist enough metadata to resume after a crash or reboot

## Usage

```bash
python -m binja_scheduler run \
    --input ./firmware.zip \
    --output-dir ./bndbs
```

Useful options:

```bash
run
start
status
stop
logs
--metadata ./bndbs/metadata.json
--initial-timeout-seconds 120
--retry-threads 4,8
--initial-concurrency 1
--retry-concurrency 1
--max-unpack-depth 4
--min-size 1024
--resume
--no-resume
--force
```

Detached launch:

```bash
python -m binja_scheduler start \
    --input ./firmware.zip \
    --output-dir ./bndbs
```

Status check:

```bash
python -m binja_scheduler status --output-dir ./bndbs
```

Stop a detached run:

```bash
python -m binja_scheduler stop --output-dir ./bndbs
```

Tail the scheduler log:

```bash
python -m binja_scheduler logs --output-dir ./bndbs --lines 80
```

## Output

The output directory contains:

- `<sha256>.bndb`
- `metadata.json`
- `runtime.json`
- `scheduler.log`

Each metadata entry records:

- SHA-256
- original logical source paths
- final BNDB path
- per-pass attempt history
- final status

`metadata.json` is also the resume journal. The scheduler writes it before jobs
start and after they finish, so a reboot or crash leaves any in-flight work
marked as interrupted and eligible to rerun on the next invocation. Existing
BNDBs are only reused when metadata says the previous attempt completed
successfully.

`start` launches the scheduler in a new session with stdio redirected into
`scheduler.log`, so the supervisor and all Binary Ninja worker subprocesses are
not tied to the terminal that started them.

`stop` terminates the detached scheduler process group and marks the runtime as
stopped. `logs` prints the tail of `scheduler.log` so you can inspect progress
without opening files manually.

## Resume Model

`metadata.json` is the durable job journal.

- Before a job starts, the scheduler records a `running` attempt.
- If the machine reboots or the process dies, the next run rewrites that
  attempt to `interrupted`.
- Interrupted jobs are retried.
- Existing BNDBs are only reused when metadata shows a known-good success.

That gives you an idempotent workflow:

```bash
python -m binja_scheduler start --input ./firmware.zip --output-dir ./bndbs
python -m binja_scheduler status --output-dir ./bndbs
python -m binja_scheduler start --input ./firmware.zip --output-dir ./bndbs
```

The second `start` is safe after a crash, disconnect, or reboot.

## Testing

The test suite covers:

- archive discovery across nested zip, tar, and gzip inputs
- path traversal and symlink rejection during archive extraction
- timeout-to-retry promotion
- detached launch bookkeeping
- detached stop/log inspection
- interrupted detached run followed by resume
- reuse of existing successful BNDBs

Run it with:

```bash
PYTHONPATH=/home/police/binja-scheduler python -m pytest tests -q
```
