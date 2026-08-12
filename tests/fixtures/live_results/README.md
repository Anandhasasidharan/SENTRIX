# Live benchmark fixtures

This directory holds the durable evidence for the deepseek-v4-flash live
benchmark (see `docs/investigations/live-deepseek-benchmark.md`).

The original run's outputs lived in `/tmp/opencode/` and were lost to a
container reset before they could be moved into the repo. The rebuilt driver
(`examples/live_benchmark.py`) writes its results **directly here** — never
to /tmp — so the re-run repopulates this directory and the regression suite
(`tests/test_live_fixtures.py`) consumes it.

- `live_benchmark_results.json` — schema_version 3, one `TaskRow` per task
  (see `src/sentrix/harness/live_runner.py` for the schema contract).

Schema v3 splits the v2 `narrated_completion` boolean into two explicit
phrase lists: `narrated_unmediated` (case (a), action narrated with no
mediated call — BLOCKED) and `narrated_with_mediation` (case (b),
narration overlapping mediated tool usage — FLAGGED, informational).
The v2→v3 derivation is reproducible via
`tests/fixtures/migrations/migrate_v2_to_v3.py`; the v2 source of truth
remains in git history (commit `35645fd`).

Regenerate with:

    DEEPSEEK_API_KEY=... python -m examples.live_benchmark --suite all
