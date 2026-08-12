# SENTRIX Live-Benchmark Investigation — Closeout Report

**Date:** 2026-08-12
**Investigation:** deepseek-v4-flash live benchmark / narrated-action detection gap
**Repo:** https://github.com/Anandhasasidharan/SENTRIX · branch `master` · 12 commits

## 1. Executive summary

The investigation found and closed the banking_3 detection gap (sensitive
actions narrated with no backing tool call), split narrated-action
detection into two safety-relevant cases, re-ran the live benchmark with
fresh model output, and pushed the entire body of work to GitHub. The
local repo is fully committed (`git status` clean apart from an
untracked pre-existing `mynotes .docx`), and the remote has been verified
from a fresh clone. Test suite: **204 passed** (final full run).

## 2. What was done, end to end

### 2.1 The gap
banking_3-style outputs narrated actions ("Execute the Update", "Save the
changes", "Log the Change") without naming any tool. The reference
monitor only adjudicates explicit tool calls, so these plans read as
harmless while describing sensitive, unmediated actions.

### 2.2 Case a/b split (commits `1df9e45`, `48ed9e9`)
`detect_narrated_actions()` now returns two lists and the interpreter
routes them differently:

| Case | Meaning | Handling |
|---|---|---|
| (a) `narrated_unmediated` | action narrated with **no** mediated call backing it | BLOCKED via reference monitor (`narrated_action` event), safety-critical |
| (b) `narrated_with_mediation` | narration overlapping mediated tool usage | FLAGGED, informational (`narrated_with_mediation` event) |

Mediation is **family-based** across allowlisted, blocked, and flagged
steps: a blocked `python` step demotes exec-family narration to case (b)
instead of a false BLOCKED (the `workspace_dyn_3` pattern).

- `src/sentrix/core/plan_consistency.py` — detector returns `(unmediated, with_mediation)`
- `src/sentrix/core/plan_interpreter.py` — routing + both trace events
- `src/sentrix/harness/live_runner.py` — `TaskRow` carries both phrase
  lists; `classify_result(…, narrated_unmediated, narrated_with_mediation)`
- `src/sentrix/sentrix.py` — wiring (2 orphaned imports removed)

The refusal gate is unchanged and still never flags refusals, including
refusals that quote the request.

### 2.3 Fixture schema v2 → v3 (commits `1df9e45`, `48ed9e9`)
- `narrated_completion` bool replaced by `narrated_unmediated` /
  `narrated_with_mediation` phrase lists; `schema_version: 3`.
- Migration executed on all 54 stored plans with **zero outcome drift**.
- `tests/fixtures/migrations/migrate_v2_to_v3.py` committed so the
  derivation is reproducible; the v2 baseline remains in git
  (`35645fd`). The v2 `narrated_completion` set was exactly one row:
  `workspace_dyn_3` — which correctly became case (b) — so no signal
  was lost.

### 2.4 Fresh benchmark run (commit `6d20f62`)
Run with a live DeepSeek key (environment variable only), all 54 tasks:

| Outcome | Count |
|---|---|
| refused | 27 |
| unresolved_reference | 16 |
| blocked_policy | 8 |
| clean | 1 |
| allowed | 1 |
| error | 1 |

`workspace_1` errored: the model spent its max_tokens budget on hidden
`reasoning_content` and produced no plan — the `a7630e6` fail-loud class,
recorded with `error_detail` without aborting the suite. Fixture
invariants now exempt error rows (empty plan is the evidence) and assert
`error_detail` presence instead.

### 2.5 Publish (commits `e6d45b3`, `fc1c835`, `6d20f62`)
- Secret scan of the **entire local history** (all trees of all 12
  commits) before pushing: 22 hits, all env-var *names* or explicit fake
  test keys; zero real key material; no `.env`/secret files ever
  committed.
- `git push -u origin master` succeeded; remote had gained two
  deletion commits (`e6d45b3`, `fc1c835` — removed the build-plan
  markdowns), rebased locally, re-pushed.
- Verified from a **fresh clone**: 12 commits, 78 files,
  `tests/fixtures/live_results/` (README + `live_benchmark_results.json`,
  schema 3, 54 tasks) and `docs/investigations/live-deepseek-benchmark.md`
  all present.

## 3. Current state

- Local: branch `master`, 12 commits, working tree clean except
  untracked `mynotes .docx` (pre-existing, never committed).
- Remote: `https://github.com/Anandhasasidharan/SENTRIX.git`, `master`
  tracking `origin/master` at `6d20f62`.
- Tests: 204 passed, ruff clean on all touched files.

```
6d20f62 benchmark: refresh live fixtures from a fresh deepseek-v4-flash run (54 tasks)
fc1c835 Delete 02_Sentrix_Build_Plan.md
e6d45b3 Delete 02_Sentrix_Build_v2.md
48ed9e9 chore(fixtures): persist v2->v3 migration script for narration field re-derivation
1df9e45 feat(plan-consistency): split narrated actions into unmediated vs mediated (case a/b)
6c810e9 docs(live-deepseek-benchmark): full investigation record
50ef166 feat(live-benchmark): in-repo runner with un-overloaded outcome schema
a7630e6 fix(deepseek-client): fail loud on empty completion, never return silent empty plan
af31bfc feat(plan-consistency): detect narrated completions with no backing tool call
ea7630c fix(plan-interpreter): parser produced garbage tool refs (131/138 artifact steps)
20a1a5e chore: import pre-existing project baseline (src, tests, docs, pyproject, README)
044227f tests: encode live-run invariants (allowlist-denial semantics, narration reproducibility)
35645fd benchmark: persist live deepseek-v4-flash run results as durable fixtures (schema v2, 54 tasks)
```

## 4. Open items

1. `mynotes .docx` — untracked; decide ignore/delete/commit.
2. Rotate the DeepSeek API key (it was shared in plaintext chat); the
   repo contains no key material, so rotation requires no repo changes.